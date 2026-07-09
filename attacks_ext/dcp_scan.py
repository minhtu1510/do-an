"""
DCP_IDENTIFY_SCAN
Kỹ thuật: Profinet DCP Identify broadcast để tìm thiết bị Siemens.
Layer 2, EtherType 0x8892, KHÔNG ảnh hưởng PLC.
MITRE: T0846 — Remote System Discovery.

Gọi từ bash:
  python -m attacks_ext.dcp_scan \
      --duration 60 --iface eth0 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import time
from attacks_ext.config_ext import base_parser, write_label


def run(args):
    label_prefix = "DCP_IDENTIFY_SCAN"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s iface={args.iface}")

    sent = 0
    try:
        from scapy.all import Ether, Raw, sendp, conf
        conf.verb = 0

        dcp_identify = (
            b"\xfe\xfe"           # FrameID
            + bytes([0x05, 0x00])  # Service ID + Type (Identify)
            + bytes([0x00, 0x00])  # XID
            + bytes([0x00, 0x00])  # Response delay
            + bytes([0x00, 0x06])  # DCP length
            + bytes(6)             # padding
        )

        print(f"[*] DCP Identify Scan — iface={args.iface}")
        print(f"[*] EtherType 0x8892, Broadcast L2")

        end_time = time.time() + args.duration
        while time.time() < end_time:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff", type=0x8892) / Raw(load=dcp_identify)
            sendp(pkt, iface=args.iface, verbose=False)
            sent += 1
            if sent % 20 == 0:
                print(f"  [{sent}] DCP Identify frames sent")
            time.sleep(2)

    except ImportError:
        print("[ERR] scapy not installed: pip install scapy")
    except PermissionError:
        print("[ERR] Need Admin/root for raw L2 frames")
    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"frames={sent}")


def main():
    p = base_parser("DCP Identify Scan (Profinet Layer 2 Discovery)")
    p.add_argument("--iface", default="eth0")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
