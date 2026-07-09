"""
SMB_RECON_ENUM
SMB Reconnaissance tren HMI host — lateral movement discovery.
MITRE: T0842 (Network Share Discovery)

Goi tu bash:
  python -m attacks_ext.smb_enum \
      --target 192.168.210.31 --duration 120 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import socket
import time
import random
from attacks_ext.config_ext import base_parser, write_label

SMBS = ["C$", "ADMIN$", "IPC$", "Users", "WinCC", "SCADA", "HMI", "PLC",
        "Engineering", "Project", "Backup", "Config", "Data", "Logs", "Share"]

RPC_PIPES = ["srvsvc", "wkssvc", "samr", "lsarpc", "netlogon", "svcctl", "winreg", "atsvc"]

SMB2_NEGOTIATE = bytes([
    0x00,0x00,0x00,0x2e,0xfe,0x53,0x4d,0x42,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x1f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x24,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x02,
])


def smb2_neg(ip, port=445, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(SMB2_NEGOTIATE)
        s.recv(256)
        s.close()
        return True
    except Exception:
        return False


def run(args):
    label_prefix = "SMB_RECON_ENUM"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s target={args.target}")

    probes = 0
    try:
        print(f"[*] SMB Recon -> {args.target}")
        end_time = time.time() + args.duration

        while time.time() < end_time:
            # Round-robin SMB2 negotiate
            for _ in range(5):
                smb2_neg(args.target)
                probes += 1
                time.sleep(random.uniform(0.2, 0.5))

            # Share probe burst
            for share in SMBS:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    s.connect_ex((args.target, 445))
                    s.close()
                    probes += 1
                except Exception:
                    pass
                time.sleep(0.1)

            # RPC pipe probe
            for _ in RPC_PIPES:
                smb2_neg(args.target)
                probes += 1
                time.sleep(random.uniform(0.3, 0.6))

            if probes % 30 == 0:
                print(f"  [{probes}] SMB probes sent")

    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"probes={probes}")


def main():
    p = base_parser("SMB Reconnaissance Enumeration")
    p.add_argument("--target", default="192.168.210.31")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
