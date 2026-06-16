#!/usr/bin/env python3
"""
tests_ext/test_ews_rogue_engineer.py
Test: Kết nối S7 trực tiếp từ IP attacker, đọc CPU info + DB.

Chạy:
  python tests_ext/test_ews_rogue_engineer.py --target 192.168.1.10 --rack 0 --slot 1
"""

import argparse
import time


def run(target, rack, slot):
    import snap7

    print(f"\n{'='*50}")
    print(f"[TEST] EWS_ROGUE_ENGINEER")
    print(f"       Target: {target}  Rack={rack}  Slot={slot}")
    print(f"{'='*50}\n")

    c = snap7.client.Client()

    try:
        c.connect(target, rack, slot)
        print(f"  [+] Kết nối thành công từ IP attacker!")

        info = c.get_cpu_info()
        module = info.ModuleTypeName.decode() if isinstance(info.ModuleTypeName, bytes) else str(info.ModuleTypeName)
        serial = info.SerialNumber.decode() if isinstance(info.SerialNumber, bytes) else str(info.SerialNumber)

        print(f"  [+] Module: {module}")
        print(f"  [+] Serial:  {serial}")
        print(f"  [+] State:   {c.get_cpu_state()}")

        data = c.db_read(1, 0, 10)
        print(f"  [+] DB1[0:10] = {data.hex()}")

        print(f"\n  {'='*50}")
        print(f"  [RESULT] PASS - EWS_ROGUE_ENGINEER hoạt động")
        print(f"  {'='*50}\n")

    except Exception as e:
        print(f"\n  {'='*50}")
        print(f"  [RESULT] FAIL - {e}")
        print(f"  {'='*50}\n")
    finally:
        if c.get_connected():
            c.disconnect()


def main():
    p = argparse.ArgumentParser(description="Test EWS Rogue Engineer")
    p.add_argument("--target", default="192.168.1.10", help="PLC IP")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    args = p.parse_args()
    run(args.target, args.rack, args.slot)


if __name__ == "__main__":
    main()
