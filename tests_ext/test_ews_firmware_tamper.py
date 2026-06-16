#!/usr/bin/env python3
"""
tests_ext/test_ews_firmware_tamper.py
Test: Burst write + restore DB1 (giả lập firmware upload).

Chạy:
  python tests_ext/test_ews_firmware_tamper.py --target 192.168.1.10 --rack 0 --slot 1
"""

import argparse
import time


def run(target, rack, slot):
    import snap7

    print(f"\n{'='*50}")
    print(f"[TEST] EWS_FIRMWARE_TAMPER — Burst write + restore")
    print(f"       Target: {target}  Rack={rack}  Slot={slot}")
    print(f"{'='*50}\n")

    c = snap7.client.Client()

    try:
        c.connect(target, rack, slot)
        print(f"  [+] Kết nối PLC thành công")

        original = c.db_read(1, 0, 10)
        print(f"  [READ] DB1 gốc: {original.hex()}")

        print(f"  [BURST WRITE] 5 lần liên tiếp...")
        for i in range(5):
            fake_chunk = bytes([(i * 10) % 256] * 10)
            c.db_write(1, 0, fake_chunk)
            print(f"    #{i+1} {fake_chunk.hex()}")
            time.sleep(0.2)

        c.db_write(1, 0, bytes(original))
        verify = c.db_read(1, 0, 10)
        print(f"  [RESTORE] DB1 sau khôi phục: {verify.hex()}")

        match = verify == original
        print(f"\n  {'='*50}")
        if match:
            print(f"  [RESULT] PASS - Burst write + restore OK")
        else:
            print(f"  [RESULT] WARN - Write OK nhưng restore lệch")
        print(f"  {'='*50}\n")

    except Exception as e:
        print(f"\n  {'='*50}")
        print(f"  [RESULT] FAIL - {e}")
        print(f"  {'='*50}\n")
    finally:
        if c.get_connected():
            c.disconnect()


def main():
    p = argparse.ArgumentParser(description="Test EWS Firmware Tamper")
    p.add_argument("--target", default="192.168.1.10", help="PLC IP")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    args = p.parse_args()
    run(args.target, args.rack, args.slot)


if __name__ == "__main__":
    main()
