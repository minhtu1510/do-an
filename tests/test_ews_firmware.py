#!/usr/bin/env python3
"""
tests/test_ews_firmware.py
Burst write nhiều chunk với interval ngắn — giả lập firmware upload pattern.

Chạy: python tests/test_ews_firmware.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *

BURST_COUNT = 10
BURST_INTERVAL = 0.15


def main():
    print(f"\n{B}[TEST] EWS_FIRMWARE_TAMPER{X}")
    info(f"Burst {BURST_COUNT} writes, interval {BURST_INTERVAL}s")

    changes = []
    observable = []
    notes = []
    error = None
    success = False
    t0 = time.time()

    try:
        import snap7

        c = snap7.client.Client()
        c.connect(PLC_IP, RACK, SLOT)
        ok("Ket noi S7 thanh cong")

        before = plc_snapshot(c)
        original = bytes(c.db_read(1, 0, 10))
        info(f"DB1 goc: {original.hex()}")

        for i in range(BURST_COUNT):
            chunk = bytes([(i * 17) % 256] * 10)
            c.db_write(1, 0, chunk)
            info(f"  Write #{i+1:02d}: {chunk.hex()}")
            time.sleep(BURST_INTERVAL)

        observable.append(f"S7 burst: {BURST_COUNT} writes trong {BURST_COUNT * BURST_INTERVAL:.1f}s")
        observable.append(f"Interval deu dan {BURST_INTERVAL}s — bat thuong so voi normal ops")

        after = plc_snapshot(c)
        changes = plc_diff(before, after)

        c.db_write(1, 0, original)
        verify = bytes(c.db_read(1, 0, 10))
        if verify == original:
            ok("Khoi phuc thanh cong")
        else:
            warn(f"Khoi phuc lech: {verify.hex()}")

        notes.append("CIC feature: Fwd Packet Length Mean cao bat thuong")
        notes.append("CIC feature: Flow Duration ngan, Packet Count cao")
        success = True
        c.disconnect()

    except ImportError:
        error = "python-snap7 chua cai"
        fail(error)
    except Exception as e:
        error = str(e)
        fail(str(e))

    print_result("EWS_FIRMWARE_TAMPER", success, changes, observable, notes, time.time() - t0, error)


if __name__ == "__main__":
    main()
