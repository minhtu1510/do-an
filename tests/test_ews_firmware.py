#!/usr/bin/env python3
"""
tests/test_ews_firmware.py
Burst write nhiều chunk với interval ngắn — giả lập firmware upload pattern.
Tự scan DB tồn tại, nếu không có thì dùng Marker area.

Chạy: python tests/test_ews_firmware.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *

BURST_COUNT = 10
BURST_INTERVAL = 0.15


def scan_available_dbs(client, max_db=20):
    """Scan DB1..max_db, trả về list DB tồn tại."""
    found = []
    info(f"Scanning DB1..DB{max_db}...")
    for db_num in range(1, max_db + 1):
        try:
            client.db_read(db_num, 0, 1)
            found.append(db_num)
            ok(f"  DB{db_num} ton tai")
        except Exception:
            pass
    return found


def burst_write_db(client, db_num, observable):
    """Burst write vào DB."""
    original = bytes(client.db_read(db_num, 0, 10))
    info(f"DB{db_num} goc: {original.hex()}")

    for i in range(BURST_COUNT):
        chunk = bytes([(i * 17) % 256] * 10)
        client.db_write(db_num, 0, chunk)
        info(f"  Write #{i+1:02d}: {chunk.hex()}")
        time.sleep(BURST_INTERVAL)

    observable.append(f"S7 burst: {BURST_COUNT} writes DB{db_num} trong {BURST_COUNT * BURST_INTERVAL:.1f}s")

    client.db_write(db_num, 0, original)
    verify = bytes(client.db_read(db_num, 0, 10))
    if verify == original:
        ok(f"Khoi phuc DB{db_num} thanh cong")
    else:
        warn(f"Khoi phuc lech: {verify.hex()}")


def burst_write_marker(client, observable):
    """Fallback: burst write vào Marker area (luôn tồn tại)."""
    try:
        from snap7.type import Areas
    except ImportError:
        from snap7.types import Areas

    warn("Khong co DB nao — chuyen sang Marker area (MB0)")
    original = bytes(client.read_area(Areas.MK, 0, 0, 10))
    info(f"MB0 goc: {original.hex()}")

    for i in range(BURST_COUNT):
        chunk = bytearray([(i * 17) % 256] * 10)
        client.write_area(Areas.MK, 0, 0, chunk)
        info(f"  Write #{i+1:02d}: {chunk.hex()}")
        time.sleep(BURST_INTERVAL)

    observable.append(f"S7 burst: {BURST_COUNT} writes MK area trong {BURST_COUNT * BURST_INTERVAL:.1f}s")

    client.write_area(Areas.MK, 0, 0, bytearray(original))
    verify = bytes(client.read_area(Areas.MK, 0, 0, 10))
    if verify == original:
        ok("Khoi phuc Marker thanh cong")
    else:
        warn(f"Khoi phuc lech: {verify.hex()}")


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

        # Auto scan DB
        dbs = scan_available_dbs(c)

        if dbs:
            target_db = dbs[0]
            info(f"Dung DB{target_db} de burst write")
            burst_write_db(c, target_db, observable)
            notes.append(f"Target: DB{target_db} (auto scan)")
        else:
            burst_write_marker(c, observable)
            notes.append("Target: Marker area MB0 (fallback — khong co DB)")

        observable.append(f"Interval deu dan {BURST_INTERVAL}s — bat thuong so voi normal ops")

        after = plc_snapshot(c)
        changes = plc_diff(before, after)

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
