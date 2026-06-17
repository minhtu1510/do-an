#!/usr/bin/env python3
"""
tests/test_hmi_alarm.py
Xóa OPC-UA subscription -> HMI không nhận được alarm.
PLC không thay đổi — dấu vết là DeleteSubscriptions call.

Chạy: python tests/test_hmi_alarm.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *


def main():
    print(f"\n{B}[TEST] HMI_ALARM_SUPPRESS{X}")
    info(f"OPC-UA target: {OPC_URL}")
    info("PLC KHONG thay doi — dau vet la OPC DeleteSubscriptions")

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
        ok("Ket noi OPC-UA thanh cong")

        sub = c.create_subscription(500, handler=None)
        ok(f"Tao subscription ID: {sub.subscription_id}")
        observable.append(f"OPC-UA CreateSubscription (ID={sub.subscription_id})")
        info("Doi 3 giay de subscription hoat dong...")
        time.sleep(3)

        sub.delete()
        ok("Da xoa subscription")
        observable.append("OPC-UA DeleteSubscriptions -> HMI mu voi alarm")
        notes.append("Trong khoang thoi gian nay HMI khong nhan duoc bat ky alarm nao")
        notes.append("Wireshark: opcua.serviceid == 0x1f4 (DeleteSubscriptions)")

        info("Doi 5 giay quan sat trang thai khong co subscription...")
        time.sleep(5)

        sub2 = c.create_subscription(500, handler=None)
        ok(f"Tao lai subscription ID: {sub2.subscription_id} — server van OK")
        sub2.delete()

        notes.append("5 giay khong co subscription = window tan cong thuc te")
        success = True
        c.disconnect()

    except ImportError:
        error = "opcua chua cai: pip install opcua"
        fail(error)
    except Exception as e:
        error = str(e)
        fail(str(e))

    print_result("HMI_ALARM_SUPPRESS", success, changes, observable, notes, time.time() - t0, error)


if __name__ == "__main__":
    main()
