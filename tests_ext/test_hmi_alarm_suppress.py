#!/usr/bin/env python3
"""
tests_ext/test_hmi_alarm_suppress.py
Test: OPC-UA create subscription -> delete subscription.

Chạy:
  python tests_ext/test_hmi_alarm_suppress.py --opc-url opc.tcp://192.168.1.20:4840
"""

import argparse
import time


def run(opc_url, username="", password=""):
    from opcua import Client

    print(f"\n{'='*50}")
    print(f"[TEST] HMI_ALARM_SUPPRESS — Create + Delete OPC subscription")
    print(f"       OPC: {opc_url}")
    print(f"{'='*50}\n")

    c = Client(opc_url)

    try:
        if username:
            c.set_user(username)
        if password:
            c.set_password(password)
        c.connect()
        print(f"  [+] Kết nối OPC-UA thành công")

        sub = c.create_subscription(500, handler=None)
        print(f"  [+] Tạo subscription ID: {sub.subscription_id}")
        time.sleep(2)

        sub.delete()
        print(f"  [+] Xóa subscription thành công")

        print(f"\n  {'='*50}")
        print(f"  [RESULT] PASS - Create/Delete subscription OK")
        print(f"  {'='*50}\n")

    except ImportError:
        print(f"  [SKIP] opcua chưa cài: pip install opcua")
    except Exception as e:
        print(f"\n  {'='*50}")
        print(f"  [RESULT] FAIL - {e}")
        print(f"  {'='*50}\n")
    finally:
        try:
            c.disconnect()
        except Exception:
            pass


def main():
    p = argparse.ArgumentParser(description="Test HMI Alarm Suppress")
    p.add_argument("--opc-url", default="opc.tcp://192.168.1.20:4840")
    p.add_argument("--opc-username", default="admin")
    p.add_argument("--opc-password", default="admin123")
    args = p.parse_args()
    run(args.opc_url, args.opc_username, args.opc_password)


if __name__ == "__main__":
    main()
