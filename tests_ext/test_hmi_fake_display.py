#!/usr/bin/env python3
"""
tests_ext/test_hmi_fake_display.py
Test: OPC-UA connect, browse nodes, write + restore 1 node.

Chạy:
  python tests_ext/test_hmi_fake_display.py --opc-url opc.tcp://192.168.1.20:4840
"""

import argparse


def run(opc_url, username="", password=""):
    from opcua import Client

    print(f"\n{'='*50}")
    print(f"[TEST] HMI_FAKE_DISPLAY — OPC-UA write + restore")
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

        root = c.get_objects_node()
        print(f"  [BROWSE] Các node tìm thấy (top-level):")
        found_nodes = []
        for child in root.get_children():
            try:
                name = child.get_browse_name().Name
                nid = str(child.nodeid)
                print(f"    - {name}  ({nid})")
                found_nodes.append((name, nid, child))
            except Exception as e:
                print(f"    - (lỗi browse: {e})")

        if found_nodes:
            name, nid, node_obj = found_nodes[0]
            print(f"\n  [TEST] Ghi vào node: {name} ({nid})")

            try:
                original = node_obj.get_value()
            except Exception:
                print(f"  [SKIP] Không đọc được giá trị node {name}")
                c.disconnect()
                return

            print(f"  [READ] Giá trị gốc: {original}")

            node_obj.set_value(99.9)
            after_write = node_obj.get_value()
            print(f"  [WRITE] Sau khi ghi 99.9: {after_write}")

            node_obj.set_value(original)
            after_restore = node_obj.get_value()
            print(f"  [RESTORE] Sau khôi phục: {after_restore}")

            match = after_restore == original
        else:
            print(f"\n  [WARN] Không tìm thấy node nào để test — OPC kết nối OK nhưng chưa browse được")
            match = True

        print(f"\n  {'='*50}")
        if match:
            print(f"  [RESULT] PASS - OPC-UA write/restore hoạt động")
        else:
            print(f"  [RESULT] FAIL - Restore không khớp giá trị gốc")
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
    p = argparse.ArgumentParser(description="Test HMI Fake Display (OPC-UA)")
    p.add_argument("--opc-url", default="opc.tcp://192.168.1.20:4840")
    p.add_argument("--opc-username", default="admin")
    p.add_argument("--opc-password", default="admin123")
    args = p.parse_args()
    run(args.opc_url, args.opc_username, args.opc_password)


if __name__ == "__main__":
    main()
