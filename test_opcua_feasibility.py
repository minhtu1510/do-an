#!/usr/bin/env python3
"""
test_opcua_feasibility.py — Kiem tra kha nang tan cong OPC UA THAT tren PLC/HMI.

CHI DOC (read-only): connect + lay endpoint/security policy + browse namespace
+ doc thu 1 gia tri. KHONG ghi, KHONG xoa subscription, KHONG dung gi ca.
Dung de xac nhan kha thi TRUOC KHI dua OPC UA attack vao kich ban chinh thuc.

Cai thu vien (neu chua co):
  pip install opcua

Cach dung:
  python test_opcua_feasibility.py --url opc.tcp://192.168.210.31:4840
  python test_opcua_feasibility.py --url opc.tcp://192.168.210.31:4840 --username admin --password admin123
  python test_opcua_feasibility.py --url opc.tcp://192.168.210.31:4840 --read-node "ns=3;s=\"DB1\".\"TimeG1\""

Chay xong, copy toan bo log tren terminal gui lai de danh gia.
"""

import argparse
import sys
import time


def log(tag, msg):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] [{tag:<8}] {msg}", flush=True)


def check_endpoints(url):
    log("STEP1", f"Lay danh sach endpoint/security policy tu {url} (chua tao session)...")
    try:
        from opcua import Client
    except ImportError:
        log("FATAL", "Thieu thu vien 'opcua'. Cai bang: pip install opcua")
        sys.exit(1)

    client = Client(url, timeout=5)
    try:
        endpoints = client.connect_and_get_server_endpoints()
        log("OK", f"Server tra ve {len(endpoints)} endpoint(s):")
        for i, ep in enumerate(endpoints):
            try:
                sec_policy = str(ep.SecurityPolicyUri).split("#")[-1]
                sec_mode = str(ep.SecurityMode)
                log("ENDPOINT", f"  [{i}] policy={sec_policy} mode={sec_mode}")
            except Exception as e:
                log("WARN", f"  [{i}] khong doc duoc chi tiet endpoint: {e}")
        return endpoints
    except Exception as e:
        log("FAIL", f"Khong lay duoc endpoint list: {type(e).__name__}: {e}")
        return None
    finally:
        try:
            client.disconnect()
        except Exception:
            pass


def try_anonymous_connect(url):
    log("STEP2", "Thu ket noi ANONYMOUS (khong username/password)...")
    from opcua import Client
    client = Client(url, timeout=5)
    try:
        client.connect()
        log("OK", "Ket noi anonymous THANH CONG -> server cho phep truy cap khong xac thuc.")
        return client
    except Exception as e:
        log("FAIL", f"Ket noi anonymous bi tu choi: {type(e).__name__}: {e}")
        try:
            client.disconnect()
        except Exception:
            pass
        return None


def try_auth_connect(url, username, password):
    log("STEP2B", f"Thu ket noi voi username='{username}'...")
    from opcua import Client
    client = Client(url, timeout=5)
    client.set_user(username)
    client.set_password(password or "")
    try:
        client.connect()
        log("OK", f"Ket noi voi cred '{username}:{password}' THANH CONG.")
        return client
    except Exception as e:
        log("FAIL", f"Ket noi voi cred '{username}:{password}' that bai: {type(e).__name__}: {e}")
        try:
            client.disconnect()
        except Exception:
            pass
        return None


def browse_nodes(client, max_depth=2, max_nodes=200):
    log("STEP3", "Browse namespace (chi doc, khong ghi)...")
    discovered = []

    def _walk(node, depth, prefix=""):
        if depth > max_depth or len(discovered) >= max_nodes:
            return
        try:
            children = node.get_children()
        except Exception as e:
            log("WARN", f"{prefix}khong browse duoc: {e}")
            return
        for child in children:
            if len(discovered) >= max_nodes:
                log("WARN", f"Da dat gioi han {max_nodes} node, dung browse som de tranh lam qua tai server.")
                return
            try:
                name = child.get_browse_name().Name
                node_id = str(child.nodeid)
                node_class = child.get_node_class()
                log("NODE", f"{prefix}{name}  (NodeId={node_id}, class={node_class})")
                discovered.append({"name": name, "node_id": node_id, "class": str(node_class)})
                _walk(child, depth + 1, prefix + "  ")
            except Exception as e:
                log("WARN", f"{prefix}loi doc 1 node con: {e}")

    try:
        root_objects = client.get_objects_node()
        _walk(root_objects, 0)
    except Exception as e:
        log("FAIL", f"Khong browse duoc Objects node: {e}")

    log("SUMMARY", f"Tong cong tim thay {len(discovered)} node (gioi han {max_nodes}).")
    return discovered


def try_read_one_value(client, node_id):
    log("STEP4", f"Thu DOC (read-only) gia tri node {node_id}...")
    try:
        node = client.get_node(node_id)
        value = node.get_value()
        log("OK", f"Doc thanh cong: {node_id} = {value}")
        return value
    except Exception as e:
        log("FAIL", f"Doc that bai: {type(e).__name__}: {e}")
        return None


def main():
    p = argparse.ArgumentParser(description="Kiem tra kha thi tan cong OPC UA (read-only, an toan)")
    p.add_argument("--url", required=True, help="vd: opc.tcp://192.168.210.31:4840")
    p.add_argument("--username", default=None)
    p.add_argument("--password", default=None)
    p.add_argument("--read-node", default=None, help='NodeId cu the muon thu doc, vd ns=3;s="DB1"."TimeG1"')
    p.add_argument("--max-depth", type=int, default=2, help="Do sau browse namespace (default 2)")
    args = p.parse_args()

    log("START", f"=== Kiem tra OPC UA feasibility: {args.url} ===")
    log("WARN", "Script nay CHI DOC (connect + browse + read 1 gia tri). Khong ghi/xoa/suppress gi ca.")

    check_endpoints(args.url)

    client = try_anonymous_connect(args.url)
    auth_mode = "anonymous"

    if client is None and args.username:
        client = try_auth_connect(args.url, args.username, args.password)
        auth_mode = f"user={args.username}"

    if client is None:
        log("RESULT", "KHONG ket noi duoc bang cach nao da thu.")
        log("RESULT", "=> Chua kha thi voi cau hinh hien tai (co the do security policy yeu cau cert/auth khac,")
        log("RESULT", "   hoac OPC UA server chua bat tren PLC). Day van la thong tin huu ich (outcome=blocked).")
        sys.exit(1)

    try:
        discovered = browse_nodes(client, max_depth=args.max_depth)

        if args.read_node:
            try_read_one_value(client, args.read_node)
        elif discovered:
            first = discovered[0]
            log("INFO", f"Thu doc node dau tien tim duoc: {first['node_id']}")
            try_read_one_value(client, first["node_id"])
        else:
            log("INFO", "Khong tim thay node nao de thu doc.")
    finally:
        try:
            client.disconnect()
        except Exception:
            pass
        log("END", f"Da ngat ket noi. Auth mode dung duoc: {auth_mode}")

    log("RESULT", "=== HOAN TAT - copy toan bo log tren gui lai de danh gia kha thi ===")


if __name__ == "__main__":
    main()
