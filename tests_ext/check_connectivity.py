#!/usr/bin/env python3
"""
tests_ext/check_connectivity.py
Kiểm tra kết nối cơ bản: ping PLC, check port S7/OPC, snap7.

Chạy:
  python tests_ext/check_connectivity.py --target 192.168.1.10

  python tests_ext/check_connectivity.py --target 192.168.1.10 \
      --hmi-ip 192.168.1.20 --opc-port 4840 --hmi-port 5000
"""

import argparse
import socket
import subprocess
import time


def ping_host(ip, count=3):
    """Ping target, return success."""
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-W", "1", ip],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def check_tcp_port(ip, port, timeout=2):
    """TCP connect test."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def check_http(ip, port, timeout=3):
    """HTTP GET check."""
    try:
        import urllib.request
        url = f"http://{ip}:{port}"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status in [200, 301, 302]
    except Exception:
        return False


def check_snap7(ip, rack, slot):
    """Test snap7 connect to PLC."""
    try:
        import snap7
        c = snap7.client.Client()
        c.connect(ip, rack, slot)
        state = str(c.get_cpu_state())
        info = c.get_cpu_info()
        module = info.ModuleTypeName.decode() if isinstance(info.ModuleTypeName, bytes) else str(info.ModuleTypeName)
        c.disconnect()
        return True, f"S7 OK: {module} (state={state})"
    except Exception as e:
        return False, f"S7 FAIL: {e}"


def main():
    p = argparse.ArgumentParser(description="Kiểm tra kết nối ICS testbed")
    p.add_argument("--target", default="192.168.1.10", help="PLC IP")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    p.add_argument("--hmi-ip", default="", help="HMI IP (auto từ subnet target)")
    p.add_argument("--opc-port", type=int, default=4840)
    p.add_argument("--hmi-port", type=int, default=5000)
    args = p.parse_args()

    if not args.hmi_ip:
        prefix = ".".join(args.target.split(".")[:3])
        args.hmi_ip = f"{prefix}.20"

    print()
    print("=" * 60)
    print("  CHECKLIST — ICS Testbed Connectivity")
    print(f"  PLC: {args.target}  |  HMI: {args.hmi_ip}")
    print("=" * 60)
    print()

    results = []
    passed = 0
    failed = 0

    # 1. Ping PLC
    ok = ping_host(args.target)
    results.append(("Ping PLC", ok))
    print(f"  {'✅' if ok else '❌'} Ping {args.target}")

    # 2. S7 port 102
    ok = check_tcp_port(args.target, 102)
    results.append(("S7 port 102", ok))
    print(f"  {'✅' if ok else '❌'} TCP {args.target}:102 (S7)")

    # 3. Snap7 connect
    ok, msg = check_snap7(args.target, args.rack, args.slot)
    results.append(("Snap7 S7", ok))
    print(f"  {'✅' if ok else '❌'} {msg}")

    # 4. Ping HMI
    ok = ping_host(args.hmi_ip)
    results.append(("Ping HMI", ok))
    print(f"  {'✅' if ok else '❌'} Ping {args.hmi_ip}")

    # 5. OPC-UA port 4840
    ok = check_tcp_port(args.hmi_ip, args.opc_port)
    results.append((f"OPC-UA port {args.opc_port}", ok))
    print(f"  {'✅' if ok else '❌'} TCP {args.hmi_ip}:{args.opc_port} (OPC-UA)")

    # 6. HMI web port
    ok = check_http(args.hmi_ip, args.hmi_port)
    results.append((f"HMI web port {args.hmi_port}", ok))
    print(f"  {'✅' if ok else '❌'} HTTP {args.hmi_ip}:{args.hmi_port}")

    print()
    print("=" * 60)
    for name, ok in results:
        status = "PASS" if ok else "FAIL"
        mark = "✅" if ok else "❌"
        print(f"  {mark} {status:4s}  {name}")
    print("=" * 60)
    print(f"  Summary: {sum(1 for _, ok in results if ok)}/{len(results)} checks passed")
    print()


if __name__ == "__main__":
    main()
