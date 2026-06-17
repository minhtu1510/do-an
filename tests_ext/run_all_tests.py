#!/usr/bin/env python3
"""
tests_ext/run_all_tests.py
Chạy toàn bộ test trên Windows & Linux — không phụ thuộc bash.

Usage:
  python tests_ext/run_all_tests.py 192.168.210.211 192.168.210.20
  python tests_ext/run_all_tests.py 192.168.210.211 192.168.210.20 --iface "\\Device\\NPF_{GUID}"
"""

import argparse
import subprocess
import sys
import socket
import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent.parent

TESTS = [
    ("Ping PLC",          lambda a: _ping(a.target)),
    ("TCP S7 port 102",   lambda a: _tcp_port(a.target, 102)),
    ("Snap7 connect",     lambda a: _snap7_connect(a.target, a.rack, a.slot)),
    ("EWS Rogue Engineer",lambda a: _run_py("tests_ext/test_ews_rogue_engineer.py", "--target", a.target)),
    ("EWS Firmware Tamper",lambda a: _run_py("tests_ext/test_ews_firmware_tamper.py", "--target", a.target)),
    ("HMI Credential Brute", lambda a: _run_py("tests_ext/test_hmi_credential_brute.py", "--target-url", f"http://{a.hmi_ip}:{a.hmi_port}")),
    ("HMI Alarm Suppress", lambda a: _run_py("tests_ext/test_hmi_alarm_suppress.py", "--opc-url", f"opc.tcp://{a.hmi_ip}:{a.opc_port}")),
    ("HMI Fake Display", lambda a: _run_py("tests_ext/test_hmi_fake_display.py", "--opc-url", f"opc.tcp://{a.hmi_ip}:{a.opc_port}")),
    ("DNS Spoof (scapy)", lambda a: _run_py("tests_ext/test_dns_spoof_ics.py", "--iface", a.iface, "--attacker-ip", a.attacker_ip)),
]


def _ping(ip: str) -> bool:
    param = "-n" if sys.platform == "win32" else "-c"
    try:
        r = subprocess.run(["ping", param, "2", "-w", "1000", ip],
                           capture_output=True, text=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def _tcp_port(ip: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        result = sock.connect_ex((ip, port))
        return result == 0
    except Exception:
        return False
    finally:
        sock.close()


def _snap7_connect(ip: str, rack: int, slot: int) -> bool:
    try:
        import snap7
        c = snap7.client.Client()
        c.connect(ip, rack, slot)
        state = str(c.get_cpu_state())
        c.disconnect()
        print(f"    S7 OK — state={state}")
        return True
    except Exception as e:
        print(f"    {e}")
        return False


def _run_py(script: str, *args) -> bool:
    cmd = [sys.executable, str(PROJECT_ROOT / script)] + list(args)
    try:
        r = subprocess.run(cmd, capture_output=False, timeout=60,
                           cwd=str(PROJECT_ROOT))
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        print("    TIMEOUT")
        return False
    except Exception as e:
        print(f"    {e}")
        return False


def _get_attacker_ip():
    """Get attacker IP, works on Windows & Linux."""
    hostname = socket.gethostname()
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        pass
    # Fallback: scan interfaces
    try:
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            if ip and not ip.startswith("127.") and ":" not in ip:
                return ip
    except Exception:
        pass
    return "192.168.1.100"


def main():
    p = argparse.ArgumentParser(description="Run all ICS attack module tests")
    p.add_argument("target", nargs="?", default="192.168.210.211", help="PLC IP")
    p.add_argument("hmi_ip", nargs="?", default="", help="HMI IP (auto from target subnet)")
    p.add_argument("--iface", default="eth0", help="Network interface for DNS test")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    p.add_argument("--hmi-port", type=int, default=5000)
    p.add_argument("--opc-port", type=int, default=4840)
    args = p.parse_args()

    if not args.hmi_ip:
        prefix = ".".join(args.target.split(".")[:3])
        args.hmi_ip = f"{prefix}.20"

    args.attacker_ip = _get_attacker_ip()

    print()
    print("=" * 60)
    print("  ICS ATTACK TEST SUITE")
    print(f"  PLC: {args.target}  |  HMI: {args.hmi_ip}")
    print(f"  Attacker: {args.attacker_ip}  |  Iface: {args.iface}")
    print("=" * 60)
    print()

    passed = 0
    failed = 0
    skipped = 0

    for i, (name, test_fn) in enumerate(TESTS, 1):
        print(f"  [{i}/{len(TESTS)}] {name} ...", end=" ", flush=True)
        try:
            ok = test_fn(args)
            if ok:
                print("PASS")
                passed += 1
            else:
                print("FAIL")
                failed += 1
        except Exception as e:
            print(f"FAIL ({e})")
            failed += 1

    print()
    print("=" * 60)
    print(f"  Passed: {passed} / {len(TESTS)}")
    print(f"  Failed: {failed} / {len(TESTS)}")
    print("=" * 60)

    if failed > 0:
        print("  [!] Có test FAIL — sửa trước khi chạy Day 7")
        print()
        print("  Kiểm tra:")
        print(f"    1. ping {args.target}")
        print(f"    2. pip install requests opcua")
        print(f"    3. PLC bật + dây mạng cắm đúng cổng")
        sys.exit(1)
    else:
        print("  [OK] Sẵn sàng chạy Day 7:")
        print(f"       bash run_day_bangtruyen_ext.sh --day 7 --role attacker --session-id bt_s1 --iface {args.iface}")
        sys.exit(0)


if __name__ == "__main__":
    main()
