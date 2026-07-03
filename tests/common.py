"""
tests/common.py — hàm dùng chung cho tất cả test.

Tự load config từ testbed.conf.
Mỗi test chạy độc lập, lưu kết quả vào test_results/.
"""

import re
import os
import time
import json
from datetime import datetime


# ── Load config từ testbed.conf ──────────────────────────────────
def _load_conf(name, default=""):
    try:
        with open("testbed.conf", encoding="utf-8") as f:
            for line in f:
                m = re.match(rf'^\s*{re.escape(name)}\s*=\s*["\']?([^"\'#\n]*)', line)
                if m:
                    return m.group(1).strip()
    except OSError:
        pass
    return default


PLC_IP = os.getenv("TARGET_IP") or _load_conf("TARGET_IP", "192.168.1.10")
HMI_IP = os.getenv("HMI_IP") or _load_conf("HMI_IP", "192.168.1.20")
OPC_URL = os.getenv("OPC_URL") or _load_conf("OPC_URL", f"opc.tcp://{HMI_IP}:4840")
HMI_URL = os.getenv("HMI_WEB_URL") or _load_conf("HMI_WEB_URL", f"http://{HMI_IP}:5000")
RACK = int(_load_conf("RACK", "0"))
SLOT = int(_load_conf("SLOT", "1"))
IFACE = os.getenv("CAPTURE_IFACE") or _load_conf("CAPTURE_IFACE", "eth0")

# ── Màu terminal ─────────────────────────────────────────────────
G = "\033[92m"
R = "\033[91m"
Y = "\033[93m"
C = "\033[96m"
B = "\033[1m"
X = "\033[0m"


def ok(m):
    print(f"  {G}[OK]{X} {m}")


def fail(m):
    print(f"  {R}[FAIL]{X} {m}")


def info(m):
    print(f"  {C}[*]{X} {m}")


def warn(m):
    print(f"  {Y}[!]{X} {m}")


def sep():
    print(f"  {'─' * 50}")


# ── Snapshot PLC ─────────────────────────────────────────────────
def plc_snapshot(client) -> dict:
    snap = {"ts": datetime.now().isoformat(), "cpu": None, "db1": None, "db2": None}
    try:
        snap["cpu"] = str(client.get_cpu_state())
        try:
            snap["db1"] = client.db_read(1, 0, 20).hex()
        except Exception:
            snap["db1"] = "N/A"
        try:
            snap["db2"] = client.db_read(2, 0, 20).hex()
        except Exception:
            snap["db2"] = "N/A"
    except Exception as e:
        snap["error"] = str(e)
    return snap


def plc_diff(before, after) -> list:
    changes = []
    for k in ["cpu", "db1", "db2"]:
        if before.get(k) != after.get(k):
            changes.append(f"{k}: {before.get(k)} -> {after.get(k)}")
    return changes


# ── In kết quả cuối + lưu JSON ───────────────────────────────────
def print_result(name, success, changes, observable, notes, duration, error=None):
    print(f"\n{'='*52}")
    status = f"{G}PASS{X}" if success else f"{R}FAIL{X}"
    print(f"  {B}{name}{X}  [{status}]  ({duration:.1f}s)")
    sep()

    if changes:
        print(f"  {Y}PLC thay doi:{X}")
        for c in changes:
            print(f"    -> {c}")
    else:
        print(f"  PLC thay doi: {C}khong co{X}")

    if observable:
        print(f"  Dau vet network:")
        for o in observable:
            print(f"    . {o}")

    if notes:
        print(f"  Notes:")
        for n in notes:
            print(f"    # {n}")

    if error:
        print(f"  {R}Error:{X} {error}")

    print(f"{'='*52}\n")

    os.makedirs("test_results", exist_ok=True)
    fname = f"test_results/{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({
            "name": name,
            "success": success,
            "changes": changes,
            "observable": observable,
            "notes": notes,
            "duration_s": duration,
            "error": error,
        }, f, indent=2, ensure_ascii=False)
    info(f"Ket qua luu: {fname}")
