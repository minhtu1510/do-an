from __future__ import annotations
"""
enum_tags.py – PLC Tag / Variable Enumeration Attack
------------------------------------------------------
Systematically READ every address in the PLC's M (Marker), I (Input),
Q (Output), and DB (Data Block) areas to build a complete map of the
process variables stored in the controller.

MITRE ATT&CK for ICS
---------------------
  Tactic    : Collection
  Technique : T0861 – Point & Tag Identification

Why this matters for dataset
-----------------------------
Unlike `monitor` (which watches a fixed block passively), enum_tags
generates a unique traffic pattern:
  - Sequential address access: byte_index increases monotonically
  - High READ rate with very low write rate (ratio ≈ 1.0)
  - Address entropy across the session is LOW (predictable sweep)
  - All requests are READ_VAR (function_code 0x04)

These features create a clearly separable class in an IDS dataset,
distinct from normal SCADA polling (which reads fixed specific tags)
and from data-manipulation attacks (which WRITE).

Usage
-----
  enum_tags [--area M|I|Q|all] [--start 0] [--end 99] [--type byte]
            [--interval 0.05] [--output tags.json]

Examples
--------
  enum_tags                                  # scan M area, bytes 0-99
  enum_tags --area all --output plc_map.json # full map, save result
  enum_tags --area M --start 0 --end 255 --type int
"""

import json
import time
import os
from typing import List, Optional, Dict, Any

from s7pwn.runtime import get_current_target
from s7pwn.utils import s7_connect
from s7pwn.core_io import AREA_MAP, TYPE_MAP


_AREA_ALL = ["M", "I", "Q"]


def enum_tags(args: List[str]) -> None:
    # ── Parse args ──────────────────────────────────────────────────
    area_arg  = "M"
    start     = 0
    end       = 99
    type_str  = "byte"
    interval  = 0.05
    output    = None
    loop_mode = False
    churn_mode = False

    i = 0
    while i < len(args):
        a = args[i]
        if a == "--area"     and i + 1 < len(args): area_arg = args[i+1].upper(); i += 2
        elif a == "--start"  and i + 1 < len(args): start    = int(args[i+1]);    i += 2
        elif a == "--end"    and i + 1 < len(args): end      = int(args[i+1]);    i += 2
        elif a == "--type"   and i + 1 < len(args): type_str = args[i+1].lower(); i += 2
        elif a == "--interval" and i+1 < len(args): interval = float(args[i+1]); i += 2
        elif a == "--output" and i + 1 < len(args): output   = args[i+1];         i += 2
        elif a == "--loop": loop_mode = True; i += 1
        elif a == "--churn": churn_mode = True; i += 1
        else: i += 1

    areas = _AREA_ALL if area_arg == "ALL" else [area_arg]
    for a in areas:
        if a not in AREA_MAP:
            print(f"[!] Unsupported area: {a}"); return

    if type_str not in TYPE_MAP:
        print(f"[!] Unsupported type: {type_str}"); return

    tinfo = TYPE_MAP[type_str]
    if tinfo["is_bit"]:
        print("[!] Use byte/int/uint/etc for enum_tags (not bool)."); return

    # ── Connect ─────────────────────────────────────────────────────
    t = get_current_target()
    if not t:
        print("[!] No target selected. Use 'set_target' or 'select'."); return

    c = None
    if not churn_mode:
        c = s7_connect(t["ip"], t["rack"], t["slot"])
        if not c:
            print("[!] Connection failed."); return

    # ── Sweep ───────────────────────────────────────────────────────
    print(f"\n[*] Tag Enumeration  target={t['ip']}  areas={areas}")
    print(f"    byte_range=[{start}..{end}]  type={type_str}  interval={interval}s")
    print(f"    MITRE ATT&CK ICS T0861 – Point & Tag Identification\n")

    results: Dict[str, Any] = {
        "target": dict(t),
        "scan_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "type": type_str,
        "areas": {}
    }

    total_read = 0
    total_nonzero = 0

    try:
        while True:
            for area_str in areas:
                if churn_mode:
                    c = s7_connect(t["ip"], t["rack"], t["slot"])
                    if not c:
                        print(f"  [!] Churn connect failed for area {area_str}. Skipping."); continue

                area_enum = AREA_MAP[area_str]
                results["areas"][area_str] = {}
                print(f"  [Area {area_str}]  scanning bytes {start}–{end} ...")

                for byte_idx in range(start, end + 1):
                    try:
                        raw = c.read_area(area_enum, 0, byte_idx, tinfo["size"])
                        value = tinfo["get"](raw, 0)
                        results["areas"][area_str][str(byte_idx)] = value
                        total_read += 1

                        marker = ""
                        if isinstance(value, float):
                            nonzero = abs(value) > 1e-6
                        else:
                            nonzero = (value != 0)

                        if nonzero:
                            total_nonzero += 1
                            marker = f"  ← {value}"
                            print(f"    {area_str}{byte_idx}:{type_str} = {value}{marker}")

                    except Exception as e:
                        results["areas"][area_str][str(byte_idx)] = None
                        # skip silently for inaccessible addresses

                    time.sleep(interval)
                
                if churn_mode and c:
                    try: c.disconnect()
                    except: pass
                    c = None
            
            if not loop_mode:
                break

    except KeyboardInterrupt:
        print("\n[!] Enumeration interrupted.")
    finally:
        if c:
            try: c.disconnect()
            except Exception: pass

    # ── Summary ─────────────────────────────────────────────────────
    print(f"\n[+] Done. {total_read} addresses read, {total_nonzero} non-zero values found.")

    if output:
        with open(output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[+] Saved: {os.path.abspath(output)}")
    else:
        # Print compact summary table
        print("\n  Address        Value")
        print("  " + "-" * 30)
        for area_str, addrs in results["areas"].items():
            for idx, val in addrs.items():
                if val is not None and val != 0:
                    print(f"  {area_str}{idx:<10}     {val}")
