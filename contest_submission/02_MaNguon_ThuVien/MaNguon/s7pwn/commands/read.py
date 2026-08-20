from __future__ import annotations
from typing import List, Dict
from s7pwn.runtime import get_current_target
from s7pwn.utils import s7_connect
from s7pwn.core_io import AREA_MAP, TYPE_MAP

def _parse_reads(tokens: List[str]):
    items = []
    for tok in tokens:
        if ":" not in tok:
            print(f"Invalid read format: {tok}. Must be address:type.")
            return None
        address, type_str = tok.split(":",1)
        area = address[0].upper(); idx = address[1:]
        if area not in AREA_MAP: print(f"Unsupported area: {area}"); return None
        if type_str not in TYPE_MAP: print(f"Unsupported type: {type_str}"); return None
        if TYPE_MAP[type_str]["is_bit"] and "." not in idx:
            print("Bool requires byte.bit format, e.g. M2.1"); return None
        if (not TYPE_MAP[type_str]["is_bit"]) and "." in idx:
            print("Non-bool requires byte format, e.g. M2"); return None
        items.append({"area": area, "index": idx, "type": type_str})
    return items

def read(args: List[str]) -> None:
    if not args:
        print("Usage: read <addr>:<type> [...]"); return
    items = _parse_reads(args)
    if items is None: return
    t = get_current_target()
    if not t:
        print("No target selected. Use 'set_target' or 'select'."); return
    c = s7_connect(t["ip"], t["rack"], t["slot"])
    if not c:
        print("Connect failed."); return
    try:
        for it in items:
            area = AREA_MAP[it["area"]]; tinfo = TYPE_MAP[it["type"]]; idx = it["index"]
            if tinfo["is_bit"]:
                byte_index, bit_index = map(int, idx.split("."))
                data = c.read_area(area, 0, byte_index, tinfo["size"])
                val  = tinfo["get"](data, 0, bit_index)
            else:
                byte_index = int(idx)
                data = c.read_area(area, 0, byte_index, tinfo["size"])
                val  = tinfo["get"](data, 0)
            print(f"Read {it['area']}{idx}:{it['type']} = {val}")
        print()
    except Exception as e:
        print(f"Read error: {e}")
    finally:
        try: c.disconnect()
        except Exception: pass
