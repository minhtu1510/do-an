from __future__ import annotations
from typing import List
from s7pwn.runtime import get_current_target
from s7pwn.utils import s7_connect
from s7pwn.core_io import AREA_MAP, TYPE_MAP, coerce_value, EPSILON_REAL, EPSILON_LREAL

def _parse_writes(tokens: List[str]):
    items = []
    for tok in tokens:
        if "=" not in tok or ":" not in tok:
            print(f"Invalid write format: {tok}. Must be address=value:type.")
            return None
        addr_val, typ = tok.split(":",1)
        address, value_str = addr_val.split("=",1)
        area = address[0].upper(); idx = address[1:]
        if area not in AREA_MAP: print(f"Unsupported area: {area}"); return None
        if typ not in TYPE_MAP: print(f"Unsupported type: {typ}"); return None
        if TYPE_MAP[typ]["is_bit"] and "." not in idx:
            print("Bool requires byte.bit format, e.g. M0.0"); return None
        if (not TYPE_MAP[typ]["is_bit"]) and "." in idx:
            print("Non-bool requires byte format, e.g. M2"); return None
        items.append({"area": area, "index": idx, "type": typ, "value": value_str})
    return items

def write(args: List[str]) -> None:
    if not args:
        print("Usage: write <addr>=<val>:<type> [...]"); return
    items = _parse_writes(args)
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
            try:
                value = coerce_value(it["type"], it["value"])
                if tinfo["is_bit"]:
                    byte_index, bit_index = map(int, idx.split("."))
                    buf = bytearray(c.read_area(area, 0, byte_index, tinfo["size"]))
                    tinfo["set"](buf, 0, bit_index, value)
                    c.write_area(area, 0, byte_index, buf)
                    v = tinfo["get"](c.read_area(area, 0, byte_index, tinfo["size"]), 0, bit_index)
                    ok = (v == value)
                else:
                    byte_index = int(idx)
                    buf = bytearray(tinfo["size"])
                    tinfo["set"](buf, 0, value)
                    c.write_area(area, 0, byte_index, buf)
                    v = tinfo["get"](c.read_area(area, 0, byte_index, tinfo["size"]), 0)
                    if it["type"] == "real":
                        ok = abs(float(v) - float(value)) <= EPSILON_REAL
                    elif it["type"] == "lreal":
                        ok = abs(float(v) - float(value)) <= EPSILON_LREAL
                    else:
                        ok = (v == value)
                if ok:
                    print(f"Successfully wrote {it['area']}{idx}={it['value']}:{it['type']}")
                else:
                    print(f"Error: Failed to verify write {it['area']}{idx}:{it['type']}")
            except Exception as e:
                print(f"Error writing {it['area']}{idx}:{it['type']}: {e}")
        print()
    finally:
        try: c.disconnect()
        except Exception: pass
