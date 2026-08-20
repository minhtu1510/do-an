from __future__ import annotations
from typing import List, Dict, Any, Tuple
import time
from snap7.util import get_bool, set_bool
from snap7.type import Areas
from s7pwn.runtime import get_current_target
from s7pwn.utils import s7_connect
from s7pwn.core_io import AREA_MAP, TYPE_MAP, coerce_value, INTERVAL_DEFAULT, EPSILON_REAL, EPSILON_LREAL

def _parse(tokens: List[str]):
    items = []
    for tok in tokens:
        if "=" not in tok or ":" not in tok:
            print(f"Invalid format: {tok}. Must be address=value:type.")
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

def rwrite(args: List[str]) -> None:
    if not args:
        print("Usage: rwrite <addr>=<val>:<type> [...]"); return
    items = _parse(args)
    if items is None: return
    t = get_current_target()
    if not t:
        print("No target selected. Use 'set_target' or 'select'."); return
    c = s7_connect(t["ip"], t["rack"], t["slot"])
    if not c:
        print("Connect failed."); return

    norm: List[Dict[str, Any]] = []
    for it in items:
        try:
            target_val = coerce_value(it["type"], it["value"])
            norm.append({
                "area": it["area"], "index": it["index"], "type": it["type"],
                "value_str": it["value"], "target": target_val
            })
        except ValueError as ve:
            print(f"Skip invalid value: {ve}")

    if not norm:
        print("No valid items to overwrite."); 
        try: c.disconnect()
        except Exception: pass
        return

    print("Starting overwrite loop (0.5s interval). Overwriting variables:")
    for it in norm:
        print(f"  - {it['area']}{it['index']}={it['value_str']}:{it['type']}")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            bool_groups: Dict[Tuple[Areas,int,str], List[Dict[str,Any]]] = {}
            others: List[Dict[str,Any]] = []

            for it in norm:
                area_enum = AREA_MAP[it["area"]]
                if TYPE_MAP[it["type"]]["is_bit"]:
                    byte_index, bit_index = map(int, it["index"].split("."))
                    bool_groups.setdefault((area_enum, byte_index, it["area"]), []).append(
                        {"bit": bit_index, "target": it["target"], "addr": f"{it['area']}{it['index']}", "value_str": it["value_str"]}
                    )
                else:
                    others.append({
                        "area_enum": area_enum, "area_str": it["area"],
                        "byte_index": int(it["index"]),
                        "type": it["type"], "target": it["target"], "value_str": it["value_str"]
                    })

            # Merge writes per byte for bool
            for (area_enum, byte_index, area_str), group in bool_groups.items():
                try:
                    data = bytearray(c.read_area(area_enum, 0, byte_index, 1))
                    changed = False
                    logs = []
                    for g in group:
                        cur = get_bool(data, 0, g["bit"])
                        if cur != g["target"]:
                            set_bool(data, 0, g["bit"], g["target"])
                            changed = True
                            logs.append((g["addr"], cur, g["value_str"]))
                    if changed:
                        c.write_area(area_enum, 0, byte_index, data)
                        for addr, old, new_str in logs:
                            print(f"Overwrote {addr} {int(bool(old))} -> {new_str}")
                except Exception as e:
                    print(f"Error overwriting {area_str}{byte_index}.x:bool: {e}")

            # Other numeric/float
            for it in others:
                tinfo = TYPE_MAP[it["type"]]
                try:
                    cur_buf = c.read_area(it["area_enum"], 0, it["byte_index"], tinfo["size"])
                    cur_val = tinfo["get"](cur_buf, 0)
                    if it["type"] == "real":
                        need = abs(float(cur_val) - float(it["target"])) > EPSILON_REAL
                    elif it["type"] == "lreal":
                        need = abs(float(cur_val) - float(it["target"])) > EPSILON_LREAL
                    else:
                        need = (cur_val != it["target"])
                    if need:
                        buf = bytearray(tinfo["size"])
                        tinfo["set"](buf, 0, it["target"])
                        c.write_area(it["area_enum"], 0, it["byte_index"], buf)
                        print(f"Overwrote {it['area_str']}{it['byte_index']} {cur_val} -> {it['value_str']}")
                except Exception as e:
                    print(f"Error overwriting {it['area_str']}{it['byte_index']}:{it['type']}: {e}")

            time.sleep(INTERVAL_DEFAULT)
    except KeyboardInterrupt:
        print("\nOverwrite stopped. Returning to command prompt.")
    finally:
        try: c.disconnect()
        except Exception: pass
