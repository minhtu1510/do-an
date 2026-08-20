from __future__ import annotations
import struct
from typing import Any, Dict
from snap7.util import (
    set_bool, get_bool,
    set_int,  get_int,
    set_dint, get_dint,
    set_uint, get_uint,
    set_byte, get_byte,
    set_real, get_real,
    set_lreal, get_lreal,
)
from snap7.type import Areas

MONITOR_RANGE_DEFAULT = 100
INTERVAL_DEFAULT = 0.5
EPSILON_REAL  = 1e-6
EPSILON_LREAL = 1e-12

AREA_MAP: Dict[str, Areas] = {
    "M": Areas.MK,
    "Q": Areas.PA,
    "I": Areas.PE,
}

def get_lint(data: bytes, byte_index: int) -> int:
    return struct.unpack_from(">q", data, byte_index)[0]

def set_lint(buf: bytearray, byte_index: int, value: int) -> None:
    struct.pack_into(">q", buf, byte_index, value)

TYPE_MAP: Dict[str, Dict[str, Any]] = {
    "bool":  {"size": 1, "get": get_bool,  "set": set_bool,  "is_bit": True},
    "byte":  {"size": 1, "get": get_byte,  "set": set_byte,  "is_bit": False},
    "int":   {"size": 2, "get": get_int,   "set": set_int,   "is_bit": False},
    "uint":  {"size": 2, "get": get_uint,  "set": set_uint,  "is_bit": False},
    "dint":  {"size": 4, "get": get_dint,  "set": set_dint,  "is_bit": False},
    "lint":  {"size": 8, "get": get_lint,  "set": set_lint,  "is_bit": False},
    "real":  {"size": 4, "get": get_real,  "set": set_real,  "is_bit": False},
    "lreal": {"size": 8, "get": get_lreal, "set": set_lreal, "is_bit": False},
}

def coerce_value(type_str: str, value_str: str) -> Any:
    t = type_str.lower().strip()
    vs = value_str.strip()
    is_hex = vs.lower().startswith("0x")
    base = 16 if is_hex else 10
    if t == "bool":
        v = vs.lower()
        if v in ("1","true","t","on"):  return True
        if v in ("0","false","f","off"): return False
        return bool(int(v, base))
    if t in ("int","dint","lint"):
        return int(vs, base)
    if t == "uint":
        val = int(vs, base)
        if val < 0: raise ValueError("uint must be >= 0")
        return val
    if t == "byte":
        val = int(vs, base)
        if not (0 <= val <= 255): raise ValueError("byte must be 0-255")
        return val
    if t in ("real","lreal"):
        return float(vs)
    raise ValueError(f"Unsupported type: {type_str}")

def b01(v: bool) -> int:
    return 1 if v else 0

def bool_chain(seq: list[int|bool]) -> str:
    return "->".join("1" if bool(x) else "0" for x in seq)
