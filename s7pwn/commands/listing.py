from __future__ import annotations
from typing import List
from s7pwn.runtime import get_plc_list, set_current_target

def show_list() -> None:
    lst = get_plc_list()
    print("PLC devices (Siemens S7-1500/1200/300/400):")
    for i, d in enumerate(lst):
        print(f"  [{i}] IP={d['ip']} MAC={d['mac']} vendor={d['vendor']} model={d['model']} rack={d['rack']} slot={d['slot']}")

def select_index(args: List[str]) -> None:
    if len(args) != 1 or not args[0].isdigit():
        print("Usage: select <number>"); return
    idx = int(args[0])
    lst = get_plc_list()
    if not (0 <= idx < len(lst)):
        print("Invalid index."); return
    d = lst[idx]
    set_current_target(d["ip"], d["rack"], d["slot"])
    print(f"Current target set to {d['ip']} (rack={d['rack']}, slot={d['slot']})")
