from __future__ import annotations
from typing import List
from s7pwn.runtime import set_current_target, get_current_target

def set_target(args: List[str]) -> None:
    if len(args) != 3:
        print("Usage: set_target <plc_ip> <rack> <slot>"); return
    ip, rack, slot = args[0], args[1], args[2]
    try:
        set_current_target(ip, int(rack), int(slot))
        print(f"Current target set to {ip} (rack={rack}, slot={slot})")
    except ValueError:
        print("Invalid rack/slot.")

def show_target() -> None:
    t = get_current_target()
    if not t:
        print("No target selected.")
        return
    print(f"Target: IP={t['ip']} rack={t['rack']} slot={t['slot']}")
