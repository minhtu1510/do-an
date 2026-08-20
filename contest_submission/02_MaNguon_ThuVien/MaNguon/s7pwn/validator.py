from __future__ import annotations
from typing import Dict, Any, List

def parse_command(line: str) -> Dict[str, Any]:
    """
    Trả về {"cmd": str, "args": List[str]} hoặc {"error": "..."}.
    Không kiểm tra sâu tham số; từng module sẽ validate chi tiết.
    """
    if not line:
        return {"error": "Empty command"}
    parts = line.strip().split()
    cmd = parts[0].lower()
    args: List[str] = parts[1:]

    known = {
        "help","scan","list","select","set_target","show_target",
        "probe_target","flood","monitor","read","write","rwrite","exit","quit"
    }
    if cmd not in known:
        return {"error": "Unknown command. Type 'help' for usage."}
    return {"cmd": cmd, "args": args}
