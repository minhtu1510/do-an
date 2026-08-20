from __future__ import annotations
import ipaddress
from typing import Dict, Any, Tuple, List

HELP_TEXT = """\
  scan <network>/<subnet mask>         Scan Profinet devices
  list                                 Show PLC list
  select <number>                      Set chosen PLC to current target
  set_target <plc_ip> <rack> <slot>    Set attack target ip, rack and slot
  show_target                          Show current target info
  probe_target                         Connect and check target status
  flood <numbers of connection> <hold> Perform connection flood attack (hold seconds; 0=infinite)
  monitor [--bit|--byte]               Monitor PLC memory changes
  read <addr>:<type> [...]             Read one or more values
  write <addr>=<val>:<type> [...]      Write one or more values
  rwrite <addr>=<val>:<type> [...]     Repeatedly write one or more values
  help                                 Print this help summary page
"""

def _ok(cmd: str, **kwargs) -> Tuple[str, Dict[str, Any]]:
    return cmd, kwargs

def _err(msg: str) -> Tuple[str, Dict[str, Any]]:
    return "error", {"message": msg}

def _is_addr_datatype(token: str) -> bool:
    return ":" in token and len(token.split(":", 1)[0]) >= 2

def _is_write_token(token: str) -> bool:
    return ("=" in token) and (":" in token)

def print_help() -> None:
    print(HELP_TEXT)

def parse_and_validate(line: str) -> Tuple[str, Dict[str, Any]]:
    parts = line.strip().split()
    if not parts:
        return _err("Empty command.")
    cmd = parts[0].lower()
    args = parts[1:]

    if cmd in ("help", "-h", "--help"):
        return _ok("help")

    if cmd == "scan":
        if len(args) != 1:
            return _err("Usage: scan <network>/<subnet mask>")
        try:
            ipaddress.ip_network(args[0], strict=False)
        except Exception:
            return _err("Invalid network/CIDR.")
        return _ok("scan", cidr=args[0])

    if cmd == "list":
        return _ok("list") if not args else _err("Usage: list")

    if cmd == "select":
        if len(args) != 1 or not args[0].isdigit():
            return _err("Usage: select <number>")
        return _ok("select", index=int(args[0]))

    if cmd == "set_target":
        if len(args) != 3:
            return _err("Usage: set_target <plc_ip> <rack> <slot>")
        ip, rack, slot = args
        try:
            ipaddress.ip_address(ip)
            rack_i = int(rack); slot_i = int(slot)
        except Exception:
            return _err("Invalid ip/rack/slot.")
        return _ok("set_target", ip=ip, rack=rack_i, slot=slot_i)

    if cmd == "show_target":
        return _ok("show_target") if not args else _err("Usage: show_target")

    if cmd == "probe_target":
        return _ok("probe_target") if not args else _err("Usage: probe_target")

    if cmd == "flood":
        if len(args) != 2:
            return _err("Usage: flood <numbers of connection> <hold>")
        try:
            n = int(args[0]); hold = float(args[1])
        except Exception:
            return _err("Invalid number or hold seconds.")
        if n <= 0: return _err("numbers of connection must be > 0.")
        if hold < 0: return _err("hold must be >= 0.")
        return _ok("flood", n=n, hold=hold)

    if cmd == "monitor":
        fmt = "bit"
        if args:
            if args[0] == "--byte": fmt = "byte"
            elif args[0] == "--bit": fmt = "bit"
            else: return _err("Usage: monitor [--bit|--byte]")
        return _ok("monitor", format=fmt)

    if cmd == "read":
        if not args:
            return _err("Usage: read <addr>:<type> [...]")
        tokens: List[str] = []
        for t in args:
            if not _is_addr_datatype(t):
                return _err(f"Invalid token: {t}")
            tokens.append(t)
        return _ok("read", tokens=tokens)

    if cmd == "write":
        if not args:
            return _err("Usage: write <addr>=<val>:<type> [...]")
        tokens: List[str] = []
        for t in args:
            if not _is_write_token(t):
                return _err(f"Invalid token: {t}")
            tokens.append(t)
        return _ok("write", tokens=tokens)

    if cmd == "rwrite":
        if not args:
            return _err("Usage: rwrite <addr>=<val>:<type> [...]")
        tokens: List[str] = []
        for t in args:
            if not _is_write_token(t):
                return _err(f"Invalid token: {t}")
            tokens.append(t)
        return _ok("rwrite", tokens=tokens)

    return _err("Unknown command. Type 'help' for usage.")
