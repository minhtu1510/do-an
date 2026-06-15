from __future__ import annotations
import sys
from typing import List
from s7pwn.commands import (
    scan as cmd_scan, listing as cmd_list,
    target as cmd_target, probe as cmd_probe,
    flood as cmd_flood, monitor as cmd_monitor,
    read as cmd_read, write as cmd_write, rwrite as cmd_rwrite,
    export as cmd_export, help as cmd_help, auth as cmd_auth,
)

def dispatch(cmd: str, args: List[str]) -> None:
    if cmd == "scan":         cmd_scan.scan(args);         return
    if cmd == "list":         cmd_list.show_list();        return
    if cmd == "select":       cmd_list.select_index(args); return
    if cmd == "set_target":   cmd_target.set_target(args); return
    if cmd == "show_target":  cmd_target.show_target();    return
    if cmd == "probe_target": cmd_probe.probe();           return
    if cmd == "flood":        cmd_flood.flood(args);       return
    if cmd == "monitor":      cmd_monitor.monitor(args);   return
    if cmd == "read":         cmd_read.read(args);         return
    if cmd == "write":        cmd_write.write(args);       return
    if cmd == "rwrite":       cmd_rwrite.rwrite(args);     return
    if cmd == "export":       cmd_export.export_data(args);return
    if cmd == "auth":         cmd_auth.auth(args);         return
    if cmd == "webgui":       start_webgui(args);          return
    if cmd == "help":         cmd_help.print_help();       return
    if cmd in ("exit","quit"): sys.exit(0)
    print("Unknown command. Type 'help' for usage.")

def start_webgui(args: List[str]) -> None:
    """Start the web GUI"""
    from s7pwn.web_gui import start_web_gui
    host = args[0] if len(args) > 0 else '127.0.0.1'
    port = int(args[1]) if len(args) > 1 else 5000
    start_web_gui(host, port)
