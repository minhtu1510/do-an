from __future__ import annotations

HELP_TEXT = """\
  scan <network>/<subnet mask>         Scan Profinet devices
  list                                 Show PLC list
  select <number>                      Set chosen PLC to current target
  set_target <plc_ip> <rack> <slot>    Set attack target ip, rack and slot
  show_target                          Show current target info
  probe_target                         Connect and check target status
  flood <numbers of connection> <hold> [<delay>|--delay <sec>]  Perform connection flood attack (hold seconds; 0=infinite)
  monitor [--bit|--byte]               Monitor PLC memory changes
  read <addr>:<type> [...]             Read one or more values
  write <addr>=<val>:<type> [...]      Write one or more values
  rwrite <addr>=<val>:<type> [...]     Repeatedly write one or more values
  export <type> <format>               Export data (type: scan/devices/plcs, format: json/csv/html)
  webgui [host] [port]                 Start web GUI (default: 127.0.0.1:5000)
  help                                 Print this help summary page
  
  exit | quit                          Exit S7Pwn
"""

def print_help() -> None:
    print(HELP_TEXT)
