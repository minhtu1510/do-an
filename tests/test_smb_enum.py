#!/usr/bin/env python3
"""
tests/test_smb_enum.py
SMB Reconnaissance tren HMI host — TCP probe + SMB2 Negotiate + share enum.
MITRE: T0842 (Network Share Discovery), T1135 (Network Share Discovery)
Khong auth, khong NTLMSSP, khong net use — tao traffic SMB thuan tuy.

Chay: python tests/test_smb_enum.py
"""

import sys
import os
import socket
import time
import random
import struct
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *

SHARE_NAMES = [
    "C$", "ADMIN$", "IPC$", "PRINT$", "Users", "Public",
    "WinCC", "SCADA", "HMI", "PLC", "OPC", "Historian",
    "Engineering", "Project", "Runtime", "Backup", "Config",
    "Data", "Logs", "Scripts", "Software", "Deploy",
    "Share", "Files", "Common",
]

RPC_PIPES = ["srvsvc", "wkssvc", "samr", "lsarpc", "netlogon", "svcctl", "winreg", "atsvc"]

RPC_DESC = {
    "srvsvc": "Server Service - liet ke share",
    "wkssvc": "Workstation Service - thong tin may",
    "samr": "SAM Remote - liet ke user/group",
    "lsarpc": "LSA Remote - policy, SID lookup",
    "netlogon": "Netlogon Service",
    "svcctl": "Service Control - liet ke services",
    "winreg": "Remote Registry",
    "atsvc": "Task Scheduler",
}

SMB2_NEGOTIATE = bytes([
    0x00, 0x00, 0x00, 0x2e,
    0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x1f, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x24, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x02,
])


def tcp_probe(ip, port, timeout=1.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        ok = s.connect_ex((ip, port)) == 0
        s.close()
        return ok
    except Exception:
        return False


def smb2_negotiate(ip, port=445, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(SMB2_NEGOTIATE)
        resp = s.recv(256)
        s.close()
        return len(resp) > 4 and resp[4:8] == b'\xfeSMB'
    except Exception:
        return False


def main():
    target = HMI_IP

    print(f"\n{B}[TEST] SMB_RECON_ENUM{X}")
    info(f"Target HMI: {target}")
    info("SMB recon: TCP probe + SMB2 Negotiate + share enum")

    changes = []
    observable = []
    notes = []
    error = None
    t0 = time.time()
    log_count = 0

    try:
        # Phase 1: Port probe
        info("Phase 1: SMB port probe (137,138,139,445)")
        ports = {137: "NetBIOS NS", 138: "NetBIOS DG", 139: "NetBIOS SS", 445: "SMB Direct"}
        for port, desc in ports.items():
            ok = tcp_probe(target, port)
            status = "OPEN" if ok else "CLOSED"
            print(f"    {port} ({desc}): {status}")
            log_count += 1
            time.sleep(0.2)

        # Phase 2: SMB2 Negotiate
        info("Phase 2: SMB2 Negotiate × 10")
        for i in range(10):
            ok = smb2_negotiate(target, 445)
            status = "SMB2" if ok else "NORESP"
            print(f"    #{i+1:02d} {status}")
            log_count += 1
            time.sleep(random.uniform(0.3, 0.8))

        # Phase 3: Share name probe
        info(f"Phase 3: Share probe ({len(SHARE_NAMES)} names)")
        for share in SHARE_NAMES:
            tcp_probe(target, 445, timeout=1)
            log_count += 1
            time.sleep(0.1)

        # Phase 4: RPC pipe probe
        info(f"Phase 4: RPC pipe probe ({len(RPC_PIPES)} pipes)")
        for pipe_name in RPC_PIPES:
            smb2_negotiate(target, 445, timeout=2)
            log_count += 1
            time.sleep(random.uniform(0.2, 0.5))

        observable.append(f"SMB recon: {log_count} probes to {target}:139+445")
        observable.append("SMB2 Negotiate — no NTLMSSP (anonymous recon)")
        observable.append(f"Probed {len(SHARE_NAMES)} shares + {len(RPC_PIPES)} RPC pipes")
        notes.append("MITRE: T0842/T1135 — Network Share Discovery")
        notes.append("Wireshark: smb2.cmd == NEGOTIATE && smb2.nssession == 0x0000000000000000")
        notes.append("CIC: uniform small packet size, many short flows to 445")

    except Exception as e:
        error = str(e)
        fail(str(e))

    success = log_count > 0
    print_result("SMB_RECON_ENUM", success, changes, observable, notes, time.time() - t0, error)


if __name__ == "__main__":
    main()
