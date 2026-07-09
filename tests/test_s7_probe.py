#!/usr/bin/env python3
"""
tests/test_s7_probe.py
S7 Function Code Probe — gui nhieu ma lenh S7 de do khai nang PLC.

Chay: python tests/test_s7_probe.py
"""

import sys
import os
import socket
import time
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *

FUNC_CODES = [
    (0xF0, "Setup Communication"),
    (0x04, "Read Var"),
    (0x05, "Write Var"),
    (0x1A, "Request Download"),
    (0x1B, "Download Block"),
    (0x1C, "Download Ended"),
    (0x1D, "Start Upload"),
    (0x1E, "Upload"),
    (0x1F, "End Upload"),
    (0x28, "PLC Control"),
    (0x29, "PLC Stop"),
]


def build_probe(func_code):
    tpkt = b"\x03\x00\x00\x16"
    cotp = b"\x02\xf0\x80"
    s7_hdr = bytes([0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00])
    s7_param = bytes([func_code] + [0x00] * 7)
    return tpkt + cotp + s7_hdr + s7_param


def main():
    target = PLC_IP

    print(f"\n{B}[TEST] S7_FUNC_PROBE (Function Code Scan){X}")
    info(f"Target: {target}:102  Probes: {len(FUNC_CODES)} func codes")
    info("MITRE: T0846 — Remote System Discovery")

    changes = []
    observable = []
    notes = []
    error = None
    sent = 0
    responses = {}
    t0 = time.time()

    try:
        for func_code, func_name in FUNC_CODES:
            pkt = build_probe(func_code)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((target, 102))
                s.send(pkt)
                try:
                    resp = s.recv(1024)
                    status = f"resp={len(resp)}b"
                    responses[func_name] = len(resp)
                except socket.timeout:
                    status = "timeout"
                    responses[func_name] = 0
                s.close()
            except Exception as e:
                status = str(e)[:30]
                responses[func_name] = -1

            sent += 1
            mark = "OK" if isinstance(responses.get(func_name, -1), int) and responses[func_name] > 0 else "—"
            print(f"  0x{func_code:02X} {func_name:<22} [{mark}]")
            time.sleep(random.uniform(0.3, 0.8))

        responded = sum(1 for v in responses.values() if v > 0)
        ok(f"Probed {sent} functions, {responded} responded")

        observable.append(f"S7 func probe: {sent} function codes -> {responded} responded")
        notes.append(f"Response map: {responses}")
        notes.append("Wireshark: s7comm.rosctr==1 (Job) && s7comm.func in [0x04,0x05,0x1A..0x1F,0x28,0x29]")

    except Exception as e:
        error = str(e)
        fail(str(e))

    success = sent > 0
    print_result("S7_FUNC_PROBE", success, changes, observable, notes, time.time() - t0, error)


if __name__ == "__main__":
    main()
