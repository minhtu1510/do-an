#!/usr/bin/env python3
"""
tests/test_hmi_fake.py
HMI_FAKE_DISPLAY — Giả lập HMI kết nối OPC-UA bất thường.
Dùng raw socket vì server không cho phép full session.
Tạo burst connect/HEL pattern — dấu vết rõ trong pcap.

Chạy: python tests/test_hmi_fake.py
"""

import sys
import os
import socket
import struct
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *

TOTAL_CONNECTS = 30
INTERVAL = 0.2


def build_hello(host, port):
    endpoint = f"opc.tcp://{host}:{port}".encode()
    ep_len = len(endpoint)
    msg_size = 28 + ep_len
    return (
        b'HEL' + b'F' +
        struct.pack('<IIIIII', msg_size, 0, 65536, 65536, 0, 0) +
        struct.pack('<I', ep_len) + endpoint
    )


def fake_hmi_connect(host, port, hello_msg):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        s.send(hello_msg)
        try:
            s.recv(1024)
        except Exception:
            pass
        s.close()
        return True
    except Exception:
        return False


def main():
    host = HMI_IP
    port = 4840

    print(f"\n{B}[TEST] HMI_FAKE_DISPLAY (Raw OPC-UA){X}")
    info(f"Target: {host}:{port}")
    info(f"Burst {TOTAL_CONNECTS} connects, interval {INTERVAL}s")
    info("Simulating rogue HMI — rapid connect/HEL bursts")
    info("PLC KHONG thay doi — dau vet la OPC-UA TCP burst tu IP la")

    changes = []
    observable = []
    notes = []
    error = None
    success_count = 0
    t0 = time.time()

    hello = build_hello(host, port)

    for i in range(TOTAL_CONNECTS):
        result = fake_hmi_connect(host, port, hello)
        if result:
            success_count += 1
            if (i + 1) % 10 == 0:
                ok(f"Connect #{i+1:02d} -> HEL sent")
        else:
            if (i + 1) % 10 == 0:
                warn(f"Connect #{i+1:02d} -> reset/fail")
        time.sleep(INTERVAL)

    observable.append(f"OPC-UA burst: {TOTAL_CONNECTS} connects trong {time.time()-t0:.1f}s")
    observable.append(f"IP nguon: attacker (khong phai HMI process)")
    observable.append(f"Pattern: TCP SYN -> HEL -> RST (rapid, deu dan)")
    notes.append(f"{success_count}/{TOTAL_CONNECTS} connections thanh cong")
    notes.append("Wireshark: tcp.port==4840 && tcp.flags.syn==1")
    notes.append("CIC feature: high Flow Packet/s, short Flow Duration")

    success = success_count > 0
    print_result("HMI_FAKE_DISPLAY", success, changes, observable, notes, time.time() - t0, error)


if __name__ == "__main__":
    main()
