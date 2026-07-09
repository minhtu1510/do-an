#!/usr/bin/env python3
"""
tests/test_dcp_scan.py
Profinet DCP Identify Scan — quét Layer 2 tìm tất cả thiết bị Siemens.
Không ảnh hưởng PLC, MITRE T0846 (Remote System Discovery).

Chạy: python tests/test_dcp_scan.py
"""

import sys
import os
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *

DCP_ETHERTYPE = 0x8892
DCP_SERVICE_ID = 0x05      # Identify
DCP_REQUEST = 0x00

BURST_COUNT = 30
BURST_INTERVAL = 0.5


def build_dcp_identify():
    """DCP Identify Request frame (Layer 2, EtherType 0x8892)."""
    return (
        b"\xff\xff\xff\xff\xff\xff"  # broadcast MAC
        b"\xff\xff\xff\xff\xff\xff"  # src MAC (spoofed)
        + DCP_ETHERTYPE.to_bytes(2, "big")
        + bytes([DCP_SERVICE_ID, DCP_REQUEST])
        + bytes([0x00, 0x00])       # XID
        + bytes([0x00, 0x00])       # Response delay
        + bytes([0x00, 0x04])       # DCP data length
        + b"\x00\x00\x00\x00"       # padding
    )


def main():
    iface = IFACE

    print(f"\n{B}[TEST] PROFINET_DCP_SCAN (Layer 2 Discover){X}")
    info(f"Interface: {iface}  EtherType: 0x{DCP_ETHERTYPE:04X}")
    info(f"Burst: {BURST_COUNT} frames, interval {BURST_INTERVAL}s")
    info("MITRE: T0846 — Remote System Discovery (Layer 2)")

    changes = []
    observable = []
    notes = []
    error = None
    success = False
    t0 = time.time()

    try:
        from scapy.all import Ether, sendp, sniff, Raw

        dcp_frame = build_dcp_identify()

        # Sniff for DCP responses
        responses = []

        def sniff_callback(pkt):
            if pkt.haslayer(Ether) and pkt[Ether].type == DCP_ETHERTYPE:
                src_mac = pkt[Ether].src
                if src_mac != "ff:ff:ff:ff:ff:ff":
                    responses.append(src_mac)
                    info(f"  [RESPONSE] from {src_mac}")

        sniffer = threading.Thread(
            target=lambda: sniff(
                iface=iface,
                filter="ether proto 0x8892",
                prn=sniff_callback,
                timeout=BURST_COUNT * BURST_INTERVAL + 5,
                store=False,
                promisc=True
            ),
            daemon=True
        )
        sniffer.start()
        time.sleep(0.5)

        # Send DCP bursts
        for i in range(BURST_COUNT):
            ether = Ether(dst="ff:ff:ff:ff:ff:ff", type=DCP_ETHERTYPE) / Raw(load=dcp_frame[12:])
            sendp(ether, iface=iface, verbose=False)
            if (i + 1) % 10 == 0:
                info(f"  Sent {i+1}/{BURST_COUNT}")
            time.sleep(BURST_INTERVAL)

        sniffer.join(timeout=5)

        unique_devices = list(set(responses))
        ok(f"Found {len(unique_devices)} Profinet devices: {unique_devices}")

        observable.append(f"Profinet DCP: {BURST_COUNT} identify frames sent")
        observable.append(f"Devices discovered: {len(unique_devices)}")
        observable.append("Layer 2 EtherType 0x8892 — không qua IP")
        notes.append("Wireshark: eth.type == 0x8892")
        notes.append("MITRE T0846 — Remote System Discovery")
        notes.append("CIC feature: Flow Duration thấp, DCP payload uniform")
        success = BURST_COUNT > 0

    except ImportError:
        error = "scapy not installed: pip install scapy"
        fail(error)
    except PermissionError:
        error = "Need Admin/root to send raw L2 frames"
        fail(error)
    except Exception as e:
        error = str(e)
        fail(str(e))

    print_result("PROFINET_DCP_SCAN", success, changes, observable, notes, time.time() - t0, error)


if __name__ == "__main__":
    main()
