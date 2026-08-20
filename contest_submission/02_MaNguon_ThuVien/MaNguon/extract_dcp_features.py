#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_dcp_features.py

Profinet DCP (Discovery and Configuration Protocol) Feature Extractor.
Hoạt động ở Tầng 2 (Data Link Layer) - EtherType 0x8892.

Mục tiêu:
- Trích xuất đặc trưng từ Profinet DCP frames trong PCAP/PCAPNG.
- Phát hiện DCP Discovery Scan (T0846 – Remote System Discovery).
- Nhóm gói tin theo time-window để tích hợp với extract_s7_features.py.

DCP Frame Structure:
  Ethernet Header (14 bytes):
    [Dst MAC 6B][Src MAC 6B][EtherType 2B: 0x8892]
  DCP Payload:
    [FrameID 2B][ServiceID 1B][ServiceType 1B][Xid 4B][ResponseDelay 2B][DCPDataLength 2B]
    [Blocks...]

Service IDs quan trọng:
  0x05 = Identify (Request: ServiceType=0x00, Response: ServiceType=0x01)
  0x04 = Set
  0x06 = Hello

Cách dùng:
  python extract_dcp_features.py --pcap capture.pcap --output dcp_features.csv --window 10
"""

from __future__ import annotations

import argparse
import csv
import os
import statistics
import sys
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROFINET_ETHERTYPE = 0x8892
PROFINET_MULTICAST_MAC = "01:0e:cf:00:00:00"

# DCP Service IDs
DCP_SERVICE_IDENTIFY = 0x05
DCP_SERVICE_SET = 0x04
DCP_SERVICE_HELLO = 0x06
DCP_SERVICE_GET = 0x03

# DCP Service Types
DCP_TYPE_REQUEST = 0x00
DCP_TYPE_RESPONSE_SUCCESS = 0x01

# DCP Block Option/Sub-option IDs
DCP_BLOCK_IP = 0x01
DCP_BLOCK_DEVICE_PROPERTIES = 0x02
DCP_BLOCK_DHCP = 0x03
DCP_BLOCK_CONTROL = 0x05
DCP_BLOCK_DEVICE_INITIATIVE = 0x06

# Known Profinet Vendor IDs
PROFINET_VENDORS = {
    "002a": "Siemens",
    "000a": "Wago",
    "001c": "Beckhoff",
    "0060": "Phoenix Contact",
    "00a0": "Hirschmann",
    "0083": "Molex",
    "00cb": "SEW-Eurodrive",
}


# ---------------------------------------------------------------------------
# Scapy import with graceful fallback
# ---------------------------------------------------------------------------

try:
    from scapy.all import rdpcap, Ether, Raw, PcapReader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# DCP Frame Parser
# ---------------------------------------------------------------------------

def parse_dcp_frame(raw_payload: bytes) -> Optional[dict]:
    """
    Parse một Profinet DCP payload (sau Ethernet header).

    Returns dict với các trường:
        frame_id, service_id, service_type, xid, dcp_data_length,
        blocks: List[dict{option, sub_option, data_hex}],
        ip_addr, device_name, vendor_id, device_id, device_role
    """
    if len(raw_payload) < 10:
        return None

    try:
        frame_id = int.from_bytes(raw_payload[0:2], "big")
        service_id = raw_payload[2]
        service_type = raw_payload[3]
        xid = int.from_bytes(raw_payload[4:8], "big")
        response_delay = int.from_bytes(raw_payload[8:10], "big")
        dcp_data_length = int.from_bytes(raw_payload[10:12], "big")

        result = {
            "frame_id": frame_id,
            "service_id": service_id,
            "service_type": service_type,
            "xid": xid,
            "response_delay": response_delay,
            "dcp_data_length": dcp_data_length,
            "blocks": [],
            "ip_addr": None,
            "device_name": None,
            "vendor_id": None,
            "device_id": None,
            "device_role": None,
        }

        # Parse DCP blocks
        offset = 12
        end = min(12 + dcp_data_length, len(raw_payload))

        while offset + 4 <= end:
            option = raw_payload[offset]
            sub_option = raw_payload[offset + 1]
            block_len = int.from_bytes(raw_payload[offset + 2: offset + 4], "big")
            block_data = raw_payload[offset + 4: offset + 4 + block_len]

            block = {
                "option": option,
                "sub_option": sub_option,
                "data_hex": block_data.hex(),
            }
            result["blocks"].append(block)

            # Extract IP Address (option=0x01, sub=0x02)
            if option == 0x01 and sub_option == 0x02 and len(block_data) >= 4:
                result["ip_addr"] = ".".join(str(b) for b in block_data[:4])

            # Extract Device Name (option=0x02, sub=0x02)
            if option == 0x02 and sub_option == 0x02 and block_data:
                try:
                    result["device_name"] = block_data.decode("latin-1").strip("\x00")
                except Exception:
                    pass

            # Extract Vendor/Device ID (option=0x02, sub=0x03)
            if option == 0x02 and sub_option == 0x03 and len(block_data) >= 4:
                result["vendor_id"] = block_data[0:2].hex()
                result["device_id"] = block_data[2:4].hex()

            # Extract Device Role (option=0x02, sub=0x04)
            if option == 0x02 and sub_option == 0x04 and block_data:
                role_byte = block_data[0]
                roles = {0x01: "IO-Device", 0x02: "IO-Controller",
                         0x04: "IO-Multidevice", 0x08: "PN-Supervisor"}
                result["device_role"] = roles.get(role_byte, f"0x{role_byte:02x}")

            # Align to 2-byte boundary
            padded_len = block_len + (block_len % 2)
            offset += 4 + padded_len

        return result

    except Exception:
        return None


# ---------------------------------------------------------------------------
# Window accumulator
# ---------------------------------------------------------------------------

def new_dcp_window() -> dict:
    return {
        # Identify Request (từ scanner gửi đến multicast)
        "dcp_identify_request_count": 0,
        # Identify Response (từ thiết bị phản hồi)
        "dcp_identify_response_count": 0,
        # Các DCP service khác
        "dcp_set_count": 0,
        "dcp_get_count": 0,
        "dcp_hello_count": 0,
        # Tổng số frame DCP
        "dcp_total_frame_count": 0,

        # Phân tích nguồn gốc scanner
        "dcp_unique_src_macs": set(),      # MAC đã gửi Identify Request
        "dcp_unique_response_macs": set(), # MAC đã phản hồi (thiết bị thực)

        # Thông tin thiết bị phát hiện được
        "dcp_discovered_ips": set(),
        "dcp_discovered_vendors": Counter(),
        "dcp_discovered_device_ids": set(),

        # Timing
        "dcp_timestamps": [],              # epoch timestamps

        # Bytes
        "dcp_total_bytes": 0,
    }


# ---------------------------------------------------------------------------
# Main extractor
# ---------------------------------------------------------------------------

def extract_dcp_features(
    pcap_path: str,
    window_size: int,
    output_path: str,
    role: str = "attacker",
) -> None:
    """
    Trích xuất DCP features từ PCAP, nhóm theo time-window.

    Args:
        pcap_path:   Đường dẫn file PCAP/PCAPNG
        window_size: Kích thước cửa sổ thời gian (giây)
        output_path: File CSV đầu ra
        role:        Vai trò capture (attacker/controller/logger)
    """
    if not SCAPY_AVAILABLE:
        print("[ERROR] scapy chưa được cài. Chạy: pip install scapy")
        sys.exit(1)

    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP không tồn tại: {pcap_path}")

    print(f"[INFO] DCP Feature Extractor")
    print(f"[INFO] PCAP:   {pcap_path}")
    print(f"[INFO] Window: {window_size}s")
    print(f"[INFO] Output: {output_path}")

    # windows[w_start] = dcp_window_dict
    windows: Dict[int, dict] = defaultdict(new_dcp_window)

    total_packets = 0
    dcp_packets = 0

    try:
        reader = PcapReader(pcap_path)
    except Exception as e:
        raise RuntimeError(f"Không đọc được PCAP: {e}")

    for pkt in reader:
        total_packets += 1

        # Chỉ xử lý Ethernet frames với EtherType = 0x8892
        if not pkt.haslayer(Ether):
            continue
        if pkt[Ether].type != PROFINET_ETHERTYPE:
            continue

        dcp_packets += 1

        # Timestamp → window key
        try:
            ts = float(pkt.time)
        except Exception:
            continue

        w_start = int(ts // window_size) * window_size * 1000
        w = windows[w_start]

        src_mac = pkt[Ether].src.lower()
        dst_mac = pkt[Ether].dst.lower()

        # Frame size
        frame_len = len(pkt)
        w["dcp_total_frame_count"] += 1
        w["dcp_total_bytes"] += frame_len
        w["dcp_timestamps"].append(ts)

        # Parse DCP payload
        raw_payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
        dcp = parse_dcp_frame(raw_payload)

        if dcp is None:
            continue

        service_id = dcp["service_id"]
        service_type = dcp["service_type"]

        # Phân loại theo service
        if service_id == DCP_SERVICE_IDENTIFY:
            if service_type == DCP_TYPE_REQUEST:
                # Scanner → Multicast: Identify Request
                w["dcp_identify_request_count"] += 1
                w["dcp_unique_src_macs"].add(src_mac)

            elif service_type == DCP_TYPE_RESPONSE_SUCCESS:
                # Device → Scanner: Identify Response
                w["dcp_identify_response_count"] += 1
                w["dcp_unique_response_macs"].add(src_mac)

                # Thu thập thông tin thiết bị
                if dcp["ip_addr"]:
                    w["dcp_discovered_ips"].add(dcp["ip_addr"])
                if dcp["vendor_id"]:
                    vendor_name = PROFINET_VENDORS.get(dcp["vendor_id"], dcp["vendor_id"])
                    w["dcp_discovered_vendors"][vendor_name] += 1
                if dcp["device_id"]:
                    w["dcp_discovered_device_ids"].add(dcp["device_id"])

        elif service_id == DCP_SERVICE_SET:
            w["dcp_set_count"] += 1
        elif service_id == DCP_SERVICE_GET:
            w["dcp_get_count"] += 1
        elif service_id == DCP_SERVICE_HELLO:
            w["dcp_hello_count"] += 1

    reader.close()

    print(f"[INFO] Tổng packets: {total_packets}, DCP packets: {dcp_packets}")

    if dcp_packets == 0:
        print("[WARNING] Không tìm thấy Profinet DCP frame nào trong PCAP.")
        print("[HINT]    Kiểm tra lại: tcpdump có bắt được 'ether proto 0x8892' không?")
        print("[HINT]    Nếu chụp qua router thì DCP (L2) không đi qua – cần SPAN port.")

    # -----------------------------------------------------------------------
    # Write output CSV
    # -----------------------------------------------------------------------
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    header = [
        "window_start_ms",
        "window_end_ms",
        "capture_role",

        # Core DCP counters
        "dcp_identify_request_count",
        "dcp_identify_response_count",
        "dcp_set_count",
        "dcp_get_count",
        "dcp_hello_count",
        "dcp_total_frame_count",

        # Scanner analysis
        "dcp_unique_scanner_mac_count",   # Số MAC đã gửi Identify Request
        "dcp_unique_device_mac_count",    # Số thiết bị đã phản hồi
        "dcp_scan_detected",              # 1 nếu phát hiện scan (request ≥ 2)

        # Device discovery
        "dcp_discovered_device_count",
        "dcp_discovered_vendor_count",

        # Traffic metrics
        "dcp_total_bytes",
        "dcp_frame_rate",                 # frames/giây
        "dcp_bytes_per_second",

        # Timing
        "dcp_inter_frame_interval_mean",  # ms
        "dcp_inter_frame_interval_std",   # ms
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)

        for w_start in sorted(windows.keys()):
            w = windows[w_start]
            w_end = w_start + window_size * 1000

            # Compute derived metrics
            frame_rate = w["dcp_total_frame_count"] / window_size
            bytes_per_sec = w["dcp_total_bytes"] / window_size

            # Inter-frame intervals
            ts_list = sorted(w["dcp_timestamps"])
            if len(ts_list) >= 2:
                intervals_ms = [(ts_list[i+1] - ts_list[i]) * 1000
                                for i in range(len(ts_list) - 1)]
                ifi_mean = statistics.mean(intervals_ms)
                ifi_std = statistics.stdev(intervals_ms) if len(intervals_ms) > 1 else 0.0
            else:
                ifi_mean = 0.0
                ifi_std = 0.0

            scan_detected = int(w["dcp_identify_request_count"] >= 2)

            writer.writerow([
                w_start,
                w_end,
                role,

                w["dcp_identify_request_count"],
                w["dcp_identify_response_count"],
                w["dcp_set_count"],
                w["dcp_get_count"],
                w["dcp_hello_count"],
                w["dcp_total_frame_count"],

                len(w["dcp_unique_src_macs"]),
                len(w["dcp_unique_response_macs"]),
                scan_detected,

                len(w["dcp_discovered_ips"]),
                len(w["dcp_discovered_vendors"]),

                w["dcp_total_bytes"],
                round(frame_rate, 6),
                round(bytes_per_sec, 6),

                round(ifi_mean, 3),
                round(ifi_std, 3),
            ])

    total_windows = len(windows)
    scan_windows = sum(1 for w in windows.values()
                       if w["dcp_identify_request_count"] >= 2)

    print(f"[OK] Extracted {total_windows} time windows")
    if scan_windows > 0:
        print(f"[ALERT] ⚠️  Phát hiện DCP SCAN trong {scan_windows} time window(s)!")
    print(f"[OK] Saved: {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract Profinet DCP (Layer 2) features from PCAP for IDS dataset.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python extract_dcp_features.py --pcap capture.pcap --output dcp_features.csv
  python extract_dcp_features.py --pcap attack_scan.pcap --output out.csv --window 5 --role attacker

Note:
  Profinet DCP chạy ở Layer 2 (EtherType 0x8892).
  File PCAP cần được bắt trực tiếp từ switch (SPAN port) hoặc trên
  cùng subnet với thiết bị Profinet – không đi qua router.
  
  Để bắt DCP bằng tcpdump:
    tcpdump -i eth0 'ether proto 0x8892' -w dcp_capture.pcap
  
  Để bắt cả DCP và S7:
    tcpdump -i eth0 '(ether proto 0x8892) or (tcp port 102)' -w capture.pcap
""",
    )
    parser.add_argument("--pcap", required=True, help="Input .pcap/.pcapng file")
    parser.add_argument("--output", required=True, help="Output CSV file")
    parser.add_argument("--window", type=int, default=10,
                        help="Time window size in seconds (default: 10)")
    parser.add_argument(
        "--role",
        default="attacker",
        choices=["attacker", "controller", "logger", "unknown"],
        help="Capture role label",
    )
    args = parser.parse_args()

    try:
        extract_dcp_features(
            pcap_path=args.pcap,
            window_size=args.window,
            output_path=args.output,
            role=args.role,
        )
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
