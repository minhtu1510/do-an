#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_industrial_ids_features.py

Unified Industrial IDS Feature Extractor for PLC/ICS PCAP/PCAPNG.

Gộp ý tưởng từ:
- extract_s7_features.py: S7/TCP, TPKT, COTP, S7comm/S7comm-plus, payload/network features
- extract_dcp_features.py: Profinet DCP discovery/scan features
- Bổ sung scan/recon features: ARP scan, ICMP scan, TCP port scan, PLC port 102 probe
- Bổ sung optional tag_log generic features để hỗ trợ logic attack nếu có log tag.

Output chính: 1 dòng / 1 time-window => phù hợp train IDS theo cửa sổ thời gian.

Cách dùng cơ bản:
  python extract_industrial_ids_features.py \
    --pcap capture.pcapng \
    --output industrial_features.csv \
    --window 5 \
    --plc-ip 192.168.0.1 \
    --label benign

Port scan / scan PLC:
  python extract_industrial_ids_features.py \
    --pcap scan.pcapng \
    --output scan_features.csv \
    --window 5 \
    --plc-ip 192.168.0.1 \
    --label port_scan

Có tag log:
  python extract_industrial_ids_features.py \
    --pcap day2.pcapng \
    --tag-log tag_log.csv \
    --output day2_features.csv \
    --window 5 \
    --plc-ip 192.168.0.1 \
    --timeline timeline.csv

Timeline CSV hỗ trợ cột:
  start,end,label
hoặc:
  start_time,end_time,label
Trong đó start/end có thể là epoch seconds hoặc epoch milliseconds.

Yêu cầu:
  - Wireshark/TShark đã cài và nằm trong PATH.
  - Scapy là optional, chỉ dùng để fallback parse Profinet DCP nếu TShark không có field pn_dcp.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import math
import os
import re
import shutil
import statistics
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple, Any


# ============================================================
# 0. Constants
# ============================================================

PROFINET_ETHERTYPE = 0x8892
PROFINET_MULTICAST_MAC = "01:0e:cf:00:00:00"

DCP_SERVICE_IDENTIFY = 0x05
DCP_SERVICE_SET = 0x04
DCP_SERVICE_GET = 0x03
DCP_SERVICE_HELLO = 0x06

DCP_TYPE_REQUEST = 0x00
DCP_TYPE_RESPONSE_SUCCESS = 0x01

PROFINET_VENDORS = {
    "002a": "Siemens",
    "000a": "Wago",
    "001c": "Beckhoff",
    "0060": "Phoenix Contact",
    "00a0": "Hirschmann",
    "0083": "Molex",
    "00cb": "SEW-Eurodrive",
}

META_COLS = {
    "window_start_ms",
    "window_end_ms",
    "label",
    "capture_role",
    "plc_ip",
    "decode_level",
    "session_id",
    "host_id",
    "scenario_id",
    "episode_id",
}

# Columns that should not be used as ML inputs in scientific IDS experiments.
# Keep these in the full feature CSV for audit/debug, but drop them from the
# ML-safe copy to avoid identity leakage and target leakage.
ML_UNSAFE_EXACT_COLS = {
    # metadata / identity / time
    "window_start_ms",
    "window_end_ms",
    "capture_role",
    "capture_source",
    "plc_ip",
    "decode_level",
    "session_id",
    "host_id",
    "scenario_id",
    "episode_id",
    "top_src_ip",
    "top_dst_ip",
    "top_protocol",
    "top_dst_port",

    # hand-written rule/anomaly outputs; use only as a rule baseline
    "scan_detected_rule",
    "dcp_scan_detected_rule",
    "dcp_scan_detected",
    "port_scan_score",
    "arp_scan_score",
    "plc_scan_score",
    "green_conflict",
    "red_green_d1",
    "red_green_d2",
    "multi_light_d1",
    "multi_light_d2",
    "no_light_d1",
    "no_light_d2",
    "timer_out_of_range",
    "setpoint_corrupted",
    "q_output_unexpected",
    "belt_stopped_unexpectedly",
    "stop_flag_unexpected",
    "all_sensors_active",
    "sensor_vs_belt_conflict",
    "cd_timer_out_of_range",
    "cd_timer_corrupted",
}


# ============================================================
# 1. Generic helpers
# ============================================================

def find_tshark() -> str:
    exe = shutil.which("tshark")
    if exe:
        return exe

    if os.name == "nt" or "MINGW" in os.environ.get("MSYSTEM", ""):
        candidates = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]
        for p in candidates:
            if os.path.exists(p):
                return p

    raise FileNotFoundError(
        "Không tìm thấy tshark. Hãy cài Wireshark/TShark và thêm tshark vào PATH."
    )


def get_available_fields(tshark_cmd: str) -> Set[str]:
    try:
        proc = subprocess.run(
            [tshark_cmd, "-G", "fields"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            encoding="utf-8",
            errors="ignore",
        )
    except Exception:
        return set()

    fields: Set[str] = set()
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        for p in parts:
            p = p.strip()
            if "." in p and not p.startswith("http://"):
                fields.add(p)
    return fields


def choose_existing_fields(available: Set[str], wanted: Iterable[str]) -> List[str]:
    if not available:
        return list(wanted)
    return [f for f in wanted if f.startswith("_ws.") or f in available]


def safe_int(x: Any, default: int = 0) -> int:
    if x is None:
        return default
    s = str(x).strip().strip('"')
    if not s:
        return default
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(float(s))
    except Exception:
        return default


def safe_float(x: Any, default: float = 0.0) -> float:
    if x is None:
        return default
    s = str(x).strip().strip('"')
    if not s:
        return default
    try:
        return float(s)
    except Exception:
        return default


def split_multi(x: Any) -> List[str]:
    if x is None:
        return []
    s = str(x).strip().strip('"')
    if not s:
        return []
    vals = re.split(r"[;,]", s)
    return [v.strip() for v in vals if v.strip()]


def has_truthy_flag(x: Any) -> bool:
    s = str(x).strip().strip('"').lower()
    return s in {"1", "true", "set", "yes"}


def mean(xs: List[float]) -> float:
    return statistics.mean(xs) if xs else 0.0


def std(xs: List[float]) -> float:
    return statistics.stdev(xs) if len(xs) > 1 else 0.0


def normalize_hex_payload(x: str) -> str:
    if not x:
        return ""
    x = str(x).strip().strip('"').lower()
    x = x.replace(":", "").replace(" ", "").replace("-", "")
    x = re.sub(r"[^0-9a-f]", "", x)
    if len(x) % 2 != 0:
        x = x[:-1]
    return x


def payload_bytes_from_hex(x: str) -> bytes:
    hx = normalize_hex_payload(x)
    if not hx:
        return b""
    try:
        return bytes.fromhex(hx)
    except Exception:
        return b""


def payload_entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = Counter(b)
    total = len(b)
    ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent


def payload_hash_short(b: bytes) -> str:
    if not b:
        return ""
    return hashlib.sha1(b).hexdigest()[:16]


def decode_level_from_rank(rank: int) -> str:
    if rank >= 3:
        return "s7_full"
    if rank == 2:
        return "s7_partial"
    if rank == 1:
        return "cotp_tpkt"
    return "network_only"


def normalize_epoch_ms(x: Any) -> int:
    """Accept epoch seconds or milliseconds and return ms."""
    v = safe_float(x, -1)
    if v < 0:
        return -1
    if v > 10_000_000_000:  # likely ms
        return int(v)
    return int(v * 1000)


# ============================================================
# 2. S7 classification helpers
# ============================================================

def classify_s7_function(func_values: List[str]) -> Tuple[int, int, int, int]:
    read = write = setup = cpu = 0
    for raw in func_values:
        s = str(raw).lower().strip()
        if not s:
            continue
        if "read" in s:
            read += 1
            continue
        if "write" in s:
            write += 1
            continue
        if "setup" in s or "communication" in s:
            setup += 1
            continue
        if "cpu" in s or "stop" in s or "start" in s or "plc control" in s:
            cpu += 1
            continue
        val = safe_int(s, -1)
        if val == 0x04:
            read += 1
        elif val == 0x05:
            write += 1
        elif val == 0xF0:
            setup += 1
    return read, write, setup, cpu


def classify_rosctr(rosctr_values: List[str]) -> Tuple[int, int, int, int]:
    job = ack = ack_data = userdata = 0
    for raw in rosctr_values:
        s = str(raw).lower().strip()
        if not s:
            continue
        if "ack_data" in s or "ack data" in s:
            ack_data += 1
            continue
        if "userdata" in s or "user data" in s:
            userdata += 1
            continue
        if "job" in s:
            job += 1
            continue
        if s == "ack" or "acknowledge" in s:
            ack += 1
            continue
        val = safe_int(s, -1)
        if val == 0x01:
            job += 1
        elif val == 0x02:
            ack += 1
        elif val == 0x03:
            ack_data += 1
        elif val == 0x07:
            userdata += 1
    return job, ack, ack_data, userdata


def classify_s7_plus_function(plus_funcs: List[str]) -> Tuple[int, int, int, int]:
    read = write = setup = cpu = 0
    for f in plus_funcs:
        fs = str(f).lower().strip()
        if not fs:
            continue
        if any(x in fs for x in ["getmultivariables", "getvarsubstreamed", "getlink", "read"]):
            read += 1
            continue
        if any(x in fs for x in ["setmultivariables", "setvariable", "write"]):
            write += 1
            continue
        if any(x in fs for x in ["stop", "start", "cpu", "control", "plc control"]):
            cpu += 1
            continue
        if any(x in fs for x in ["createobject", "deleteobject", "explore", "sequence", "invoke", "setup", "negotiate"]):
            setup += 1
            continue

        val = safe_int(fs, -1)
        if val in [0x054C, 0x0586, 0x0524]:
            read += 1
        elif val in [0x0542, 0x04F2]:
            write += 1
        elif val in [0x04CA, 0x04D4, 0x04BB, 0x0556, 0x0560, 0x056B]:
            setup += 1
        elif val in [0x0545, 0x0546]:
            cpu += 1
    return read, write, setup, cpu


# ============================================================
# 3. DCP parser for Scapy fallback
# ============================================================

def parse_dcp_frame(raw_payload: bytes) -> Optional[dict]:
    if len(raw_payload) < 12:
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
            "ip_addr": None,
            "device_name": None,
            "vendor_id": None,
            "device_id": None,
            "device_role": None,
        }
        offset = 12
        end = min(12 + dcp_data_length, len(raw_payload))
        while offset + 4 <= end:
            option = raw_payload[offset]
            sub_option = raw_payload[offset + 1]
            block_len = int.from_bytes(raw_payload[offset + 2: offset + 4], "big")
            block_data = raw_payload[offset + 4: offset + 4 + block_len]

            if option == 0x01 and sub_option == 0x02 and len(block_data) >= 4:
                result["ip_addr"] = ".".join(str(b) for b in block_data[:4])
            if option == 0x02 and sub_option == 0x02 and block_data:
                try:
                    result["device_name"] = block_data.decode("latin-1").strip("\x00")
                except Exception:
                    pass
            if option == 0x02 and sub_option == 0x03 and len(block_data) >= 4:
                result["vendor_id"] = block_data[0:2].hex()
                result["device_id"] = block_data[2:4].hex()
            if option == 0x02 and sub_option == 0x04 and block_data:
                role_byte = block_data[0]
                roles = {0x01: "IO-Device", 0x02: "IO-Controller", 0x04: "IO-Multidevice", 0x08: "PN-Supervisor"}
                result["device_role"] = roles.get(role_byte, f"0x{role_byte:02x}")

            padded_len = block_len + (block_len % 2)
            offset += 4 + padded_len
        return result
    except Exception:
        return None


# ============================================================
# 4. Window data structure
# ============================================================

def new_window() -> dict:
    return {
        # metadata/debug sets
        "src_ips": set(),
        "dst_ips": set(),
        "src_macs": set(),
        "dst_macs": set(),
        "src_ports": set(),
        "dst_ports": set(),
        "tcp_streams": set(),

        # context counters: top IP/protocol/port per window (for debugging + merge filtering)
        "_src_ip_ctr": {},
        "_dst_ip_ctr": {},
        "_dst_port_ctr": {},
        "_proto_ctr": {},

        # total traffic
        "packet_count": 0,
        "byte_count": 0,
        "frame_lengths": [],
        "tcp_payload_lengths": [],
        "malformed_packet_count": 0,

        # L3/L4 protocol counts
        "tcp_count": 0,
        "udp_count": 0,
        "arp_count": 0,
        "icmp_count": 0,
        "other_l3_count": 0,

        # TCP flags/analysis
        "tcp_syn_count": 0,
        "tcp_ack_count": 0,
        "tcp_rst_count": 0,
        "tcp_fin_count": 0,
        "tcp_psh_count": 0,
        "tcp_102_packet_count": 0,
        "tcp_102_probe_count": 0,
        "tcp_low_port_probe_count": 0,
        "tcp_high_port_probe_count": 0,
        "tcp_time_deltas": [],
        "tcp_retransmit_count": 0,
        "tcp_out_of_order_count": 0,
        "tcp_prev_seg_lost_count": 0,

        # scan aggregation by source IP/MAC
        "scan_by_src": defaultdict(lambda: {
            "packets": 0,
            "bytes": 0,
            "dst_ips": set(),
            "dst_ports": set(),
            "src_ports": set(),
            "syn": 0,
            "ack": 0,
            "rst": 0,
            "fin": 0,
            "icmp": 0,
            "icmp_echo": 0,
            "arp_req": 0,
            "arp_rep": 0,
            "arp_targets": set(),
            "tcp_102": 0,
        }),

        # ARP details
        "arp_request_count": 0,
        "arp_reply_count": 0,
        "arp_unique_target_ips": set(),
        "arp_unique_sender_ips": set(),
        "arp_unique_sender_macs": set(),
        "arp_broadcast_count": 0,

        # ICMP details
        "icmp_echo_request_count": 0,
        "icmp_echo_reply_count": 0,

        # Profinet DCP
        "dcp_total_frame_count": 0,
        "dcp_total_bytes": 0,
        "dcp_identify_request_count": 0,
        "dcp_identify_response_count": 0,
        "dcp_set_count": 0,
        "dcp_get_count": 0,
        "dcp_hello_count": 0,
        "dcp_unique_scanner_macs": set(),
        "dcp_unique_device_macs": set(),
        "dcp_discovered_ips": set(),
        "dcp_discovered_vendors": Counter(),
        "dcp_discovered_device_ids": set(),
        "dcp_timestamps": [],

        # Industrial protocol counters
        "tpkt_count": 0,
        "cotp_count": 0,
        "cotp_cr_count": 0,
        "cotp_cc_count": 0,
        "cotp_dt_count": 0,
        "cotp_dr_count": 0,
        "cotp_fragment_count": 0,
        "pres_data_transfer_count": 0,
        "s7comm_packet_count": 0,
        "s7comm_plus_packet_count": 0,

        # direction relative to PLC
        "to_plc_packet_count": 0,
        "to_plc_byte_count": 0,
        "from_plc_packet_count": 0,
        "from_plc_byte_count": 0,
        "plc_response_timestamps": [],

        # S7 semantic counters
        "s7_read_count": 0,
        "s7_write_count": 0,
        "s7_setup_count": 0,
        "s7_cpu_control_count": 0,
        "s7_error_count": 0,
        "s7_pdu_job_count": 0,
        "s7_pdu_ack_count": 0,
        "s7_pdu_ack_data_count": 0,
        "s7_pdu_userdata_count": 0,
        "s7_dbs": set(),
        "s7_areas": set(),
        "s7_offsets": set(),
        "s7_transport_sizes": set(),
        "s7_command_keys": Counter(),
        "s7_unique_commands": set(),
        "s7_offsets_ordered": [],
        "s7_db_area_count": 0,
        "s7_merker_area_count": 0,
        "s7_input_area_count": 0,
        "s7_output_area_count": 0,
        "s7_other_area_count": 0,
        "s7_input_write_count": 0,
        "s7_output_write_count": 0,
        "s7_write_payload_bytes": [],
        "s7_write_payload_bytes_total": 0,
        "s7_max_item_count": 0,

        # payload stats
        "raw_payload_lengths": [],
        "payload_entropies": [],
        "payload_hashes": Counter(),

        # tag log generic features
        "tag_event_count": 0,
        "tag_names": set(),
        "tag_changed_names": set(),
        "tag_numeric_values": [],
        "tag_change_count": 0,
        "tag_binary_one_count": 0,
        "tag_binary_zero_count": 0,

        # CICFlowMeter-compatible directional & IAT features
        # fwd = toward PLC (to_plc); bwd = from PLC (from_plc)
        "fwd_pkt_lengths": [],
        "bwd_pkt_lengths": [],
        "fwd_tcp_payload_lengths": [],
        "bwd_tcp_payload_lengths": [],

        # Inter-arrival time (seconds) — flow-level and per-direction
        "flow_iat": [],
        "fwd_iat": [],
        "bwd_iat": [],
        "_last_pkt_ts": None,
        "_last_fwd_ts": None,
        "_last_bwd_ts": None,

        # TCP flags — directional and extra (URG/CWE/ECE)
        "fwd_psh_count": 0,
        "bwd_psh_count": 0,
        "tcp_urg_count": 0,
        "fwd_urg_count": 0,
        "bwd_urg_count": 0,
        "tcp_cwe_count": 0,
        "tcp_ece_count": 0,

        # TCP window sizes per direction
        "fwd_win_sizes": [],
        "bwd_win_sizes": [],
        "fwd_init_win_bytes": -1,   # window size of first SYN (client→PLC)
        "bwd_init_win_bytes": -1,   # window size of first SYN-ACK (PLC→client)

        # Header lengths (IP hdr + TCP hdr, bytes)
        "fwd_header_lengths": [],
        "bwd_header_lengths": [],

        # Data packets (tcp_len > 0) and segment sizes
        "fwd_data_pkt_count": 0,
        "bwd_data_pkt_count": 0,
        "fwd_seg_sizes": [],
        "bwd_seg_sizes": [],

        # Active/Idle periods within window (gap > IDLE_THRESHOLD=1s → idle)
        "active_durations": [],
        "idle_durations": [],
        "_active_period_start": None,
        "_last_active_ts": None,

        # decode quality
        "decode_rank": 0,
    }


def new_flow() -> dict:
    """Directional flow/debug accumulator: 1 row = 1 time-window + 5-tuple-ish flow."""
    return {
        "packet_count": 0,
        "byte_count": 0,
        "frame_lengths": [],
        "tcp_payload_lengths": [],
        "tcp_syn_count": 0,
        "tcp_ack_count": 0,
        "tcp_rst_count": 0,
        "tcp_fin_count": 0,
        "tcp_psh_count": 0,
        "arp_request_count": 0,
        "arp_reply_count": 0,
        "icmp_echo_request_count": 0,
        "icmp_echo_reply_count": 0,
        "tcp_retransmit_count": 0,
        "tcp_out_of_order_count": 0,
        "tcp_prev_seg_lost_count": 0,
        "tpkt_count": 0,
        "cotp_count": 0,
        "s7comm_packet_count": 0,
        "s7comm_plus_packet_count": 0,
        "dcp_total_frame_count": 0,
        "to_plc_packet_count": 0,
        "from_plc_packet_count": 0,
        "raw_payload_lengths": [],
        "payload_entropies": [],
    }


def update_decode_rank(w: dict, rank: int) -> None:
    if rank > w["decode_rank"]:
        w["decode_rank"] = rank


# ============================================================
# 5. TShark command
# ============================================================

def build_tshark_command(
    tshark_cmd: str,
    pcap_path: str,
    available_fields: Set[str],
    plc_ip: Optional[str] = None,
    include_payload: bool = True,
    tls_keylog: Optional[str] = None,
    ssl_keys: Optional[str] = None,
) -> Tuple[List[str], List[str], bool]:
    base_fields = [
        "frame.time_epoch",
        "frame.len",
        "frame.protocols",
        "eth.src",
        "eth.dst",
        "eth.type",
        "ip.src",
        "ip.dst",
        "ip.proto",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.len",
        "tcp.stream",
        "tcp.time_delta",
        "tcp.flags.syn",
        "tcp.flags.ack",
        "tcp.flags.reset",
        "tcp.flags.push",
        "tcp.flags.fin",
        "tcp.analysis.retransmission",
        "tcp.analysis.out_of_order",
        "tcp.analysis.previous_segment_not_captured",
        "udp.srcport",
        "udp.dstport",
        "arp.opcode",
        "arp.src.proto_ipv4",
        "arp.dst.proto_ipv4",
        "arp.src.hw_mac",
        "arp.dst.hw_mac",
        "icmp.type",
        "icmp.code",
        # CICFlowMeter-equivalent extra fields
        "tcp.flags.urg",
        "tcp.flags.cwr",
        "tcp.flags.ecn",
        "tcp.window_size",
        "tcp.hdr_len",
        "ip.hdr_len",
        "ip.len",
        "_ws.malformed",
        "_ws.col.Protocol",
        "_ws.col.Info",
    ]

    payload_fields = ["tcp.payload", "data.data"] if include_payload else []

    dcp_fields = [
        "pn_dcp.service_id",
        "pn_dcp.service_type",
        "pn_dcp.xid",
        "pn_dcp.response_delay",
        "pn_dcp.option",
        "pn_dcp.suboption",
        "pn_dcp.block_info",
        "pn_dcp.ip",
        "pn_dcp.name_of_station",
        "pn_dcp.vendor_id",
        "pn_dcp.device_id",
    ]

    s7_fields = [
        "s7comm.header.rosctr",
        "s7comm.param.func",
        "s7comm.param.item.db",
        "s7comm.param.item.area",
        "s7comm.param.item.address",
        "s7comm.param.item.transport_size",
        "s7comm.resp.error_class",
        "s7comm.resp.error_code",
        "s7comm.data.returncode",
    ]

    s7_plus_fields = [
        "s7comm-plus.rosctr",
        "s7comm-plus.opcode",
        "s7comm-plus.function",
        "s7comm-plus.param.item.db",
        "s7comm-plus.param.item.area",
        "s7comm-plus.param.item.address",
        "s7comm-plus.resp.error_code",
        "s7comm-plus.data.opcode",
        "s7comm-plus.data.function",
        "s7comm-plus.item.addr.dbnumber",
        "s7comm-plus.item.addr.area",
        "s7comm-plus.data.item_address",
        "s7comm-plus.returnvalue.errorcode",
        "s7comm_plus.rosctr",
        "s7comm_plus.opcode",
        "s7comm_plus.function",
        "s7comm_plus.param.item.db",
        "s7comm_plus.param.item.area",
        "s7comm_plus.param.item.address",
        "s7comm_plus.resp.error_code",
        "s7commplus.rosctr",
        "s7commplus.opcode",
        "s7commplus.function",
        "s7commplus.param.item.db",
        "s7commplus.param.item.area",
        "s7commplus.param.item.address",
        "s7commplus.resp.error_code",
        "s7plus.rosctr",
        "s7plus.opcode",
        "s7plus.function",
        "s7plus.param.item.db",
        "s7plus.param.item.area",
        "s7plus.param.item.address",
        "s7plus.resp.error_code",
    ]

    fields = []
    for group in [base_fields, payload_fields, dcp_fields, s7_fields, s7_plus_fields]:
        fields.extend(choose_existing_fields(available_fields, group))

    # Deduplicate while preserving order
    seen = set()
    fields = [f for f in fields if not (f in seen or seen.add(f))]

    # Broad filter intentionally keeps network recon, DCP, and S7 traffic.
    # Offline PCAP processing: filter rộng giúp không bỏ sót scan/PLC discovery.
    if plc_ip:
        display_filter = (
            f"(ip.addr == {plc_ip}) || arp || icmp || pn_dcp || eth.type == 0x8892 || tcp.port == 102"
        )
    else:
        display_filter = "tcp || udp || arp || icmp || pn_dcp || eth.type == 0x8892"

    cmd = [
        tshark_cmd,
        "-r", pcap_path,
        "-o", "tcp.desegment_tcp_streams:TRUE",
        "-o", "cotp.reassemble:TRUE",
    ]
    if tls_keylog:
        cmd += ["-o", f"tls.keylog_file:{tls_keylog}", "-o", f"ssl.keylog_file:{tls_keylog}"]
    if ssl_keys:
        cmd += ["-o", f"tls.keys_list:{ssl_keys}", "-o", f"ssl.keys_list:{ssl_keys}"]

    cmd += ["-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=a"]

    has_pn_dcp = any(f.startswith("pn_dcp.") for f in fields)
    return cmd, fields, has_pn_dcp


# ============================================================
# 6. Label/timeline and tag_log loading
# ============================================================

@dataclass
class TimelineLabel:
    start_ms: int
    end_ms: int
    label: str


def load_timeline(path: Optional[str]) -> List[TimelineLabel]:
    if not path:
        return []
    labels: List[TimelineLabel] = []
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return labels
        lower_map = {c.lower().strip(): c for c in reader.fieldnames}
        start_col = lower_map.get("start") or lower_map.get("start_time") or lower_map.get("start_timestamp")
        end_col = lower_map.get("end") or lower_map.get("end_time") or lower_map.get("end_timestamp")
        label_col = lower_map.get("label") or lower_map.get("attack") or lower_map.get("class")
        if not start_col or not end_col or not label_col:
            raise ValueError("Timeline CSV cần cột start,end,label hoặc start_time,end_time,label")
        for row in reader:
            s = normalize_epoch_ms(row.get(start_col))
            e = normalize_epoch_ms(row.get(end_col))
            lab = str(row.get(label_col, "")).strip()
            if s >= 0 and e >= s and lab:
                labels.append(TimelineLabel(s, e, lab))
    return labels


def label_for_window(w_start_ms: int, w_end_ms: int, timeline: List[TimelineLabel], default_label: str) -> str:
    if not timeline:
        return default_label
    # choose label with maximum overlap
    best_label = default_label
    best_overlap = 0
    for item in timeline:
        overlap = max(0, min(w_end_ms, item.end_ms) - max(w_start_ms, item.start_ms))
        if overlap > best_overlap:
            best_overlap = overlap
            best_label = item.label
    return best_label


def detect_tag_columns(fieldnames: List[str]) -> Tuple[str, str, str]:
    lower = {c.lower().strip(): c for c in fieldnames}
    ts_col = (
        lower.get("timestamp") or lower.get("time") or lower.get("ts") or
        lower.get("frame.time_epoch") or lower.get("datetime")
    )
    tag_col = (
        lower.get("tag_name") or lower.get("tag") or lower.get("name") or
        lower.get("variable") or lower.get("address")
    )
    val_col = (
        lower.get("value") or lower.get("tag_value") or lower.get("val") or
        lower.get("state")
    )
    if not ts_col or not tag_col or not val_col:
        raise ValueError(
            "tag_log cần có các cột tương đương: timestamp,time/ts; tag_name,tag/name; value,val/state"
        )
    return ts_col, tag_col, val_col


def update_tag_features(windows: Dict[int, dict], tag_log_path: Optional[str], window_size: int) -> None:
    if not tag_log_path:
        return
    if not os.path.exists(tag_log_path):
        raise FileNotFoundError(f"Không tìm thấy tag_log: {tag_log_path}")

    last_value_by_tag: Dict[str, str] = {}
    with open(tag_log_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return
        ts_col, tag_col, val_col = detect_tag_columns(reader.fieldnames)
        for row in reader:
            ts_ms = normalize_epoch_ms(row.get(ts_col))
            if ts_ms < 0:
                continue
            w_start_ms = (ts_ms // (window_size * 1000)) * (window_size * 1000)
            w = windows[w_start_ms]
            tag = str(row.get(tag_col, "")).strip()
            val = str(row.get(val_col, "")).strip()
            if not tag:
                continue
            w["tag_event_count"] += 1
            w["tag_names"].add(tag)

            v_float = safe_float(val, default=float("nan"))
            if not math.isnan(v_float):
                w["tag_numeric_values"].append(v_float)
                if v_float == 1:
                    w["tag_binary_one_count"] += 1
                elif v_float == 0:
                    w["tag_binary_zero_count"] += 1

            if tag in last_value_by_tag and last_value_by_tag[tag] != val:
                w["tag_change_count"] += 1
                w["tag_changed_names"].add(tag)
            elif tag not in last_value_by_tag:
                # lần xuất hiện đầu tiên không tính là change, chỉ ghi trạng thái nền
                pass
            last_value_by_tag[tag] = val


# ============================================================
# 7. Main packet processing
# ============================================================

def parse_int_any(x: str) -> int:
    vals = split_multi(x)
    if vals:
        return safe_int(vals[0], -1)
    return safe_int(x, -1)


def update_area_counters(w: dict, area: str, is_write_cmd: bool) -> None:
    s = str(area).lower().strip()
    if not s:
        return
    w["s7_areas"].add(area)
    if "db" in s or "data block" in s or "0x84" in s or s == "132":
        w["s7_db_area_count"] += 1
    elif "merker" in s or "0x83" in s or s == "131":
        w["s7_merker_area_count"] += 1
    elif "input" in s or "0x81" in s or s == "129":
        w["s7_input_area_count"] += 1
        if is_write_cmd:
            w["s7_input_write_count"] += 1
    elif "output" in s or "0x82" in s or s == "130":
        w["s7_output_area_count"] += 1
        if is_write_cmd:
            w["s7_output_write_count"] += 1
    else:
        w["s7_other_area_count"] += 1


def extract_features(
    pcap_path: str,
    output_path: str,
    window_size: int = 5,
    plc_ip: Optional[str] = None,
    role: str = "unknown",
    label: str = "unknown",
    timeline_path: Optional[str] = None,
    tag_log_path: Optional[str] = None,
    session_id: str = "unknown_session",
    host_id: str = "unknown_host",
    scenario_id: str = "unlabeled",
    episode_id: str = "unlabeled",
    standalone_labeling: bool = False,
    include_payload: bool = True,
    tls_keylog: Optional[str] = None,
    ssl_keys: Optional[str] = None,
    scapy_dcp_fallback: bool = True,
    flow_debug_path: Optional[str] = None,
) -> None:
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP không tồn tại: {pcap_path}")

    tshark_cmd = find_tshark()
    available_fields = get_available_fields(tshark_cmd)
    cmd, field_names, has_pn_dcp_fields = build_tshark_command(
        tshark_cmd=tshark_cmd,
        pcap_path=pcap_path,
        available_fields=available_fields,
        plc_ip=plc_ip,
        include_payload=include_payload,
        tls_keylog=tls_keylog,
        ssl_keys=ssl_keys,
    )
    field_index = {name: i for i, name in enumerate(field_names)}

    def get(parts: List[str], name: str) -> str:
        idx = field_index.get(name)
        if idx is None or idx >= len(parts):
            return ""
        return parts[idx].strip('"')

    windows: Dict[int, dict] = defaultdict(new_window)
    flow_windows: Dict[int, Dict[Tuple[str, str, str, str, str], dict]] = defaultdict(lambda: defaultdict(new_flow))

    print(f"[INFO] TShark: {tshark_cmd}")
    print(f"[INFO] PCAP: {pcap_path}")
    print(f"[INFO] Window: {window_size}s")
    print(f"[INFO] PLC IP: {plc_ip if plc_ip else 'None'}")
    print(f"[INFO] Raw payload: {include_payload}")
    print(f"[INFO] pn_dcp fields: {has_pn_dcp_fields}")
    print(f"[INFO] Output: {output_path}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
    except Exception as e:
        raise RuntimeError(f"Không chạy được tshark: {e}")

    packet_count_debug = 0
    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip("\n")
        if not line:
            continue
        try:
            parts = next(csv.reader([line], delimiter="\t", quotechar='"'))
        except Exception:
            continue

        ts = safe_float(get(parts, "frame.time_epoch"), -1.0)
        if ts < 0:
            continue
        packet_count_debug += 1
        w_start_ms = int(ts * 1000) // (window_size * 1000) * (window_size * 1000)
        w = windows[w_start_ms]

        frame_len = safe_int(get(parts, "frame.len"), 0)
        eth_src = get(parts, "eth.src").lower()
        eth_dst = get(parts, "eth.dst").lower()
        eth_type = get(parts, "eth.type").lower()
        ip_src = get(parts, "ip.src")
        ip_dst = get(parts, "ip.dst")
        tcp_sport = get(parts, "tcp.srcport")
        tcp_dport = get(parts, "tcp.dstport")
        udp_sport = get(parts, "udp.srcport")
        udp_dport = get(parts, "udp.dstport")
        tcp_len = safe_int(get(parts, "tcp.len"), 0)
        protocols = get(parts, "frame.protocols").lower()
        proto_col = get(parts, "_ws.col.Protocol").lower()
        proto_all = f"{proto_col}:{protocols}"
        info_col = get(parts, "_ws.col.Info")
        info_lower = info_col.lower()

        w["packet_count"] += 1
        w["byte_count"] += frame_len
        w["frame_lengths"].append(frame_len)
        if eth_src:
            w["src_macs"].add(eth_src)
        if eth_dst:
            w["dst_macs"].add(eth_dst)
        if ip_src:
            w["src_ips"].add(ip_src)
        else:
            _arp_src = get(parts, "arp.src.proto_ipv4")
            if _arp_src: w["src_ips"].add(_arp_src)
            
        if ip_dst:
            w["dst_ips"].add(ip_dst)
        else:
            _arp_dst = get(parts, "arp.dst.proto_ipv4")
            if _arp_dst: w["dst_ips"].add(_arp_dst)
        if tcp_sport or udp_sport:
            w["src_ports"].add(tcp_sport or udp_sport)
        if tcp_dport or udp_dport:
            w["dst_ports"].add(tcp_dport or udp_dport)

        # Determine protocol
        is_arp = "arp" in proto_all or eth_type == "0x0806"
        is_icmp = "icmp" in proto_all
        is_tcp = "tcp" in protocols or tcp_sport or tcp_dport
        is_udp = "udp" in protocols or udp_sport or udp_dport
        is_dcp = "pn_dcp" in proto_all or eth_type in {"0x8892", "8892"}

        if is_tcp:
            w["tcp_count"] += 1
            w["tcp_payload_lengths"].append(tcp_len)
        elif is_udp:
            w["udp_count"] += 1
        elif is_arp:
            w["arp_count"] += 1
        elif is_icmp:
            w["icmp_count"] += 1
        else:
            w["other_l3_count"] += 1

        # Context counters (top IP/proto/port per window)
        _proto_str = proto_col.upper() if proto_col else (
            "TCP" if is_tcp else ("UDP" if is_udp else
            ("ARP" if is_arp else ("ICMP" if is_icmp else
            ("DCP" if is_dcp else "OTHER"))))
        )
        _sip = ip_src or get(parts, "arp.src.proto_ipv4") or eth_src or ""
        _dip = ip_dst or get(parts, "arp.dst.proto_ipv4") or eth_dst or ""
        _dpt = tcp_dport or udp_dport
        if _sip:
            w["_src_ip_ctr"][_sip] = w["_src_ip_ctr"].get(_sip, 0) + 1
        if _dip:
            w["_dst_ip_ctr"][_dip] = w["_dst_ip_ctr"].get(_dip, 0) + 1
        if _dpt:
            _k = str(_dpt)
            w["_dst_port_ctr"][_k] = w["_dst_port_ctr"].get(_k, 0) + 1
        w["_proto_ctr"][_proto_str] = w["_proto_ctr"].get(_proto_str, 0) + 1

        # TCP flags and analysis
        syn = has_truthy_flag(get(parts, "tcp.flags.syn"))
        ack = has_truthy_flag(get(parts, "tcp.flags.ack"))
        rst = has_truthy_flag(get(parts, "tcp.flags.reset"))
        fin = has_truthy_flag(get(parts, "tcp.flags.fin"))
        psh = has_truthy_flag(get(parts, "tcp.flags.push"))
        if syn:
            w["tcp_syn_count"] += 1
        if ack:
            w["tcp_ack_count"] += 1
        if rst:
            w["tcp_rst_count"] += 1
        if fin:
            w["tcp_fin_count"] += 1
        if psh:
            w["tcp_psh_count"] += 1

        # ----------------------------------------------------
        # Directional flow/debug aggregation
        # This is NOT the main ML output. It is for checking packet/flow identity.
        # For IP packets: src/dst are ip.src/ip.dst. For ARP/DCP L2 packets, use ARP IP/MAC fallback.
        # ----------------------------------------------------
        if is_dcp:
            flow_proto = "DCP"
        elif is_arp:
            flow_proto = "ARP"
        elif is_icmp:
            flow_proto = "ICMP"
        elif is_tcp:
            flow_proto = "TCP"
        elif is_udp:
            flow_proto = "UDP"
        else:
            flow_proto = "OTHER"

        arp_src_ip_dbg = get(parts, "arp.src.proto_ipv4")
        arp_dst_ip_dbg = get(parts, "arp.dst.proto_ipv4")
        flow_src = ip_src or arp_src_ip_dbg or eth_src or ""
        flow_dst = ip_dst or arp_dst_ip_dbg or eth_dst or ""
        flow_sport = tcp_sport or udp_sport or "0"
        flow_dport = tcp_dport or udp_dport or "0"
        flow_key = (flow_src, flow_dst, flow_sport, flow_dport, flow_proto)
        fw = flow_windows[w_start_ms][flow_key]
        fw["packet_count"] += 1
        fw["byte_count"] += frame_len
        fw["frame_lengths"].append(frame_len)
        if is_tcp:
            fw["tcp_payload_lengths"].append(tcp_len)
        if syn:
            fw["tcp_syn_count"] += 1
        if ack:
            fw["tcp_ack_count"] += 1
        if rst:
            fw["tcp_rst_count"] += 1
        if fin:
            fw["tcp_fin_count"] += 1
        if psh:
            fw["tcp_psh_count"] += 1
        if has_truthy_flag(get(parts, "tcp.analysis.retransmission")):
            fw["tcp_retransmit_count"] += 1
        if has_truthy_flag(get(parts, "tcp.analysis.out_of_order")):
            fw["tcp_out_of_order_count"] += 1
        if has_truthy_flag(get(parts, "tcp.analysis.previous_segment_not_captured")):
            fw["tcp_prev_seg_lost_count"] += 1
        if tcp_sport == "102" or tcp_dport == "102":
            w["tcp_102_packet_count"] += 1
            if syn and tcp_dport == "102":
                w["tcp_102_probe_count"] += 1

        dport = safe_int(tcp_dport or udp_dport, -1)
        if dport >= 0:
            if dport <= 1024:
                w["tcp_low_port_probe_count"] += 1 if is_tcp and syn else 0
            else:
                w["tcp_high_port_probe_count"] += 1 if is_tcp and syn else 0

        tcp_stream = get(parts, "tcp.stream")
        if tcp_stream:
            w["tcp_streams"].add(tcp_stream)
        tcp_delta = safe_float(get(parts, "tcp.time_delta"), -1.0)
        if tcp_delta >= 0:
            w["tcp_time_deltas"].append(tcp_delta)
        if has_truthy_flag(get(parts, "tcp.analysis.retransmission")):
            w["tcp_retransmit_count"] += 1
        if has_truthy_flag(get(parts, "tcp.analysis.out_of_order")):
            w["tcp_out_of_order_count"] += 1
        if has_truthy_flag(get(parts, "tcp.analysis.previous_segment_not_captured")):
            w["tcp_prev_seg_lost_count"] += 1

        # scan-by-source aggregation. ARP source IP fallback.
        arp_src_ip = get(parts, "arp.src.proto_ipv4")
        arp_dst_ip = get(parts, "arp.dst.proto_ipv4")
        scan_src = ip_src or arp_src_ip or eth_src
        if scan_src:
            sw = w["scan_by_src"][scan_src]
            sw["packets"] += 1
            sw["bytes"] += frame_len
            if ip_dst:
                sw["dst_ips"].add(ip_dst)
            if arp_dst_ip:
                sw["arp_targets"].add(arp_dst_ip)
            if tcp_dport or udp_dport:
                sw["dst_ports"].add(tcp_dport or udp_dport)
            if tcp_sport or udp_sport:
                sw["src_ports"].add(tcp_sport or udp_sport)
            if syn:
                sw["syn"] += 1
            if ack:
                sw["ack"] += 1
            if rst:
                sw["rst"] += 1
            if fin:
                sw["fin"] += 1
            if is_icmp:
                sw["icmp"] += 1
            if tcp_dport == "102" and syn:
                sw["tcp_102"] += 1

        # ARP details
        if is_arp:
            opcode_raw = get(parts, "arp.opcode").lower()
            opcode = parse_int_any(opcode_raw)
            if opcode == 1 or "request" in opcode_raw:
                w["arp_request_count"] += 1
                fw["arp_request_count"] += 1
                if scan_src:
                    w["scan_by_src"][scan_src]["arp_req"] += 1
            elif opcode == 2 or "reply" in opcode_raw:
                w["arp_reply_count"] += 1
                fw["arp_reply_count"] += 1
                if scan_src:
                    w["scan_by_src"][scan_src]["arp_rep"] += 1
            if arp_dst_ip:
                w["arp_unique_target_ips"].add(arp_dst_ip)
            if arp_src_ip:
                w["arp_unique_sender_ips"].add(arp_src_ip)
            arp_src_mac = get(parts, "arp.src.hw_mac").lower()
            if arp_src_mac:
                w["arp_unique_sender_macs"].add(arp_src_mac)
            if eth_dst in {"ff:ff:ff:ff:ff:ff", "broadcast"}:
                w["arp_broadcast_count"] += 1

        # ICMP details
        if is_icmp:
            icmp_type = safe_int(get(parts, "icmp.type"), -1)
            if icmp_type == 8:
                w["icmp_echo_request_count"] += 1
                fw["icmp_echo_request_count"] += 1
                if scan_src:
                    w["scan_by_src"][scan_src]["icmp_echo"] += 1
            elif icmp_type == 0:
                w["icmp_echo_reply_count"] += 1
                fw["icmp_echo_reply_count"] += 1

        # DCP via TShark fields
        if is_dcp:
            w["dcp_total_frame_count"] += 1
            fw["dcp_total_frame_count"] += 1
            w["dcp_total_bytes"] += frame_len
            w["dcp_timestamps"].append(ts)
            service_vals = split_multi(get(parts, "pn_dcp.service_id"))
            type_vals = split_multi(get(parts, "pn_dcp.service_type"))
            # If no fields exist, only count total here; Scapy fallback can fill details later.
            service_id = safe_int(service_vals[0], -1) if service_vals else -1
            service_type = safe_int(type_vals[0], -1) if type_vals else -1
            if service_id == DCP_SERVICE_IDENTIFY:
                if service_type == DCP_TYPE_REQUEST:
                    w["dcp_identify_request_count"] += 1
                    if eth_src:
                        w["dcp_unique_scanner_macs"].add(eth_src)
                elif service_type == DCP_TYPE_RESPONSE_SUCCESS:
                    w["dcp_identify_response_count"] += 1
                    if eth_src:
                        w["dcp_unique_device_macs"].add(eth_src)
            elif service_id == DCP_SERVICE_SET:
                w["dcp_set_count"] += 1
            elif service_id == DCP_SERVICE_GET:
                w["dcp_get_count"] += 1
            elif service_id == DCP_SERVICE_HELLO:
                w["dcp_hello_count"] += 1

            for ip in split_multi(get(parts, "pn_dcp.ip")):
                if ip:
                    w["dcp_discovered_ips"].add(ip)
            for vid in split_multi(get(parts, "pn_dcp.vendor_id")):
                v = str(vid).lower().replace("0x", "")
                if v:
                    w["dcp_discovered_vendors"][PROFINET_VENDORS.get(v, v)] += 1
            for did in split_multi(get(parts, "pn_dcp.device_id")):
                if did:
                    w["dcp_discovered_device_ids"].add(did)

        # Industrial protocol detection
        if "tpkt" in proto_all:
            w["tpkt_count"] += 1
            fw["tpkt_count"] += 1
            update_decode_rank(w, 1)
        if "cotp" in proto_all:
            w["cotp_count"] += 1
            fw["cotp_count"] += 1
            update_decode_rank(w, 1)
        if any(x in proto_all for x in ["s7comm_plus", "s7comm-plus", "s7commplus", "s7plus"]):
            w["s7comm_plus_packet_count"] += 1
            fw["s7comm_plus_packet_count"] += 1
        elif "s7comm" in proto_all or proto_col == "s7" or "s7" in proto_col:
            w["s7comm_packet_count"] += 1
            fw["s7comm_packet_count"] += 1
            update_decode_rank(w, 2)

        if "tpkt" in proto_all or "cotp" in proto_all or "s7" in proto_all:
            if "connection request" in info_lower or " cr " in f" {info_lower} ":
                w["cotp_cr_count"] += 1
            if "connection confirm" in info_lower or " cc " in f" {info_lower} ":
                w["cotp_cc_count"] += 1
            if "data transfer" in info_lower or " dt " in f" {info_lower} " or "dt tpdu" in info_lower:
                w["cotp_dt_count"] += 1
            if "disconnect request" in info_lower or " dr " in f" {info_lower} ":
                w["cotp_dr_count"] += 1
            if "fragment" in info_lower:
                w["cotp_fragment_count"] += 1
        if "pres" in proto_all or "datatransfer" in info_lower or "data transfer" in info_lower:
            w["pres_data_transfer_count"] += 1

        # Direction relative to PLC
        is_to_plc = False
        is_from_plc = False
        if plc_ip:
            is_to_plc = ip_dst == plc_ip
            is_from_plc = ip_src == plc_ip
        else:
            is_from_plc = tcp_sport == "102"
            is_to_plc = tcp_dport == "102"
        if is_to_plc:
            w["to_plc_packet_count"] += 1
            fw["to_plc_packet_count"] += 1
            w["to_plc_byte_count"] += frame_len
        elif is_from_plc:
            w["from_plc_packet_count"] += 1
            fw["from_plc_packet_count"] += 1
            w["from_plc_byte_count"] += frame_len
            w["plc_response_timestamps"].append(ts)

        # ---- CICFlowMeter-style: IAT, directional, active/idle tracking ----
        _IDLE_THRESH = 1.0  # seconds — gap > this between packets → idle period

        # Flow-level IAT (all packets)
        _lp = w["_last_pkt_ts"]
        if _lp is not None and ts > _lp:
            w["flow_iat"].append(ts - _lp)
        w["_last_pkt_ts"] = ts

        # Active/Idle period tracking
        if w["_last_active_ts"] is None:
            w["_active_period_start"] = ts
            w["_last_active_ts"] = ts
        else:
            _gap = ts - w["_last_active_ts"]
            if _gap > _IDLE_THRESH:
                _adur = w["_last_active_ts"] - (w["_active_period_start"] or ts)
                if _adur > 0:
                    w["active_durations"].append(_adur)
                w["idle_durations"].append(_gap)
                w["_active_period_start"] = ts
            w["_last_active_ts"] = ts

        # New TCP flag fields
        _urg = has_truthy_flag(get(parts, "tcp.flags.urg"))
        _cwe = has_truthy_flag(get(parts, "tcp.flags.cwr"))
        _ece = has_truthy_flag(get(parts, "tcp.flags.ecn"))
        _tcp_win = safe_int(get(parts, "tcp.window_size"), -1)
        _ip_hdr  = safe_int(get(parts, "ip.hdr_len"),    0)
        _tcp_hdr = safe_int(get(parts, "tcp.hdr_len"),   0)
        _hdr_len = _ip_hdr + _tcp_hdr

        if _urg: w["tcp_urg_count"] += 1
        if _cwe: w["tcp_cwe_count"] += 1
        if _ece: w["tcp_ece_count"] += 1

        # Directional stats: fwd = to_plc, bwd = from_plc
        if is_to_plc:
            w["fwd_pkt_lengths"].append(frame_len)
            if is_tcp:
                w["fwd_tcp_payload_lengths"].append(tcp_len)
            if tcp_len > 0:
                w["fwd_data_pkt_count"] += 1
                w["fwd_seg_sizes"].append(tcp_len)
            _lf = w["_last_fwd_ts"]
            if _lf is not None and ts > _lf:
                w["fwd_iat"].append(ts - _lf)
            w["_last_fwd_ts"] = ts
            if psh: w["fwd_psh_count"] += 1
            if _urg: w["fwd_urg_count"] += 1
            if _tcp_win >= 0:
                w["fwd_win_sizes"].append(_tcp_win)
                if w["fwd_init_win_bytes"] < 0 and syn and not ack:
                    w["fwd_init_win_bytes"] = _tcp_win
            if _hdr_len > 0:
                w["fwd_header_lengths"].append(_hdr_len)

        elif is_from_plc:
            w["bwd_pkt_lengths"].append(frame_len)
            if is_tcp:
                w["bwd_tcp_payload_lengths"].append(tcp_len)
            if tcp_len > 0:
                w["bwd_data_pkt_count"] += 1
                w["bwd_seg_sizes"].append(tcp_len)
            _lb = w["_last_bwd_ts"]
            if _lb is not None and ts > _lb:
                w["bwd_iat"].append(ts - _lb)
            w["_last_bwd_ts"] = ts
            if psh: w["bwd_psh_count"] += 1
            if _urg: w["bwd_urg_count"] += 1
            if _tcp_win >= 0:
                w["bwd_win_sizes"].append(_tcp_win)
                if w["bwd_init_win_bytes"] < 0 and syn and ack:
                    w["bwd_init_win_bytes"] = _tcp_win
            if _hdr_len > 0:
                w["bwd_header_lengths"].append(_hdr_len)

        # Raw payload stats
        raw_payload = get(parts, "tcp.payload") or get(parts, "data.data")
        pb = payload_bytes_from_hex(raw_payload)
        if pb:
            w["raw_payload_lengths"].append(len(pb))
            fw["raw_payload_lengths"].append(len(pb))
            ent = payload_entropy(pb)
            w["payload_entropies"].append(ent)
            fw["payload_entropies"].append(ent)
            h = payload_hash_short(pb)
            if h:
                w["payload_hashes"][h] += 1

        if get(parts, "_ws.malformed"):
            w["malformed_packet_count"] += 1

        # S7 classic semantic fields
        rosctr_vals = split_multi(get(parts, "s7comm.header.rosctr"))
        func_vals = split_multi(get(parts, "s7comm.param.func"))
        db_vals = split_multi(get(parts, "s7comm.param.item.db"))
        area_vals = split_multi(get(parts, "s7comm.param.item.area"))
        addr_vals = split_multi(get(parts, "s7comm.param.item.address"))
        tsz_vals = split_multi(get(parts, "s7comm.param.item.transport_size"))
        error_vals = (
            split_multi(get(parts, "s7comm.resp.error_class")) +
            split_multi(get(parts, "s7comm.resp.error_code")) +
            split_multi(get(parts, "s7comm.data.returncode"))
        )

        if rosctr_vals:
            job, ackc, ack_data, userdata = classify_rosctr(rosctr_vals)
            w["s7_pdu_job_count"] += job
            w["s7_pdu_ack_count"] += ackc
            w["s7_pdu_ack_data_count"] += ack_data
            w["s7_pdu_userdata_count"] += userdata
            update_decode_rank(w, 2)

        is_write_cmd = False
        if func_vals:
            read, write, setup, cpu = classify_s7_function(func_vals)
            w["s7_read_count"] += read
            w["s7_write_count"] += write
            w["s7_setup_count"] += setup
            w["s7_cpu_control_count"] += cpu
            is_write_cmd = write > 0
            update_decode_rank(w, 2)

        for db in db_vals:
            w["s7_dbs"].add(db)
        for area in area_vals:
            update_area_counters(w, area, is_write_cmd)
        for addr in addr_vals:
            w["s7_offsets"].add(addr)
            a = safe_int(addr, -1)
            if a >= 0:
                w["s7_offsets_ordered"].append(a)
        for tsz in tsz_vals:
            w["s7_transport_sizes"].add(tsz)
        if func_vals and (db_vals or addr_vals or tsz_vals):
            update_decode_rank(w, 3)
        elif db_vals or addr_vals or tsz_vals:
            update_decode_rank(w, 3)
        for e in error_vals:
            es = str(e).strip().lower()
            if es and es not in {"0", "0x00", "success", "ok"}:
                w["s7_error_count"] += 1

        # S7comm-plus semantic fields across possible dissector names
        def first_multi(names: List[str]) -> List[str]:
            for n in names:
                vals = split_multi(get(parts, n))
                if vals:
                    return vals
            return []

        s7p_rosctr = first_multi(["s7comm_plus.rosctr", "s7commplus.rosctr", "s7plus.rosctr", "s7comm-plus.rosctr"])
        s7p_opcode = first_multi(["s7comm_plus.opcode", "s7commplus.opcode", "s7plus.opcode", "s7comm-plus.opcode", "s7comm-plus.data.opcode"])
        s7p_func = first_multi(["s7comm_plus.function", "s7commplus.function", "s7plus.function", "s7comm-plus.function", "s7comm-plus.data.function"])
        s7p_db = first_multi(["s7comm_plus.param.item.db", "s7commplus.param.item.db", "s7plus.param.item.db", "s7comm-plus.param.item.db", "s7comm-plus.item.addr.dbnumber"])
        s7p_area = first_multi(["s7comm_plus.param.item.area", "s7commplus.param.item.area", "s7plus.param.item.area", "s7comm-plus.param.item.area", "s7comm-plus.item.addr.area"])
        s7p_addr = first_multi(["s7comm_plus.param.item.address", "s7commplus.param.item.address", "s7plus.param.item.address", "s7comm-plus.param.item.address", "s7comm-plus.data.item_address"])
        s7p_error = first_multi(["s7comm_plus.resp.error_code", "s7commplus.resp.error_code", "s7plus.resp.error_code", "s7comm-plus.resp.error_code", "s7comm-plus.returnvalue.errorcode"])

        if s7p_rosctr:
            for rc in s7p_rosctr:
                s = str(rc).lower()
                if "job" in s or "0x01" in s:
                    w["s7_pdu_job_count"] += 1
                elif "ack" in s or "0x02" in s or "0x03" in s:
                    w["s7_pdu_ack_data_count"] += 1
                elif "userdata" in s or "0x07" in s:
                    w["s7_pdu_userdata_count"] += 1
            update_decode_rank(w, 2)

        plus_funcs = s7p_opcode + s7p_func
        if plus_funcs:
            read, write, setup, cpu = classify_s7_plus_function(plus_funcs)
            w["s7_read_count"] += read
            w["s7_write_count"] += write
            w["s7_setup_count"] += setup
            w["s7_cpu_control_count"] += cpu
            is_write_cmd = is_write_cmd or write > 0
            update_decode_rank(w, 2)

        for db in s7p_db:
            w["s7_dbs"].add(db)
        for area in s7p_area:
            update_area_counters(w, area, is_write_cmd)
        for addr in s7p_addr:
            w["s7_offsets"].add(addr)
            a = safe_int(addr, -1)
            if a >= 0:
                w["s7_offsets_ordered"].append(a)
        if s7p_db or s7p_addr:
            update_decode_rank(w, 3)
        for err in s7p_error:
            es = str(err).strip().lower()
            if es and es not in {"0", "0x00", "success", "ok"}:
                w["s7_error_count"] += 1

        # Advanced command keys and write payload bytes
        if is_write_cmd:
            w["s7_write_payload_bytes_total"] += tcp_len
            w["s7_write_payload_bytes"].append(tcp_len)

        curr_items = max(len(db_vals), len(s7p_db), 0)
        w["s7_max_item_count"] = max(w["s7_max_item_count"], curr_items)

        max_len = max(len(func_vals), len(db_vals), len(area_vals), len(addr_vals), len(tsz_vals), 0)
        for i in range(max_len):
            func = func_vals[i] if i < len(func_vals) else ""
            db = db_vals[i] if i < len(db_vals) else ""
            area = area_vals[i] if i < len(area_vals) else ""
            addr = addr_vals[i] if i < len(addr_vals) else ""
            tsz = tsz_vals[i] if i < len(tsz_vals) else ""
            key = (func, db, area, addr, tsz)
            if any(key):
                w["s7_command_keys"][key] += 1
                w["s7_unique_commands"].add((func, db, area, addr))

        max_plus_len = max(len(plus_funcs), len(s7p_db), len(s7p_area), len(s7p_addr), 0)
        for i in range(max_plus_len):
            func = plus_funcs[i] if i < len(plus_funcs) else ""
            db = s7p_db[i] if i < len(s7p_db) else ""
            area = s7p_area[i] if i < len(s7p_area) else ""
            addr = s7p_addr[i] if i < len(s7p_addr) else ""
            key = (func, db, area, addr, "")
            if any(key[:-1]):
                w["s7_command_keys"][key] += 1
                w["s7_unique_commands"].add((func, db, area, addr))

    stderr_output = proc.stderr.read() if proc.stderr is not None else ""
    ret = proc.wait()
    if stderr_output.strip():
        print("[TShark stderr]")
        print(stderr_output.strip())
    if ret != 0:
        print(f"[WARNING] tshark exited with code {ret}. Vẫn thử xuất dữ liệu nếu có packet.")
    if packet_count_debug == 0:
        print("[WARNING] Không tìm thấy packet phù hợp. Kiểm tra PCAP/filter/tshark.")

    # Optional DCP fallback using Scapy if TShark did not expose useful pn_dcp fields.
    if scapy_dcp_fallback and not has_pn_dcp_fields:
        try:
            update_dcp_with_scapy(windows, pcap_path, window_size)
        except Exception as e:
            print(f"[INFO] Bỏ qua Scapy DCP fallback: {e}")

    # Optional tag log features
    update_tag_features(windows, tag_log_path, window_size)

    if timeline_path and not standalone_labeling:
        print(
            "[WARNING] --timeline was provided to the extractor, but extractor-side "
            "labeling is disabled by default to avoid double-labeling. "
            "Use merge_dataset.py for timeline labels, or pass --standalone-labeling "
            "only for standalone/debug exports."
        )
        timeline = []
    else:
        timeline = load_timeline(timeline_path)
    write_output(
        windows,
        output_path,
        window_size,
        role,
        label,
        plc_ip,
        timeline,
        session_id=session_id,
        host_id=host_id,
        scenario_id=scenario_id,
        episode_id=episode_id,
    )
    if flow_debug_path:
        write_flow_debug_csv(
            flow_windows,
            flow_debug_path,
            window_size,
            role,
            label,
            plc_ip,
            timeline,
            session_id=session_id,
            host_id=host_id,
            scenario_id=scenario_id,
            episode_id=episode_id,
        )


# ============================================================
# 8. Scapy DCP fallback
# ============================================================

def update_dcp_with_scapy(windows: Dict[int, dict], pcap_path: str, window_size: int) -> None:
    try:
        from scapy.all import PcapReader, Ether, Raw  # type: ignore
    except ImportError:
        raise RuntimeError("scapy chưa cài. Cài bằng: pip install scapy")

    total_dcp = 0
    reader = PcapReader(pcap_path)
    for pkt in reader:
        if not pkt.haslayer(Ether):
            continue
        if pkt[Ether].type != PROFINET_ETHERTYPE:
            continue
        total_dcp += 1
        try:
            ts = float(pkt.time)
        except Exception:
            continue
        w_start_ms = int(ts * 1000) // (window_size * 1000) * (window_size * 1000)
        w = windows[w_start_ms]
        src_mac = pkt[Ether].src.lower()
        frame_len = len(pkt)

        # If tshark already counted total by eth.type, avoid incrementing total too much.
        # Because fallback only runs when pn_dcp fields are missing, total can be incremented safely.
        w["dcp_total_frame_count"] += 1
        w["dcp_total_bytes"] += frame_len
        w["dcp_timestamps"].append(ts)
        raw_payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
        dcp = parse_dcp_frame(raw_payload)
        if not dcp:
            continue
        service_id = dcp["service_id"]
        service_type = dcp["service_type"]
        if service_id == DCP_SERVICE_IDENTIFY:
            if service_type == DCP_TYPE_REQUEST:
                w["dcp_identify_request_count"] += 1
                w["dcp_unique_scanner_macs"].add(src_mac)
            elif service_type == DCP_TYPE_RESPONSE_SUCCESS:
                w["dcp_identify_response_count"] += 1
                w["dcp_unique_device_macs"].add(src_mac)
                if dcp.get("ip_addr"):
                    w["dcp_discovered_ips"].add(dcp["ip_addr"])
                if dcp.get("vendor_id"):
                    v = dcp["vendor_id"]
                    w["dcp_discovered_vendors"][PROFINET_VENDORS.get(v, v)] += 1
                if dcp.get("device_id"):
                    w["dcp_discovered_device_ids"].add(dcp["device_id"])
        elif service_id == DCP_SERVICE_SET:
            w["dcp_set_count"] += 1
        elif service_id == DCP_SERVICE_GET:
            w["dcp_get_count"] += 1
        elif service_id == DCP_SERVICE_HELLO:
            w["dcp_hello_count"] += 1
    reader.close()
    print(f"[INFO] Scapy DCP fallback parsed DCP frames: {total_dcp}")


# ============================================================
# 9. Output writer
# ============================================================

def compute_sequential_offset_score(offsets: List[int]) -> float:
    if len(offsets) < 3:
        return 0.0
    diffs = [abs(offsets[i + 1] - offsets[i]) for i in range(len(offsets) - 1)]
    if not diffs:
        return 0.0
    # common enumeration can step 1, 2, 4, 8; count repeated small positive diffs
    good = sum(1 for d in diffs if d in {1, 2, 4, 8})
    return good / len(diffs)


def max_by_src(w: dict, key: str, set_len: bool = False) -> int:
    best = 0
    for sw in w["scan_by_src"].values():
        val = sw.get(key, 0)
        if set_len:
            val = len(val)
        best = max(best, int(val))
    return best


def write_output(
    windows: Dict[int, dict],
    output_path: str,
    window_size: int,
    role: str,
    default_label: str,
    plc_ip: Optional[str],
    timeline: List[TimelineLabel],
    session_id: str = "unknown_session",
    host_id: str = "unknown_host",
    scenario_id: str = "unlabeled",
    episode_id: str = "unlabeled",
) -> None:
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    header = [
        # metadata & context (NOT ML features — use --keep-meta or drop before training)
        "window_start_ms", "window_end_ms", "label", "capture_role", "plc_ip", "decode_level",
        "session_id", "host_id", "scenario_id", "episode_id",
        "top_src_ip", "top_dst_ip", "top_protocol", "top_dst_port",

        # general traffic
        "packet_count", "byte_count", "packet_rate", "byte_rate",
        "unique_src_ip_count", "unique_dst_ip_count", "unique_src_mac_count", "unique_dst_mac_count",
        "unique_src_port_count", "unique_dst_port_count",
        "packet_len_mean", "packet_len_std", "packet_len_min", "packet_len_max", "malformed_packet_count",

        # protocol counts
        "tcp_count", "udp_count", "arp_count", "icmp_count", "other_l3_count",
        "tcp_active_streams", "tcp_syn_count", "tcp_ack_count", "tcp_rst_count", "tcp_fin_count", "tcp_psh_count",
        "tcp_syn_ack_ratio", "tcp_rst_syn_ratio", "tcp_conn_churn_rate",
        "tcp_time_delta_mean", "tcp_time_delta_std", "tcp_retransmit_count", "tcp_out_of_order_count", "tcp_prev_seg_lost_count",
        "tcp_payload_len_mean", "tcp_payload_len_std",

        # scan/recon features
        "max_unique_dst_port_by_src", "max_unique_dst_ip_by_src", "max_unique_src_port_by_src",
        "max_syn_by_src", "max_rst_by_src", "max_arp_target_by_src", "max_tcp_102_probe_by_src",
        "tcp_102_packet_count", "tcp_102_probe_count", "tcp_low_port_probe_count", "tcp_high_port_probe_count",
        "arp_request_count", "arp_reply_count", "arp_unique_target_ip_count", "arp_unique_sender_ip_count", "arp_unique_sender_mac_count", "arp_broadcast_count",
        "icmp_echo_request_count", "icmp_echo_reply_count",
        "port_scan_score", "arp_scan_score", "plc_scan_score", "scan_detected_rule",

        # DCP / Profinet discovery
        "dcp_total_frame_count", "dcp_total_bytes", "dcp_frame_rate", "dcp_identify_request_count", "dcp_identify_response_count",
        "dcp_set_count", "dcp_get_count", "dcp_hello_count", "dcp_unique_scanner_mac_count", "dcp_unique_device_mac_count",
        "dcp_discovered_ip_count", "dcp_discovered_vendor_count", "dcp_discovered_device_id_count",
        "dcp_inter_frame_interval_mean_ms", "dcp_inter_frame_interval_std_ms", "dcp_scan_detected_rule",

        # industrial protocols and direction
        "tpkt_count", "cotp_count", "cotp_cr_count", "cotp_cc_count", "cotp_dt_count", "cotp_dr_count", "cotp_fragment_count", "pres_data_transfer_count",
        "s7comm_packet_count", "s7comm_plus_packet_count",
        "to_plc_packet_count", "to_plc_byte_count", "from_plc_packet_count", "from_plc_byte_count", "from_plc_packet_ratio", "plc_response_gap_max_ms",

        # S7 semantic
        "s7_read_count", "s7_write_count", "s7_setup_count", "s7_cpu_control_count", "s7_error_count",
        "s7_pdu_job_count", "s7_pdu_ack_count", "s7_pdu_ack_data_count", "s7_pdu_userdata_count",
        "s7_unique_db_count", "s7_unique_area_count", "s7_unique_offset_count", "s7_transport_size_count", "s7_repeated_command_count",
        "s7_db_area_count", "s7_merker_area_count", "s7_input_area_count", "s7_output_area_count", "s7_other_area_count",
        "s7_input_write_count", "s7_output_write_count", "s7_write_payload_bytes_total", "s7_write_payload_bytes_mean", "s7_max_item_count",
        "s7_write_read_ratio", "s7_unique_commands_count", "s7_sequential_offset_score", "s7_negotiation_only_ratio",

        # payload stats
        "raw_payload_len_mean", "raw_payload_len_std", "raw_payload_len_min", "raw_payload_len_max",
        "payload_entropy_mean", "payload_entropy_std", "payload_entropy_max",
        "payload_hash_unique_count", "payload_repeated_hash_count", "payload_hash_unique_ratio",

        # optional tag log generic features
        "tag_event_count", "tag_unique_name_count", "tag_change_count", "tag_unique_changed_count",
        "tag_change_ratio", "tag_numeric_mean", "tag_numeric_std", "tag_numeric_min", "tag_numeric_max",
        "tag_binary_one_count", "tag_binary_zero_count", "tag_binary_one_ratio",

        # CICFlowMeter-compatible features (custom, ICS per-window)
        "fwd_pkt_count", "bwd_pkt_count", "fwd_byte_count", "bwd_byte_count",
        "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
        "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
        "fwd_pkts_per_sec", "bwd_pkts_per_sec", "down_up_ratio", "pkt_len_variance",
        "flow_iat_mean_ms", "flow_iat_std_ms", "flow_iat_max_ms", "flow_iat_min_ms",
        "fwd_iat_total_ms", "fwd_iat_mean_ms", "fwd_iat_std_ms", "fwd_iat_max_ms", "fwd_iat_min_ms",
        "bwd_iat_total_ms", "bwd_iat_mean_ms", "bwd_iat_std_ms", "bwd_iat_max_ms", "bwd_iat_min_ms",
        "fwd_psh_flag_count", "bwd_psh_flag_count",
        "fwd_urg_flag_count", "bwd_urg_flag_count",
        "tcp_urg_count", "tcp_cwe_count", "tcp_ece_count",
        "fwd_init_win_bytes", "bwd_init_win_bytes",
        "fwd_win_size_mean", "bwd_win_size_mean",
        "fwd_header_len_mean", "bwd_header_len_mean",
        "fwd_data_pkt_count", "bwd_data_pkt_count",
        "avg_fwd_seg_size", "avg_bwd_seg_size", "min_fwd_seg_size",
        "active_mean_ms", "active_std_ms", "active_max_ms", "active_min_ms",
        "idle_mean_ms", "idle_std_ms", "idle_max_ms", "idle_min_ms",
    ]

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)

        for w_start in sorted(windows.keys()):
            w = windows[w_start]
            w_end = w_start + window_size * 1000
            lab = label_for_window(w_start, w_end, timeline, default_label)

            pkt = w["packet_count"]
            syn = w["tcp_syn_count"]
            ack = w["tcp_ack_count"]
            rst = w["tcp_rst_count"]
            fin = w["tcp_fin_count"]
            frame_lengths = w["frame_lengths"]
            payload_lengths = w["tcp_payload_lengths"]
            raw_lengths = w["raw_payload_lengths"]
            payload_ents = w["payload_entropies"]
            payload_total = sum(w["payload_hashes"].values())
            payload_unique = len(w["payload_hashes"])

            max_unique_ports = max_by_src(w, "dst_ports", set_len=True)
            max_unique_ips = max_by_src(w, "dst_ips", set_len=True)
            max_unique_src_ports = max_by_src(w, "src_ports", set_len=True)
            max_syn = max_by_src(w, "syn")
            max_rst = max_by_src(w, "rst")
            max_arp_targets = max_by_src(w, "arp_targets", set_len=True)
            max_tcp102 = max_by_src(w, "tcp_102")

            syn_ack_ratio = syn / max(ack, 1)
            rst_syn_ratio = rst / max(syn, 1)
            tcp_conn_churn = syn / max(fin, 1)

            port_scan_score = max_unique_ports + max_syn + max_rst
            arp_scan_score = w["arp_request_count"] + len(w["arp_unique_target_ips"])
            plc_scan_score = (w["tcp_102_probe_count"] * 3) + max_unique_ports + w["arp_request_count"] + w["dcp_identify_request_count"]
            scan_detected_rule = int(
                max_unique_ports >= 10 or
                max_arp_targets >= 5 or
                w["dcp_identify_request_count"] >= 2 or
                (w["tcp_102_probe_count"] >= 1 and syn >= 3)
            )

            dcp_ts = sorted(w["dcp_timestamps"])
            if len(dcp_ts) >= 2:
                dcp_intervals = [(dcp_ts[i + 1] - dcp_ts[i]) * 1000 for i in range(len(dcp_ts) - 1)]
            else:
                dcp_intervals = []
            dcp_scan_detected = int(w["dcp_identify_request_count"] >= 2 or len(w["dcp_discovered_ips"]) >= 2)

            plc_ts = sorted(w["plc_response_timestamps"])
            if len(plc_ts) >= 2:
                plc_gaps = [(plc_ts[i + 1] - plc_ts[i]) * 1000 for i in range(len(plc_ts) - 1)]
                plc_gap_max = max(plc_gaps)
            else:
                plc_gap_max = 0.0

            s7_repeated_command_count = sum(max(0, c - 1) for c in w["s7_command_keys"].values())
            s7_total_sem = w["s7_read_count"] + w["s7_write_count"] + w["s7_setup_count"] + w["s7_cpu_control_count"]
            s7_neg_ratio = w["s7_setup_count"] / max(s7_total_sem, 1)

            tag_vals = w["tag_numeric_values"]
            tag_events = w["tag_event_count"]
            tag_one_ratio = w["tag_binary_one_count"] / max(w["tag_binary_one_count"] + w["tag_binary_zero_count"], 1)

            # ---- CICFlowMeter-compatible computed values ----
            _fwd_lens   = w["fwd_pkt_lengths"]
            _bwd_lens   = w["bwd_pkt_lengths"]
            _flow_iats  = w["flow_iat"]
            _fwd_iats   = w["fwd_iat"]
            _bwd_iats   = w["bwd_iat"]
            # Close the last active period (not yet closed by an idle gap)
            _active_durs = list(w["active_durations"])
            if w["_active_period_start"] is not None and w["_last_active_ts"] is not None:
                _d = w["_last_active_ts"] - w["_active_period_start"]
                if _d > 0:
                    _active_durs.append(_d)
            _idle_durs = w["idle_durations"]

            # ---- Context: top IP/protocol/port in this window ----
            def _top_key(d: dict, default=""):
                return max(d, key=d.get) if d else default
            top_src_ip   = _top_key(w["_src_ip_ctr"])
            top_dst_ip   = _top_key(w["_dst_ip_ctr"])
            top_protocol = _top_key(w["_proto_ctr"])
            top_dst_port = _top_key(w["_dst_port_ctr"], default=0)

            row = [
                w_start, w_end, lab, role, plc_ip or "", decode_level_from_rank(w["decode_rank"]),
                session_id, host_id, scenario_id, episode_id,
                top_src_ip, top_dst_ip, top_protocol, top_dst_port,

                pkt, w["byte_count"], round(pkt / window_size, 6), round(w["byte_count"] / window_size, 6),
                len(w["src_ips"]), len(w["dst_ips"]), len(w["src_macs"]), len(w["dst_macs"]),
                len(w["src_ports"]), len(w["dst_ports"]),
                round(mean(frame_lengths), 6), round(std(frame_lengths), 6), min(frame_lengths) if frame_lengths else 0, max(frame_lengths) if frame_lengths else 0, w["malformed_packet_count"],

                w["tcp_count"], w["udp_count"], w["arp_count"], w["icmp_count"], w["other_l3_count"],
                len(w["tcp_streams"]), syn, ack, rst, fin, w["tcp_psh_count"],
                round(syn_ack_ratio, 6), round(rst_syn_ratio, 6), round(tcp_conn_churn, 6),
                round(mean(w["tcp_time_deltas"]), 6), round(std(w["tcp_time_deltas"]), 6),
                w["tcp_retransmit_count"], w["tcp_out_of_order_count"], w["tcp_prev_seg_lost_count"],
                round(mean(payload_lengths), 6), round(std(payload_lengths), 6),

                max_unique_ports, max_unique_ips, max_unique_src_ports,
                max_syn, max_rst, max_arp_targets, max_tcp102,
                w["tcp_102_packet_count"], w["tcp_102_probe_count"], w["tcp_low_port_probe_count"], w["tcp_high_port_probe_count"],
                w["arp_request_count"], w["arp_reply_count"], len(w["arp_unique_target_ips"]), len(w["arp_unique_sender_ips"]), len(w["arp_unique_sender_macs"]), w["arp_broadcast_count"],
                w["icmp_echo_request_count"], w["icmp_echo_reply_count"],
                round(port_scan_score, 6), round(arp_scan_score, 6), round(plc_scan_score, 6), scan_detected_rule,

                w["dcp_total_frame_count"], w["dcp_total_bytes"], round(w["dcp_total_frame_count"] / window_size, 6),
                w["dcp_identify_request_count"], w["dcp_identify_response_count"],
                w["dcp_set_count"], w["dcp_get_count"], w["dcp_hello_count"],
                len(w["dcp_unique_scanner_macs"]), len(w["dcp_unique_device_macs"]),
                len(w["dcp_discovered_ips"]), len(w["dcp_discovered_vendors"]), len(w["dcp_discovered_device_ids"]),
                round(mean(dcp_intervals), 3), round(std(dcp_intervals), 3), dcp_scan_detected,

                w["tpkt_count"], w["cotp_count"], w["cotp_cr_count"], w["cotp_cc_count"], w["cotp_dt_count"], w["cotp_dr_count"], w["cotp_fragment_count"], w["pres_data_transfer_count"],
                w["s7comm_packet_count"], w["s7comm_plus_packet_count"],
                w["to_plc_packet_count"], w["to_plc_byte_count"], w["from_plc_packet_count"], w["from_plc_byte_count"],
                round(w["from_plc_packet_count"] / max(pkt, 1), 6), round(plc_gap_max, 3),

                w["s7_read_count"], w["s7_write_count"], w["s7_setup_count"], w["s7_cpu_control_count"], w["s7_error_count"],
                w["s7_pdu_job_count"], w["s7_pdu_ack_count"], w["s7_pdu_ack_data_count"], w["s7_pdu_userdata_count"],
                len(w["s7_dbs"]), len(w["s7_areas"]), len(w["s7_offsets"]), len(w["s7_transport_sizes"]), s7_repeated_command_count,
                w["s7_db_area_count"], w["s7_merker_area_count"], w["s7_input_area_count"], w["s7_output_area_count"], w["s7_other_area_count"],
                w["s7_input_write_count"], w["s7_output_write_count"], w["s7_write_payload_bytes_total"], round(mean(w["s7_write_payload_bytes"]), 6), w["s7_max_item_count"],
                round(w["s7_write_count"] / max(w["s7_read_count"], 1), 6), len(w["s7_unique_commands"]),
                round(compute_sequential_offset_score(w["s7_offsets_ordered"]), 6), round(s7_neg_ratio, 6),

                round(mean(raw_lengths), 6), round(std(raw_lengths), 6), min(raw_lengths) if raw_lengths else 0, max(raw_lengths) if raw_lengths else 0,
                round(mean(payload_ents), 6), round(std(payload_ents), 6), round(max(payload_ents) if payload_ents else 0.0, 6),
                payload_unique, sum(max(0, c - 1) for c in w["payload_hashes"].values()), round(payload_unique / max(payload_total, 1), 6),

                tag_events, len(w["tag_names"]), w["tag_change_count"], len(w["tag_changed_names"]),
                round(w["tag_change_count"] / max(tag_events, 1), 6),
                round(mean(tag_vals), 6), round(std(tag_vals), 6), round(min(tag_vals) if tag_vals else 0.0, 6), round(max(tag_vals) if tag_vals else 0.0, 6),
                w["tag_binary_one_count"], w["tag_binary_zero_count"], round(tag_one_ratio, 6),

                # CICFlowMeter-compatible features
                len(_fwd_lens), len(_bwd_lens),
                sum(_fwd_lens), sum(_bwd_lens),
                max(_fwd_lens) if _fwd_lens else 0,
                min(_fwd_lens) if _fwd_lens else 0,
                round(mean(_fwd_lens), 6),
                round(std(_fwd_lens), 6),
                max(_bwd_lens) if _bwd_lens else 0,
                min(_bwd_lens) if _bwd_lens else 0,
                round(mean(_bwd_lens), 6),
                round(std(_bwd_lens), 6),
                round(len(_fwd_lens) / window_size, 6),
                round(len(_bwd_lens) / window_size, 6),
                round(len(_bwd_lens) / max(len(_fwd_lens), 1), 6),
                round(std(frame_lengths) ** 2, 6),
                # Flow IAT (ms)
                round(mean(_flow_iats) * 1000, 6),
                round(std(_flow_iats)  * 1000, 6),
                round((max(_flow_iats) if _flow_iats else 0.0) * 1000, 6),
                round((min(_flow_iats) if _flow_iats else 0.0) * 1000, 6),
                # Fwd IAT (ms)
                round(sum(_fwd_iats) * 1000, 6),
                round(mean(_fwd_iats) * 1000, 6),
                round(std(_fwd_iats)  * 1000, 6),
                round((max(_fwd_iats) if _fwd_iats else 0.0) * 1000, 6),
                round((min(_fwd_iats) if _fwd_iats else 0.0) * 1000, 6),
                # Bwd IAT (ms)
                round(sum(_bwd_iats) * 1000, 6),
                round(mean(_bwd_iats) * 1000, 6),
                round(std(_bwd_iats)  * 1000, 6),
                round((max(_bwd_iats) if _bwd_iats else 0.0) * 1000, 6),
                round((min(_bwd_iats) if _bwd_iats else 0.0) * 1000, 6),
                # Directional flags
                w["fwd_psh_count"], w["bwd_psh_count"],
                w["fwd_urg_count"], w["bwd_urg_count"],
                w["tcp_urg_count"], w["tcp_cwe_count"], w["tcp_ece_count"],
                # TCP window
                max(0, w["fwd_init_win_bytes"]),
                max(0, w["bwd_init_win_bytes"]),
                round(mean(w["fwd_win_sizes"]), 6),
                round(mean(w["bwd_win_sizes"]), 6),
                # Header lengths
                round(mean(w["fwd_header_lengths"]), 6),
                round(mean(w["bwd_header_lengths"]), 6),
                # Data packets & segment sizes
                w["fwd_data_pkt_count"], w["bwd_data_pkt_count"],
                round(mean(w["fwd_seg_sizes"]), 6),
                round(mean(w["bwd_seg_sizes"]), 6),
                min(w["fwd_seg_sizes"]) if w["fwd_seg_sizes"] else 0,
                # Active/Idle (ms)
                round(mean(_active_durs) * 1000, 6),
                round(std(_active_durs)  * 1000, 6),
                round((max(_active_durs) if _active_durs else 0.0) * 1000, 6),
                round((min(_active_durs) if _active_durs else 0.0) * 1000, 6),
                round(mean(_idle_durs)   * 1000, 6),
                round(std(_idle_durs)    * 1000, 6),
                round((max(_idle_durs)   if _idle_durs else 0.0) * 1000, 6),
                round((min(_idle_durs)   if _idle_durs else 0.0) * 1000, 6),
            ]
            writer.writerow(row)

    print(f"[OK] Windows: {len(windows)}")
    print(f"[OK] Saved: {output_path}")



def write_flow_debug_csv(
    flow_windows: Dict[int, Dict[Tuple[str, str, str, str, str], dict]],
    output_path: str,
    window_size: int,
    role: str,
    default_label: str,
    plc_ip: Optional[str],
    timeline: List[TimelineLabel],
    session_id: str = "unknown_session",
    host_id: str = "unknown_host",
    scenario_id: str = "unlabeled",
    episode_id: str = "unlabeled",
) -> None:
    """Write optional flow-level debug CSV with explicit src/dst/protocol.

    This file is useful to inspect what packets/flows were seen. Do not train directly
    on raw IP/port columns unless you intentionally want device-specific rules.
    """
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    header = [
        "window_start_ms", "window_end_ms", "label", "capture_role", "plc_ip",
        "session_id", "host_id", "scenario_id", "episode_id",
        "src_id", "dst_id", "src_port", "dst_port", "protocol",
        "packet_count", "byte_count", "packet_rate", "byte_rate",
        "packet_len_mean", "packet_len_std", "packet_len_min", "packet_len_max",
        "tcp_payload_len_mean", "tcp_payload_len_std",
        "tcp_syn_count", "tcp_ack_count", "tcp_rst_count", "tcp_fin_count", "tcp_psh_count",
        "arp_request_count", "arp_reply_count", "icmp_echo_request_count", "icmp_echo_reply_count",
        "tcp_retransmit_count", "tcp_out_of_order_count", "tcp_prev_seg_lost_count",
        "tpkt_count", "cotp_count", "s7comm_packet_count", "s7comm_plus_packet_count", "dcp_total_frame_count",
        "to_plc_packet_count", "from_plc_packet_count",
        "raw_payload_len_mean", "raw_payload_len_std", "payload_entropy_mean", "payload_entropy_std",
    ]
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for w_start in sorted(flow_windows.keys()):
            w_end = w_start + window_size * 1000
            lab = label_for_window(w_start, w_end, timeline, default_label)
            for (src, dst, sport, dport, proto), fw in sorted(flow_windows[w_start].items()):
                pkt = fw["packet_count"]
                flens = fw["frame_lengths"]
                plens = fw["tcp_payload_lengths"]
                raw_lens = fw["raw_payload_lengths"]
                ents = fw["payload_entropies"]
                writer.writerow([
                    w_start, w_end, lab, role, plc_ip or "",
                    session_id, host_id, scenario_id, episode_id,
                    src, dst, sport, dport, proto,
                    pkt, fw["byte_count"], round(pkt / window_size, 6), round(fw["byte_count"] / window_size, 6),
                    round(mean(flens), 6), round(std(flens), 6), min(flens) if flens else 0, max(flens) if flens else 0,
                    round(mean(plens), 6), round(std(plens), 6),
                    fw["tcp_syn_count"], fw["tcp_ack_count"], fw["tcp_rst_count"], fw["tcp_fin_count"], fw["tcp_psh_count"],
                    fw["arp_request_count"], fw["arp_reply_count"], fw["icmp_echo_request_count"], fw["icmp_echo_reply_count"],
                    fw["tcp_retransmit_count"], fw["tcp_out_of_order_count"], fw["tcp_prev_seg_lost_count"],
                    fw["tpkt_count"], fw["cotp_count"], fw["s7comm_packet_count"], fw["s7comm_plus_packet_count"], fw["dcp_total_frame_count"],
                    fw["to_plc_packet_count"], fw["from_plc_packet_count"],
                    round(mean(raw_lens), 6), round(std(raw_lens), 6), round(mean(ents), 6), round(std(ents), 6),
                ])
    print(f"[OK] Flow debug saved: {output_path}")

def write_ml_safe_copy(input_csv: str, output_csv: str) -> None:
    """Create an ML-safe supervised CSV by dropping metadata and rule-leakage columns.

    The `label` column is intentionally kept as the supervised target. The dropped
    columns remain available in the full CSV for audit, rule-baseline evaluation,
    and dataset documentation.
    """
    with open(input_csv, "r", encoding="utf-8", newline="") as fin, open(output_csv, "w", encoding="utf-8", newline="") as fout:
        reader = csv.DictReader(fin)
        if not reader.fieldnames:
            return
        keep_cols = [c for c in reader.fieldnames if c == "label" or c not in ML_UNSAFE_EXACT_COLS]
        writer = csv.DictWriter(fout, fieldnames=keep_cols)
        writer.writeheader()
        for row in reader:
            writer.writerow({c: row.get(c, "") for c in keep_cols})
    print(f"[OK] ML-safe copy saved: {output_csv}")


# ============================================================
# 10. CLI
# ============================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Unified feature extractor for Industrial/PLC IDS from PCAP/PCAPNG.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python extract_industrial_ids_features.py --pcap capture.pcapng --output features.csv --window 5 --plc-ip 192.168.0.1 --label benign
  python extract_industrial_ids_features.py --pcap scan.pcapng --output scan.csv --window 5 --plc-ip 192.168.0.1 --label port_scan
  python extract_industrial_ids_features.py --pcap day2.pcapng --tag-log tag_log.csv --timeline day2_timeline.csv --output day2_features.csv --window 5 --plc-ip 192.168.0.1

Notes:
  - Output chính có cả metadata. Khi train model, dùng --ml-safe-copy để tạo bản drop metadata.
  - Nếu S7comm-plus bị TLS và không có keylog, các feature S7 semantic có thể bằng 0; khi đó tag_log rất quan trọng cho logic attack.
  - Profinet DCP là Layer 2, cần PCAP bắt cùng subnet/SPAN port mới thấy được.
""",
    )
    parser.add_argument("--pcap", required=True, help="Input PCAP/PCAPNG file")
    parser.add_argument("--output", required=True, help="Output feature CSV")
    parser.add_argument("--window", type=float, default=5.0, help="Time window size in seconds, default=5.0")
    parser.add_argument("--plc-ip", default=None, help="PLC IP address for to/from PLC directional features")
    parser.add_argument("--role", default="unknown", choices=["attacker", "controller", "logger", "unknown"], help="Capture role metadata")
    parser.add_argument("--label", default="unknown", help="Default label if no timeline is provided")
    parser.add_argument("--timeline", default=None, help="Optional timeline CSV with start,end,label")
    parser.add_argument("--tag-log", default=None, help="Optional tag log CSV with timestamp,tag_name,value")
    parser.add_argument("--session-id", default="unknown_session", help="Session metadata kept for grouped splits; never use as ML input")
    parser.add_argument("--host-id", default="unknown_host", help="Capture host metadata kept for grouped splits; never use as ML input")
    parser.add_argument("--scenario-id", default="unlabeled", help="Scenario metadata for audit only; merge_dataset.py assigns final labels")
    parser.add_argument("--episode-id", default="unlabeled", help="Episode metadata for grouped splits; merge_dataset.py can override")
    parser.add_argument("--standalone-labeling", action="store_true", help="Allow extractor-side timeline labeling for standalone/debug exports only")
    parser.add_argument("--tls-keylog", default=None, help="Optional TLS keylog file for decrypting S7comm-plus/TLS")
    parser.add_argument("--ssl-keys", default=None, help="Optional legacy RSA key list for TShark TLS/SSL")
    parser.add_argument("--no-payload", action="store_true", help="Disable raw payload extraction")
    parser.add_argument("--no-scapy-dcp", action="store_true", help="Disable Scapy DCP fallback")
    parser.add_argument("--ml-safe-copy", default=None, help="Optional path to write a metadata-dropped CSV for ML training")
    parser.add_argument("--flow-debug-copy", default=None, help="Optional flow-level debug CSV with src/dst/port/protocol columns")

    args = parser.parse_args()

    try:
        extract_features(
            pcap_path=args.pcap,
            output_path=args.output,
            window_size=args.window,
            plc_ip=args.plc_ip,
            role=args.role,
            label=args.label,
            timeline_path=args.timeline,
            tag_log_path=args.tag_log,
            session_id=args.session_id,
            host_id=args.host_id,
            scenario_id=args.scenario_id,
            episode_id=args.episode_id,
            standalone_labeling=args.standalone_labeling,
            include_payload=not args.no_payload,
            tls_keylog=args.tls_keylog,
            ssl_keys=args.ssl_keys,
            scapy_dcp_fallback=not args.no_scapy_dcp,
            flow_debug_path=args.flow_debug_copy,
        )
        if args.ml_safe_copy:
            write_ml_safe_copy(args.output, args.ml_safe_copy)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
