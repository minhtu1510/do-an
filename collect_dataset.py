#!/usr/bin/env python3
"""
collect_dataset.py – ICS Security Testbed Dataset Collection Script
====================================================================
Tự động chạy từng loại tấn công theo kịch bản, đồng thời capture pcap
và extract flow features → tạo dataset CSV có nhãn sẵn sàng cho IDS.

Tham khảo phương pháp:
  - CIC-IDS2017/2018 (Sharafaldin et al.) – flow-based feature extraction
  - SWaT Dataset (iTrust, SUTD) – sensor + network hybrid features  
  - BATADAL (Taormina et al.) – labeled attack windows
  - "Towards the Development of Realistic Botnet Dataset" (Koroniotis, 2019)

Kiến trúc thu thập:
  ┌─────────────────────────────────────────┐
  │  Testbed Machine (attacker)             │
  │  ┌──────────┐    ┌────────────────────┐ │
  │  │ s7pwn    │───▶│ collect_dataset.py │ │
  │  │ attacks  │    │  + tcpdump/scapy   │ │
  │  └──────────┘    └────────────────────┘ │
  │         │                │              │
  │         ▼                ▼              │
  │     PLC Target      dataset/            │
  │     192.168.x.x     ├── raw_pcap/       │
  │                     ├── flows_csv/      │
  │                     └── labeled.csv     │
  └─────────────────────────────────────────┘

Usage:
  python collect_dataset.py --target 192.168.1.10 --rack 0 --slot 1
  python collect_dataset.py --target 192.168.1.10 --phase normal
  python collect_dataset.py --target 192.168.1.10 --phase all
  python collect_dataset.py --config testbed_config.json

Requirements:
  pip install scapy snap7 pandas
  apt-get install tcpdump   (hoặc dùng Wireshark)
"""

from __future__ import annotations
import argparse
import json
import os
import multiprocessing
import random
import subprocess
import sys
import time
import threading
import csv
import struct
import signal
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Profinet DCP constants (Layer 2 - EtherType 0x8892)
PROFINET_ETHERTYPE = 0x8892
DCP_SERVICE_IDENTIFY = 0x05
DCP_TYPE_REQUEST = 0x00
DCP_TYPE_RESPONSE = 0x01

# ══════════════════════════════════════════════════════════════════════
#  CONFIG & CONSTANTS
# ══════════════════════════════════════════════════════════════════════

VERSION = "1.0.0"

# Attack phase definitions (giống phương pháp CIC-IDS2017)
# Mỗi phase: tên nhãn, lệnh s7pwn, thời gian chạy (giây)
ATTACK_PHASES = {
    "normal": {
        "label": "NORMAL",
        "description": "Legitimate SCADA polling – periodic READ of fixed tags",
        "duration_s": 120,
        "mitre": "–",
    },
    "scan": {
        "label": "SCAN",
        "description": "Network Discovery – Profinet DCP + TCP port sweep",
        "duration_s": 60,
        "mitre": "T0846",
    },
    "enum_tags": {
        "label": "ENUM_TAGS",
        "description": "Tag Enumeration – sequential read of all M/I/Q addresses",
        "duration_s": 90,
        "mitre": "T0861",
    },
    "flood": {
        "label": "FLOOD",
        "description": "Connection DoS – exhaust TCP connection limit",
        "duration_s": 60,
        "mitre": "T0814",
    },
    "rwrite": {
        "label": "RWRITE",
        "description": "Data Manipulation – continuous overwrite of process variables",
        "duration_s": 90,
        "mitre": "T0836",
    },
    "spoof_constant": {
        "label": "SPOOF",
        "description": "Signal Spoofing – lock sensor values to fixed fake readings",
        "duration_s": 90,
        "mitre": "T0836",
    },
    "replay": {
        "label": "REPLAY",
        "description": "Replay Attack – re-send captured legitimate write sequence",
        "duration_s": 60,
        "mitre": "T0843",
    },
    "cpu_control": {
        "label": "CPU_CONTROL",
        "description": "CPU Stop – send S7 STOP control PDU",
        "duration_s": 30,
        "mitre": "T0816",
    },
    "fuzz": {
        "label": "FUZZ",
        "description": "Protocol Fuzzing – malformed S7 PDUs",
        "duration_s": 90,
        "mitre": "T0819",
    },
}

# ══════════════════════════════════════════════════════════════════════
#  DIRECTORY SETUP
# ══════════════════════════════════════════════════════════════════════

def setup_directories(base_dir: str) -> Dict[str, Path]:
    dirs = {
        "base":      Path(base_dir),
        "raw_pcap":  Path(base_dir) / "raw_pcap",
        "flows":     Path(base_dir) / "flows_csv",
        "logs":      Path(base_dir) / "logs",
        "replay_capture": Path(base_dir) / "replay_captures",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs

# ══════════════════════════════════════════════════════════════════════
#  PCAP CAPTURE via tcpdump / scapy
# ══════════════════════════════════════════════════════════════════════

class PcapCapture:
    """Manages a background tcpdump process for packet capture."""

    def __init__(self, iface: str, output_file: str, bpf_filter: str = ""):
        self.iface       = iface
        self.output_file = output_file
        self.bpf_filter  = bpf_filter
        self._proc: Optional[subprocess.Popen] = None

    def start(self) -> bool:
        cmd = ["tcpdump", "-i", self.iface, "-w", self.output_file, "-n"]
        if self.bpf_filter:
            cmd += self.bpf_filter.split()
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(0.5)   # let tcpdump initialise
            print(f"    [pcap] Capturing on {self.iface} → {self.output_file}")
            return True
        except FileNotFoundError:
            print("    [!] tcpdump not found – skipping packet capture")
            print("        Install: sudo apt-get install tcpdump")
            return False

    def stop(self) -> int:
        if self._proc and self._proc.poll() is None:
            self._proc.send_signal(signal.SIGTERM)
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        return self._proc.returncode if self._proc else -1

# ══════════════════════════════════════════════════════════════════════
#  FLOW FEATURE EXTRACTOR
#  Inspired by CICFlowMeter feature set (46 features)
#  Adapted for S7comm / Modbus specific fields
# ══════════════════════════════════════════════════════════════════════

def _parse_s7_details(raw: bytes) -> dict:
    """
    S7comm decoder bóc tách sâu payload (DPI).
    Trả về dict chứa PDU type, Memory Area truy cập, kích thước Payload.
    """
    res = {
        "type": "OTHER",
        "area": -1,       # 0x84: DB, 0x83: Merker(M), 0x81: Input, 0x82: Output
        "db_num": 0,
        "item_count": 0,
        "write_payload_size": 0,
        "byte_offset": None,
        "bit_offset": None,
        "transport_size": None
    }
    if len(raw) < 10 or raw[0] != 0x03:
        return res
        
    cotp_len = raw[4] + 1
    s7_start = 4 + cotp_len
    
    if len(raw) < s7_start + 2 or raw[s7_start] != 0x32:
        return res
        
    rosctr = raw[s7_start + 1]
    param_len = int.from_bytes(raw[s7_start + 6 : s7_start + 8], byteorder='big')
    data_len = int.from_bytes(raw[s7_start + 8 : s7_start + 10], byteorder='big')
    
    func = raw[s7_start + 10] if len(raw) > s7_start + 10 else 0
    
    mapping = {
        (0x01, 0x04): "S7_READ",
        (0x01, 0x05): "S7_WRITE",
        (0x01, 0x29): "S7_STOP",
        (0x01, 0x28): "S7_START",
        (0x01, 0xF0): "S7_NEGOTIATE",
        (0x03, 0x04): "S7_READ_RESP",
        (0x03, 0x05): "S7_WRITE_RESP",
    }
    
    res["type"] = mapping.get((rosctr, func), f"S7_0x{rosctr:02x}_0x{func:02x}")
    
    # Parse Parameter cho lệnh READ/WRITE
    if res["type"] in ("S7_READ", "S7_WRITE"):
        if len(raw) >= s7_start + 12:
            res["item_count"] = raw[s7_start + 11]
            item_start = s7_start + 12
            # Đọc item đầu tiên để lấy vùng nhớ (Area)
            if len(raw) >= item_start + 12 and raw[item_start] == 0x12:
                res["transport_size"] = raw[item_start+3]
                res["db_num"] = int.from_bytes(raw[item_start+6:item_start+8], byteorder='big')
                res["area"] = raw[item_start+8] # 0x84=DB, 0x83=M, v.v..
                
                # Tính toán Byte/Bit offset từ 3 byte địa chỉ
                addr_val = int.from_bytes(raw[item_start+9:item_start+12], byteorder='big')
                res["byte_offset"] = addr_val >> 3
                res["bit_offset"] = addr_val & 0x07
    
    if res["type"] == "S7_WRITE":
        res["write_payload_size"] = data_len

    return res


def extract_flow_features_from_pcap(
    pcap_file: str,
    label: str,
    output_csv: str,
    target_ip: str,
    window_seconds: float = 5.0,
    session_id: str = "unknown_session",
    host_id: str = "unknown_host",
    scenario_id: str = "unlabeled",
    episode_id: str = "unlabeled",
) -> int:
    """
    Extract flow-based features from a PCAP file using scapy.
    Uses time-windowed aggregation (similar to CICFlowMeter approach).
    
    Returns number of rows written.
    """
    try:
        from scapy.all import rdpcap, IP, TCP, Raw
    except ImportError:
        print("    [!] scapy not available – skipping feature extraction")
        return 0

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"    [!] Cannot read {pcap_file}: {e}")
        return 0

    # Group packets into time windows
    if not packets:
        return 0

    FIELDS = [
        "window_start_ms", "window_end_ms", "window_start", "window_end", "label", "mitre_technique",
        "session_id", "host_id", "scenario_id", "episode_id",
        "src_ip", "dst_ip", "dst_port",
        # Volume features
        "pkt_count", "byte_count", "avg_pkt_size", "std_pkt_size",
        # Timing features
        "flow_duration_ms", "avg_iat_ms", "std_iat_ms", "max_iat_ms",
        # TCP features
        "tcp_syn_count", "tcp_ack_count", "tcp_rst_count", "tcp_fin_count",
        "tcp_psh_count",
        # S7/ICS specific features
        "s7_pkt_count", "s7_read_count", "s7_write_count",
        "s7_stop_count", "s7_negotiate_count", "s7_error_count",
        "s7_other_count",
        # Đặc trưng Payload DPI
        "s7_m_area_count", "s7_db_area_count",
        "s7_input_area_count", "s7_output_area_count",  # SPOOF detection
        "s7_write_payload_bytes", "s7_max_item_count",
        "unique_db_count", "unique_offset_count",
        # Ratio features
        "write_read_ratio",
        "bytes_per_second",
        "pkts_per_second",
        "syn_rate",
        "tcp_conn_churn_rate",           # FLOOD/FUZZ: SYN/(FIN+1)
        # Profinet DCP features (Layer 2) – SCAN detection
        "dcp_identify_request_count",   # >0 → DCP scan đang xảy ra
        "dcp_identify_response_count",  # số thiết bị phản hồi
        "dcp_total_frame_count",        # tổng frame DCP trong window
        "dcp_scan_detected",            # binary flag: 1 nếu scan
    ]

    rows = []
    t_start = float(packets[0].time)
    t_end   = t_start + window_seconds
    window  : List[Any] = []

    def _process_window(pkts, ws, we):
        if not pkts:
            return None
        sizes     = [len(p) for p in pkts]
        times     = [float(p.time) for p in pkts]
        iats      = [times[i+1]-times[i] for i in range(len(times)-1)] or [0]
        duration  = (times[-1] - times[0]) * 1000  # ms
        elapsed_s = max((times[-1] - times[0]), 0.001)

        # Count TCP flags
        syn = ack = rst = fin = psh = 0
        for p in pkts:
            if p.haslayer(TCP):
                flags = p[TCP].flags
                syn += bool(flags & 0x02)
                ack += bool(flags & 0x10)
                rst += bool(flags & 0x04)
                fin += bool(flags & 0x01)
                psh += bool(flags & 0x08)

        # Count S7 PDU types & DPI Payload Features
        s7_total = s7_read = s7_write = s7_stop = s7_neg = s7_err = s7_other = 0
        s7_m_area = s7_db_area = s7_write_bytes = s7_max_items = 0
        s7_input_area = s7_output_area = 0  # SPOOF detection
        unique_dbs = set()
        unique_offsets = set()
        tcp_syn_local = tcp_fin_local = 0  # for churn rate

        # Count DCP frames (Layer 2 – EtherType 0x8892)
        dcp_req = dcp_resp = dcp_total = 0
        try:
            from scapy.all import Ether, Raw as ScapyRaw
            for p in pkts:
                if Ether in p and p[Ether].type == PROFINET_ETHERTYPE:
                    dcp_total += 1
                    raw_dcp = bytes(p[ScapyRaw].load) if p.haslayer(ScapyRaw) else b""
                    if len(raw_dcp) >= 4:
                        svc_id = raw_dcp[2]
                        svc_type = raw_dcp[3]
                        if svc_id == DCP_SERVICE_IDENTIFY and svc_type == DCP_TYPE_REQUEST:
                            dcp_req += 1
                        elif svc_id == DCP_SERVICE_IDENTIFY and svc_type == DCP_TYPE_RESPONSE:
                            dcp_resp += 1
        except ImportError:
            pass

        for p in pkts:
            if not (p.haslayer(TCP) and p.haslayer(Raw)):
                # Count TCP SYN/FIN từ packets không có Raw (bare SYN)
                if p.haslayer(TCP):
                    flags = p[TCP].flags
                    if flags & 0x02: tcp_syn_local += 1
                    if flags & 0x01: tcp_fin_local += 1
                continue
            dport = p[TCP].dport
            sport = p[TCP].sport
            flags = p[TCP].flags
            if flags & 0x02: tcp_syn_local += 1
            if flags & 0x01: tcp_fin_local += 1

            if 102 not in (dport, sport):
                continue
            raw_bytes = bytes(p[Raw].load)
            parsed = _parse_s7_details(raw_bytes)
            
            s7_total += 1
            ptype = parsed["type"]
            if ptype == "S7_READ":       s7_read += 1
            elif ptype == "S7_WRITE":    s7_write += 1
            elif ptype == "S7_STOP":     s7_stop += 1
            elif ptype == "S7_NEGOTIATE":s7_neg += 1
            elif "ERR" in ptype:         s7_err += 1
            else:                        s7_other += 1

            # Tích lũy đặc trưng payload
            area = parsed["area"]
            if area == 0x83: s7_m_area += 1          # Merker
            if area == 0x84:                           # Data Block
                s7_db_area += 1
                unique_dbs.add(parsed["db_num"])
            if area == 0x81: s7_input_area += 1       # Input (SPOOF target)
            if area == 0x82: s7_output_area += 1      # Output (SPOOF target)
            
            if parsed["byte_offset"] is not None:
                unique_offsets.add(parsed["byte_offset"])
                
            if parsed["item_count"] > s7_max_items: s7_max_items = parsed["item_count"]
            s7_write_bytes += parsed["write_payload_size"]

        # Determine dominant flow direction
        src_ips  = [p[IP].src  for p in pkts if p.haslayer(IP)]
        dst_ips  = [p[IP].dst  for p in pkts if p.haslayer(IP)]
        dst_ports= [p[TCP].dport for p in pkts if p.haslayer(TCP)]
        src_ip  = max(set(src_ips),   key=src_ips.count)   if src_ips   else ""
        dst_ip  = max(set(dst_ips),   key=dst_ips.count)   if dst_ips   else ""
        dst_port= max(set(dst_ports), key=dst_ports.count) if dst_ports else 0

        wr_ratio = round(s7_write / max(s7_read, 1), 4)
        tcp_conn_churn = round(tcp_syn_local / max(tcp_fin_local, 1), 4)
        dcp_scan_flag = int(dcp_req >= 2)
        n = len(pkts)
        byte_total = sum(sizes)
        import statistics
        std_pkt  = round(statistics.stdev(sizes), 2) if len(sizes) > 1 else 0.0
        std_iat  = round(statistics.stdev([i*1000 for i in iats]), 2) if len(iats)>1 else 0.0

        return {
            "window_start_ms": int(round(ws * 1000)),
            "window_end_ms": int(round(we * 1000)),
            "window_start":    round(ws, 3),
            "window_end":      round(we, 3),
            "label":           label,
            "mitre_technique": ATTACK_PHASES.get(label.lower(), {}).get("mitre", ""),
            "session_id":      session_id,
            "host_id":         host_id,
            "scenario_id":     scenario_id,
            "episode_id":      episode_id,
            "src_ip":          src_ip,
            "dst_ip":          dst_ip,
            "dst_port":        dst_port,
            "pkt_count":       n,
            "byte_count":      byte_total,
            "avg_pkt_size":    round(byte_total / n, 2),
            "std_pkt_size":    std_pkt,
            "flow_duration_ms":round(duration, 2),
            "avg_iat_ms":      round(sum(iats)/len(iats)*1000, 2),
            "std_iat_ms":      std_iat,
            "max_iat_ms":      round(max(iats)*1000, 2),
            "tcp_syn_count":   syn,
            "tcp_ack_count":   ack,
            "tcp_rst_count":   rst,
            "tcp_fin_count":   fin,
            "tcp_psh_count":   psh,
            "s7_pkt_count":    s7_total,
            "s7_read_count":   s7_read,
            "s7_write_count":  s7_write,
            "s7_stop_count":   s7_stop,
            "s7_negotiate_count": s7_neg,
            "s7_error_count":  s7_err,
            "s7_other_count":  s7_other,
            "s7_m_area_count": s7_m_area,
            "s7_db_area_count": s7_db_area,
            "s7_input_area_count": s7_input_area,
            "s7_output_area_count": s7_output_area,
            "s7_write_payload_bytes": s7_write_bytes,
            "s7_max_item_count": s7_max_items,
            "unique_db_count": len(unique_dbs),
            "unique_offset_count": len(unique_offsets),
            "write_read_ratio":wr_ratio,
            "bytes_per_second":round(byte_total / elapsed_s, 2),
            "pkts_per_second": round(n / elapsed_s, 2),
            "syn_rate":        round(syn / elapsed_s, 4),
            "tcp_conn_churn_rate": tcp_conn_churn,
            "dcp_identify_request_count": dcp_req,
            "dcp_identify_response_count": dcp_resp,
            "dcp_total_frame_count": dcp_total,
            "dcp_scan_detected": dcp_scan_flag,
        }

    # Slide through time windows
    for pkt in packets:
        pt = float(pkt.time)
        if pt > t_end:
            row = _process_window(window, t_start, t_end)
            if row:
                rows.append(row)
            t_start = t_end
            t_end   = t_start + window_seconds
            window  = []
        if pkt.haslayer(IP):
            window.append(pkt)

    if window:
        row = _process_window(window, t_start, t_end)
        if row:
            rows.append(row)

    # Write CSV
    with open(output_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)


# ══════════════════════════════════════════════════════════════════════
#  ATTACK RUNNERS  (gọi s7pwn commands qua Python API)
# ══════════════════════════════════════════════════════════════════════

def _sample_benign_params(rng: random.Random) -> Dict[str, Any]:
    profile = rng.choice(["steady_polling", "engineering_write", "bursty_hmi", "quiet_monitoring"])
    return {
        "profile": profile,
        "seed": rng.randint(1, 2_000_000_000),
        "read_start": rng.choice([0, 4, 8, 16, 32]),
        "read_size": rng.choice([4, 8, 10, 16]),
        "poll_min_s": rng.uniform(0.4, 1.5) if profile != "quiet_monitoring" else rng.uniform(1.5, 3.0),
        "poll_max_s": rng.uniform(1.5, 4.0) if profile != "quiet_monitoring" else rng.uniform(3.0, 6.0),
        "write_probability": {
            "steady_polling": 0.10,
            "engineering_write": 0.35,
            "bursty_hmi": 0.22,
            "quiet_monitoring": 0.04,
        }[profile],
        "idle_probability": 0.18 if profile == "bursty_hmi" else 0.06,
        "write_offsets": rng.sample([20, 24, 28, 32, 100, 104, 108], k=3),
    }


def _sample_attack_params(phase: str, duration: int, rng: random.Random, ip: str) -> Dict[str, Any]:
    if phase == "scan":
        return {
            "network_cidr": f"{ip}/24",
            "protocols": rng.choice(["s7", "profinet,s7", "profinet,modbus,s7", "all"]),
        }
    if phase == "enum_tags":
        start = rng.randint(0, 48)
        return {
            "area": rng.choice(["M", "I", "Q"]),
            "start": start,
            "end": start + rng.choice([32, 64, 96, 128]),
            "type": rng.choice(["byte", "word"]),
            "interval": round(rng.uniform(0.03, 0.18), 3),
        }
    if phase == "flood":
        return {
            "connections": rng.randint(25, 120),
            "hold_seconds": max(5, min(duration, rng.randint(10, max(10, duration)))),
            "delay": round(rng.uniform(0.01, 0.12), 3),
        }
    if phase == "rwrite":
        offsets = rng.sample([0, 1, 2, 10, 20, 24, 100, 104], k=3)
        return {"items": [f"M{off}={rng.randint(1, 255)}:byte" for off in offsets]}
    if phase == "spoof_constant":
        mode = rng.choice(["constant", "zigzag", "random"])
        return {
            "items": [f"M{rng.choice([10, 12, 14, 16])}={round(rng.uniform(20.0, 120.0), 1)}:real"],
            "mode": mode,
            "interval": round(rng.uniform(0.25, 1.2), 2),
            "min": round(rng.uniform(0.0, 20.0), 1),
            "max": round(rng.uniform(80.0, 140.0), 1),
        }
    if phase == "replay":
        return {"speed": round(rng.uniform(0.7, 1.8), 2), "times": rng.randint(1, 4)}
    if phase == "fuzz":
        return {
            "mode": rng.choice(["header", "function", "length", "full"]),
            "count": rng.randint(80, 350),
            "delay": round(rng.uniform(0.01, 0.10), 3),
        }
    if phase == "cpu_control":
        return {"action": "status"}
    return {}


def _run_normal_traffic(ip: str, rack: int, slot: int, duration: int, params: Dict[str, Any]) -> None:
    """Simulate varied legitimate SCADA/HMI traffic without using attack labels."""
    import snap7
    from snap7.type import Areas
    rng = random.Random(params.get("seed"))
    end_time = time.time() + duration
    client = snap7.client.Client()
    try:
        client.connect(ip, rack, slot)
        print(f"    [normal] profile={params.get('profile')} duration={duration}s params={params}")
        loop_count = 0
        while time.time() < end_time:
            read_start = int(params.get("read_start", 0))
            read_size = int(params.get("read_size", 10))
            for area in rng.sample([Areas.MK, Areas.PE, Areas.PA], k=rng.randint(1, 3)):
                try:
                    client.read_area(area, 0, read_start, read_size)
                except Exception:
                    pass

            if rng.random() < float(params.get("write_probability", 0.1)):
                try:
                    offset = rng.choice(params.get("write_offsets", [100]))
                    val = bytearray([rng.randint(0, 100)])
                    client.write_area(Areas.MK, 0, int(offset), val)
                except Exception:
                    pass

            if rng.random() < float(params.get("idle_probability", 0.05)):
                time.sleep(rng.uniform(2.0, 6.0))
            loop_count += 1
            time.sleep(rng.uniform(float(params.get("poll_min_s", 0.8)), float(params.get("poll_max_s", 3.0))))
    except Exception as e:
        print(f"    [!] Normal traffic error: {e}")
    finally:
        try: client.disconnect()
        except Exception: pass


def _attack_process_entry(phase: str, ip: str, rack: int, slot: int, extra: Dict[str, Any]) -> None:
    try:
        from s7pwn.runtime import set_current_target
        set_current_target(ip, rack, slot)
        params = extra.get("attack_params", {})

        if phase == "scan":
            from s7pwn.commands.scan import scan
            scan([params.get("network_cidr", f"{ip}/24"), "--protocols", params.get("protocols", "s7")])

        elif phase == "enum_tags":
            from s7pwn.commands.enum_tags import enum_tags
            enum_tags([
                "--area", str(params.get("area", "M")),
                "--start", str(params.get("start", 0)),
                "--end", str(params.get("end", 99)),
                "--type", str(params.get("type", "byte")),
                "--interval", str(params.get("interval", 0.05)),
            ])

        elif phase == "flood":
            from s7pwn.commands.flood import flood
            flood([
                str(params.get("connections", 50)),
                str(params.get("hold_seconds", 10)),
                str(params.get("delay", 0.05)),
            ])

        elif phase == "rwrite":
            from s7pwn.commands.rwrite import rwrite
            rwrite(list(params.get("items", ["M0=255:byte", "M1=128:byte", "M2=0:byte"])))

        elif phase == "spoof_constant":
            from s7pwn.commands.spoof import spoof
            args = list(params.get("items", ["M10=99.9:real"])) + [
                "--mode", str(params.get("mode", "constant")),
                "--interval", str(params.get("interval", 0.5)),
                "--min", str(params.get("min", 0)),
                "--max", str(params.get("max", 255)),
            ]
            spoof(args)

        elif phase == "replay":
            replay_file = extra.get("replay_file", "capture.s7replay")
            from s7pwn.commands.replay import replay
            if os.path.exists(replay_file):
                replay(["run", replay_file, "--speed", str(params.get("speed", 1.0)), "--times", str(params.get("times", 1))])
            else:
                print(f"    [!] Replay file not found: {replay_file}")
                print(f"    [*] Run 'replay capture' first, then re-run this phase.")

        elif phase == "cpu_control":
            from s7pwn.commands.cpu_control import cpu_control
            cpu_control([str(params.get("action", "status"))])

        elif phase == "fuzz":
            from s7pwn.commands.fuzz import fuzz
            fuzz([
                "--mode", str(params.get("mode", "full")),
                "--count", str(params.get("count", 200)),
                "--delay", str(params.get("delay", 0.05)),
                "--output", extra.get("fuzz_log", "fuzz_log.jsonl"),
            ])

    except Exception as e:
        print(f"    [attack process error] {e}")


def _run_attack_subprocess(phase: str, ip: str, rack: int, slot: int, duration: int,
                           extra: Dict[str, Any]) -> None:
    """Run one bounded attack episode in a child process and terminate on timeout."""
    proc = multiprocessing.Process(target=_attack_process_entry, args=(phase, ip, rack, slot, extra), daemon=True)
    proc.start()
    proc.join(timeout=duration)
    if proc.is_alive():
        proc.terminate()
        proc.join(timeout=5)


# ══════════════════════════════════════════════════════════════════════
#  MAIN COLLECTION LOOP
# ══════════════════════════════════════════════════════════════════════

def run_collection(
    target_ip: str,
    rack: int = 0,
    slot: int = 1,
    phases: List[str] = None,
    iface: str = "eth0",
    base_dir: str = "dataset",
    window_s: float = 5.0,
    replay_file: str = "",
    session_id: str = "",
    host_id: str = "attacker_host",
    benign_episodes: int = 3,
    episodes_per_attack: int = 3,
    cooldown_s: float = 3.0,
    seed: Optional[int] = None,
) -> None:

    phases = phases or list(ATTACK_PHASES.keys())
    dirs   = setup_directories(base_dir)
    ts_run = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_id = session_id or f"session_{ts_run}"
    rng = random.Random(seed)

    print(f"""
╔══════════════════════════════════════════════════════════╗
║   ICS SECURITY TESTBED - DATASET COLLECTION v{VERSION}     ║
╠══════════════════════════════════════════════════════════╣
║  Target   : {target_ip:<44} ║
║  Rack/Slot: {rack}/{slot:<43} ║
║  Interface: {iface:<44} ║
║  Output   : {base_dir:<44} ║
║  Phases   : {len(phases):<44} ║
║  Run ID   : {ts_run:<44} ║
║  Session  : {session_id:<44} ║
║  Host ID  : {host_id:<44} ║
╚══════════════════════════════════════════════════════════╝
  Method: Time-windowed flow features ({window_s}s window)
  Ref   : CIC-IDS2017, SWaT, BATADAL dataset methodology
  Episodes: benign={benign_episodes}, attack={episodes_per_attack}, seed={seed}
""")

    all_csv_files = []
    meta_log = []

    for phase in phases:
        if phase not in ATTACK_PHASES:
            print(f"[!] Unknown phase '{phase}' – skipping.")
            continue

        info = ATTACK_PHASES[phase]
        label = info["label"]
        duration = info["duration_s"]
        episode_count = benign_episodes if phase == "normal" else episodes_per_attack

        print(f"{'─'*60}")
        print(f"  Phase : {label}  ({info['mitre']})")
        print(f"  Desc  : {info['description']}")
        print(f"  Time  : {duration}s x {episode_count} episode(s)")

        for episode_idx in range(1, episode_count + 1):
            episode_id = f"{session_id}:{host_id}:{phase}:ep{episode_idx}"
            scenario_id = phase.upper()
            pcap_file = str(dirs["raw_pcap"] / f"{ts_run}_{phase}_ep{episode_idx}.pcap")
            csv_file = str(dirs["flows"] / f"{ts_run}_{phase}_ep{episode_idx}_flows.csv")
            params = _sample_benign_params(rng) if phase == "normal" else _sample_attack_params(phase, duration, rng, target_ip)

            print(f"  Episode {episode_idx}/{episode_count}: {episode_id}")
            print(f"  Params : {json.dumps(params, ensure_ascii=False)}")

            capture = PcapCapture(
                iface=iface,
                output_file=pcap_file,
                # Bắt cả DCP (L2 EtherType 0x8892) VÀ S7/Modbus (TCP port 102/502)
                bpf_filter=f"(ether proto 0x8892) or (host {target_ip} and (tcp port 102 or tcp port 502))",
            )
            capturing = capture.start()

            t0 = time.time()
            print(f"  Start : {datetime.now().strftime('%H:%M:%S')}")

            extra = {
                "replay_file": replay_file or str(dirs["replay_capture"] / "capture.s7replay"),
                "fuzz_log": str(dirs["logs"] / f"{ts_run}_{phase}_ep{episode_idx}_fuzz.jsonl"),
                "attack_params": params,
            }
            if phase == "normal":
                _run_normal_traffic(target_ip, rack, slot, duration, params)
            else:
                _run_attack_subprocess(phase, target_ip, rack, slot, duration, extra)
                elapsed = time.time() - t0
                if elapsed < duration:
                    time.sleep(duration - elapsed)

            capture.stop()
            elapsed_total = round(time.time() - t0, 1)
            print(f"  Done  : {datetime.now().strftime('%H:%M:%S')}  ({elapsed_total}s)")

            if capturing and os.path.exists(pcap_file):
                print(f"  Extract features from pcap ...")
                n_rows = extract_flow_features_from_pcap(
                    pcap_file=pcap_file,
                    label=label,
                    output_csv=csv_file,
                    target_ip=target_ip,
                    window_seconds=window_s,
                    session_id=session_id,
                    host_id=host_id,
                    scenario_id=scenario_id,
                    episode_id=episode_id,
                )
                print(f"  → {n_rows} flow windows extracted → {csv_file}")
                if n_rows > 0:
                    all_csv_files.append(csv_file)
            else:
                print(f"  [!] No pcap captured – check tcpdump + interface name")

            meta_log.append({
                "phase": phase,
                "episode_index": episode_idx,
                "episode_id": episode_id,
                "session_id": session_id,
                "host_id": host_id,
                "label": label,
                "mitre": info["mitre"],
                "duration_s": duration,
                "parameters": params,
                "pcap": pcap_file,
                "flows_csv": csv_file,
                "run_id": ts_run,
            })

            print()
            time.sleep(cooldown_s)

    # ── Merge all CSVs into one labeled dataset ───────────────────────
    merged_csv = str(dirs["base"] / f"labeled_dataset_{ts_run}.csv")
    print(f"{'═'*60}")
    print(f"  Merging {len(all_csv_files)} phase CSV files ...")

    if all_csv_files:
        try:
            import pandas as pd
            dfs = [pd.read_csv(f) for f in all_csv_files if os.path.exists(f)]
            if dfs:
                merged = pd.concat(dfs, ignore_index=True)
                merged.to_csv(merged_csv, index=False)
                print(f"\n  ✓ Labeled dataset: {merged_csv}")
                print(f"    Total rows : {len(merged)}")
                print(f"    Features   : {len(merged.columns)}")
                print(f"\n  Class distribution:")
                for lbl, cnt in merged["label"].value_counts().items():
                    print(f"    {lbl:<20} {cnt:>5} rows")
        except ImportError:
            # Fallback: manual CSV merge
            header_written = False
            with open(merged_csv, "w") as fout:
                for csv_f in all_csv_files:
                    if not os.path.exists(csv_f):
                        continue
                    with open(csv_f) as fin:
                        lines = fin.readlines()
                    if not lines:
                        continue
                    if not header_written:
                        fout.writelines(lines)
                        header_written = True
                    else:
                        fout.writelines(lines[1:])   # skip header
            print(f"  ✓ Merged (no pandas): {merged_csv}")

    # ── Save metadata ─────────────────────────────────────────────────
    meta_file = str(dirs["base"] / f"collection_meta_{ts_run}.json")
    with open(meta_file, "w") as f:
        json.dump({
            "run_id": ts_run,
            "session_id": session_id,
            "host_id": host_id,
            "target_ip": target_ip,
            "rack": rack,
            "slot": slot,
            "iface": iface,
            "window_s": window_s,
            "seed": seed,
            "benign_episodes": benign_episodes,
            "episodes_per_attack": episodes_per_attack,
            "cooldown_s": cooldown_s,
            "phases": meta_log,
            "merged_csv": merged_csv,
            "methodology": {
                "reference": "CIC-IDS2017, SWaT, BATADAL",
                "features": "Time-windowed bidirectional flow features",
                "labeling": "Per-window ground-truth label from attack schedule",
                "tool": "S7Pwn testbed collector v" + VERSION,
            }
        }, f, indent=2)

    print(f"\n  Metadata : {meta_file}")
    print(f"{'═'*60}")
    print("  Collection complete.")
    print(f"{'═'*60}\n")


# ══════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="ICS Testbed Dataset Collector – S7Pwn",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    ap.add_argument("--target",  required=True,  help="PLC IP address")
    ap.add_argument("--rack",    type=int, default=0,    help="S7 rack (default 0)")
    ap.add_argument("--slot",    type=int, default=1,    help="S7 slot (default 1)")
    ap.add_argument("--iface",   default="eth0",         help="Network interface for capture")
    ap.add_argument("--output",  default="dataset",      help="Output base directory")
    ap.add_argument("--window",  type=float, default=5.0,help="Feature aggregation window (s)")
    ap.add_argument("--replay-file", default="",         help="Pre-captured .s7replay for replay phase")
    ap.add_argument("--phase",   default="all",
        help=("Phase(s) to run: all | normal | scan | enum_tags | flood |\n"
              "rwrite | spoof_constant | replay | cpu_control | fuzz\n"
              "Comma-separated for multiple: normal,scan,flood"))
    ap.add_argument("--session-id", default="", help="Session metadata for grouped split")
    ap.add_argument("--host-id", default="attacker_host", help="Attacker host metadata; use a distinct value for host-holdout validation")
    ap.add_argument("--benign-episodes", type=int, default=3, help="Number of varied benign episodes for normal phase")
    ap.add_argument("--episodes-per-attack", type=int, default=3, help="Number of repeated randomized episodes per attack phase")
    ap.add_argument("--cooldown", type=float, default=3.0, help="Cooldown seconds between episodes")
    ap.add_argument("--seed", type=int, default=None, help="Random seed for reproducible episode parameters")
    ap.add_argument("--config",  default="",             help="Load config from JSON file")
    ap.add_argument("--list-phases", action="store_true",help="List all available phases and exit")

    args = ap.parse_args()

    if args.list_phases:
        print("\nAvailable phases:\n")
        print(f"  {'Phase':<20} {'Label':<15} {'MITRE':<10} {'Duration':>8}  Description")
        print("  " + "─"*80)
        for k, v in ATTACK_PHASES.items():
            print(f"  {k:<20} {v['label']:<15} {v['mitre']:<10} {v['duration_s']:>6}s  {v['description']}")
        print()
        sys.exit(0)

    # Load config override
    cfg = {}
    if args.config and os.path.exists(args.config):
        with open(args.config) as f:
            cfg = json.load(f)

    target_ip   = cfg.get("target", args.target)
    rack        = cfg.get("rack",   args.rack)
    slot        = cfg.get("slot",   args.slot)
    iface       = cfg.get("iface",  args.iface)
    base_dir    = cfg.get("output", args.output)
    window_s    = cfg.get("window", args.window)
    replay_file = cfg.get("replay_file", args.replay_file)
    session_id  = cfg.get("session_id", args.session_id)
    host_id     = cfg.get("host_id", args.host_id)
    benign_episodes = int(cfg.get("benign_episodes", args.benign_episodes))
    episodes_per_attack = int(cfg.get("episodes_per_attack", args.episodes_per_attack))
    cooldown_s = float(cfg.get("cooldown", args.cooldown))
    seed = cfg.get("seed", args.seed)

    if args.phase.lower() == "all":
        phases = list(ATTACK_PHASES.keys())
    else:
        phases = [p.strip() for p in args.phase.split(",")]

    run_collection(
        target_ip=target_ip,
        rack=rack,
        slot=slot,
        phases=phases,
        iface=iface,
        base_dir=base_dir,
        window_s=window_s,
        replay_file=replay_file,
        session_id=session_id,
        host_id=host_id,
        benign_episodes=benign_episodes,
        episodes_per_attack=episodes_per_attack,
        cooldown_s=cooldown_s,
        seed=seed,
    )
