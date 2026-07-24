#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_opcua_features.py

OPC UA feature extractor for PLC/ICS PCAP/PCAPNG, windowed like
extract_s7_features.py so the two can eventually be merged the same way
(merge_dataset.py joins on window_start_ms).

Why this file exists (see paper-readiness-plan.md / conversation context):
extract_s7_features.py, extract_dcp_features.py and pcap_to_csv.py only
parse S7comm/Profinet DCP -- none of them touch OPC UA (port 4840). This
was the concrete blocker for building an OPC UA attack detector, so this
script fills that specific gap. It reuses the tshark plumbing, timeline
labeling and numeric-safety helpers from extract_s7_features.py instead of
duplicating them.

Service classification is done via opcua.servicenodeid.numeric, matching
against the well-known OPC UA NodeIds for each Service's *_Encoding_DefaultBinary
type (verified against the OPC Foundation's authoritative
NodeIds.csv: https://www.opcfoundation.org/UA/schemas/1.04/NodeIds.csv).
This was validated end-to-end against a real installed TShark 4.2.2: a
hand-built CreateSessionRequest MSG chunk (TypeId 461, the
_Encoding_DefaultBinary id, matching the OPC UA binary wire encoding) was
correctly dissected into opcua.servicenodeid.numeric=461 and correctly
classified as "create_session" by this script. The abstract DataType id
(e.g. 459) is kept in each set too as a defensive fallback for other
dissector versions, but 461-style Encoding_DefaultBinary ids are the
confirmed real-world value. Still: re-run against your own captured OPC UA
traffic once and eyeball non-zero counts before trusting the numbers for
training -- one synthetic packet is not the same as real attacker traffic.

Basic usage:
  python extract_opcua_features.py \\
    --pcap capture.pcapng \\
    --output opcua_features.csv \\
    --window 5 \\
    --plc-ip 192.168.210.211 \\
    --label benign

With a day8 scenario timeline (received_at / scenario_id from
tests/day8/run_day8.py results, converted to start,end,label CSV):
  python extract_opcua_features.py \\
    --pcap opcua_scenarios.pcapng \\
    --timeline opcua_timeline.csv \\
    --output opcua_features.csv \\
    --window 5 \\
    --plc-ip 192.168.210.211

Requires: Wireshark/TShark installed and on PATH.
"""

from __future__ import annotations

import argparse
import csv
import subprocess
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from extract_s7_features import (
    choose_existing_fields,
    find_tshark,
    get_available_fields,
    label_for_window,
    load_timeline,
    mean,
    normalize_epoch_ms,
    safe_float,
    safe_int,
    std,
)

# ============================================================
# 0. OPC UA service NodeId map
#
# Verified against files.opcfoundation.org/schemas/1.04/NodeIds.csv:
#   <Service>Request                       -> abstract DataType id
#   <Service>Request_Encoding_DefaultBinary -> id actually seen on the wire
# Both are matched defensively (see module docstring).
# ============================================================

SERVICE_NODE_IDS: Dict[str, Set[int]] = {
    "get_endpoints":           {426, 428},
    "open_secure_channel":     {444, 446},
    "close_secure_channel":    {448, 450},
    "create_session":          {459, 461},
    "activate_session":        {465, 467},
    "close_session":           {471, 473},
    "browse":                  {523, 525, 527},  # Browse + BrowseNext family
    "read":                    {629, 631},
    "write":                   {671, 673},
    "create_subscription":     {785, 787},
    "create_monitored_items":  {749, 751},
}

# OPC UA StatusCode encoding (Part 4): top 2 bits of the 32-bit value.
STATUS_SEVERITY_MASK = 0xC0000000
STATUS_SEVERITY_GOOD = 0x00000000
STATUS_SEVERITY_UNCERTAIN = 0x40000000
STATUS_SEVERITY_BAD = 0x80000000

META_COLS = {
    "window_start_ms",
    "window_end_ms",
    "label",
    "capture_role",
    "plc_ip",
    "session_id",
    "host_id",
    "scenario_id",
    "episode_id",
}

ML_UNSAFE_EXACT_COLS = {
    "window_start_ms", "window_end_ms", "capture_role", "plc_ip",
    "session_id", "host_id", "scenario_id", "episode_id",
}


# ============================================================
# 1. tshark command
# ============================================================

def build_tshark_command(tshark_cmd: str, pcap_path: str, available_fields: Set[str], plc_ip: Optional[str]):
    base_fields = [
        "frame.time_epoch",
        "frame.len",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
    ]
    opcua_fields = [
        "opcua.transport.type",
        "opcua.servicenodeid.numeric",
        "opcua.StatusCode",
        "opcua.ServiceResult",
    ]

    fields = []
    for group in [base_fields, opcua_fields]:
        fields.extend(choose_existing_fields(available_fields, group))
    seen = set()
    fields = [f for f in fields if not (f in seen or seen.add(f))]

    if plc_ip:
        display_filter = f"tcp.port == 4840 && ip.addr == {plc_ip}"
    else:
        display_filter = "tcp.port == 4840"

    cmd = [
        tshark_cmd, "-r", pcap_path,
        "-o", "tcp.desegment_tcp_streams:TRUE",
        "-Y", display_filter, "-T", "fields",
    ]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=a"]
    return cmd, fields


# ============================================================
# 2. Per-window aggregation
# ============================================================

def new_window() -> dict:
    w = {
        "packet_count": 0,
        "byte_count": 0,
        "frame_lengths": [],
        "src_ips": set(),
        "dst_ips": set(),
        "tcp_streams": set(),
        "hel_count": 0,
        "opn_count": 0,
        "msg_count": 0,
        "clo_count": 0,
        "err_count": 0,
        "status_good_count": 0,
        "status_uncertain_count": 0,
        "status_bad_count": 0,
        "scan_by_src": defaultdict(lambda: {"packets": 0, "create_session": 0, "browse": 0}),
    }
    for service in SERVICE_NODE_IDS:
        w[f"{service}_count"] = 0
    return w


def classify_service(node_id: int) -> Optional[str]:
    for service, ids in SERVICE_NODE_IDS.items():
        if node_id in ids:
            return service
    return None


def classify_status(value: int) -> str:
    severity = value & STATUS_SEVERITY_MASK
    if severity == STATUS_SEVERITY_BAD:
        return "bad"
    if severity == STATUS_SEVERITY_UNCERTAIN:
        return "uncertain"
    return "good"


def extract_features(
    pcap_path: str,
    output_path: str,
    window_size: float,
    plc_ip: Optional[str],
    role: str,
    label: str,
    timeline_path: Optional[str],
    session_id: str,
    host_id: str,
    scenario_id: str,
    episode_id: str,
) -> None:
    tshark_cmd = find_tshark()
    available_fields = get_available_fields(tshark_cmd)
    cmd, fields = build_tshark_command(tshark_cmd, pcap_path, available_fields, plc_ip)
    field_index = {name: i for i, name in enumerate(fields)}

    def get(parts: List[str], name: str) -> str:
        idx = field_index.get(name)
        if idx is None or idx >= len(parts):
            return ""
        # tshark's -E quote=d wraps every field in literal double quotes.
        return parts[idx].strip().strip('"')

    window_ms = int(window_size * 1000)
    windows: Dict[int, dict] = {}

    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="ignore")
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed (exit {proc.returncode}): {proc.stderr.strip()[:500]}")

    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")

        t_epoch = safe_float(get(parts, "frame.time_epoch"), -1)
        if t_epoch < 0:
            continue
        t_ms = int(t_epoch * 1000)
        w_start = (t_ms // window_ms) * window_ms
        w = windows.setdefault(w_start, new_window())

        w["packet_count"] += 1
        frame_len = safe_int(get(parts, "frame.len"))
        w["byte_count"] += frame_len
        w["frame_lengths"].append(frame_len)

        src_ip = get(parts, "ip.src")
        dst_ip = get(parts, "ip.dst")
        if src_ip:
            w["src_ips"].add(src_ip)
        if dst_ip:
            w["dst_ips"].add(dst_ip)

        stream = get(parts, "tcp.stream")
        if stream:
            w["tcp_streams"].add(stream)

        transport_type = get(parts, "opcua.transport.type").strip().upper()
        if transport_type == "HEL":
            w["hel_count"] += 1
        elif transport_type == "OPN":
            w["opn_count"] += 1
        elif transport_type == "MSG":
            w["msg_count"] += 1
        elif transport_type == "CLO":
            w["clo_count"] += 1
        elif transport_type == "ERR":
            w["err_count"] += 1

        node_id_raw = get(parts, "opcua.servicenodeid.numeric")
        if node_id_raw:
            for single in node_id_raw.split(","):
                node_id = safe_int(single, -1)
                if node_id < 0:
                    continue
                service = classify_service(node_id)
                if service:
                    w[f"{service}_count"] += 1
                    if src_ip and service in ("create_session", "browse"):
                        w["scan_by_src"][src_ip][service] += 1
                    if src_ip:
                        w["scan_by_src"][src_ip]["packets"] += 1

        status_raw = get(parts, "opcua.StatusCode") or get(parts, "opcua.ServiceResult")
        if status_raw:
            for single in status_raw.split(","):
                status_val = safe_int(single, -1)
                if status_val < 0:
                    continue
                sev = classify_status(status_val)
                w[f"status_{sev}_count"] += 1

    timeline = load_timeline(timeline_path)
    write_output(
        windows=windows,
        output_path=output_path,
        window_ms=window_ms,
        role=role,
        label=label,
        plc_ip=plc_ip,
        timeline=timeline,
        session_id=session_id,
        host_id=host_id,
        scenario_id=scenario_id,
        episode_id=episode_id,
    )


# ============================================================
# 3. Output
# ============================================================

def write_output(
    windows: Dict[int, dict],
    output_path: str,
    window_ms: int,
    role: str,
    label: str,
    plc_ip: Optional[str],
    timeline,
    session_id: str,
    host_id: str,
    scenario_id: str,
    episode_id: str,
) -> None:
    service_cols = [f"{service}_count" for service in SERVICE_NODE_IDS]
    fieldnames = [
        "window_start_ms", "window_end_ms", "label",
        "capture_role", "plc_ip", "session_id", "host_id", "scenario_id", "episode_id",
        "opcua_packet_count", "opcua_byte_count",
        "opcua_frame_len_mean", "opcua_frame_len_std",
        "opcua_unique_src_ip_count", "opcua_unique_dst_ip_count", "opcua_unique_tcp_stream_count",
        "opcua_hel_count", "opcua_opn_count", "opcua_msg_count", "opcua_clo_count", "opcua_err_count",
        "opcua_status_good_count", "opcua_status_uncertain_count", "opcua_status_bad_count",
        *[f"opcua_{c}" for c in service_cols],
        "opcua_max_create_session_by_single_src", "opcua_max_browse_by_single_src",
    ]

    if not windows:
        print("[WARN] No OPC UA packets matched the filter -- writing an empty feature file.", file=sys.stderr)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for w_start in sorted(windows.keys()):
            w = windows[w_start]
            w_end = w_start + window_ms
            row = {
                "window_start_ms": w_start,
                "window_end_ms": w_end,
                "label": label_for_window(w_start, w_end, timeline, label),
                "capture_role": role,
                "plc_ip": plc_ip or "",
                "session_id": session_id,
                "host_id": host_id,
                "scenario_id": scenario_id,
                "episode_id": episode_id,
                "opcua_packet_count": w["packet_count"],
                "opcua_byte_count": w["byte_count"],
                "opcua_frame_len_mean": round(mean(w["frame_lengths"]), 3),
                "opcua_frame_len_std": round(std(w["frame_lengths"]), 3),
                "opcua_unique_src_ip_count": len(w["src_ips"]),
                "opcua_unique_dst_ip_count": len(w["dst_ips"]),
                "opcua_unique_tcp_stream_count": len(w["tcp_streams"]),
                "opcua_hel_count": w["hel_count"],
                "opcua_opn_count": w["opn_count"],
                "opcua_msg_count": w["msg_count"],
                "opcua_clo_count": w["clo_count"],
                "opcua_err_count": w["err_count"],
                "opcua_status_good_count": w["status_good_count"],
                "opcua_status_uncertain_count": w["status_uncertain_count"],
                "opcua_status_bad_count": w["status_bad_count"],
            }
            for service in SERVICE_NODE_IDS:
                row[f"opcua_{service}_count"] = w[f"{service}_count"]

            row["opcua_max_create_session_by_single_src"] = (
                max((s["create_session"] for s in w["scan_by_src"].values()), default=0)
            )
            row["opcua_max_browse_by_single_src"] = (
                max((s["browse"] for s in w["scan_by_src"].values()), default=0)
            )
            writer.writerow(row)

    print(f"[OK] Wrote {len(windows)} window(s) to {output_path}")


def write_ml_safe_copy(input_csv: str, output_csv: str) -> None:
    with open(input_csv, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = [c for c in (reader.fieldnames or []) if c not in ML_UNSAFE_EXACT_COLS]
        rows = list(reader)
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row[k] for k in fieldnames})
    print(f"[OK] Wrote ML-safe copy to {output_csv}")


# ============================================================
# 4. CLI
# ============================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="OPC UA feature extractor for PLC/ICS PCAP/PCAPNG, windowed like extract_s7_features.py.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--pcap", required=True, help="Input PCAP/PCAPNG file")
    parser.add_argument("--output", required=True, help="Output feature CSV")
    parser.add_argument("--window", type=float, default=5.0, help="Time window size in seconds, default=5.0")
    parser.add_argument("--plc-ip", default=None, help="PLC/OPC UA server IP; narrows the tshark filter")
    parser.add_argument("--role", default="unknown", choices=["attacker", "controller", "mirror", "unknown"], help="Capture role metadata")
    parser.add_argument("--label", default="unknown", help="Default label if no timeline is provided")
    parser.add_argument("--timeline", default=None, help="Optional timeline CSV with start,end,label (same format as extract_s7_features.py)")
    parser.add_argument("--session-id", default="unknown_session", help="Session metadata for grouped splits; never use as ML input")
    parser.add_argument("--host-id", default="unknown_host", help="Capture host metadata for grouped splits; never use as ML input")
    parser.add_argument("--scenario-id", default="unlabeled", help="Scenario metadata for audit only")
    parser.add_argument("--episode-id", default="unlabeled", help="Episode metadata for grouped splits")
    parser.add_argument("--ml-safe-copy", default=None, help="Optional path to write a metadata-dropped CSV for ML training")
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
            session_id=args.session_id,
            host_id=args.host_id,
            scenario_id=args.scenario_id,
            episode_id=args.episode_id,
        )
        if args.ml_safe_copy:
            write_ml_safe_copy(args.output, args.ml_safe_copy)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
