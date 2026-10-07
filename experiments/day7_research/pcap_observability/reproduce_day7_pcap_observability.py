#!/usr/bin/env python3
"""
Offline PCAP observability audit for the Day 7 OPC UA/S7 case-study.

This script is intentionally read-only with respect to the original PCAP,
timeline, datasets, models and thesis document. It extracts the Day 7 ZIP to a
temporary directory, queries each PCAP segment with tshark, de-duplicates near
duplicate captures conservatively, and writes audit artifacts under:

    experiments/day7_research/pcap_observability/

Reproduction command from the repository root:

    python3 experiments/day7_research/pcap_observability/reproduce_day7_pcap_observability.py
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[3]
OUT_DIR = ROOT / "experiments" / "day7_research" / "pcap_observability"
TIMELINE = ROOT / "labels" / "day7_final_timeline.csv"
PCAP_ZIP = ROOT / "data_opc" / "day7" / "ot-capture-ot1788454936.zip"
DECISION_REPORT = ROOT / "experiments" / "day7_research" / "DAY7_RESEARCH_DECISION_VI.md"

PLC_IP = "192.168.210.211"
HMI_IP = "192.168.210.31"

# The audit infers the active Day 7 test client from PCAP flows instead of
# treating it as a ground-truth label. The value below is used only for
# direction summaries after inference confirms it appears as the dominant
# OPC UA/SMB/S7 source.
EXPECTED_ATTACKER_IP = "192.168.210.32"

FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.seq",
    "tcp.ack",
    "tcp.len",
    "frame.protocols",
]


@dataclass(frozen=True)
class Stage:
    label: str
    start_ms: int
    end_ms: int
    start_note: str
    end_note: str

    @property
    def start_epoch(self) -> float:
        return self.start_ms / 1000.0

    @property
    def end_epoch(self) -> float:
        return self.end_ms / 1000.0

    @property
    def duration_s(self) -> float:
        return (self.end_ms - self.start_ms) / 1000.0

    @property
    def start_iso(self) -> str:
        return iso_utc(self.start_epoch)

    @property
    def end_iso(self) -> str:
        return iso_utc(self.end_epoch)


@dataclass(frozen=True)
class Query:
    scenario_label: str
    evidence_id: str
    evidence_group: str
    target: str
    direction_scope: str
    protocol_scope: str
    tshark_filter: str
    interpretation: str
    independent_of_module_counter: str


def iso_utc(epoch: float | None) -> str:
    if epoch is None:
        return ""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def require_file(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(path)


def run_cmd(args: list[str]) -> str:
    proc = subprocess.run(args, check=False, text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(
            "Command failed:\n"
            + " ".join(args)
            + "\nSTDOUT:\n"
            + proc.stdout
            + "\nSTDERR:\n"
            + proc.stderr
        )
    return proc.stdout


def parse_timeline(path: Path) -> dict[str, Stage]:
    starts: dict[str, dict[str, str]] = {}
    ends: dict[str, dict[str, str]] = {}
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            label = row["scenario_label"]
            if row["action"] == "START":
                starts[label] = row
            elif row["action"] == "END":
                ends[label] = row
    stages: dict[str, Stage] = {}
    for label, start in starts.items():
        end = ends[label]
        stages[label] = Stage(
            label=label,
            start_ms=int(start["attacker_timestamp_ms"]),
            end_ms=int(end["attacker_timestamp_ms"]),
            start_note=start.get("note", ""),
            end_note=end.get("note", ""),
        )
    return stages


def extract_pcaps(zip_path: Path, tmpdir: Path) -> list[Path]:
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(tmpdir)
    return sorted(tmpdir.rglob("*.pcap"))


def tshark_rows(pcap: Path, display_filter: str) -> list[dict[str, str]]:
    args = [
        "tshark",
        "-r",
        str(pcap),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
    ]
    for field in FIELDS:
        args += ["-e", field]
    out = run_cmd(args)
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < len(FIELDS):
            parts += [""] * (len(FIELDS) - len(parts))
        row = dict(zip(FIELDS, parts))
        row["segment"] = pcap.name
        rows.append(row)
    return rows


def pcap_segment_stats(pcap: Path) -> dict[str, object]:
    out = run_cmd(
        [
            "tshark",
            "-r",
            str(pcap),
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-e",
            "frame.time_epoch",
            "-e",
            "frame.len",
        ]
    )
    times: list[float] = []
    frame_count = 0
    total_bytes = 0
    for line in out.splitlines():
        if not line.strip():
            continue
        fields = line.split("\t")
        try:
            times.append(float(fields[0]))
        except Exception:
            pass
        if len(fields) > 1:
            try:
                total_bytes += int(fields[1])
            except Exception:
                pass
        frame_count += 1
    return {
        "segment": pcap.name,
        "frame_count": frame_count,
        "first_epoch": min(times) if times else None,
        "last_epoch": max(times) if times else None,
        "first_iso_utc": iso_utc(min(times)) if times else "",
        "last_iso_utc": iso_utc(max(times)) if times else "",
        "duration_s": (max(times) - min(times)) if times else 0.0,
        "frame_bytes": total_bytes,
    }


def time_filter(stage: Stage) -> str:
    # Inclusive bounds are used to match the existing Day 7 documentation and
    # earlier read-only recounts. No packet in this audit fell exactly on an
    # endpoint in a way that changed the conclusions.
    return f"frame.time_epoch >= {stage.start_epoch:.3f} && frame.time_epoch <= {stage.end_epoch:.3f}"


def build_queries(stages: dict[str, Stage]) -> list[Query]:
    return [
        Query(
            "SMB_RECON_ENUM",
            "smb2_hmi_dst_445_decoded",
            "SMB2/TCP445 tới HMI",
            HMI_IP,
            "to_hmi",
            "decoded_smb2",
            f"({time_filter(stages['SMB_RECON_ENUM'])}) && smb2 && ip.dst == {HMI_IP} && tcp.dstport == 445",
            "Gói SMB2 được Wireshark giải mã, hướng tới HMI trên TCP/445.",
            "yes_pcap_wire_evidence",
        ),
        Query(
            "SMB_RECON_ENUM",
            "tcp445_hmi_dst_all",
            "SMB2/TCP445 tới HMI",
            HMI_IP,
            "to_hmi",
            "all_tcp_445",
            f"({time_filter(stages['SMB_RECON_ENUM'])}) && ip.dst == {HMI_IP} && tcp.dstport == 445",
            "Toàn bộ frame TCP đích 445 tới HMI, gồm cả frame không được giải mã SMB2.",
            "yes_pcap_wire_evidence",
        ),
        Query(
            "SMB_RECON_ENUM",
            "tcp445_hmi_two_way_all",
            "SMB2/TCP445 tới HMI",
            HMI_IP,
            "two_way_hmi",
            "all_tcp_445",
            f"({time_filter(stages['SMB_RECON_ENUM'])}) && ip.addr == {HMI_IP} && tcp.port == 445",
            "Toàn bộ frame TCP/445 hai chiều giữa HMI và các host liên quan.",
            "yes_pcap_wire_evidence",
        ),
        Query(
            "KILL_CHAIN",
            "tcp_syn_to_hmi",
            "TCP SYN tới HMI",
            HMI_IP,
            "to_hmi",
            "tcp_syn",
            f"({time_filter(stages['KILL_CHAIN'])}) && ip.dst == {HMI_IP} && tcp.flags.syn == 1 && tcp.flags.ack == 0",
            "SYN scan/pivot tới HMI trong cửa sổ kill-chain.",
            "yes_pcap_wire_evidence",
        ),
        Query(
            "KILL_CHAIN",
            "kill_s7comm_to_plc_decoded",
            "S7comm tới PLC",
            PLC_IP,
            "to_plc",
            "decoded_s7comm",
            f"({time_filter(stages['KILL_CHAIN'])}) && s7comm && ip.dst == {PLC_IP}",
            "Gói S7comm được giải mã, hướng tới PLC trong cửa sổ kill-chain.",
            "yes_pcap_wire_evidence",
        ),
        Query(
            "KILL_CHAIN",
            "kill_s7comm_plc_two_way_decoded",
            "S7comm tới PLC",
            PLC_IP,
            "two_way_plc",
            "decoded_s7comm",
            f"({time_filter(stages['KILL_CHAIN'])}) && s7comm && ip.addr == {PLC_IP}",
            "Gói S7comm được giải mã, hai chiều với PLC trong cửa sổ kill-chain.",
            "yes_pcap_wire_evidence",
        ),
        Query(
            "KILL_CHAIN",
            "kill_tcp102_plc_two_way_all",
            "S7comm tới PLC",
            PLC_IP,
            "two_way_plc",
            "all_tcp_102",
            f"({time_filter(stages['KILL_CHAIN'])}) && ip.addr == {PLC_IP} && tcp.port == 102",
            "Toàn bộ TCP/102 hai chiều với PLC trong cửa sổ kill-chain.",
            "yes_pcap_wire_evidence",
        ),
        Query(
            "CONCEALED_STOP_ATTACK",
            "opcua_to_plc_decoded",
            "OPC UA/TCP4840 tới PLC",
            PLC_IP,
            "to_plc",
            "decoded_opcua",
            f"({time_filter(stages['CONCEALED_STOP_ATTACK'])}) && opcua && ip.dst == {PLC_IP}",
            "Gói OPC UA được giải mã, hướng tới PLC trong cửa sổ concealed stop.",
            "yes_pcap_wire_evidence",
        ),
        Query(
            "CONCEALED_STOP_ATTACK",
            "opcua_plc_two_way_decoded",
            "OPC UA/TCP4840 tới PLC",
            PLC_IP,
            "two_way_plc",
            "decoded_opcua",
            f"({time_filter(stages['CONCEALED_STOP_ATTACK'])}) && opcua && ip.addr == {PLC_IP}",
            "Gói OPC UA được giải mã, hai chiều với PLC trong cửa sổ concealed stop.",
            "yes_pcap_wire_evidence",
        ),
        Query(
            "CONCEALED_STOP_ATTACK",
            "tcp4840_to_plc_all",
            "OPC UA/TCP4840 tới PLC",
            PLC_IP,
            "to_plc",
            "all_tcp_4840",
            f"({time_filter(stages['CONCEALED_STOP_ATTACK'])}) && ip.dst == {PLC_IP} && tcp.dstport == 4840",
            "Toàn bộ TCP/4840 hướng tới PLC, gồm cả handshake/ACK/frame không giải mã OPC UA.",
            "yes_pcap_wire_evidence",
        ),
        Query(
            "CONCEALED_STOP_ATTACK",
            "tcp4840_plc_two_way_all",
            "OPC UA/TCP4840 tới PLC",
            PLC_IP,
            "two_way_plc",
            "all_tcp_4840",
            f"({time_filter(stages['CONCEALED_STOP_ATTACK'])}) && ip.addr == {PLC_IP} && tcp.port == 4840",
            "Toàn bộ TCP/4840 hai chiều với PLC, gồm cả handshake/ACK/frame không giải mã OPC UA.",
            "yes_pcap_wire_evidence",
        ),
        Query(
            "CONCEALED_STOP_ATTACK",
            "concealed_s7comm_to_plc_decoded",
            "S7comm/TCP102 tới PLC",
            PLC_IP,
            "to_plc",
            "decoded_s7comm",
            f"({time_filter(stages['CONCEALED_STOP_ATTACK'])}) && s7comm && ip.dst == {PLC_IP}",
            "Gói S7comm được giải mã, hướng tới PLC trong cửa sổ concealed stop.",
            "yes_pcap_wire_evidence",
        ),
        Query(
            "CONCEALED_STOP_ATTACK",
            "concealed_s7comm_plc_two_way_decoded",
            "S7comm/TCP102 tới PLC",
            PLC_IP,
            "two_way_plc",
            "decoded_s7comm",
            f"({time_filter(stages['CONCEALED_STOP_ATTACK'])}) && s7comm && ip.addr == {PLC_IP}",
            "Gói S7comm được giải mã, hai chiều với PLC trong cửa sổ concealed stop.",
            "yes_pcap_wire_evidence",
        ),
        Query(
            "CONCEALED_STOP_ATTACK",
            "concealed_tcp102_to_plc_all",
            "S7comm/TCP102 tới PLC",
            PLC_IP,
            "to_plc",
            "all_tcp_102",
            f"({time_filter(stages['CONCEALED_STOP_ATTACK'])}) && ip.dst == {PLC_IP} && tcp.dstport == 102",
            "Toàn bộ TCP/102 hướng tới PLC, gồm S7comm và lưu lượng S7CommPlus-like nếu không được giải mã.",
            "yes_pcap_wire_evidence",
        ),
        Query(
            "CONCEALED_STOP_ATTACK",
            "concealed_tcp102_plc_two_way_all",
            "S7comm/TCP102 tới PLC",
            PLC_IP,
            "two_way_plc",
            "all_tcp_102",
            f"({time_filter(stages['CONCEALED_STOP_ATTACK'])}) && ip.addr == {PLC_IP} && tcp.port == 102",
            "Toàn bộ TCP/102 hai chiều với PLC, gồm S7comm và lưu lượng nền HMI/engineering.",
            "yes_pcap_wire_evidence",
        ),
    ]


def tcp_signature(row: dict[str, str], include_time: bool) -> tuple[str, ...]:
    base = (
        row.get("eth.src", ""),
        row.get("eth.dst", ""),
        row.get("ip.src", ""),
        row.get("ip.dst", ""),
        row.get("tcp.srcport", ""),
        row.get("tcp.dstport", ""),
        row.get("tcp.seq", ""),
        row.get("tcp.ack", ""),
        row.get("tcp.len", ""),
        row.get("frame.len", ""),
    )
    if include_time:
        return (row.get("frame.time_epoch", ""),) + base
    return base


def dedup_rows(rows: list[dict[str, str]]) -> tuple[list[dict[str, str]], int, int]:
    exact_seen: set[tuple[str, ...]] = set()
    exact_duplicates = 0
    near_last_time: dict[tuple[str, ...], float] = {}
    deduped: list[dict[str, str]] = []
    near_duplicates = 0
    sorted_rows = sorted(rows, key=lambda r: float(r["frame.time_epoch"] or 0.0))
    for row in sorted_rows:
        exact_key = tcp_signature(row, include_time=True)
        if exact_key in exact_seen:
            exact_duplicates += 1
        exact_seen.add(exact_key)

        near_key = tcp_signature(row, include_time=False)
        try:
            t = float(row["frame.time_epoch"])
        except Exception:
            t = math.nan
        previous = near_last_time.get(near_key)
        if previous is not None and not math.isnan(t) and (t - previous) <= 0.0015:
            near_duplicates += 1
            # Keep the first frame in the near-duplicate cluster. This collapses
            # obvious multi-interface capture duplicates while retaining later
            # retransmissions and protocol events.
            continue
        near_last_time[near_key] = t
        deduped.append(row)
    return deduped, exact_duplicates, near_duplicates


def direction(row: dict[str, str]) -> str:
    src = row.get("ip.src", "")
    dst = row.get("ip.dst", "")
    if src == EXPECTED_ATTACKER_IP and dst == PLC_IP:
        return "attacker_to_plc"
    if src == PLC_IP and dst == EXPECTED_ATTACKER_IP:
        return "plc_to_attacker"
    if src == EXPECTED_ATTACKER_IP and dst == HMI_IP:
        return "attacker_to_hmi"
    if src == HMI_IP and dst == EXPECTED_ATTACKER_IP:
        return "hmi_to_attacker"
    if dst == PLC_IP:
        return "other_to_plc"
    if src == PLC_IP:
        return "plc_to_other"
    if dst == HMI_IP:
        return "other_to_hmi"
    if src == HMI_IP:
        return "hmi_to_other"
    return "other"


def summarize_query(query: Query, pcaps: list[Path]) -> tuple[dict[str, object], list[dict[str, str]]]:
    all_rows: list[dict[str, str]] = []
    for pcap in pcaps:
        all_rows.extend(tshark_rows(pcap, query.tshark_filter))
    deduped, exact_dup, near_dup = dedup_rows(all_rows)
    times = [float(r["frame.time_epoch"]) for r in deduped if r.get("frame.time_epoch")]
    dir_counts = Counter(direction(r) for r in deduped)
    src_counts = Counter(r.get("ip.src", "") for r in deduped if r.get("ip.src", ""))
    dst_counts = Counter(r.get("ip.dst", "") for r in deduped if r.get("ip.dst", ""))
    segments = sorted({r["segment"] for r in deduped})
    summary = {
        "scenario_label": query.scenario_label,
        "evidence_id": query.evidence_id,
        "evidence_group": query.evidence_group,
        "target": query.target,
        "direction_scope": query.direction_scope,
        "protocol_scope": query.protocol_scope,
        "display_filter": query.tshark_filter,
        "raw_frame_count": len(all_rows),
        "dedup_packet_count": len(deduped),
        "near_duplicate_count": near_dup,
        "exact_duplicate_count": exact_dup,
        "first_packet_epoch": min(times) if times else "",
        "last_packet_epoch": max(times) if times else "",
        "first_packet_iso_utc": iso_utc(min(times)) if times else "",
        "last_packet_iso_utc": iso_utc(max(times)) if times else "",
        "observed_duration_s": (max(times) - min(times)) if len(times) >= 2 else 0.0,
        "direction_counts_json": json.dumps(dict(dir_counts), ensure_ascii=False, sort_keys=True),
        "top_sources_json": json.dumps(dict(src_counts.most_common(10)), ensure_ascii=False),
        "top_destinations_json": json.dumps(dict(dst_counts.most_common(10)), ensure_ascii=False),
        "segments_seen": ";".join(segments),
        "interpretation": query.interpretation,
        "independent_of_module_counter": query.independent_of_module_counter,
    }
    return summary, deduped


def write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str] | None = None) -> None:
    if not fieldnames:
        fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def parse_counters(note: str) -> dict[str, str]:
    """Parse top-level key=value pairs from timeline notes.

    Values may contain spaces, semicolons and numeric sub-keys, e.g.
    hmi_open_ports=[102=S7comm (...); 135=MSRPC ...].  Therefore the
    boundary for a new top-level counter is restricted to keys that start with
    a letter or underscore, not to every token containing "=".  The original
    end_note is kept separately in day7_stage_timeline.csv for traceability.
    """
    result: dict[str, str] = {}
    matches = list(re.finditer(r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)=", note))
    for idx, match in enumerate(matches):
        key = match.group(1)
        value_start = match.end()
        value_end = matches[idx + 1].start() if idx + 1 < len(matches) else len(note)
        result[key] = note[value_start:value_end].strip().strip(";,")
    return result


def build_stage_timeline_rows(stages: dict[str, Stage], audit_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    by_stage = defaultdict(list)
    for row in audit_rows:
        by_stage[row["scenario_label"]].append(row)
    rows = []
    for label in ["SMB_RECON_ENUM", "KILL_CHAIN", "CONCEALED_STOP_ATTACK"]:
        st = stages[label]
        highlights = []
        for row in by_stage[label]:
            if row["dedup_packet_count"]:
                highlights.append(f"{row['evidence_id']}={row['dedup_packet_count']}")
        rows.append(
            {
                "scenario_label": label,
                "start_ms": st.start_ms,
                "end_ms": st.end_ms,
                "start_epoch": f"{st.start_epoch:.3f}",
                "end_epoch": f"{st.end_epoch:.3f}",
                "start_iso_utc": st.start_iso,
                "end_iso_utc": st.end_iso,
                "duration_s": f"{st.duration_s:.3f}",
                "start_note": st.start_note,
                "end_note": st.end_note,
                "parsed_end_counters_json": json.dumps(parse_counters(st.end_note), ensure_ascii=False, sort_keys=True),
                "pcap_observable_highlights": "; ".join(highlights),
            }
        )
    return rows


def build_evidence_matrix(stages: dict[str, Stage], audit_rows: list[dict[str, object]], segment_overlap: list[dict[str, object]]) -> list[dict[str, object]]:
    by_id = {r["evidence_id"]: r for r in audit_rows}
    concealed = parse_counters(stages["CONCEALED_STOP_ATTACK"].end_note)
    readback_true = int(concealed["readback_still_true"])
    readback_false = int(concealed["readback_reverted"])
    ratio = readback_true / (readback_true + readback_false)
    overlap_count = sum(1 for r in segment_overlap if r.get("overlap_s", 0) and float(r["overlap_s"]) > 0)
    return [
        {
            "research_item": "SMB recon tới HMI",
            "timeline_or_counter": stages["SMB_RECON_ENUM"].end_note,
            "pcap_evidence": f"decoded SMB2 to HMI={by_id['smb2_hmi_dst_445_decoded']['dedup_packet_count']}; TCP/445 to HMI={by_id['tcp445_hmi_dst_all']['dedup_packet_count']}",
            "artifact_source": "day7_pcap_observability_audit.csv; labels/day7_final_timeline.csv",
            "verified_claim": "Có dấu hiệu SMB2/TCP445 tới HMI trong đúng cửa sổ SMB_RECON_ENUM.",
            "limitation": "140 probes là counter nội bộ module, không đồng nhất với số gói SMB2 giải mã được.",
        },
        {
            "research_item": "Kill-chain: pivot SYN tới HMI",
            "timeline_or_counter": stages["KILL_CHAIN"].end_note,
            "pcap_evidence": f"SYN to HMI={by_id['tcp_syn_to_hmi']['dedup_packet_count']}",
            "artifact_source": "day7_pcap_observability_audit.csv",
            "verified_claim": "Có SYN scan/pivot tới HMI trong cửa sổ KILL_CHAIN.",
            "limitation": "SYN/open-port quan sát từ PCAP không chứng minh khai thác dịch vụ hoặc lateral movement thành công ở tầng ứng dụng.",
        },
        {
            "research_item": "Kill-chain: S7comm foothold tới PLC",
            "timeline_or_counter": "script kill_chain.py mô tả đọc thông tin/DB qua S7",
            "pcap_evidence": f"S7comm to PLC={by_id['kill_s7comm_to_plc_decoded']['dedup_packet_count']}; S7comm two-way={by_id['kill_s7comm_plc_two_way_decoded']['dedup_packet_count']}",
            "artifact_source": "day7_pcap_observability_audit.csv; attacks_ext/kill_chain.py",
            "verified_claim": "Có lưu lượng S7comm với PLC trong cửa sổ KILL_CHAIN.",
            "limitation": "Không có stdout/log PLC độc lập để xác nhận nội dung DB đọc được trong lần chạy.",
        },
        {
            "research_item": "Concealed stop: burst OPC UA",
            "timeline_or_counter": f"conceal_attempts={concealed['conceal_attempts']}; conceal_ok={concealed['conceal_ok']}; conceal_failed={concealed['conceal_failed']}",
            "pcap_evidence": f"decoded OPC UA to PLC={by_id['opcua_to_plc_decoded']['dedup_packet_count']}; decoded OPC UA two-way={by_id['opcua_plc_two_way_decoded']['dedup_packet_count']}; TCP/4840 to PLC={by_id['tcp4840_to_plc_all']['dedup_packet_count']}",
            "artifact_source": "day7_pcap_observability_audit.csv; labels/day7_final_timeline.csv",
            "verified_claim": "PCAP độc lập với counter module cho thấy burst OPC UA/TCP4840 tới PLC trong cửa sổ concealed stop.",
            "limitation": "Không đồng nhất số packet/write request với số thao tác ứng dụng thành công; không chứng minh trạng thái HMI.",
        },
        {
            "research_item": "Concealed stop: S7comm STOP/START channel",
            "timeline_or_counter": f"stops={concealed['stops']}; module duration=180s; label interval={stages['CONCEALED_STOP_ATTACK'].duration_s:.3f}s",
            "pcap_evidence": f"S7comm to PLC={by_id['concealed_s7comm_to_plc_decoded']['dedup_packet_count']}; S7comm two-way={by_id['concealed_s7comm_plc_two_way_decoded']['dedup_packet_count']}; TCP/102 two-way={by_id['concealed_tcp102_plc_two_way_all']['dedup_packet_count']}",
            "artifact_source": "day7_pcap_observability_audit.csv; labels/day7_final_timeline.csv; attacks_ext/concealed_stop_attack.py",
            "verified_claim": "OPC UA burst và S7comm/TCP102 cùng hiện diện trong cùng interval concealed stop.",
            "limitation": "Không gọi 9 STOP là 9 lần PLC chắc chắn đổi trạng thái nếu chưa có process tag log/LAD/HMI log độc lập.",
        },
        {
            "research_item": "Read-back còn True",
            "timeline_or_counter": f"{readback_true}/{readback_true + readback_false}={ratio:.4f}",
            "pcap_evidence": "PCAP xác nhận lưu lượng OPC UA liên quan nhưng không chứa timestamp từng read-back mẫu.",
            "artifact_source": "labels/day7_final_timeline.csv; attacks_ext/concealed_stop_attack.py",
            "verified_claim": "Tỷ lệ 17,84% là counter của sampler nội bộ client kiểm thử.",
            "limitation": "Không diễn giải thành tỷ lệ thời gian che giấu HMI hoặc duration bất nhất.",
        },
        {
            "research_item": "Kiểm tra chồng lấn PCAP segment",
            "timeline_or_counter": "7 segment trong ZIP gốc",
            "pcap_evidence": f"segment_overlaps_with_positive_duration={overlap_count}",
            "artifact_source": "segment_overlap_audit.csv",
            "verified_claim": "Có kiểm tra thời gian segment trước khi tổng hợp.",
            "limitation": "Loại gần-trùng dựa trên tuple TCP/time là kiểm toán khung capture, không thay thế phân tích payload ứng dụng.",
        },
    ]


def write_svg_timeline(path: Path, stages: dict[str, Stage], audit_rows: list[dict[str, object]]) -> None:
    width = 1800
    height = 720
    left = 420
    right = 120
    top = 120
    row_gap = 155
    bar_h = 34
    labels = ["SMB_RECON_ENUM", "KILL_CHAIN", "CONCEALED_STOP_ATTACK"]
    min_t = min(stages[l].start_epoch for l in labels) - 4
    max_t = max(stages[l].end_epoch for l in labels) + 4
    span = max_t - min_t

    def x(epoch: float) -> float:
        return left + (epoch - min_t) / span * (width - left - right)

    counts = defaultdict(dict)
    for row in audit_rows:
        counts[row["scenario_label"]][row["evidence_id"]] = row["dedup_packet_count"]

    colors = {
        "SMB_RECON_ENUM": "#4E79A7",
        "KILL_CHAIN": "#F28E2B",
        "CONCEALED_STOP_ATTACK": "#E15759",
    }
    callouts = {
        "SMB_RECON_ENUM": f"SMB2→HMI {counts['SMB_RECON_ENUM'].get('smb2_hmi_dst_445_decoded', 0)}",
        "KILL_CHAIN": f"SYN→HMI {counts['KILL_CHAIN'].get('tcp_syn_to_hmi', 0)}; S7→PLC {counts['KILL_CHAIN'].get('kill_s7comm_to_plc_decoded', 0)}",
        "CONCEALED_STOP_ATTACK": f"OPC UA→PLC {counts['CONCEALED_STOP_ATTACK'].get('opcua_to_plc_decoded', 0)}; S7→PLC {counts['CONCEALED_STOP_ATTACK'].get('concealed_s7comm_to_plc_decoded', 0)}",
    }
    text_lines = [
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' viewBox='0 0 {width} {height}'>",
        "<rect width='100%' height='100%' fill='white'/>",
        "<style>text{font-family:Arial,Helvetica,sans-serif;} .title{font-size:28px;font-weight:700;fill:#111;} .label{font-size:21px;font-weight:700;fill:#111;} .meta{font-size:18px;fill:#222;} .tiny{font-size:16px;fill:#444;} .axis{font-size:15px;fill:#555;}</style>",
        "<text x='44' y='42' class='title'>Day 7 PCAP observability timeline</text>",
        "<text x='44' y='72' class='tiny'>Bars use actual START/END timestamps; no per-STOP timestamp is inferred.</text>",
        f"<line x1='{left}' y1='{height-110}' x2='{width-right}' y2='{height-110}' stroke='#333' stroke-width='1.5'/>",
    ]
    for idx, l in enumerate(labels):
        st = stages[l]
        sx = x(st.start_epoch)
        ex = x(st.end_epoch)
        y = top + idx * row_gap
        duration_txt = f"duration {st.duration_s:.3f}s"
        text_lines += [
            f"<text x='44' y='{y+3}' class='label'>{l}</text>",
            f"<text x='44' y='{y+31}' class='meta'>{duration_txt}</text>",
            f"<text x='44' y='{y+59}' class='tiny'>{callouts[l]}</text>",
            f"<rect x='{sx:.2f}' y='{y+5}' width='{max(2, ex-sx):.2f}' height='{bar_h}' rx='6' fill='{colors[l]}' opacity='0.86'/>",
            f"<line x1='{sx:.2f}' y1='{y-8}' x2='{sx:.2f}' y2='{height-104}' stroke='{colors[l]}' stroke-dasharray='4 6' opacity='0.55'/>",
            f"<line x1='{ex:.2f}' y1='{y-8}' x2='{ex:.2f}' y2='{height-104}' stroke='{colors[l]}' stroke-dasharray='4 6' opacity='0.55'/>",
            f"<text x='{sx:.2f}' y='{y+61}' class='axis'>START {iso_utc(st.start_epoch)[11:23]}</text>",
            f"<text x='{min(ex+8, width-right-150):.2f}' y='{y+61}' class='axis'>END {iso_utc(st.end_epoch)[11:23]}</text>",
        ]
    tick_count = 8
    for i in range(tick_count + 1):
        t = min_t + span * i / tick_count
        tx = x(t)
        text_lines += [
            f"<line x1='{tx:.2f}' y1='{height-118}' x2='{tx:.2f}' y2='{height-102}' stroke='#333'/>",
            f"<text x='{tx-34:.2f}' y='{height-78}' class='axis'>{iso_utc(t)[11:19]}</text>",
        ]
    text_lines.append(
        "<text x='44' y='680' class='tiny'>Note: packet counts are PCAP observability evidence, not application-success counts or PLC/HMI state ground truth.</text>"
    )
    text_lines.append("</svg>")
    path.write_text("\n".join(text_lines), encoding="utf-8")


def try_write_png(svg_path: Path, png_path: Path) -> str:
    """Create a report-ready raster timeline using Pillow.

    The SVG remains the canonical vector figure.  The PNG is drawn from the
    same CSV artifacts so it does not depend on optional SVG rendering tools.
    """
    try:
        from PIL import Image, ImageDraw, ImageFont  # type: ignore

        stage_csv = OUT_DIR / "day7_stage_timeline.csv"
        audit_csv = OUT_DIR / "day7_pcap_observability_audit.csv"
        if not stage_csv.exists() or not audit_csv.exists():
            return "png_not_created: required CSV artifacts not found"

        with stage_csv.open(newline="", encoding="utf-8") as f:
            stages_rows = list(csv.DictReader(f))
        with audit_csv.open(newline="", encoding="utf-8") as f:
            audit_rows = list(csv.DictReader(f))

        counts: dict[str, dict[str, int]] = defaultdict(dict)
        for row in audit_rows:
            try:
                counts[row["scenario_label"]][row["evidence_id"]] = int(row["dedup_packet_count"])
            except Exception:
                pass

        width, height = 2200, 900
        left, right, top, row_gap, bar_h = 520, 140, 155, 190, 46
        img = Image.new("RGB", (width, height), "white")
        draw = ImageDraw.Draw(img)
        try:
            font_title = ImageFont.truetype("DejaVuSans-Bold.ttf", 42)
            font_label = ImageFont.truetype("DejaVuSans-Bold.ttf", 28)
            font = ImageFont.truetype("DejaVuSans.ttf", 25)
            font_small = ImageFont.truetype("DejaVuSans.ttf", 21)
        except Exception:
            font_title = font_label = font = font_small = ImageFont.load_default()

        epochs = []
        for row in stages_rows:
            epochs += [float(row["start_epoch"]), float(row["end_epoch"])]
        min_t, max_t = min(epochs) - 4, max(epochs) + 4
        span = max_t - min_t

        def x(epoch: float) -> int:
            return int(left + (epoch - min_t) / span * (width - left - right))

        colors = {
            "SMB_RECON_ENUM": (78, 121, 167),
            "KILL_CHAIN": (242, 142, 43),
            "CONCEALED_STOP_ATTACK": (225, 87, 89),
        }
        draw.text((55, 45), "Day 7 PCAP observability timeline", fill=(17, 17, 17), font=font_title)
        draw.text((55, 96), "Bars use actual START/END timestamps; no per-STOP timestamp is inferred.", fill=(60, 60, 60), font=font_small)
        draw.line((left, height - 130, width - right, height - 130), fill=(40, 40, 40), width=2)

        for idx, row in enumerate(stages_rows):
            label = row["scenario_label"]
            sx, ex = x(float(row["start_epoch"])), x(float(row["end_epoch"]))
            y = top + idx * row_gap
            color = colors.get(label, (90, 90, 90))
            if label == "SMB_RECON_ENUM":
                callout = f"SMB2→HMI {counts[label].get('smb2_hmi_dst_445_decoded', 0)}"
            elif label == "KILL_CHAIN":
                callout = f"SYN→HMI {counts[label].get('tcp_syn_to_hmi', 0)}; S7→PLC {counts[label].get('kill_s7comm_to_plc_decoded', 0)}"
            else:
                callout = f"OPC UA→PLC {counts[label].get('opcua_to_plc_decoded', 0)}; S7→PLC {counts[label].get('concealed_s7comm_to_plc_decoded', 0)}"
            draw.text((55, y), label, fill=(17, 17, 17), font=font_label)
            draw.text((55, y + 38), f"duration {float(row['duration_s']):.3f}s", fill=(35, 35, 35), font=font)
            draw.text((55, y + 74), callout, fill=(55, 55, 55), font=font_small)
            draw.rounded_rectangle((sx, y + 8, max(sx + 3, ex), y + 8 + bar_h), radius=8, fill=color)
            for tx in (sx, ex):
                draw.line((tx, y - 14, tx, height - 124), fill=tuple(int(c * 0.72) for c in color), width=2)
            draw.text((sx, y + 70), "START " + row["start_iso_utc"][11:23], fill=(70, 70, 70), font=font_small)
            end_x = min(ex + 10, width - right - 190)
            draw.text((end_x, y + 70), "END " + row["end_iso_utc"][11:23], fill=(70, 70, 70), font=font_small)

        for i in range(9):
            t = min_t + span * i / 8
            tx = x(t)
            draw.line((tx, height - 140, tx, height - 120), fill=(40, 40, 40), width=2)
            tick = datetime.fromtimestamp(t, tz=timezone.utc).isoformat()[11:19]
            draw.text((tx - 42, height - 95), tick, fill=(70, 70, 70), font=font_small)

        note = "Packet counts are PCAP observability evidence, not application-success counts or PLC/HMI state ground truth."
        draw.text((55, height - 42), note, fill=(60, 60, 60), font=font_small)
        img.save(png_path)
        return "created_with_pillow"
    except Exception as e:
        return f"png_not_created: {type(e).__name__}: {e}"


def markdown_table(rows: list[dict[str, object]], cols: list[str]) -> str:
    out = ["| " + " | ".join(cols) + " |", "| " + " | ".join(["---"] * len(cols)) + " |"]
    for row in rows:
        values = [str(row.get(c, "")).replace("\n", " ") for c in cols]
        out.append("| " + " | ".join(values) + " |")
    return "\n".join(out)


def write_report(
    path: Path,
    stages: dict[str, Stage],
    audit_rows: list[dict[str, object]],
    stage_rows: list[dict[str, object]],
    matrix_rows: list[dict[str, object]],
    segment_rows: list[dict[str, object]],
    overlap_rows: list[dict[str, object]],
    metadata: dict[str, object],
) -> None:
    by_id = {r["evidence_id"]: r for r in audit_rows}
    concealed = parse_counters(stages["CONCEALED_STOP_ATTACK"].end_note)
    readback_true = int(concealed["readback_still_true"])
    readback_false = int(concealed["readback_reverted"])
    readback_total = readback_true + readback_false
    readback_ratio = readback_true / readback_total
    positive_overlaps = [r for r in overlap_rows if float(r.get("overlap_s", 0) or 0) > 0]

    def fmt_int(value: object) -> str:
        return f"{int(value):,}".replace(",", ".")

    report = f"""# Day 7 - Kiểm toán khả năng quan sát từ PCAP offline

Ngày tạo: {datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}

Phạm vi thao tác: chỉ đọc timeline và PCAP Day 7, giải nén PCAP vào thư mục tạm, chạy `tshark` offline, tạo artifact mới trong `experiments/day7_research/pcap_observability/`. Không sửa PCAP gốc, dataset, model, artifact cũ hoặc file DOCX; không chạy huấn luyện, không chạy kịch bản tấn công và không kết nối PLC.

## 1. Đầu vào và tính tái lập

- Timeline: `labels/day7_final_timeline.csv`
- PCAP ZIP: `data_opc/day7/ot-capture-ot1788454936.zip`
- Báo cáo quyết định đã duyệt hướng 2: `experiments/day7_research/DAY7_RESEARCH_DECISION_VI.md`
- Script tái lập: `experiments/day7_research/pcap_observability/reproduce_day7_pcap_observability.py`
- Lệnh chạy lại từ gốc repository:

```bash
python3 experiments/day7_research/pcap_observability/reproduce_day7_pcap_observability.py
```

SHA-256 đầu vào:

| File | SHA-256 |
|---|---|
| `labels/day7_final_timeline.csv` | `{metadata['sha256']['timeline']}` |
| `data_opc/day7/ot-capture-ot1788454936.zip` | `{metadata['sha256']['pcap_zip']}` |
| `experiments/day7_research/DAY7_RESEARCH_DECISION_VI.md` | `{metadata['sha256']['decision_report']}` |

## 2. Kiểm tra PCAP segment và cơ chế near-duplicate filtering

ZIP PCAP chứa {len(segment_rows)} segment. Script kiểm tra khoảng thời gian từng segment trước khi tổng hợp và ghi kết quả trong `segment_overlap_audit.csv`.

- Số cặp segment có chồng lấn thời gian dương: {len(positive_overlaps)}.
- Mỗi bộ lọc xuất đồng thời `raw_frame_count`, `dedup_packet_count`, `near_duplicate_count` và `exact_duplicate_count`.
- `dedup_packet_count` là kết quả của **heuristic near-duplicate filtering**: frame sau bị loại nếu xuất hiện trong vòng 1,5 ms và có cùng Ethernet/IP/TCP tuple, `tcp.seq`, `tcp.ack`, `tcp.len` và `frame.len` với frame ngay trước đó của cùng tuple. Mục tiêu là giảm nguy cơ đếm hai lần cùng một record khi capture nhiều interface hoặc khi file segment có record gần-trùng.
- Heuristic này **không đủ bằng chứng để khẳng định mọi frame bị loại đều là bản sao đã xác minh**. Một số frame hợp lệ, ACK lặp nhanh, hoặc TCP retransmission/header gần giống nhau có thể rơi vào tiêu chí gần-trùng. Vì vậy báo cáo giữ cả raw và dedup, đặc biệt với TCP/102 trong `CONCEALED_STOP_ATTACK`: raw `{fmt_int(by_id['concealed_tcp102_plc_two_way_all']['raw_frame_count'])}` frame hai chiều, sau heuristic còn `{fmt_int(by_id['concealed_tcp102_plc_two_way_all']['dedup_packet_count'])}` frame, `near_duplicate_count={fmt_int(by_id['concealed_tcp102_plc_two_way_all']['near_duplicate_count'])}`.
- Các số decoded S7comm chính không bị ảnh hưởng bởi heuristic trong đợt này: S7comm concealed hướng tới PLC raw/dedup đều `{by_id['concealed_s7comm_to_plc_decoded']['dedup_packet_count']}`, hai chiều raw/dedup đều `{by_id['concealed_s7comm_plc_two_way_decoded']['dedup_packet_count']}`.

## 3. Timeline ba giai đoạn

{markdown_table(stage_rows, ['scenario_label', 'start_iso_utc', 'end_iso_utc', 'duration_s', 'pcap_observable_highlights'])}

Hình đề xuất cho báo cáo/slide:

![Day 7 PCAP observability timeline](day7_three_stage_timeline.svg)

Hình này chỉ đặt ba thanh theo timestamp START/END thực tế trong timeline. Không nội suy vị trí từng STOP vì artifact hiện không có timestamp từng STOP.

## 4. Kết quả kiểm toán PCAP theo từng giai đoạn

{markdown_table(audit_rows, ['scenario_label', 'evidence_id', 'protocol_scope', 'direction_scope', 'raw_frame_count', 'dedup_packet_count', 'near_duplicate_count', 'first_packet_iso_utc', 'last_packet_iso_utc', 'observed_duration_s'])}

Diễn giải thận trọng:

- `SMB_RECON_ENUM`: PCAP xác nhận lưu lượng SMB2/TCP445 tới HMI trong cửa sổ recon. Counter `probes=140` là số nội bộ của module; không đồng nhất với số packet SMB2 giải mã được.
- `KILL_CHAIN`: PCAP xác nhận SYN tới HMI và S7comm/TCP102 với PLC trong cửa sổ kill-chain. Đây là bằng chứng quan sát trên dây, không phải bằng chứng khai thác dịch vụ HMI thành công.
- `CONCEALED_STOP_ATTACK`: PCAP xác nhận burst OPC UA/TCP4840 và lưu lượng S7comm/TCP102 cùng hiện diện trong interval concealed stop. Điều này hỗ trợ narrative “kênh OPC UA ghi/đọc và kênh S7 STOP/START cùng hoạt động”, nhưng không chứng minh độc lập trạng thái vật lý PLC hoặc màn hình HMI.

## 5. Truy vết counter và giới hạn diễn giải

Từ timeline:

- SMB recon: `probes=140`.
- Concealed stop: `stops={concealed['stops']}`, `conceal_attempts={concealed['conceal_attempts']}`, `conceal_ok={concealed['conceal_ok']}`, `conceal_failed={concealed['conceal_failed']}`.
- Read-back: `{readback_true}/{readback_total} = {readback_ratio:.4%}` mẫu sampler nội bộ đọc lại `BangTai=True`.
- Tham số module: `dur=180s`; khoảng START-END timeline: `{stages['CONCEALED_STOP_ATTACK'].duration_s:.3f}s`.

Phân biệt bằng chứng:

| Đại lượng | Nguồn | Có thể kết luận | Không được kết luận |
|---|---|---|---|
| `probes=140` | counter module SMB | Module đã thực hiện 140 probe theo logic script | Có đúng 140 gói SMB2 trên dây |
| `stops=9` | counter module concealed stop | Script đã đi qua 9 chu kỳ ghi STOP theo logic của nó | PLC chắc chắn đổi trạng thái vật lý 9 lần nếu thiếu process log |
| `conceal_attempts=13604`, `conceal_ok=13604` | counter API client | Client gửi nhiều write và API không báo exception | 13.604 thay đổi trạng thái PLC/HMI thành công |
| `{readback_true}/{readback_total}` read-back True | sampler nội bộ client | Tại một phần mẫu đọc lại, client thấy `BangTai=True` | Tỷ lệ thời gian HMI bị che giấu hoặc tỷ lệ thành công độc lập |
| OPC UA/S7comm trong PCAP | capture mạng | Có lưu lượng tương ứng trên dây trong interval | Hành vi tấn công đã thành công ở tầng tiến trình |

## 6. Trả lời câu hỏi nghiên cứu

### A. Chuỗi hành vi nhiều giai đoạn có những dấu hiệu nào quan sát được từ PCAP?

Có. PCAP quan sát được ba nhóm dấu hiệu đúng theo timeline: SMB2/TCP445 tới HMI trong `SMB_RECON_ENUM`; SYN tới HMI và S7comm với PLC trong `KILL_CHAIN`; burst OPC UA/TCP4840 cùng S7comm/TCP102 với PLC trong `CONCEALED_STOP_ATTACK`.

### B. Bằng chứng nào độc lập với counter của module?

Các số trong `day7_pcap_observability_audit.csv` là bằng chứng mạng trích xuất lại từ PCAP, độc lập với counter nội bộ module. Cụ thể: số packet SMB2/SYN/S7comm/OPC UA, timestamp gói đầu/cuối và chiều truyền. Tuy nhiên PCAP vẫn là capture của cùng đợt kiểm thử, không phải một nguồn thu thập hoàn toàn độc lập về trạng thái tiến trình.

### C. Có thể liên hệ điều gì giữa lưu lượng OPC UA và S7comm trong cùng khoảng kiểm thử?

Trong interval `CONCEALED_STOP_ATTACK`, PCAP cho thấy đồng thời có OPC UA/TCP4840 tới PLC và S7comm/TCP102 tới PLC. Điều này phù hợp với thiết kế script: một kênh OPC UA ghi/đọc `BangTai`, trong khi kênh S7 điều khiển START/STOP. Liên hệ này là quan sát đồng thời trên mạng, không phải chứng minh trực tiếp rằng mỗi write OPC UA tương ứng với một thay đổi trạng thái PLC.

### D. Những kết luận nào chưa thể đưa ra?

Chưa thể kết luận trạng thái vật lý PLC, trạng thái hiển thị HMI theo thời gian, duration bất nhất, latency phát hiện hoặc precision/recall của một cơ chế phát hiện bất nhất. Lý do là repo hiện thiếu process tag log Day 7, log HMI/WinCC có timestamp, export LAD/TIA Portal hoặc timestamp từng STOP/read-back.

### E. Case-study đã đủ điều kiện tích hợp vào đồ án chưa?

Có, ở mức **case-study quan sát đa giai đoạn dựa trên PCAP**, đi kèm giới hạn rõ ràng. Không nên trình bày như thực nghiệm đánh giá phát hiện bất nhất hoặc IDS có precision/recall, vì chưa có ground truth process/HMI tương ứng.

## 7. Nội dung bổ sung đề xuất cho mục 3.11

**Case-study Day 7: quan sát chuỗi hành vi tấn công nhiều giai đoạn từ PCAP.** Day 7 được sử dụng như một case-study bổ sung cho testbed, nhằm kiểm tra khả năng ghi nhận một chuỗi hành vi gồm do thám HMI, pivot/foothold qua S7 và thao tác che giấu trạng thái qua OPC UA. Timeline gồm ba interval: `SMB_RECON_ENUM`, `KILL_CHAIN` và `CONCEALED_STOP_ATTACK`. Khác với nhánh Day 8 dùng cho đánh giá IDS theo cửa sổ, Day 7 không được trộn vào tập huấn luyện/đánh giá mô hình mà được phân tích như bằng chứng vận hành và quan sát mạng. Nguồn dữ liệu chính gồm timeline nhãn, PCAP nhiều segment và mã nguồn sinh kịch bản. Các counter của module được dùng để giải thích ý nghĩa thao tác, trong khi PCAP được dùng để xác nhận độc lập sự hiện diện của lưu lượng SMB2, SYN, S7comm và OPC UA trên dây. Phạm vi kết luận được giới hạn ở khả năng quan sát mạng; đồ án không suy diễn packet count thành số thao tác ứng dụng thành công hay trạng thái vật lý của PLC/HMI.

## 8. Nội dung bổ sung đề xuất cho mục 5.9.6

**Kết quả kiểm toán PCAP Day 7.** Kiểm toán offline trên PCAP Day 7 xác nhận chuỗi ba giai đoạn có dấu hiệu quan sát được trên mạng. Trong cửa sổ `SMB_RECON_ENUM`, PCAP ghi nhận lưu lượng SMB2/TCP445 tới HMI, trong khi counter nội bộ module ghi `probes=140`. Trong cửa sổ `KILL_CHAIN`, PCAP ghi nhận SYN tới HMI và lưu lượng S7comm với PLC, phù hợp với mô tả pivot/foothold nhưng không chứng minh khai thác dịch vụ HMI. Trong cửa sổ `CONCEALED_STOP_ATTACK`, timeline ghi `stops=9`, `conceal_attempts=13604`, `conceal_ok=13604`, `conceal_failed=0` và `{readback_true}/{readback_total}` mẫu read-back còn `BangTai=True`; PCAP đồng thời ghi nhận burst OPC UA/TCP4840 và S7comm/TCP102 với PLC. Kết quả này đủ để tích hợp Day 7 như một case-study quan sát đa giao thức, nhưng chưa đủ để tính precision/recall cho phát hiện bất nhất vì thiếu process log, LAD export và HMI log có timestamp.

## 9. Bảng/hình nên đưa vào Word

Để tránh làm đồ án dài, chỉ nên thêm:

1. Một bảng bằng chứng chính lấy từ `day7_evidence_matrix.csv`, rút gọn còn các dòng: SMB recon, kill-chain SYN/S7comm, concealed stop OPC UA/S7comm, counter/read-back và giới hạn.
2. Một hình timeline mới: `day7_three_stage_timeline.svg` hoặc bản PNG nếu cần cho Word/slide.

## 10. Đối chiếu với số liệu hiện có trong DOCX

Đã trích xuất `bao-cao/Thao_Tu_OTSecurity_vf.docx` ở chế độ đọc-only để tìm các đoạn Day 7 hiện có. Các mốc P dưới đây là thứ tự paragraph khi đọc `word/document.xml`, dùng để định vị lúc biên tập thủ công; chúng không phải số trang Word chính thức.

| Vị trí DOCX hiện có | Nội dung hiện có | Kết quả kiểm toán PCAP mới | Khuyến nghị sửa |
|---|---|---|---|
| P1278-P1284, mục 3.11 và 3.11.1 | Giới thiệu Day 7 là case-study, giữ ba kịch bản `SMB_RECON_ENUM`, `KILL_CHAIN`, `CONCEALED_STOP_ATTACK`. | Phù hợp với artifact mới. | Giữ mạch hiện tại; bổ sung 1 câu rằng case-study đã được kiểm toán lại bằng PCAP offline tại `experiments/day7_research/pcap_observability/`. |
| P1286, mục 3.11.2 | `9` STOP, `13.604` write, `183/1.026 = 17,8%` read-back còn True. | Đây là counter/module, không phải số packet. Kiểm toán PCAP không thay thế các counter này. | Giữ số cũ; có thể viết `17,84%` nếu muốn nhất quán phép tính. Nhấn mạnh đây là tỷ lệ mẫu read-back của client, không phải tỷ lệ thời gian che giấu HMI. |
| Bảng 3.17, P1288-P1306 | Bảng counter của `CONCEALED_STOP_ATTACK`. | Artifact mới bổ sung bằng chứng PCAP, nhưng không biến counter thành ground truth PLC/HMI. | Có thể giữ Bảng 3.17 là bảng counter; nếu thêm bảng mới thì chỉ thêm một bảng bằng chứng rút gọn từ `day7_evidence_matrix.csv`, tránh lặp toàn bộ CSV. |
| P1307 | “16.680 gói OPC UA hướng tới PLC và 162 gói S7comm…” | Decoded OPC UA hướng tới PLC = `{fmt_int(by_id['opcua_to_plc_decoded']['dedup_packet_count'])}`; decoded OPC UA hai chiều = `{fmt_int(by_id['opcua_plc_two_way_decoded']['dedup_packet_count'])}`. S7comm hướng tới PLC = `{by_id['concealed_s7comm_to_plc_decoded']['dedup_packet_count']}`; S7comm hai chiều = `{by_id['concealed_s7comm_plc_two_way_decoded']['dedup_packet_count']}`. | Sửa `16.680` thành `{fmt_int(by_id['opcua_to_plc_decoded']['dedup_packet_count'])}` nếu muốn khớp artifact mới; giữ `162` nếu chú thích rõ là S7comm hướng tới PLC. Tránh gọi TCP/102 nền là TLS/S7CommPlus nếu chưa có artifact giải mã chắc chắn. |
| P1308-P1314 | Đã phân biệt read-back với thời lượng HMI và nêu giới hạn cấu hình. | Phù hợp với kết luận mới. | Giữ; có thể thêm “PCAP chỉ xác nhận lưu lượng trên dây, không xác nhận trạng thái vật lý/HMI”. |
| P1315-P1318 | Giới hạn Ngày 7 và kết quả âm. | Phù hợp. | Giữ nguyên; không bổ sung precision/recall hoặc claim phát hiện bất nhất. |
| P2114-P2117, mục 5.9.6 | Liên hệ Day 7 với kết quả OPC UA, hiện chủ yếu dựa trên counter read-back. | Có thêm bằng chứng PCAP độc lập với counter: SMB2→HMI `{by_id['smb2_hmi_dst_445_decoded']['dedup_packet_count']}`, SYN→HMI `{by_id['tcp_syn_to_hmi']['dedup_packet_count']}`, OPC UA→PLC `{by_id['opcua_to_plc_decoded']['dedup_packet_count']}`, S7comm→PLC `{by_id['concealed_s7comm_to_plc_decoded']['dedup_packet_count']}`. | Bổ sung một đoạn ngắn sau P2115 hoặc P2116: “kiểm toán PCAP offline xác nhận chuỗi observability nhiều giai đoạn…”. Không đưa Day 7 vào bảng hiệu năng học máy. |

Các số liệu nên dùng khi tích hợp:

| Nội dung | Số/tuyên bố cũ thường gặp | Kết quả kiểm toán mới | Cách viết an toàn |
|---|---:|---:|---|
| SMB2 tới HMI | 65 gói SMB2 | `{fmt_int(by_id['smb2_hmi_dst_445_decoded']['dedup_packet_count'])}` decoded SMB2 tới HMI; TCP/445 tới HMI dedup `{fmt_int(by_id['tcp445_hmi_dst_all']['dedup_packet_count'])}` | “65 gói SMB2 giải mã được tới HMI; 436 frame TCP/445 tới HMI sau lọc gần-trùng”. |
| SYN tới HMI | 15 SYN | `{fmt_int(by_id['tcp_syn_to_hmi']['dedup_packet_count'])}` SYN | “15 SYN tới HMI”, không gọi là khai thác thành công. |
| S7comm kill-chain | 5 hoặc 10 gói tùy cách đếm | to-PLC `{by_id['kill_s7comm_to_plc_decoded']['dedup_packet_count']}`; two-way `{by_id['kill_s7comm_plc_two_way_decoded']['dedup_packet_count']}` | Ghi rõ “5 gói S7comm hướng tới PLC” hoặc “10 gói S7comm hai chiều”. |
| OPC UA concealed | khoảng 16.680 gói | to-PLC decoded `{fmt_int(by_id['opcua_to_plc_decoded']['dedup_packet_count'])}`; two-way decoded `{fmt_int(by_id['opcua_plc_two_way_decoded']['dedup_packet_count'])}` | Dùng `{fmt_int(by_id['opcua_to_plc_decoded']['dedup_packet_count'])}` nếu theo artifact mới; nêu đây là decoded OPC UA hướng tới PLC. |
| S7comm concealed | 162 gói | to-PLC `{by_id['concealed_s7comm_to_plc_decoded']['dedup_packet_count']}`; two-way `{by_id['concealed_s7comm_plc_two_way_decoded']['dedup_packet_count']}` | Giữ `162` nếu định nghĩa là hướng tới PLC; nếu hai chiều thì dùng `{by_id['concealed_s7comm_plc_two_way_decoded']['dedup_packet_count']}`. |
| TCP/102 nền/S7CommPlus-like | 3.702 TLS/S7CommPlus | TCP/102 two-way concealed raw `{fmt_int(by_id['concealed_tcp102_plc_two_way_all']['raw_frame_count'])}`, sau heuristic `{fmt_int(by_id['concealed_tcp102_plc_two_way_all']['dedup_packet_count'])}` | Viết “TCP/102 two-way” hoặc “lưu lượng nền TCP/102”; không gọi là TLS/S7CommPlus nếu chưa có artifact giải mã. |
| Read-back 17,8% | 183/1.026 | `{readback_true}/{readback_total}={readback_ratio:.2%}` | “tỷ lệ mẫu read-back của client”, không phải tỷ lệ thời gian che giấu HMI. |

## 11. Artifact đầu ra

- `day7_pcap_observability_audit.csv`: số đếm theo bộ lọc PCAP, timestamp gói đầu/cuối, chiều truyền và số gần-trùng đã loại.
- `day7_stage_timeline.csv`: timeline START/END ba giai đoạn và counter.
- `day7_evidence_matrix.csv`: bảng đối chiếu câu hỏi nghiên cứu - timeline/counter - PCAP - giới hạn.
- `segment_overlap_audit.csv`: kiểm tra khoảng thời gian các PCAP segment.
- `day7_three_stage_timeline.svg`: hình timeline ba giai đoạn dựa trên timestamp thực.
- `day7_three_stage_timeline.png`: bản raster nếu môi trường tạo được.
- `day7_pcap_observability_metadata.json`: hash đầu vào, lệnh chạy và metadata môi trường.
- `DAY7_PCAP_OBSERVABILITY_REPORT.md`: báo cáo này.
"""
    path.write_text(report, encoding="utf-8")


def main() -> int:
    for path in [TIMELINE, PCAP_ZIP, DECISION_REPORT]:
        require_file(path)
    if not shutil.which("tshark"):
        raise RuntimeError("tshark is required but was not found on PATH")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    stages = parse_timeline(TIMELINE)
    expected = {"SMB_RECON_ENUM", "KILL_CHAIN", "CONCEALED_STOP_ATTACK"}
    if set(stages) & expected != expected:
        raise RuntimeError(f"Timeline missing expected stages: {expected - set(stages)}")

    metadata: dict[str, object] = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "repo_root": str(ROOT),
        "inputs": {
            "timeline": str(TIMELINE.relative_to(ROOT)),
            "pcap_zip": str(PCAP_ZIP.relative_to(ROOT)),
            "decision_report": str(DECISION_REPORT.relative_to(ROOT)),
        },
        "sha256": {
            "timeline": sha256_file(TIMELINE),
            "pcap_zip": sha256_file(PCAP_ZIP),
            "decision_report": sha256_file(DECISION_REPORT),
            "script": sha256_file(Path(__file__)),
        },
        "tool_versions": {
            "python": sys.version.split()[0],
            "tshark": run_cmd(["tshark", "--version"]).splitlines()[0],
        },
        "ip_context": {
            "plc_ip": PLC_IP,
            "hmi_ip": HMI_IP,
            "expected_attacker_ip": EXPECTED_ATTACKER_IP,
            "attacker_ip_basis": "inferred/validated from dominant Day 7 PCAP client flows; not used as a label source",
        },
        "dedup_policy": {
            "raw_frame_count": "all frames matching tshark display filter",
            "dedup_packet_count": "raw frames minus near duplicates within 1.5 ms sharing Ethernet/IP/TCP tuple, seq/ack, tcp.len and frame.len",
            "reason": "avoid double counting obvious multi-interface/segment duplicate captures while retaining raw counts for traceability",
        },
        "command": "python3 experiments/day7_research/pcap_observability/reproduce_day7_pcap_observability.py",
    }

    with tempfile.TemporaryDirectory(prefix="day7_pcap_audit.") as tmp:
        pcaps = extract_pcaps(PCAP_ZIP, Path(tmp))
        if not pcaps:
            raise RuntimeError("No PCAP files found inside ZIP")
        metadata["pcap_segments"] = [p.name for p in pcaps]
        segment_rows = [pcap_segment_stats(p) for p in pcaps]
        segment_rows_sorted = sorted(segment_rows, key=lambda r: float(r["first_epoch"] or 0.0))
        overlap_rows: list[dict[str, object]] = []
        for prev, cur in zip(segment_rows_sorted, segment_rows_sorted[1:]):
            prev_end = float(prev["last_epoch"] or 0.0)
            cur_start = float(cur["first_epoch"] or 0.0)
            overlap_s = max(0.0, prev_end - cur_start)
            gap_s = max(0.0, cur_start - prev_end)
            overlap_rows.append(
                {
                    "previous_segment": prev["segment"],
                    "current_segment": cur["segment"],
                    "previous_last_epoch": prev["last_epoch"],
                    "current_first_epoch": cur["first_epoch"],
                    "previous_last_iso_utc": prev["last_iso_utc"],
                    "current_first_iso_utc": cur["first_iso_utc"],
                    "overlap_s": f"{overlap_s:.6f}",
                    "gap_s": f"{gap_s:.6f}",
                }
            )

        queries = build_queries(stages)
        audit_rows: list[dict[str, object]] = []
        for query in queries:
            summary, _deduped = summarize_query(query, pcaps)
            audit_rows.append(summary)

    stage_rows = build_stage_timeline_rows(stages, audit_rows)
    matrix_rows = build_evidence_matrix(stages, audit_rows, overlap_rows)

    write_csv(OUT_DIR / "day7_pcap_observability_audit.csv", audit_rows)
    write_csv(OUT_DIR / "day7_stage_timeline.csv", stage_rows)
    write_csv(OUT_DIR / "day7_evidence_matrix.csv", matrix_rows)
    write_csv(OUT_DIR / "pcap_segment_summary.csv", segment_rows)
    write_csv(OUT_DIR / "segment_overlap_audit.csv", overlap_rows)

    svg_path = OUT_DIR / "day7_three_stage_timeline.svg"
    png_path = OUT_DIR / "day7_three_stage_timeline.png"
    write_svg_timeline(svg_path, stages, audit_rows)
    metadata["figure_outputs"] = {
        "svg": str(svg_path.relative_to(ROOT)),
        "png": str(png_path.relative_to(ROOT)),
        "png_status": try_write_png(svg_path, png_path),
    }

    (OUT_DIR / "day7_pcap_observability_metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    write_report(
        OUT_DIR / "DAY7_PCAP_OBSERVABILITY_REPORT.md",
        stages,
        audit_rows,
        stage_rows,
        matrix_rows,
        segment_rows,
        overlap_rows,
        metadata,
    )
    print(f"Wrote Day 7 PCAP observability artifacts to {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
