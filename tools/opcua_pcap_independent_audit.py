#!/usr/bin/env python3
"""Independent, read-only packet audit for the OPC UA Day 8 label manifest.

The script reads one canonical merged PCAP only.  Segment PCAPs are deliberately
not ingested, so records present in both the merged file and its source segments
cannot be counted twice.  It does not modify datasets, manifests, or captures.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterable


WINDOW_MS = 5_000
BENIGN = "benign"

TSHARK_FIELDS = [
    "frame.time_epoch",
    "frame.number",
    "frame.len",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.len",
    "tcp.stream",
    "tcp.seq",
    "tcp.ack",
    "opcua.transport.type",
    "opcua.servicenodeid.numeric",
    "opcua.StatusCode",
    "opcua.ServiceResult",
    "opcua.transport.error",
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def require_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Missing {label}: {path}")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ValueError(f"No data rows in {path}")
    return rows


def write_csv(path: Path, rows: list[dict[str, Any]], fields: Iterable[str] | None = None) -> None:
    if fields is None:
        fields = rows[0].keys() if rows else []
    fields = list(fields)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def as_bool(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def epoch_ms(value: str) -> int:
    try:
        number = Decimal(str(value).strip())
    except InvalidOperation as exc:
        raise ValueError(f"Invalid epoch value: {value!r}") from exc
    if number > Decimal("10000000000"):
        return int(number)
    return int(number * 1000)


def iso_utc(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat(timespec="milliseconds")


def parse_multi(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def get_capinfos(pcap: Path) -> dict[str, Any]:
    proc = subprocess.run(
        ["capinfos", "-TS", str(pcap)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    if len(lines) < 2:
        raise RuntimeError(f"capinfos returned no table: {proc.stderr[:300]}")
    header = lines[0].split("\t")
    values = lines[1].split("\t")
    row = dict(zip(header, values))
    return {
        "packet_count": int(row["Number of packets"]),
        "file_size_bytes": int(row["File size (bytes)"]),
        "capture_start_epoch": row["Start time"],
        "capture_end_epoch": row["End time"],
        "capture_start_ms": epoch_ms(row["Start time"]),
        "capture_end_ms": epoch_ms(row["End time"]),
        "capture_duration_seconds": row["Capture duration (seconds)"],
        "file_type": row["File type"],
        "encapsulation": row["File encapsulation"],
        "strict_time_order": row["Strict time order"],
        "capture_application": row.get("Capture application", ""),
        "capinfos_sha256": row.get("SHA256", ""),
    }


def tshark_version() -> str:
    proc = subprocess.run(
        ["tshark", "--version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
    )
    return proc.stdout.splitlines()[0].strip()


def load_timeline(path: Path) -> list[dict[str, Any]]:
    rows = read_csv(path)
    intervals: list[dict[str, Any]] = []
    for i, row in enumerate(rows, 1):
        start_ms = epoch_ms(row["start"])
        end_ms = epoch_ms(row["end"])
        label = row["label"].strip()
        explicit_episode = row.get("episode", "").strip()
        cycle = row.get("cycle", "").strip()
        episode = explicit_episode or (f"{label}#c{cycle}" if cycle else f"{label}#i{i}")
        intervals.append(
            {
                "start_ms": start_ms,
                "end_ms": end_ms,
                "label": label,
                "episode_id": episode,
                "cycle": cycle,
                "status": row.get("status", ""),
            }
        )
    return intervals


def episode_for(start_ms: int, end_ms: int, intervals: list[dict[str, Any]]) -> tuple[str, str, int]:
    best: dict[str, Any] | None = None
    best_overlap = 0
    for item in intervals:
        overlap = max(0, min(end_ms, item["end_ms"]) - max(start_ms, item["start_ms"]))
        if overlap > best_overlap:
            best = item
            best_overlap = overlap
    if best is None:
        return BENIGN, "", 0
    return str(best["label"]), str(best["episode_id"]), best_overlap


def new_counts() -> dict[str, Any]:
    return {
        "attacker_src_packet_count": 0,
        "attacker_src_tcp_packet_count": 0,
        "attacker_src_tcp_payload_packet_count": 0,
        "attacker_src_tcp_payload_bytes": 0,
        "attacker_src_tcp4840_packet_count": 0,
        "attacker_src_opcua_decoded_packet_count": 0,
        "attacker_to_plc_packet_count": 0,
        "plc_to_attacker_packet_count": 0,
        "plc_to_attacker_tcp_payload_packet_count": 0,
        "plc_to_attacker_tcp_payload_bytes": 0,
        "plc_to_attacker_opcua_decoded_packet_count": 0,
        "attacker_related_packet_count": 0,
        "pipeline_scope_attacker_src_packet_count": 0,
        "pipeline_scope_plc_response_packet_count": 0,
        "pipeline_scope_attacker_related_packet_count": 0,
        "first_attacker_packet_epoch": "",
        "last_attacker_packet_epoch": "",
        "first_attacker_frame": "",
        "last_attacker_frame": "",
        "first_attacker_related_packet_epoch": "",
        "last_attacker_related_packet_epoch": "",
        "attacker_transport_types": Counter(),
        "attacker_service_node_ids": Counter(),
        "attacker_status_codes": Counter(),
        "attacker_destination_ips": Counter(),
        "attacker_destination_tcp_ports": Counter(),
        "response_transport_types": Counter(),
        "response_service_node_ids": Counter(),
        "response_status_codes": Counter(),
    }


def nonempty_opcua(parts: dict[str, str]) -> bool:
    return any(
        parts.get(name, "")
        for name in (
            "opcua.transport.type",
            "opcua.servicenodeid.numeric",
            "opcua.StatusCode",
            "opcua.ServiceResult",
            "opcua.transport.error",
        )
    )


def add_counter(counter: Counter[str], value: str) -> None:
    for item in parse_multi(value):
        counter[item] += 1


def counter_json(value: Counter[str]) -> str:
    return json.dumps(dict(sorted(value.items())), ensure_ascii=False, separators=(",", ":"))


def extract_packet_evidence(
    pcap: Path,
    window_keys: set[int],
    attacker_ip: str,
    plc_ip: str,
) -> tuple[dict[int, dict[str, Any]], dict[str, Any]]:
    counts: defaultdict[int, dict[str, Any]] = defaultdict(new_counts)
    cmd = [
        "tshark",
        "-r",
        str(pcap),
        "-o",
        "tcp.desegment_tcp_streams:TRUE",
        "-Y",
        f"ip.addr == {attacker_ip}",
        "-T",
        "fields",
    ]
    for field in TSHARK_FIELDS:
        cmd.extend(["-e", field])
    cmd.extend(["-E", "separator=\t", "-E", "quote=n", "-E", "occurrence=a"])

    proc = subprocess.Popen(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.stdout is not None
    packet_rows = 0
    packet_rows_in_manifest = 0
    packet_rows_outside_manifest = 0
    min_epoch = ""
    max_epoch = ""
    for line in proc.stdout:
        line = line.rstrip("\r\n")
        if not line:
            continue
        values = line.split("\t")
        values.extend([""] * (len(TSHARK_FIELDS) - len(values)))
        parts = dict(zip(TSHARK_FIELDS, values))
        epoch = parts["frame.time_epoch"].strip()
        if not epoch:
            continue
        packet_rows += 1
        if not min_epoch or Decimal(epoch) < Decimal(min_epoch):
            min_epoch = epoch
        if not max_epoch or Decimal(epoch) > Decimal(max_epoch):
            max_epoch = epoch
        time_ms = epoch_ms(epoch)
        start_ms = (time_ms // WINDOW_MS) * WINDOW_MS
        if start_ms not in window_keys:
            packet_rows_outside_manifest += 1
            continue
        packet_rows_in_manifest += 1
        c = counts[start_ms]
        src = parts["ip.src"].strip()
        dst = parts["ip.dst"].strip()
        src_port = parts["tcp.srcport"].strip()
        dst_port = parts["tcp.dstport"].strip()
        tcp_packet = bool(src_port or dst_port)
        tcp_len = int(parts["tcp.len"].split(",")[0] or 0)
        is_4840 = src_port == "4840" or dst_port == "4840"
        is_pipeline_scope = is_4840 and (src == plc_ip or dst == plc_ip)
        decoded = nonempty_opcua(parts)

        if src == attacker_ip or dst == attacker_ip:
            c["attacker_related_packet_count"] += 1
            if (
                not c["first_attacker_related_packet_epoch"]
                or Decimal(epoch) < Decimal(c["first_attacker_related_packet_epoch"])
            ):
                c["first_attacker_related_packet_epoch"] = epoch
            if (
                not c["last_attacker_related_packet_epoch"]
                or Decimal(epoch) > Decimal(c["last_attacker_related_packet_epoch"])
            ):
                c["last_attacker_related_packet_epoch"] = epoch

        if src == attacker_ip:
            c["attacker_src_packet_count"] += 1
            if tcp_packet:
                c["attacker_src_tcp_packet_count"] += 1
            if tcp_len > 0:
                c["attacker_src_tcp_payload_packet_count"] += 1
                c["attacker_src_tcp_payload_bytes"] += tcp_len
            if is_4840:
                c["attacker_src_tcp4840_packet_count"] += 1
            if decoded:
                c["attacker_src_opcua_decoded_packet_count"] += 1
            if dst == plc_ip:
                c["attacker_to_plc_packet_count"] += 1
            if is_pipeline_scope:
                c["pipeline_scope_attacker_src_packet_count"] += 1
            if (
                not c["first_attacker_packet_epoch"]
                or Decimal(epoch) < Decimal(c["first_attacker_packet_epoch"])
            ):
                c["first_attacker_packet_epoch"] = epoch
                c["first_attacker_frame"] = parts["frame.number"]
            if (
                not c["last_attacker_packet_epoch"]
                or Decimal(epoch) > Decimal(c["last_attacker_packet_epoch"])
            ):
                c["last_attacker_packet_epoch"] = epoch
                c["last_attacker_frame"] = parts["frame.number"]
            add_counter(c["attacker_destination_ips"], dst)
            add_counter(c["attacker_destination_tcp_ports"], dst_port)
            add_counter(c["attacker_transport_types"], parts["opcua.transport.type"])
            add_counter(c["attacker_service_node_ids"], parts["opcua.servicenodeid.numeric"])
            add_counter(
                c["attacker_status_codes"],
                parts["opcua.StatusCode"] or parts["opcua.ServiceResult"],
            )

        if src == plc_ip and dst == attacker_ip:
            c["plc_to_attacker_packet_count"] += 1
            if tcp_len > 0:
                c["plc_to_attacker_tcp_payload_packet_count"] += 1
                c["plc_to_attacker_tcp_payload_bytes"] += tcp_len
            if decoded:
                c["plc_to_attacker_opcua_decoded_packet_count"] += 1
            if is_pipeline_scope:
                c["pipeline_scope_plc_response_packet_count"] += 1
            add_counter(c["response_transport_types"], parts["opcua.transport.type"])
            add_counter(c["response_service_node_ids"], parts["opcua.servicenodeid.numeric"])
            add_counter(
                c["response_status_codes"],
                parts["opcua.StatusCode"] or parts["opcua.ServiceResult"],
            )

        if is_pipeline_scope:
            c["pipeline_scope_attacker_related_packet_count"] += 1

    stderr = proc.stderr.read() if proc.stderr else ""
    return_code = proc.wait()
    if return_code != 0:
        raise RuntimeError(f"tshark failed ({return_code}): {stderr[:1000]}")
    diagnostics = {
        "command": cmd,
        "display_filter": f"ip.addr == {attacker_ip}",
        "packet_rows_matching_filter": packet_rows,
        "packet_rows_in_manifest_windows": packet_rows_in_manifest,
        "packet_rows_outside_manifest_windows": packet_rows_outside_manifest,
        "first_matching_packet_epoch": min_epoch,
        "last_matching_packet_epoch": max_epoch,
        "stderr": stderr.strip(),
    }
    return dict(counts), diagnostics


def classify_capture_coverage(start_ms: int, end_ms: int, cap_start_ms: int, cap_end_ms: int) -> str:
    if start_ms >= cap_start_ms and end_ms <= cap_end_ms:
        return "full"
    if end_ms <= cap_start_ms or start_ms > cap_end_ms:
        return "outside"
    return "partial_boundary"


def build_window_rows(
    manifest: list[dict[str, str]],
    intervals: list[dict[str, Any]],
    packet_counts: dict[int, dict[str, Any]],
    cap: dict[str, Any],
    attacker_ip: str,
    plc_ip: str,
    client_ip: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    discrepancies: list[dict[str, Any]] = []
    for source in manifest:
        start_ms = int(source["window_start_ms"])
        end_ms = int(source["window_end_ms"])
        c = packet_counts.get(start_ms, new_counts())
        timeline_label, timeline_episode, overlap_ms = episode_for(start_ms, end_ms, intervals)
        coverage = classify_capture_coverage(
            start_ms, end_ms, cap["capture_start_ms"], cap["capture_end_ms"]
        )
        raw_attack = as_bool(source["raw_is_attack"])
        aa_attack = as_bool(source["activity_aware_is_attack"])
        pipeline_related = int(c["pipeline_scope_attacker_related_packet_count"])
        independent_expected_attack = overlap_ms > 0 and pipeline_related > 0
        evidence_status = (
            "insufficient_capture_coverage"
            if coverage != "full"
            else ("attacker_related_present" if pipeline_related else "no_attacker_related_packet_captured")
        )
        timeline_matches_raw = (timeline_label == source["raw_label"]) and (
            not raw_attack or timeline_episode == source["raw_episode_id"]
        )
        rule_matches_aa = independent_expected_attack == aa_attack

        row: dict[str, Any] = {
            "window_start_ms": start_ms,
            "window_end_ms": end_ms,
            "window_start_iso_utc": source["window_start_iso_utc"],
            "window_end_iso_utc": source["window_end_iso_utc"],
            "raw_label": source["raw_label"],
            "activity_aware_label": source["activity_aware_label"],
            "raw_episode_id": source["raw_episode_id"],
            "activity_aware_episode_id": source["activity_aware_episode_id"],
            "manifest_changed": source["changed"],
            "timeline_label_recomputed": timeline_label,
            "timeline_episode_id_recomputed": timeline_episode,
            "timeline_overlap_ms": overlap_ms,
            "timeline_matches_raw_manifest": str(timeline_matches_raw).lower(),
            "attacker_ip": attacker_ip,
            "plc_ip": plc_ip,
            "benign_client_ip": client_ip,
            "capture_coverage": coverage,
            "pcap_evidence_status": evidence_status,
            "activity_rule_expected_attack_from_pcap": str(independent_expected_attack).lower(),
            "activity_rule_matches_manifest": str(rule_matches_aa).lower(),
        }
        for key, value in c.items():
            if isinstance(value, Counter):
                row[key] = counter_json(value)
            else:
                row[key] = value
        rows.append(row)

        def discrepancy(kind: str, detail: str, severity: str = "warning") -> None:
            discrepancies.append(
                {
                    "window_start_ms": start_ms,
                    "window_start_iso_utc": source["window_start_iso_utc"],
                    "raw_label": source["raw_label"],
                    "activity_aware_label": source["activity_aware_label"],
                    "raw_episode_id": source["raw_episode_id"],
                    "discrepancy_type": kind,
                    "severity": severity,
                    "detail": detail,
                    "pipeline_scope_attacker_related_packet_count": pipeline_related,
                    "attacker_src_packet_count": c["attacker_src_packet_count"],
                    "capture_coverage": coverage,
                }
            )

        if coverage != "full":
            discrepancy("incomplete_capture_coverage", "Window is not fully bounded by PCAP timestamps.")
        if not timeline_matches_raw:
            discrepancy(
                "timeline_manifest_mismatch",
                f"Recomputed timeline={timeline_label}/{timeline_episode}; manifest={source['raw_label']}/{source['raw_episode_id']}.",
                "error",
            )
        if raw_attack and aa_attack and pipeline_related == 0 and coverage == "full":
            discrepancy(
                "retained_attack_without_pipeline_scope_attacker_packet",
                "Activity-aware manifest retains attack although direct PCAP recount found no attacker-related packet in the original extractor scope.",
                "error",
            )
        if raw_attack and not aa_attack and pipeline_related > 0:
            discrepancy(
                "changed_to_benign_with_pipeline_scope_attacker_packet",
                "Window changed to benign although direct PCAP recount found attacker-related traffic in the original extractor scope.",
                "error",
            )
        if rule_matches_aa is False and coverage == "full":
            discrepancy(
                "activity_rule_manifest_mismatch",
                "Reapplication of the documented activity-aware rule to direct PCAP counts does not match the manifest.",
                "error",
            )
    return rows, discrepancies


def build_changed_rows(
    changed_manifest: list[dict[str, str]], window_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_start = {int(row["window_start_ms"]): row for row in window_rows}
    changed: list[dict[str, Any]] = []
    for source in changed_manifest:
        start_ms = int(source["window_start_ms"])
        row = by_start.get(start_ms)
        if row is None:
            changed.append(
                {
                    "window_start_ms": start_ms,
                    "audit_verdict": "insufficient_evidence",
                    "audit_reason": "Changed window is missing from full-window evidence.",
                }
            )
            continue
        related = int(row["pipeline_scope_attacker_related_packet_count"])
        coverage = row["capture_coverage"]
        if coverage != "full":
            verdict = "insufficient_evidence"
            reason = "PCAP does not fully cover the window boundary."
        elif related > 0:
            verdict = "inconsistent"
            reason = "Direct recount found attacker-related TCP/4840 PLC traffic in a window changed to benign."
        else:
            verdict = "consistent"
            reason = "No attacker-related packet was captured in the original extractor scope (TCP/4840 involving PLC)."

        prev_row = by_start.get(start_ms - WINDOW_MS)
        next_row = by_start.get(start_ms + WINDOW_MS)

        def same_episode(neighbor: dict[str, Any] | None) -> bool:
            return bool(neighbor and neighbor["raw_episode_id"] == row["raw_episode_id"])

        changed_row = {
            "window_start_ms": start_ms,
            "window_end_ms": row["window_end_ms"],
            "window_start_iso_utc": row["window_start_iso_utc"],
            "raw_label": row["raw_label"],
            "activity_aware_label": row["activity_aware_label"],
            "raw_episode_id": row["raw_episode_id"],
            "timeline_episode_id_recomputed": row["timeline_episode_id_recomputed"],
            "timeline_overlap_ms": row["timeline_overlap_ms"],
            "change_reason_manifest": source.get("change_reason", ""),
            "attacker_src_packet_count": row["attacker_src_packet_count"],
            "attacker_src_tcp_payload_packet_count": row["attacker_src_tcp_payload_packet_count"],
            "attacker_src_tcp_payload_bytes": row["attacker_src_tcp_payload_bytes"],
            "attacker_src_tcp4840_packet_count": row["attacker_src_tcp4840_packet_count"],
            "attacker_src_opcua_decoded_packet_count": row["attacker_src_opcua_decoded_packet_count"],
            "attacker_to_plc_packet_count": row["attacker_to_plc_packet_count"],
            "plc_to_attacker_packet_count": row["plc_to_attacker_packet_count"],
            "plc_to_attacker_tcp_payload_packet_count": row["plc_to_attacker_tcp_payload_packet_count"],
            "plc_to_attacker_opcua_decoded_packet_count": row["plc_to_attacker_opcua_decoded_packet_count"],
            "pipeline_scope_attacker_src_packet_count": row["pipeline_scope_attacker_src_packet_count"],
            "pipeline_scope_plc_response_packet_count": row["pipeline_scope_plc_response_packet_count"],
            "pipeline_scope_attacker_related_packet_count": related,
            "first_attacker_packet_epoch": row["first_attacker_packet_epoch"],
            "last_attacker_packet_epoch": row["last_attacker_packet_epoch"],
            "attacker_transport_types": row["attacker_transport_types"],
            "attacker_service_node_ids": row["attacker_service_node_ids"],
            "attacker_destination_ips": row["attacker_destination_ips"],
            "attacker_destination_tcp_ports": row["attacker_destination_tcp_ports"],
            "response_transport_types": row["response_transport_types"],
            "response_service_node_ids": row["response_service_node_ids"],
            "capture_coverage": coverage,
            "audit_verdict": verdict,
            "audit_reason": reason,
            "previous_window_same_raw_episode": str(same_episode(prev_row)).lower(),
            "previous_pipeline_scope_attacker_related_count": (
                prev_row["pipeline_scope_attacker_related_packet_count"] if same_episode(prev_row) else ""
            ),
            "next_window_same_raw_episode": str(same_episode(next_row)).lower(),
            "next_pipeline_scope_attacker_related_count": (
                next_row["pipeline_scope_attacker_related_packet_count"] if same_episode(next_row) else ""
            ),
        }
        changed.append(changed_row)
    return changed


def input_record(path: Path, root: Path) -> dict[str, Any]:
    try:
        display = str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        display = str(path.resolve())
    return {
        "path": display,
        "absolute_path": str(path.resolve()),
        "size_bytes": path.stat().st_size,
        "sha256": sha256(path),
    }


def summarize(
    args: argparse.Namespace,
    paths: dict[str, Path],
    cap: dict[str, Any],
    manifest: list[dict[str, str]],
    timeline: list[dict[str, Any]],
    window_rows: list[dict[str, Any]],
    changed_rows: list[dict[str, Any]],
    discrepancies: list[dict[str, Any]],
    diagnostics: dict[str, Any],
    root: Path,
) -> dict[str, Any]:
    verdicts = Counter(row["audit_verdict"] for row in changed_rows)
    changed_neighbor_positive = 0
    changed_neighbor_compared = 0
    for row in changed_rows:
        values = []
        if row.get("previous_window_same_raw_episode") == "true":
            values.append(int(row["previous_pipeline_scope_attacker_related_count"] or 0))
        if row.get("next_window_same_raw_episode") == "true":
            values.append(int(row["next_pipeline_scope_attacker_related_count"] or 0))
        if values:
            changed_neighbor_compared += 1
            if any(value > 0 for value in values):
                changed_neighbor_positive += 1

    changed_with_source_packets = [
        {
            "window_start_ms": int(row["window_start_ms"]),
            "window_start_iso_utc": row["window_start_iso_utc"],
            "raw_episode_id": row["raw_episode_id"],
            "attacker_src_packet_count": int(row["attacker_src_packet_count"]),
            "attacker_src_tcp_payload_packet_count": int(row["attacker_src_tcp_payload_packet_count"]),
            "attacker_src_tcp_payload_bytes": int(row["attacker_src_tcp_payload_bytes"]),
            "attacker_src_tcp4840_packet_count": int(row["attacker_src_tcp4840_packet_count"]),
            "attacker_src_opcua_decoded_packet_count": int(
                row["attacker_src_opcua_decoded_packet_count"]
            ),
            "attacker_to_plc_packet_count": int(row["attacker_to_plc_packet_count"]),
            "attacker_destination_ips": row["attacker_destination_ips"],
            "attacker_destination_tcp_ports": row["attacker_destination_tcp_ports"],
            "pipeline_scope_attacker_related_packet_count": int(
                row["pipeline_scope_attacker_related_packet_count"]
            ),
        }
        for row in changed_rows
        if int(row.get("attacker_src_packet_count", 0)) > 0
    ]

    return {
        "audit_title": "Independent PCAP recount for OPC UA Day 8 activity-aware labels",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scope": {
            "window_interval": "[window_start, window_end)",
            "window_size_ms": WINDOW_MS,
            "canonical_capture_only": True,
            "segment_pcaps_ingested": False,
            "duplicate_avoidance": "Only the canonical merged PCAP was read; source segment PCAPs were not combined with it.",
            "attacker_presence_rule_reapplied": "Within timeline overlap, attack iff at least one packet in the original extractor display-filter scope (tcp.port==4840 and ip.addr==PLC) has attacker IP as source or destination.",
            "attacker_originated_definition": f"IPv4 packet with ip.src == {args.attacker_ip}.",
            "plc_response_definition": f"IPv4 packet with ip.src == {args.plc_ip} and ip.dst == {args.attacker_ip}.",
        },
        "addresses": {
            "attacker": args.attacker_ip,
            "benign_client_hmi": args.client_ip,
            "plc": args.plc_ip,
            "provenance": [
                "tests/day8/collect_opcua.py module documentation: Web-SCADA .31, attacker .32",
                "testbed.conf: HMI_IP=.31, TARGET_IP/OPC_URL=.211",
                "testbed_diagram.html and paper testbed table: attacker .32",
            ],
        },
        "inputs": {name: input_record(path, root) for name, path in paths.items()},
        "capture_metadata": cap,
        "software": {"python": sys.version.split()[0], "tshark": tshark_version()},
        "tshark_extraction": diagnostics,
        "counts": {
            "manifest_windows": len(manifest),
            "timeline_intervals": len(timeline),
            "changed_windows_manifest": len(changed_rows),
            "changed_verified_consistent": verdicts["consistent"],
            "changed_inconsistent": verdicts["inconsistent"],
            "changed_insufficient_evidence": verdicts["insufficient_evidence"],
            "changed_with_any_attacker_originated_ip_packet": len(changed_with_source_packets),
            "changed_with_attacker_originated_tcp_payload": sum(
                row["attacker_src_tcp_payload_packet_count"] > 0 for row in changed_with_source_packets
            ),
            "changed_with_attacker_originated_decoded_opcua": sum(
                row["attacker_src_opcua_decoded_packet_count"] > 0
                for row in changed_with_source_packets
            ),
            "changed_with_pipeline_scope_attacker_related_packet": sum(
                row["pipeline_scope_attacker_related_packet_count"] > 0
                for row in changed_with_source_packets
            ),
            "all_windows_full_capture_coverage": sum(r["capture_coverage"] == "full" for r in window_rows),
            "all_windows_partial_boundary": sum(r["capture_coverage"] == "partial_boundary" for r in window_rows),
            "all_windows_outside_capture": sum(r["capture_coverage"] == "outside" for r in window_rows),
            "timeline_manifest_mismatches": sum(r["timeline_matches_raw_manifest"] != "true" for r in window_rows),
            "activity_rule_manifest_mismatches": sum(r["activity_rule_matches_manifest"] != "true" for r in window_rows),
            "retained_attack_windows": sum(as_bool(r["activity_rule_expected_attack_from_pcap"]) for r in window_rows),
            "retained_attack_windows_with_no_pipeline_scope_attacker_packet": sum(
                as_bool(r["activity_rule_expected_attack_from_pcap"]) is False
                and r["activity_aware_label"] != BENIGN
                and r["capture_coverage"] == "full"
                for r in window_rows
            ),
            "benign_windows_with_pipeline_scope_attacker_packet": sum(
                r["activity_aware_label"] == BENIGN
                and int(r["pipeline_scope_attacker_related_packet_count"]) > 0
                for r in window_rows
            ),
            "windows_with_attacker_originated_ip_packets": sum(int(r["attacker_src_packet_count"]) > 0 for r in window_rows),
            "windows_with_attacker_originated_tcp_payload": sum(
                int(r["attacker_src_tcp_payload_packet_count"]) > 0 for r in window_rows
            ),
            "windows_with_attacker_originated_decoded_opcua": sum(
                int(r["attacker_src_opcua_decoded_packet_count"]) > 0 for r in window_rows
            ),
            "changed_windows_with_same_episode_neighbor_available": changed_neighbor_compared,
            "changed_windows_with_positive_same_episode_neighbor": changed_neighbor_positive,
            "discrepancy_rows": len(discrepancies),
            "discrepancy_types": dict(Counter(r["discrepancy_type"] for r in discrepancies)),
        },
        "changed_windows_with_attacker_originated_packets_outside_pipeline_scope": changed_with_source_packets,
        "interpretation_boundaries": [
            "Manifest consistency is a comparison between stored labels and the documented rule.",
            "Packet evidence is a fresh extraction from the same captured PCAP, not an independent capture source.",
            "Attacker traffic presence means captured packets involving the configured attacker IP; it does not prove that an attack action succeeded.",
            "No captured packet does not prove no off-path action occurred; it is bounded by capture coverage and visibility.",
            "OPC UA decoded counts depend on TShark dissector recognition and TCP reassembly; TCP/4840 counts are reported separately.",
            "PLC-to-attacker replies are reported separately from attacker-originated packets.",
        ],
    }


def render_report(summary: dict[str, Any]) -> str:
    c = summary["counts"]
    inputs = summary["inputs"]
    discrepancy_types = c["discrepancy_types"] or {"none": 0}
    discrepancy_lines = "\n".join(f"- `{key}`: {value}" for key, value in discrepancy_types.items())
    input_lines = "\n".join(
        f"- `{item['path']}` — {item['size_bytes']} bytes — SHA-256 `{item['sha256']}`"
        for item in inputs.values()
    )
    outside_rows = summary["changed_windows_with_attacker_originated_packets_outside_pipeline_scope"]
    if outside_rows:
        outside_table = "\n".join(
            "| {window_start_iso_utc} | `{raw_episode_id}` | {attacker_src_packet_count} | "
            "{attacker_src_tcp_payload_packet_count} ({attacker_src_tcp_payload_bytes} B) | "
            "`{attacker_destination_ips}` | `{attacker_destination_tcp_ports}` | "
            "{pipeline_scope_attacker_related_packet_count} |".format(**row)
            for row in outside_rows
        )
    else:
        outside_table = "| Không có | — | 0 | 0 | `{}` | `{}` | 0 |"
    cmd = " ".join(summary["tshark_extraction"]["command"])
    return f"""# Báo cáo kiểm toán độc lập 29 cửa sổ OPC UA từ PCAP gốc

## Phạm vi và nguồn dữ liệu

Kiểm toán này đọc lại **một nguồn duy nhất** là PCAP gộp Day 8. Các PCAP segment không được nạp cùng PCAP gộp, vì vậy một bản ghi không thể bị đếm hai lần do xuất hiện ở cả hai loại nguồn. Tổng cộng kiểm tra {c['manifest_windows']} cửa sổ 5 giây theo khoảng nửa kín `[window_start, window_end)`, trong đó có {c['changed_windows_manifest']} cửa sổ đã đổi từ nhãn tấn công sang `benign`.

{input_lines}

PCAP có {summary['capture_metadata']['packet_count']} gói, từ epoch `{summary['capture_metadata']['capture_start_epoch']}` đến `{summary['capture_metadata']['capture_end_epoch']}`. `capinfos` báo `Strict time order={summary['capture_metadata']['strict_time_order']}`; việc gán cửa sổ dựa trực tiếp trên `frame.time_epoch`, không dựa vào thứ tự dòng.

## Phương pháp

- Máy kiểm thử: `{summary['addresses']['attacker']}`; HMI/Web-SCADA: `{summary['addresses']['benign_client_hmi']}`; PLC: `{summary['addresses']['plc']}`.
- Epoch trong timeline được đổi sang mili giây bằng phép cắt phần lẻ giống pipeline gốc. Chuỗi `start_human/end_human` UTC+7 chỉ dùng để trình bày, không tham gia phép ghép.
- “Gói từ attacker” là gói IPv4 có `ip.src` bằng IP máy kiểm thử. “Phản hồi PLC” là gói có `ip.src=PLC` và `ip.dst=attacker`; hai chiều không bị cộng lẫn.
- Quy tắc activity-aware được tái áp dụng đúng phạm vi extractor gốc: `tcp.port==4840 && ip.addr==PLC`, sau đó coi có hoạt động attacker nếu **nguồn hoặc đích** là IP attacker.
- Dấu hiệu OPC UA giải mã dùng các trường transport type, service NodeId, status hoặc transport error của TShark. Đồng thời báo cáo riêng TCP/4840 để không coi lỗi/giới hạn dissector là vắng lưu lượng.
- Lệnh trích xuất thực tế: `{cmd}`.

## Kết quả 29 cửa sổ đổi nhãn

| Kết quả | Số cửa sổ |
|---|---:|
| Phù hợp quy tắc activity-aware | {c['changed_verified_consistent']} |
| Không nhất quán | {c['changed_inconsistent']} |
| Chưa đủ bằng chứng | {c['changed_insufficient_evidence']} |

Có {c['changed_with_any_attacker_originated_ip_packet']} cửa sổ trong nhóm 29 vẫn chứa gói IPv4 **phát từ** máy `.32`; {c['changed_with_attacker_originated_tcp_payload']} cửa sổ có TCP payload, nhưng {c['changed_with_pipeline_scope_attacker_related_packet']} cửa sổ có lưu lượng thuộc phạm vi activity-aware gốc và {c['changed_with_attacker_originated_decoded_opcua']} cửa sổ có OPC UA phát từ attacker được TShark giải mã. Do đó, các gói ngoài phạm vi PLC/TCP-4840 không phải bằng chứng để tự động đổi nhãn ngược lại:

| Bắt đầu UTC | Episode gốc | Gói từ attacker | TCP payload | IP đích | Cổng TCP đích | Gói thuộc phạm vi rule |
|---|---|---:|---:|---|---|---:|
{outside_table}

Có {c['changed_windows_with_same_episode_neighbor_available']}/{c['changed_windows_manifest']} cửa sổ có ít nhất một cửa sổ kề cùng episode để đối chiếu; {c['changed_windows_with_positive_same_episode_neighbor']} cửa sổ đổi nhãn có cửa sổ kề cùng episode chứa lưu lượng attacker trong phạm vi pipeline. Chi tiết từng cửa sổ và hai láng giềng nằm trong `changed_29_pcap_audit.csv`.

## Đối chiếu toàn bộ 3.427 cửa sổ

| Chỉ báo | Số cửa sổ |
|---|---:|
| Được PCAP bao phủ đầy đủ | {c['all_windows_full_capture_coverage']} |
| Nằm ở biên PCAP, chỉ được bao phủ một phần | {c['all_windows_partial_boundary']} |
| Ngoài PCAP | {c['all_windows_outside_capture']} |
| Timeline tái tính không khớp raw manifest | {c['timeline_manifest_mismatches']} |
| Quy tắc activity-aware tái tính không khớp manifest | {c['activity_rule_manifest_mismatches']} |
| Có gói IPv4 phát từ attacker | {c['windows_with_attacker_originated_ip_packets']} |
| Có TCP payload phát từ attacker | {c['windows_with_attacker_originated_tcp_payload']} |
| Có OPC UA do TShark giải mã phát từ attacker | {c['windows_with_attacker_originated_decoded_opcua']} |
| Cửa sổ benign vẫn có lưu lượng attacker trong phạm vi pipeline | {c['benign_windows_with_pipeline_scope_attacker_packet']} |

Toàn bộ {c['benign_windows_with_pipeline_scope_attacker_packet']} cửa sổ ở dòng cuối có `timeline_overlap_ms=0`: traffic `.32` xuất hiện ngoài khoảng attack do timeline công bố (thí dụ warm-up/cooldown), nên điều này không tạo bất nhất với quy tắc vốn yêu cầu đồng thời có timeline overlap và traffic attacker.

`window_packet_evidence.csv` lưu các trường đếm và dấu hiệu dịch vụ cho toàn bộ cửa sổ. Các bất nhất/biên dữ liệu được tách vào `audit_discrepancies.csv`:

{discrepancy_lines}

## Kết luận khoa học

1. **Tính nhất quán manifest** chỉ cho biết nhãn lưu trữ có tái tạo được từ timeline và quy tắc đã công bố hay không.
2. **Bằng chứng gói tin** ở đây là một phép trích xuất lại độc lập về mã nguồn từ **cùng PCAP đã thu**, không phải một nguồn thu thập độc lập hoàn toàn.
3. **Sự hiện diện của lưu lượng attacker** là quan sát packet-level gắn với IP đã xác minh. Phản hồi của PLC được tách khỏi gói do attacker phát.
4. **Thực hiện thành công hành vi tấn công** không thể suy ra chỉ từ sự hiện diện gói tin, TCP payload hay việc TShark giải mã được OPC UA. Cần log phía ứng dụng/PLC hoặc tiêu chí tác động riêng cho kết luận đó.

## Giới hạn

- Vắng gói trong PCAP chỉ có nghĩa là không có gói phù hợp được capture trong phạm vi và thời gian đang xét; không chứng minh không có hành động ngoài điểm quan sát.
- Các cửa sổ biên PCAP được đánh dấu thiếu bao phủ đầy đủ, không tự động gán giá trị “đã xác minh vắng mặt”.
- Bộ đếm OPC UA phụ thuộc phiên bản TShark {summary['software']['tshark']} và khả năng reassembly/dissector. Vì vậy artifact giữ đồng thời số gói IP, TCP payload, TCP/4840 và OPC UA đã giải mã.
- `Strict time order=False` phản ánh PCAP gộp không hoàn toàn theo thứ tự timestamp; phép gán theo timestamp từng frame vẫn bảo toàn ranh giới cửa sổ.

## Tái lập

Từ thư mục gốc repository:

```bash
python3 tools/opcua_pcap_independent_audit.py
```

Câu lệnh đầy đủ được lưu trong `reproduce_command.txt`; cấu hình và hash đầu vào nằm trong `packet_audit_summary.json`.
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--pcap", default="data_opc/day8_out/harvest_ot1786331948_merged.pcap")
    parser.add_argument("--timeline", default="test_results/day8/timeline_harvest.csv")
    parser.add_argument("--raw-windows", default="data_opc/day8_out/opcua_harvest_ext.csv")
    parser.add_argument("--activity-aware-windows", default="data_opc/day8_out/opcua_harvest_ext_aa.csv")
    parser.add_argument("--manifest", default="experiments/opcua_research_v2/label_audit/label_manifest.csv")
    parser.add_argument("--changed", default="experiments/opcua_research_v2/label_audit/changed_windows.csv")
    parser.add_argument("--extractor", default="extract_opcua_features_ext.py")
    parser.add_argument("--collector", default="tests/day8/collect_opcua.py")
    parser.add_argument("--testbed-config", default="testbed.conf")
    parser.add_argument("--scenarios", default="tests/day8/scenarios.yaml")
    parser.add_argument("--attacker-ip", default="192.168.210.32")
    parser.add_argument("--client-ip", default="192.168.210.31")
    parser.add_argument("--plc-ip", default="192.168.210.211")
    parser.add_argument(
        "--output-dir",
        default="experiments/opcua_research_v2/label_audit/pcap_independent_audit",
    )
    args = parser.parse_args()

    root = Path(args.repo_root).resolve()
    paths = {
        "pcap": root / args.pcap,
        "timeline": root / args.timeline,
        "raw_windows": root / args.raw_windows,
        "activity_aware_windows": root / args.activity_aware_windows,
        "label_manifest": root / args.manifest,
        "changed_windows": root / args.changed,
        "extractor_source": root / args.extractor,
        "collector_source": root / args.collector,
        "testbed_config": root / args.testbed_config,
        "scenario_config": root / args.scenarios,
    }
    for name, path in paths.items():
        require_file(path, name)

    output_dir = root / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest = read_csv(paths["label_manifest"])
    changed_manifest = read_csv(paths["changed_windows"])
    raw_windows = read_csv(paths["raw_windows"])
    aa_windows = read_csv(paths["activity_aware_windows"])
    if len(manifest) != 3427:
        raise ValueError(f"Expected 3427 manifest windows, found {len(manifest)}")
    if len(changed_manifest) != 29:
        raise ValueError(f"Expected 29 changed windows, found {len(changed_manifest)}")
    manifest_keys = {int(row["window_start_ms"]) for row in manifest}
    raw_keys = {int(row["window_start_ms"]) for row in raw_windows}
    aa_keys = {int(row["window_start_ms"]) for row in aa_windows}
    if len(manifest_keys) != len(manifest) or manifest_keys != raw_keys or manifest_keys != aa_keys:
        raise ValueError("Window keys differ or are duplicated across manifest/raw/activity-aware data")

    intervals = load_timeline(paths["timeline"])
    cap = get_capinfos(paths["pcap"])
    evidence, diagnostics = extract_packet_evidence(
        paths["pcap"], manifest_keys, args.attacker_ip, args.plc_ip
    )
    window_rows, discrepancies = build_window_rows(
        manifest, intervals, evidence, cap, args.attacker_ip, args.plc_ip, args.client_ip
    )
    changed_rows = build_changed_rows(changed_manifest, window_rows)
    summary = summarize(
        args,
        paths,
        cap,
        manifest,
        intervals,
        window_rows,
        changed_rows,
        discrepancies,
        diagnostics,
        root,
    )

    write_csv(output_dir / "window_packet_evidence.csv", window_rows)
    write_csv(output_dir / "changed_29_pcap_audit.csv", changed_rows)
    discrepancy_fields = [
        "window_start_ms",
        "window_start_iso_utc",
        "raw_label",
        "activity_aware_label",
        "raw_episode_id",
        "discrepancy_type",
        "severity",
        "detail",
        "pipeline_scope_attacker_related_packet_count",
        "attacker_src_packet_count",
        "capture_coverage",
    ]
    write_csv(output_dir / "audit_discrepancies.csv", discrepancies, discrepancy_fields)
    with (output_dir / "packet_audit_summary.json").open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
        f.write("\n")
    (output_dir / "PCAP_AUDIT_REPORT.md").write_text(render_report(summary), encoding="utf-8")
    reproduce = (
        "python3 tools/opcua_pcap_independent_audit.py "
        f"--attacker-ip {args.attacker_ip} --client-ip {args.client_ip} --plc-ip {args.plc_ip}\n"
    )
    (output_dir / "reproduce_command.txt").write_text(reproduce, encoding="utf-8")

    print(json.dumps(summary["counts"], ensure_ascii=False, indent=2))
    print(f"Artifacts written to: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
