#!/usr/bin/env python3
"""Build an auditable OPC UA window-label manifest.

This script compares the original extended feature table with the
activity-aware table. It does not inspect PCAP files or contact the PLC.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


KEY = ("window_start_ms", "window_end_ms")
EVIDENCE_COLUMNS = (
    "opcua_packet_count",
    "opcua_client_src_count",
    "opcua_unique_src_ip_count",
    "opcua_unique_tcp_stream_count",
    "opcua_hel_count",
    "opcua_opn_count",
    "opcua_create_session_count",
    "opcua_create_subscription_count",
    "opcua_create_monitored_items_count",
    "opcua_publish_count",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--raw", default="data_opc/day8_out/opcua_harvest_ext.csv"
    )
    parser.add_argument(
        "--activity-aware",
        default="data_opc/day8_out/opcua_harvest_ext_aa.csv",
    )
    parser.add_argument(
        "--output",
        default="experiments/opcua_research_v2/label_audit/label_manifest.csv",
    )
    parser.add_argument(
        "--changed-output",
        default="experiments/opcua_research_v2/label_audit/changed_windows.csv",
    )
    parser.add_argument(
        "--summary",
        default="experiments/opcua_research_v2/label_audit/summary.json",
    )
    return parser.parse_args()


def read_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError(f"CSV has no header: {path}")
        rows = list(reader)
        return list(reader.fieldnames), rows


def row_key(row: dict[str, str]) -> tuple[str, str]:
    return tuple(row.get(name, "") for name in KEY)  # type: ignore[return-value]


def is_attack(label: str) -> bool:
    return bool(label) and label.strip().lower() != "benign"


def iso_from_ms(value: str) -> str:
    if not value:
        return ""
    try:
        return datetime.fromtimestamp(float(value) / 1000.0, tz=timezone.utc).isoformat()
    except ValueError:
        return ""


def main() -> None:
    args = parse_args()
    raw_path = Path(args.raw)
    aa_path = Path(args.activity_aware)
    _, raw_rows = read_rows(raw_path)
    _, aa_rows = read_rows(aa_path)

    raw_by_key = {row_key(row): row for row in raw_rows}
    aa_by_key = {row_key(row): row for row in aa_rows}
    raw_keys = set(raw_by_key)
    aa_keys = set(aa_by_key)
    if raw_keys != aa_keys:
        missing_in_aa = sorted(raw_keys - aa_keys)
        missing_in_raw = sorted(aa_keys - raw_keys)
        raise ValueError(
            "Window sets differ: "
            f"missing_in_activity_aware={len(missing_in_aa)}, "
            f"missing_in_raw={len(missing_in_raw)}"
        )

    manifest: list[dict[str, str]] = []
    changes = Counter()
    for key in sorted(raw_keys, key=lambda item: (float(item[0]), float(item[1]))):
        raw = raw_by_key[key]
        aa = aa_by_key[key]
        raw_label = raw.get("label", "")
        aa_label = aa.get("label", "")
        changed = raw_label != aa_label
        if changed and is_attack(raw_label) and not is_attack(aa_label):
            reason = "activity_aware_no_attacker_traffic_in_window"
            attacker_evidence = "false"
        elif changed:
            reason = "label_changed"
            attacker_evidence = ""
        elif is_attack(aa_label):
            reason = ""
            attacker_evidence = "true"
        else:
            reason = ""
            attacker_evidence = ""

        item = {
            "window_start_ms": key[0],
            "window_end_ms": key[1],
            "window_start_iso_utc": iso_from_ms(key[0]),
            "window_end_iso_utc": iso_from_ms(key[1]),
            "raw_label": raw_label,
            "activity_aware_label": aa_label,
            "raw_episode_id": raw.get("episode_id", ""),
            "activity_aware_episode_id": aa.get("episode_id", ""),
            "scenario_id": aa.get("scenario_id", raw.get("scenario_id", "")),
            "capture_role": aa.get("capture_role", raw.get("capture_role", "")),
            "plc_ip": aa.get("plc_ip", raw.get("plc_ip", "")),
            "changed": str(changed).lower(),
            "change_reason": reason,
            "raw_is_attack": str(is_attack(raw_label)).lower(),
            "activity_aware_is_attack": str(is_attack(aa_label)).lower(),
            "has_attacker_traffic_inferred": attacker_evidence,
            "attacker_packet_count": "",
        }
        for name in EVIDENCE_COLUMNS:
            item[name] = aa.get(name, raw.get(name, ""))
        manifest.append(item)
        if changed:
            changes[f"{raw_label} -> {aa_label}"] += 1

    fieldnames = list(manifest[0]) if manifest else []
    output = Path(args.output)
    changed_output = Path(args.changed_output)
    summary_path = Path(args.summary)
    for path in (output, changed_output, summary_path):
        path.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(manifest)

    changed_rows = [row for row in manifest if row["changed"] == "true"]
    with changed_output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(changed_rows)

    summary = {
        "raw_csv": str(raw_path),
        "activity_aware_csv": str(aa_path),
        "n_windows": len(manifest),
        "n_changed": len(changed_rows),
        "changes": dict(sorted(changes.items())),
        "raw_label_counts": dict(sorted(Counter(r["raw_label"] for r in manifest).items())),
        "activity_aware_label_counts": dict(
            sorted(Counter(r["activity_aware_label"] for r in manifest).items())
        ),
        "limitation": (
            "The source feature CSV does not persist attacker_packet_count. "
            "has_attacker_traffic_inferred records only what can be inferred from "
            "the activity-aware relabeling rule."
        ),
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
