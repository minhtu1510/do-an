#!/usr/bin/env python3
"""Summarize OPC UA warmup, steady-benign, and attack prediction errors."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


FEATURES = (
    "opcua_hel_count",
    "opcua_opn_count",
    "opcua_create_session_count",
    "opcua_create_subscription_count",
    "opcua_create_monitored_items_count",
    "opcua_publish_count",
    "opcua_client_src_count",
    "opcua_unique_tcp_stream_count",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--predictions",
        default="experiments/opcua_research_v2/warmup_ood/ood2_predictions.csv",
    )
    parser.add_argument(
        "--support-output",
        default="experiments/opcua_research_v2/warmup_ood/label_support.csv",
    )
    parser.add_argument(
        "--feature-output",
        default="experiments/opcua_research_v2/warmup_ood/phase_feature_summary.csv",
    )
    parser.add_argument(
        "--summary",
        default="experiments/opcua_research_v2/warmup_ood/error_summary.json",
    )
    return parser.parse_args()


def number(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def phase(row: dict[str, str]) -> str:
    if row.get("true_binary") == "attack":
        return "attack"
    if row.get("benign_phase") == "warmup":
        return "benign_warmup"
    return "benign_steady"


def main() -> None:
    args = parse_args()
    with Path(args.predictions).open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError("Prediction CSV is empty")

    support = Counter(
        (phase(row), row.get("label_original", ""), row.get("pred_label_eval", ""))
        for row in rows
    )
    support_rows = [
        {
            "phase": key[0],
            "label_original": key[1],
            "pred_label_eval": key[2],
            "n_windows": count,
        }
        for key, count in sorted(support.items())
    ]

    grouped: dict[tuple[str, str], list[float]] = defaultdict(list)
    for row in rows:
        current_phase = phase(row)
        for feature in FEATURES:
            value = number(row.get(feature, ""))
            if value is not None:
                grouped[(current_phase, feature)].append(value)
    feature_rows = []
    for (current_phase, feature), values in sorted(grouped.items()):
        ordered = sorted(values)
        q95_index = min(len(ordered) - 1, int(0.95 * (len(ordered) - 1)))
        feature_rows.append(
            {
                "phase": current_phase,
                "feature": feature,
                "n": len(values),
                "mean": sum(values) / len(values),
                "p95": ordered[q95_index],
                "max": max(values),
            }
        )

    support_path = Path(args.support_output)
    feature_path = Path(args.feature_output)
    summary_path = Path(args.summary)
    for path in (support_path, feature_path, summary_path):
        path.parent.mkdir(parents=True, exist_ok=True)
    with support_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(support_rows[0]))
        writer.writeheader()
        writer.writerows(support_rows)
    with feature_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(feature_rows[0]))
        writer.writeheader()
        writer.writerows(feature_rows)

    phase_counts = Counter(phase(row) for row in rows)
    false_positives = Counter(phase(row) for row in rows if row.get("is_fp") == "True")
    false_negatives = Counter(phase(row) for row in rows if row.get("is_fn") == "True")
    summary = {
        "phase_counts": dict(sorted(phase_counts.items())),
        "false_positives": dict(sorted(false_positives.items())),
        "false_negatives": dict(sorted(false_negatives.items())),
        "warmup_fp_share": (
            false_positives.get("benign_warmup", 0) / sum(false_positives.values())
            if sum(false_positives.values())
            else None
        ),
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
