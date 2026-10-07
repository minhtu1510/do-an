#!/usr/bin/env python3
"""Evaluate OPC UA detection at the episode level from exported predictions."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--predictions",
        default="experiments/opcua_research_v2/warmup_ood/ood2_predictions.csv",
    )
    parser.add_argument(
        "--output",
        default="experiments/opcua_research_v2/warmup_ood/ood2_episode_results.csv",
    )
    parser.add_argument(
        "--summary",
        default="experiments/opcua_research_v2/warmup_ood/ood2_episode_summary.json",
    )
    parser.add_argument(
        "--negative-output",
        default="experiments/opcua_research_v2/warmup_ood/ood2_negative_episode_results.csv",
    )
    parser.add_argument("--min-alert-windows", type=int, default=1)
    parser.add_argument("--confidence-threshold", type=float, default=0.5)
    parser.add_argument("--score-column", default="pred_attack_score")
    return parser.parse_args()


def as_float(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def main() -> None:
    args = parse_args()
    with Path(args.predictions).open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError("Prediction CSV is empty")

    units: dict[str, list[dict[str, str]]] = defaultdict(list)
    for index, row in enumerate(rows):
        episode_id = row.get("episode_id", "").strip()
        key = episode_id or f"row_without_episode_{index}"
        units[key].append(row)

    mixed_units = {
        key: group
        for key, group in units.items()
        if len({row.get("true_binary") for row in group}) > 1
    }
    if mixed_units:
        raise ValueError(
            "Episode precision is ambiguous because some episode_id values mix "
            f"attack and benign rows: {sorted(mixed_units)}"
        )
    episodes = {
        key: group
        for key, group in units.items()
        if group[0].get("true_binary") == "attack"
    }
    benign_chunks = {
        key: group
        for key, group in units.items()
        if group[0].get("true_binary") == "benign"
    }

    output_rows: list[dict[str, object]] = []
    detected_count = 0
    for episode_id, group in sorted(episodes.items()):
        qualifying = [
            row
            for row in group
            if as_float(row.get(args.score_column, ""), 0.0)
            >= args.confidence_threshold
        ]
        detected = len(qualifying) >= args.min_alert_windows
        detected_count += int(detected)
        true_labels = Counter(row.get("label_eval", "") for row in group)
        pred_labels = Counter(row.get("pred_label_eval", "") for row in group)
        first_alert = ""
        if qualifying:
            first_alert = min(
                qualifying,
                key=lambda row: as_float(row.get("window_start_ms", ""), float("inf")),
            ).get("window_start_ms", "")
        output_rows.append(
            {
                "episode_id": episode_id,
                "true_labels": json.dumps(dict(sorted(true_labels.items()))),
                "n_windows": len(group),
                "n_true_attack_windows": sum(
                    row.get("true_binary") == "attack" for row in group
                ),
                "n_alert_windows": len(qualifying),
                "detected": str(detected).lower(),
                "first_alert_window_start_ms": first_alert,
                "pred_labels": json.dumps(dict(sorted(pred_labels.items()))),
            }
        )

    negative_rows: list[dict[str, object]] = []
    for episode_id, group in sorted(benign_chunks.items()):
        qualifying = [
            row
            for row in group
            if as_float(row.get(args.score_column, ""), 0.0)
            >= args.confidence_threshold
        ]
        false_positive = len(qualifying) >= args.min_alert_windows
        current_phase = (
            "warmup"
            if any(row.get("benign_phase") == "warmup" for row in group)
            else "steady"
        )
        first_alert = ""
        if qualifying:
            first_alert = min(
                qualifying,
                key=lambda row: as_float(row.get("window_start_ms", ""), float("inf")),
            ).get("window_start_ms", "")
        negative_rows.append(
            {
                "episode_id": episode_id,
                "phase": current_phase,
                "n_windows": len(group),
                "n_alert_windows": len(qualifying),
                "false_positive": str(false_positive).lower(),
                "first_alert_window_start_ms": first_alert,
                "original_labels": json.dumps(
                    dict(sorted(Counter(row.get("label_original", "") for row in group).items()))
                ),
                "pred_labels": json.dumps(
                    dict(sorted(Counter(row.get("pred_label_eval", "") for row in group).items()))
                ),
            }
        )
    false_alert_chunks = sum(
        row["false_positive"] == "true" for row in negative_rows
    )
    output_path = Path(args.output)
    negative_output_path = Path(args.negative_output)
    summary_path = Path(args.summary)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    negative_output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(output_rows[0]) if output_rows else [
        "episode_id",
        "true_labels",
        "n_windows",
        "n_true_attack_windows",
        "n_alert_windows",
        "detected",
        "first_alert_window_start_ms",
        "pred_labels",
    ]
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_rows)

    negative_fieldnames = list(negative_rows[0]) if negative_rows else [
        "episode_id",
        "phase",
        "n_windows",
        "n_alert_windows",
        "false_positive",
        "first_alert_window_start_ms",
        "original_labels",
        "pred_labels",
    ]
    with negative_output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=negative_fieldnames)
        writer.writeheader()
        writer.writerows(negative_rows)

    n_episodes = len(episodes)
    episode_tp = detected_count
    episode_fn = n_episodes - detected_count
    episode_fp = false_alert_chunks
    episode_tn = len(benign_chunks) - false_alert_chunks
    negative_phase_counts = Counter(str(row["phase"]) for row in negative_rows)
    false_positive_phase_counts = Counter(
        str(row["phase"])
        for row in negative_rows
        if row["false_positive"] == "true"
    )
    negative_episode_fpr_by_phase = {
        phase: false_positive_phase_counts.get(phase, 0) / count
        for phase, count in sorted(negative_phase_counts.items())
    }
    summary = {
        "n_attack_episodes": n_episodes,
        "n_detected_attack_episodes": detected_count,
        "episode_recall": detected_count / n_episodes if n_episodes else None,
        "n_benign_chunks": len(benign_chunks),
        "n_false_alert_benign_chunks": false_alert_chunks,
        "episode_tp": episode_tp,
        "episode_fp": episode_fp,
        "episode_tn": episode_tn,
        "episode_fn": episode_fn,
        "episode_precision": (
            episode_tp / (episode_tp + episode_fp)
            if episode_tp + episode_fp
            else None
        ),
        "negative_episode_fpr": (
            episode_fp / (episode_fp + episode_tn)
            if episode_fp + episode_tn
            else None
        ),
        "negative_episode_phase_counts": dict(sorted(negative_phase_counts.items())),
        "false_positive_episode_phase_counts": dict(
            sorted(false_positive_phase_counts.items())
        ),
        "negative_episode_fpr_by_phase": negative_episode_fpr_by_phase,
        "n_mixed_label_episode_ids": len(mixed_units),
        "min_alert_windows": args.min_alert_windows,
        "confidence_threshold": args.confidence_threshold,
        "score_column": args.score_column,
        "definition": (
            "An attack episode is detected when at least min_alert_windows windows "
            "have score_column at or above confidence_threshold."
        ),
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
