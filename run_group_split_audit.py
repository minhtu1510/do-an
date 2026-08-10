#!/usr/bin/env python3
"""Audit grouped-CV and holdout split isolation for the released CSV views."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pandas as pd

import train_ml


EXPECTED_GROUP_COUNTS = {
    "network_only": {"total": 228, "benign": 192, "attack": 36},
    "fusion": {"total": 228, "benign": 192, "attack": 36},
    "process_only": {"total": 49, "benign": 40, "attack": 9},
}


def group_class_summary(df: pd.DataFrame, groups: pd.Series) -> dict[str, int]:
    labels = df["label"].astype(str).reset_index(drop=True)
    group_frame = pd.DataFrame({"group": groups.astype(str), "label": labels})

    benign_groups = 0
    attack_groups = 0
    mixed_groups = 0
    for _, subset in group_frame.groupby("group", sort=False):
        benign_mask = subset["label"].map(train_ml.is_benign_label)
        if bool(benign_mask.all()):
            benign_groups += 1
        else:
            attack_groups += 1
            if bool(benign_mask.any()):
                mixed_groups += 1

    return {
        "total": int(group_frame["group"].nunique()),
        "benign": benign_groups,
        "attack": attack_groups,
        "mixed": mixed_groups,
    }


def summarize_cv_splits(
    y: pd.Series,
    groups: pd.Series,
    n_splits: int,
    seeds: list[int],
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    max_overlap = 0
    for seed in seeds:
        for fold, (train_idx, test_idx) in enumerate(train_ml.make_splits(y, groups, n_splits, seed), start=1):
            train_groups = set(groups.iloc[train_idx].astype(str))
            test_groups = set(groups.iloc[test_idx].astype(str))
            overlap = sorted(train_groups & test_groups)
            max_overlap = max(max_overlap, len(overlap))
            rows.append(
                {
                    "seed": seed,
                    "fold": fold,
                    "train_rows": int(len(train_idx)),
                    "test_rows": int(len(test_idx)),
                    "train_groups": int(len(train_groups)),
                    "test_groups": int(len(test_groups)),
                    "overlap_count": int(len(overlap)),
                    "overlap_examples": overlap[:10],
                }
            )
    return {
        "max_group_overlap": int(max_overlap),
        "folds": rows,
    }


def summarize_session_holdout(
    df: pd.DataFrame,
    groups: pd.Series,
    train_sessions: set[str] | None,
    test_sessions: set[str],
) -> dict[str, Any]:
    sessions = df["session_id"].astype(str).reset_index(drop=True)
    if train_sessions is None:
        train_mask = ~sessions.isin(test_sessions)
    else:
        train_mask = sessions.isin(train_sessions)
    test_mask = sessions.isin(test_sessions)

    train_groups = set(groups[train_mask].astype(str))
    test_groups = set(groups[test_mask].astype(str))
    overlap = sorted(train_groups & test_groups)

    return {
        "train_sessions": sorted(set(sessions[train_mask].astype(str))),
        "test_sessions": sorted(set(sessions[test_mask].astype(str))),
        "train_rows": int(train_mask.sum()),
        "test_rows": int(test_mask.sum()),
        "train_groups": int(len(train_groups)),
        "test_groups": int(len(test_groups)),
        "group_overlap_count": int(len(overlap)),
        "group_overlap_examples": overlap[:10],
    }


def audit_view(path: Path, view: str, args: argparse.Namespace) -> dict[str, Any]:
    df = pd.read_csv(path, low_memory=False).reset_index(drop=True)
    required = {"label", "session_id", "host_id", "episode_id"}
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError(f"{path} is missing required columns: {', '.join(missing)}")

    groups = train_ml.choose_group_series(df, args.group_col).astype(str).reset_index(drop=True)
    y = (~df["label"].map(train_ml.is_benign_label)).astype(int).reset_index(drop=True)
    group_counts = group_class_summary(df, groups)

    report = {
        "view": view,
        "path": str(path),
        "rows": int(len(df)),
        "group_key": "|".join(train_ml.DEFAULT_GROUP_COLUMNS),
        "group_counts": group_counts,
        "label_counts": {str(k): int(v) for k, v in df["label"].value_counts().items()},
        "session_counts": {str(k): int(v) for k, v in df["session_id"].value_counts().items()},
        "group_cv": summarize_cv_splits(y, groups, args.n_splits, args.seeds),
        "day6_holdout": summarize_session_holdout(df, groups, None, {"day6"}),
        "day5_temporal_holdout": summarize_session_holdout(
            df,
            groups,
            {"day1", "day2", "day3", "day4"},
            {"day5"},
        ),
    }
    return report


def validate_report(report: dict[str, Any]) -> None:
    failures: list[str] = []
    for view, item in report["views"].items():
        expected = EXPECTED_GROUP_COUNTS.get(view)
        actual = item["group_counts"]
        if expected:
            for key, expected_value in expected.items():
                if actual.get(key) != expected_value:
                    failures.append(f"{view}: expected {key} groups={expected_value}, got {actual.get(key)}")
        if item["group_cv"]["max_group_overlap"] != 0:
            failures.append(f"{view}: grouped CV has train/test group overlap")
        for holdout_name in ("day6_holdout", "day5_temporal_holdout"):
            if item[holdout_name]["group_overlap_count"] != 0:
                failures.append(f"{view}: {holdout_name} has train/test group overlap")
    if failures:
        raise AssertionError("\n".join(failures))


def write_markdown(report: dict[str, Any], output_path: Path) -> None:
    lines = ["# Group Split Audit", ""]
    lines.append("The evaluator forms groups from `session_id|host_id|episode_id` when all three columns are present.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| View | Rows | Groups | Benign Groups | Attack Groups | Group-CV Max Overlap | Day-6 Overlap | Day-5 Overlap |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for view, item in report["views"].items():
        counts = item["group_counts"]
        lines.append(
            "| {view} | {rows} | {groups} | {benign} | {attack} | {cv_overlap} | {day6_overlap} | {day5_overlap} |".format(
                view=view,
                rows=item["rows"],
                groups=counts["total"],
                benign=counts["benign"],
                attack=counts["attack"],
                cv_overlap=item["group_cv"]["max_group_overlap"],
                day6_overlap=item["day6_holdout"]["group_overlap_count"],
                day5_overlap=item["day5_temporal_holdout"]["group_overlap_count"],
            )
        )
    lines.append("")
    lines.append("## Validation")
    lines.append("")
    lines.append("- Expected group counts match the released processed CSVs.")
    lines.append("- Every grouped-CV fold has zero train/test group overlap for seeds `" + ", ".join(map(str, report["seeds"])) + "`.")
    lines.append("- Day-6 and Day-5 session holdouts have zero train/test group overlap.")
    lines.append("- BENIGN windows are grouped into 10-minute `episode_id` chunks before the final composite key is formed; they are not collapsed into one benign group per day.")
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit grouped-CV and session-holdout split isolation")
    parser.add_argument("--network-data", default="SemanticAware-S7comm-Dataset/processed/network.csv")
    parser.add_argument("--fusion-data", default="SemanticAware-S7comm-Dataset/processed/fusion.csv")
    parser.add_argument("--process-data", default="SemanticAware-S7comm-Dataset/processed/process.csv")
    parser.add_argument("--output-dir", default="ml_results/group_split_audit")
    parser.add_argument("--group-col", default="auto")
    parser.add_argument("--n-splits", type=int, default=5)
    parser.add_argument("--seeds", nargs="*", type=int, default=[42, 43, 44, 45, 46])
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    paths = {
        "network_only": Path(args.network_data),
        "fusion": Path(args.fusion_data),
        "process_only": Path(args.process_data),
    }
    report = {
        "group_col_argument": args.group_col,
        "effective_group_key": "|".join(train_ml.DEFAULT_GROUP_COLUMNS),
        "n_splits": args.n_splits,
        "seeds": args.seeds,
        "views": {view: audit_view(path, view, args) for view, path in paths.items()},
    }
    validate_report(report)

    json_path = output_dir / "group_split_audit.json"
    md_path = output_dir / "group_split_audit.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(report, md_path)
    print(f"[AUDIT] Wrote {json_path} and {md_path}")


if __name__ == "__main__":
    main()
