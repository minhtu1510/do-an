#!/usr/bin/env python3
"""Sanity checks for the near-perfect Day-5 temporal holdout results."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

import train_ml


SUSPICIOUS_FEATURE_EXACT = {
    "label",
    "label_network",
    "label_system",
    "binary_label",
    "scenario_id",
    "episode_id",
    "session_id",
    "host_id",
    "day",
    "window_start_ms",
    "window_end_ms",
    "timestamp_ms",
    "attacker_timestamp_ms",
    "capture_role",
    "capture_source",
    "plc_ip",
    "extractor_label",
    "proc_data_valid",
    "plc_under_attack",
}

SUSPICIOUS_FEATURE_TOKENS = (
    "scenario",
    "episode",
    "session",
    "host_id",
    "capture_",
    "rule",
    "anomaly",
    "detected",
)

KEY_DAY5_FEATURES = [
    "packet_count",
    "byte_count",
    "packet_rate",
    "byte_rate",
    "tcp_count",
    "tcp_syn_count",
    "tcp_rst_count",
    "tcp_102_packet_count",
    "tcp_102_probe_count",
    "s7comm_packet_count",
    "s7_setup_count",
    "malformed_packet_count",
    "flow_iat_mean_ms",
    "idle_mean_ms",
]


def to_float(value: Any) -> float | None:
    try:
        if pd.isna(value):
            return None
        return float(value)
    except Exception:
        return None


def summarize_series(series: pd.Series) -> dict[str, float | int | None]:
    numeric = pd.to_numeric(series, errors="coerce").dropna()
    if numeric.empty:
        return {"count": 0, "min": None, "median": None, "max": None}
    return {
        "count": int(numeric.size),
        "min": float(numeric.min()),
        "median": float(numeric.median()),
        "max": float(numeric.max()),
    }


def flatten_summary_columns(summary: pd.DataFrame) -> pd.DataFrame:
    if not isinstance(summary.columns, pd.MultiIndex):
        return summary
    summary.columns = ["_".join(part for part in col if part) for col in summary.columns.to_flat_index()]
    return summary.reset_index()


def confusion_from_files(result_dir: Path) -> dict[str, dict[str, list[list[int]]]]:
    out: dict[str, dict[str, list[list[int]]]] = {}
    for path in sorted(result_dir.glob("*_host_holdout/binary_*_seed*_holdout_confusion.csv")):
        view = path.parent.name.removesuffix("_host_holdout")
        name = path.name.removeprefix("binary_").removesuffix("_confusion.csv")
        model, seed_part = name.rsplit("_seed", 1)
        seed = seed_part.removesuffix("_holdout")
        matrix = pd.read_csv(path, index_col=0).to_numpy(dtype=int).tolist()
        out.setdefault(view, {}).setdefault(model, {})[seed] = matrix
    return out


def threshold_summary(result_dir: Path) -> list[dict[str, Any]]:
    metrics_path = result_dir / "all_fold_metrics.csv"
    if not metrics_path.exists():
        return []
    metrics = pd.read_csv(metrics_path)
    cols = [
        "experiment",
        "model",
        "seed",
        "binary_threshold",
        "macro_f1",
        "mcc",
        "false_positive_count",
        "fpr_per_hour",
    ]
    return metrics[cols].sort_values(["experiment", "model", "seed"]).to_dict(orient="records")


def view_checks(path: Path, view: str, train_sessions: set[str], test_sessions: set[str]) -> dict[str, Any]:
    df = pd.read_csv(path, low_memory=False).reset_index(drop=True)
    if "session_id" not in df.columns:
        raise ValueError(f"{path} does not contain session_id")
    y = (~df["label"].map(train_ml.is_benign_label)).astype(int).reset_index(drop=True)
    X, feature_cols, dropped = train_ml.select_feature_matrix(df, leakage_mode=False, feature_profile="hybrid")
    session = df["session_id"].astype(str)
    train_mask = session.isin(train_sessions)
    test_mask = session.isin(test_sessions)

    groups = train_ml.choose_group_series(df, "auto").astype(str).reset_index(drop=True)
    train_groups = set(groups[train_mask])
    test_groups = set(groups[test_mask])
    group_overlap = sorted(train_groups & test_groups)

    suspicious = [
        col for col in feature_cols
        if col in SUSPICIOUS_FEATURE_EXACT or any(token in col.lower() for token in SUSPICIOUS_FEATURE_TOKENS)
    ]

    train_hash = pd.util.hash_pandas_object(X.loc[train_mask, feature_cols], index=False)
    test_hash = pd.util.hash_pandas_object(X.loc[test_mask, feature_cols], index=False)
    duplicated_test = test_hash.isin(set(train_hash.tolist()))
    duplicate_by_label = (
        pd.DataFrame({"label": df.loc[test_mask, "label"].to_numpy(), "duplicate": duplicated_test.to_numpy()})
        .groupby("label")["duplicate"]
        .agg(["sum", "count"])
        .reset_index()
    )

    day5 = df.loc[test_mask].copy()
    day5_y = y.loc[test_mask].to_numpy()
    X_day5 = X.loc[test_mask, feature_cols]
    benign_mask = day5_y == 0
    attack_mask = day5_y == 1
    perfect_separators = []
    for col in feature_cols:
        values = pd.to_numeric(X_day5[col], errors="coerce")
        benign = values[benign_mask].dropna()
        attack = values[attack_mask].dropna()
        if benign.empty or attack.empty:
            continue
        direction = None
        if benign.max() < attack.min():
            direction = "attack_gt_benign"
        elif attack.max() < benign.min():
            direction = "attack_lt_benign"
        if direction:
            perfect_separators.append(
                {
                    "feature": col,
                    "direction": direction,
                    "benign_max": float(benign.max()),
                    "attack_min": float(attack.min()),
                    "attack_max": float(attack.max()),
                    "benign_min": float(benign.min()),
                }
            )

    key_feature_summary = {}
    for col in KEY_DAY5_FEATURES:
        if col in X_day5.columns:
            key_feature_summary[col] = {
                "benign": summarize_series(X_day5.loc[benign_mask, col]),
                "attack": summarize_series(X_day5.loc[attack_mask, col]),
            }

    return {
        "view": view,
        "rows": int(len(df)),
        "train_rows": int(train_mask.sum()),
        "test_rows": int(test_mask.sum()),
        "candidate_features": int(len(feature_cols)),
        "dropped_features": int(len(dropped)),
        "suspicious_feature_columns": suspicious,
        "train_group_count": int(len(train_groups)),
        "test_group_count": int(len(test_groups)),
        "train_test_group_overlap_count": int(len(group_overlap)),
        "train_test_group_overlap_examples": group_overlap[:10],
        "duplicate_test_rows_total": int(duplicated_test.sum()),
        "duplicate_test_rows_by_label": duplicate_by_label.to_dict(orient="records"),
        "perfect_single_feature_separators_count": int(len(perfect_separators)),
        "perfect_single_feature_separators_examples": perfect_separators[:20],
        "key_day5_feature_summary": key_feature_summary,
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    train_sessions = set(args.train_sessions)
    test_sessions = set(args.test_sessions)
    paths = {
        "network_only": Path(args.network_data),
        "fusion": Path(args.fusion_data),
        "process_only": Path(args.process_data),
    }
    views = {
        name: view_checks(path, name, train_sessions, test_sessions)
        for name, path in paths.items()
    }
    report = {
        "train_sessions": sorted(train_sessions),
        "test_sessions": sorted(test_sessions),
        "result_dir": args.result_dir,
        "views": views,
        "thresholds_and_metrics": threshold_summary(Path(args.result_dir)),
        "confusion_matrices": confusion_from_files(Path(args.result_dir)),
    }
    return report


def write_markdown(report: dict[str, Any], output_path: Path) -> None:
    lines = ["# Day-5 Temporal Holdout Sanity Check", ""]
    lines.append(f"Train sessions: `{', '.join(report['train_sessions'])}`; test sessions: `{', '.join(report['test_sessions'])}`.")
    lines.append("")
    lines.append("## Leakage And Split Checks")
    lines.append("")
    lines.append("| View | Train rows | Test rows | Features | Suspicious feature columns | Group overlap | Duplicate test rows | Perfect Day5 single-feature separators |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for view in report["views"].values():
        lines.append(
            "| {view} | {train_rows} | {test_rows} | {candidate_features} | {suspicious} | {overlap} | {dups} | {separators} |".format(
                view=view["view"],
                train_rows=view["train_rows"],
                test_rows=view["test_rows"],
                candidate_features=view["candidate_features"],
                suspicious=len(view["suspicious_feature_columns"]),
                overlap=view["train_test_group_overlap_count"],
                dups=view["duplicate_test_rows_total"],
                separators=view["perfect_single_feature_separators_count"],
            )
        )
    lines.append("")
    lines.append("## Thresholds And Metrics")
    lines.append("")
    lines.append("| View | Model | Seed | Threshold | Macro-F1 | MCC | FP count | FPR/hour |")
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|")
    for row in report["thresholds_and_metrics"]:
        lines.append(
            "| {experiment} | {model} | {seed} | {threshold:.6f} | {macro_f1:.6f} | {mcc:.6f} | {false_positive_count:.0f} | {fpr_per_hour:.6f} |".format(
                experiment=row["experiment"],
                model=row["model"],
                seed=int(row["seed"]),
                threshold=float(row["binary_threshold"]),
                macro_f1=float(row["macro_f1"]),
                mcc=float(row["mcc"]),
                false_positive_count=float(row["false_positive_count"]),
                fpr_per_hour=float(row["fpr_per_hour"]),
            )
        )
    lines.append("")
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sanity-check Day5 fbeta_oof temporal holdout")
    parser.add_argument("--network-data", default="SemanticAware-S7comm-Dataset/processed/network.csv")
    parser.add_argument("--fusion-data", default="SemanticAware-S7comm-Dataset/processed/fusion.csv")
    parser.add_argument("--process-data", default="SemanticAware-S7comm-Dataset/processed/process.csv")
    parser.add_argument("--result-dir", default="ml_results/lodo_day5_fbeta_oof_temporal")
    parser.add_argument("--output-dir", default="ml_results/day5_sanity")
    parser.add_argument("--train-sessions", nargs="+", default=["day1", "day2", "day3", "day4"])
    parser.add_argument("--test-sessions", nargs="+", default=["day5"])
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    report = run(args)
    json_path = output_dir / "summary.json"
    md_path = output_dir / "summary.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(report, md_path)
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    for view in report["views"].values():
        print(
            f"{view['view']}: suspicious_features={len(view['suspicious_feature_columns'])} "
            f"group_overlap={view['train_test_group_overlap_count']} "
            f"duplicates={view['duplicate_test_rows_total']} "
            f"perfect_separators={view['perfect_single_feature_separators_count']}"
        )


if __name__ == "__main__":
    main()
