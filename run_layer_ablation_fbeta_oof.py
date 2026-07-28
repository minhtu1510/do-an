#!/usr/bin/env python3
"""Run layer-wise binary ablation with out-of-fold F-beta thresholding.

The main evaluator exposes view/profile ablations, while the paper table needs a
semantic layer taxonomy (L0-L3). This runner keeps the protocol aligned with
train_ml.py by importing the same preprocessing, model, threshold, and metric
helpers.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

import train_ml


ICS_PRESENCE_PREFIXES = (
    "dcp_",
    "tpkt_",
    "cotp_",
    "pres_",
    "to_plc_",
    "from_plc_",
)

ICS_PRESENCE_EXACT = {
    "s7comm_packet_count",
    "s7comm_plus_packet_count",
    "plc_response_gap_max_ms",
    "fr_s7_present",
    "fr_s7_packet_share",
    "fr_to_plc_packet_share",
}


def classify_layer(column: str) -> str:
    if column.startswith("proc__"):
        return "L3"
    if column in ICS_PRESENCE_EXACT or column.startswith(ICS_PRESENCE_PREFIXES):
        return "L1"
    if column.startswith("s7_") or column.startswith("fr_s7_"):
        return "L2"
    return "L0"


def flatten_summary_columns(summary: pd.DataFrame) -> pd.DataFrame:
    summary.columns = ["_".join(part for part in col if part) for col in summary.columns.to_flat_index()]
    return summary.reset_index()


def select_config_columns(layer_by_column: dict[str, str], layers: Iterable[str]) -> list[str]:
    wanted = set(layers)
    return [column for column, layer in layer_by_column.items() if layer in wanted]


def run(args: argparse.Namespace) -> tuple[pd.DataFrame, pd.DataFrame]:
    df = pd.read_csv(args.fusion_data, low_memory=False)
    if "label" not in df.columns or "session_id" not in df.columns:
        raise ValueError("fusion data must contain label and session_id columns")

    y = (~df["label"].map(train_ml.is_benign_label)).astype(int).reset_index(drop=True)
    data = df.reset_index(drop=True)
    X_all, kept, dropped = train_ml.select_feature_matrix(
        data,
        leakage_mode=False,
        feature_profile=args.feature_profile,
    )
    layer_by_column = {column: classify_layer(column) for column in kept}

    train_sessions = set(args.train_sessions)
    test_sessions = set(args.test_sessions)
    session = data["session_id"].astype(str)
    train_mask = session.isin(train_sessions).to_numpy()
    test_mask = session.isin(test_sessions).to_numpy()
    if not train_mask.any() or not test_mask.any():
        raise ValueError("train/test session selection produced an empty split")

    y_train = y.loc[train_mask].reset_index(drop=True)
    y_test = y.loc[test_mask].reset_index(drop=True)
    groups = train_ml.choose_group_series(data, args.group_col).reset_index(drop=True)
    groups_train = groups.loc[train_mask].reset_index(drop=True)
    sample_hours = train_ml.infer_sample_hours(data, args.default_window_seconds).reset_index(drop=True)
    sample_hours_test = sample_hours.loc[test_mask].reset_index(drop=True)
    labels = [0, 1]

    configs = [
        ("A - Network volume only", "L0", ("L0",)),
        ("B - + ICS presence", "L0+L1", ("L0", "L1")),
        ("C - + S7 op semantics", "L0+L1+L2", ("L0", "L1", "L2")),
        ("D - + Process state", "L0+L1+L2+L3", ("L0", "L1", "L2", "L3")),
    ]

    rows: list[dict[str, object]] = []
    for config_name, layer_label, layers in configs:
        columns = select_config_columns(layer_by_column, layers)
        if not columns:
            raise ValueError(f"no features selected for {config_name}")
        for seed in args.seeds:
            X_train_raw = X_all.loc[train_mask, columns].reset_index(drop=True)
            X_test_raw = X_all.loc[test_mask, columns].reset_index(drop=True)
            threshold = train_ml.tune_fbeta_threshold_oof(
                X_train_raw,
                y_train,
                groups_train,
                args.model,
                seed,
                args.n_splits,
                args.corr_threshold,
                labels,
                args.binary_threshold_beta,
            )
            X_train, X_test, removed_cols = train_ml.fold_filter_features(
                X_train_raw.copy(),
                X_test_raw.copy(),
                args.corr_threshold,
            )
            model = train_ml.make_models(seed, task="binary").get(args.model)
            if model is None:
                raise ValueError(f"model {args.model!r} is not available")
            model.fit(X_train, y_train)
            y_pred, y_score, applied_threshold = train_ml.predict_with_optional_binary_threshold(
                model,
                X_train,
                y_train,
                X_test,
                labels,
                "binary",
                "fbeta_oof",
                args.binary_threshold_beta,
                None,
                threshold,
            )
            metrics = train_ml.compute_metrics(y_test, y_pred, labels, y_score, "binary", sample_hours_test)
            rows.append(
                {
                    "config": config_name,
                    "layers": layer_label,
                    "model": args.model,
                    "seed": seed,
                    "threshold_mode": "fbeta_oof",
                    "threshold_beta": args.binary_threshold_beta,
                    "threshold": applied_threshold,
                    "features_selected": len(columns),
                    "features_after_filter": X_train.shape[1],
                    "removed_fold_columns": len(removed_cols),
                    "train_sessions": ",".join(args.train_sessions),
                    "test_sessions": ",".join(args.test_sessions),
                    "n_train": int(train_mask.sum()),
                    "n_test": int(test_mask.sum()),
                    **metrics,
                }
            )

    results = pd.DataFrame(rows)
    metric_cols = [
        "balanced_accuracy",
        "macro_f1",
        "macro_precision",
        "macro_recall",
        "mcc",
        "false_positive_count",
        "benign_hours",
        "fpr_per_hour",
        "pr_auc_macro",
        "features_selected",
        "features_after_filter",
    ]
    summary = results.groupby(["config", "layers", "model", "threshold_mode"])[metric_cols].agg(["mean", "std"])
    summary = flatten_summary_columns(summary)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    results.to_csv(output_dir / "ablation_results.csv", index=False)
    summary.to_csv(output_dir / "summary_mean_std.csv", index=False)
    with (output_dir / "feature_layers.json").open("w", encoding="utf-8") as f:
        json.dump(
            {
                "feature_profile": args.feature_profile,
                "dropped_by_safe_selector": dropped,
                "layers": {
                    layer: [column for column, assigned in layer_by_column.items() if assigned == layer]
                    for layer in ("L0", "L1", "L2", "L3")
                },
            },
            f,
            indent=2,
        )
    return results, summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Layer-wise ablation with fbeta_oof thresholding")
    parser.add_argument("--fusion-data", default="SemanticAware-S7comm-Dataset/processed/fusion.csv")
    parser.add_argument("--output-dir", default="ml_results/ablation_layers_fbeta_oof")
    parser.add_argument("--feature-profile", choices=train_ml.FEATURE_PROFILES, default="hybrid")
    parser.add_argument("--train-sessions", nargs="+", default=["day1", "day2", "day3", "day4"])
    parser.add_argument("--test-sessions", nargs="+", default=["day6"])
    parser.add_argument("--model", default="catboost")
    parser.add_argument("--seeds", nargs="*", type=int, default=[42, 43, 44, 45, 46])
    parser.add_argument("--n-splits", type=int, default=5)
    parser.add_argument("--group-col", default="auto")
    parser.add_argument("--corr-threshold", type=float, default=0.98)
    parser.add_argument("--default-window-seconds", type=float, default=2.0)
    parser.add_argument("--binary-threshold-beta", type=float, default=2.0)
    return parser.parse_args()


def main() -> None:
    _, summary = run(parse_args())
    print(summary.to_string(index=False))


if __name__ == "__main__":
    main()
