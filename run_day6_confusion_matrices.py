#!/usr/bin/env python3
"""Export normalized Day-6 multiclass confusion matrices for CatBoost."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report

import train_ml


VIEW_PATHS = {
    "network": "SemanticAware-S7comm-Dataset/processed/network.csv",
    "fusion": "SemanticAware-S7comm-Dataset/processed/fusion.csv",
}

PREFERRED_LABEL_ORDER = [
    "BENIGN",
    "SCAN",
    "ENUM",
    "ENUMERATION",
    "FLOOD",
    "RWRITE",
    "SETPOINT_ATTACK",
    "SPOOF",
    "REPLAY",
    "CPU_CONTROL",
    "FUZZ",
    "STEALTHY",
]

MODEL_LABELS = {
    "catboost": "catboost",
    "random_forest": "random_forest",
    "xgboost": "xgboost",
    "logistic_regression": "logistic_regression",
}


def ordered_labels(values: pd.Series) -> list[str]:
    present = {str(value) for value in values.dropna().unique()}
    ordered = [label for label in PREFERRED_LABEL_ORDER if label in present]
    ordered.extend(sorted(present - set(ordered)))
    return ordered


def run_view(view: str, path: str, args: argparse.Namespace) -> dict[str, object]:
    data = pd.read_csv(path, low_memory=False).reset_index(drop=True)
    if "label" not in data.columns or "session_id" not in data.columns:
        raise ValueError(f"{path} must contain label and session_id columns")

    y = data["label"].astype(str).reset_index(drop=True)
    X_all, feature_cols, dropped = train_ml.select_feature_matrix(
        data,
        leakage_mode=False,
        feature_profile=args.feature_profile,
    )
    sessions = data["session_id"].astype(str)
    train_sessions = {str(value) for value in args.train_sessions}
    test_sessions = {str(value) for value in args.test_sessions}
    train_mask = sessions.isin(train_sessions).to_numpy()
    test_mask = sessions.isin(test_sessions).to_numpy()
    if not train_mask.any() or not test_mask.any():
        raise ValueError(f"{view}: train/test session selection produced an empty split")

    X_train_raw = X_all.loc[train_mask].reset_index(drop=True)
    X_test_raw = X_all.loc[test_mask].reset_index(drop=True)
    y_train = y.loc[train_mask].reset_index(drop=True)
    y_test = y.loc[test_mask].reset_index(drop=True)
    X_train, X_test, removed_cols = train_ml.fold_filter_features(
        X_train_raw.copy(),
        X_test_raw.copy(),
        args.corr_threshold,
    )
    if X_train.empty:
        raise ValueError(f"{view}: no features left after fold filtering")

    model = train_ml.make_models(args.seed, task="multiclass").get(args.model)
    if model is None:
        raise ValueError(f"model {args.model!r} is not available")
    model.fit(X_train, y_train)
    y_pred = np.asarray(model.predict(X_test))

    labels = ordered_labels(pd.concat([y_train, y_test], ignore_index=True))
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    model_slug = MODEL_LABELS.get(args.model, args.model)
    base = output_dir / f"day6_{model_slug}_{view}_confusion_matrix"
    train_ml.save_confusion_matrix(y_test, y_pred, labels, str(base))

    report = classification_report(y_test, y_pred, labels=labels, output_dict=True, zero_division=0)
    with (output_dir / f"day6_{model_slug}_{view}_classification_report.json").open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    metrics = train_ml.compute_metrics(
        y_test,
        y_pred,
        labels,
        train_ml.predict_scores(model, X_test, labels),
        "multiclass",
    )
    return {
        "view": view,
        "model": args.model,
        "seed": args.seed,
        "train_sessions": ",".join(args.train_sessions),
        "test_sessions": ",".join(args.test_sessions),
        "n_train": int(train_mask.sum()),
        "n_test": int(test_mask.sum()),
        "n_features_selected": len(feature_cols),
        "n_dropped_safe_selector": len(dropped),
        "n_features_after_filter": X_train.shape[1],
        "n_removed_filter_columns": len(removed_cols),
        "confusion_counts_csv": str(base) + ".csv",
        "confusion_normalized_csv": str(base) + "_normalized_true.csv",
        "confusion_pdf": str(base) + ".pdf",
        **metrics,
    }


def run(args: argparse.Namespace) -> pd.DataFrame:
    rows = []
    for view in args.views:
        rows.append(run_view(view, VIEW_PATHS[view], args))
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    results = pd.DataFrame(rows)
    results.to_csv(output_dir / "day6_confusion_matrix_metrics.csv", index=False)
    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export Day-6 multiclass confusion matrices")
    parser.add_argument("--output-dir", default="ml_results/day6_confusion_matrices")
    parser.add_argument("--feature-profile", choices=train_ml.FEATURE_PROFILES, default="hybrid")
    parser.add_argument("--train-sessions", nargs="+", default=["day1", "day2", "day3", "day4", "day5"])
    parser.add_argument("--test-sessions", nargs="+", default=["day6"])
    parser.add_argument("--views", nargs="+", choices=sorted(VIEW_PATHS), default=["network", "fusion"])
    parser.add_argument("--model", choices=sorted(MODEL_LABELS), default="catboost")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--corr-threshold", type=float, default=0.98)
    return parser.parse_args()


def main() -> None:
    results = run(parse_args())
    print(results.to_string(index=False))


if __name__ == "__main__":
    main()
