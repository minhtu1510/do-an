#!/usr/bin/env python3
"""Day-6 binary threshold sensitivity for network-only models.

Thresholds are selected from grouped out-of-fold predictions on the training
partition only. Day 6 is used only after each threshold is locked.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score
from sklearn.model_selection import StratifiedKFold

import train_ml


MODEL_LABELS = {
    "catboost": "CatBoost",
    "logistic_regression": "LR",
    "xgboost": "XGBoost",
    "random_forest": "RF",
}


def collect_grouped_oof_scores(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    groups_train: pd.Series,
    model_name: str,
    seed: int,
    n_splits: int,
    corr_threshold: float,
    labels: Sequence[object],
) -> np.ndarray:
    y_train = y_train.reset_index(drop=True)
    X_train = X_train.reset_index(drop=True)
    groups = groups_train.reset_index(drop=True)
    if y_train.nunique() < 2 or len(y_train) < 2:
        return np.full(len(y_train), np.nan, dtype="float64")

    try:
        if groups.nunique(dropna=True) >= 2:
            split_iter = list(train_ml.make_splits(y_train, groups, n_splits, seed))
        else:
            split_count = min(n_splits, int(y_train.value_counts().min()))
            if split_count < 2:
                return np.full(len(y_train), np.nan, dtype="float64")
            splitter = StratifiedKFold(n_splits=split_count, shuffle=True, random_state=seed)
            split_iter = list(splitter.split(np.zeros(len(y_train)), y_train))
    except ValueError:
        return np.full(len(y_train), np.nan, dtype="float64")

    oof_scores = np.full(len(y_train), np.nan, dtype="float64")
    for inner_train_idx, inner_valid_idx in split_iter:
        y_inner_train = y_train.iloc[inner_train_idx]
        if y_inner_train.nunique() < 2:
            continue
        X_inner_train = X_train.iloc[inner_train_idx].copy()
        X_inner_valid = X_train.iloc[inner_valid_idx].copy()
        X_inner_train, X_inner_valid, _ = train_ml.fold_filter_features(
            X_inner_train,
            X_inner_valid,
            corr_threshold,
        )
        if X_inner_train.empty:
            continue
        inner_model = train_ml.make_models(seed, task="binary").get(model_name)
        if inner_model is None:
            continue
        inner_model.fit(X_inner_train, y_inner_train)
        valid_scores = train_ml.positive_class_scores(
            train_ml.predict_scores(inner_model, X_inner_valid, labels),
            labels,
        )
        if valid_scores is not None:
            oof_scores[inner_valid_idx] = valid_scores
    return oof_scores


def select_macro_f1_threshold(y_true: pd.Series, scores: np.ndarray) -> float:
    y_true_array = np.asarray(y_true).astype(int)
    if len(np.unique(y_true_array)) < 2 or scores.size == 0:
        return 0.5

    thresholds = np.linspace(0.01, 0.99, 199)
    best_threshold = 0.5
    best_score = -1.0
    for threshold in thresholds:
        y_pred = (scores >= threshold).astype(int)
        score = f1_score(y_true_array, y_pred, average="macro", zero_division=0)
        if score > best_score:
            best_score = score
            best_threshold = float(threshold)
    return best_threshold


def threshold_candidates(
    y_train: pd.Series,
    oof_scores: np.ndarray,
    beta: float,
) -> dict[str, float]:
    valid_score_mask = np.isfinite(oof_scores)
    thresholds = {"fixed_0.5": 0.5}
    if valid_score_mask.sum() == 0 or y_train[valid_score_mask].nunique() < 2:
        thresholds["fbeta_oof_f2"] = 0.5
        thresholds["macro_f1_oof"] = 0.5
        return thresholds

    y_valid = y_train[valid_score_mask]
    scores_valid = oof_scores[valid_score_mask]
    thresholds["fbeta_oof_f2"] = train_ml.tune_fbeta_threshold(y_valid, scores_valid, beta)
    thresholds["macro_f1_oof"] = select_macro_f1_threshold(y_valid, scores_valid)
    return thresholds


def run(args: argparse.Namespace) -> tuple[pd.DataFrame, pd.DataFrame]:
    data = pd.read_csv(args.network_data, low_memory=False).reset_index(drop=True)
    if "label" not in data.columns or "session_id" not in data.columns:
        raise ValueError("network data must contain label and session_id columns")

    y = (~data["label"].map(train_ml.is_benign_label)).astype(int).reset_index(drop=True)
    X_all, feature_cols, dropped = train_ml.select_feature_matrix(
        data,
        leakage_mode=False,
        feature_profile=args.feature_profile,
    )
    if X_all.empty:
        raise ValueError("no usable features after leakage-safe selection")

    sessions = data["session_id"].astype(str)
    train_sessions = {str(value) for value in args.train_sessions}
    test_sessions = {str(value) for value in args.test_sessions}
    train_mask = sessions.isin(train_sessions).to_numpy()
    test_mask = sessions.isin(test_sessions).to_numpy()
    if not train_mask.any() or not test_mask.any():
        raise ValueError("train/test session selection produced an empty split")

    y_train = y.loc[train_mask].reset_index(drop=True)
    y_test = y.loc[test_mask].reset_index(drop=True)
    groups = train_ml.choose_group_series(data, args.group_col).reset_index(drop=True)
    groups_train = groups.loc[train_mask].reset_index(drop=True)
    sample_hours = train_ml.infer_sample_hours(data, args.default_window_seconds).reset_index(drop=True)
    sample_hours_test = sample_hours.loc[test_mask].reset_index(drop=True)
    labels = [0, 1]

    rows: list[dict[str, object]] = []
    for seed in args.seeds:
        X_train_raw = X_all.loc[train_mask].reset_index(drop=True)
        X_test_raw = X_all.loc[test_mask].reset_index(drop=True)
        X_train, X_test, removed_cols = train_ml.fold_filter_features(
            X_train_raw.copy(),
            X_test_raw.copy(),
            args.corr_threshold,
        )
        if X_train.empty:
            continue

        available_models = train_ml.make_models(seed, task="binary")
        for model_name in args.models:
            model = available_models.get(model_name)
            if model is None:
                print(f"[WARN] model {model_name!r} is not available; skipping")
                continue

            oof_scores = collect_grouped_oof_scores(
                X_train_raw,
                y_train,
                groups_train,
                model_name,
                seed,
                args.n_splits,
                args.corr_threshold,
                labels,
            )
            thresholds = threshold_candidates(y_train, oof_scores, args.binary_threshold_beta)

            model.fit(X_train, y_train)
            y_score = train_ml.predict_scores(model, X_test, labels)
            test_scores = train_ml.positive_class_scores(y_score, labels)
            if test_scores is None:
                print(f"[WARN] model {model_name!r} did not provide attack probabilities; skipping")
                continue

            for threshold_mode, threshold in thresholds.items():
                y_pred = (test_scores >= threshold).astype(int)
                metrics = train_ml.compute_metrics(
                    y_test,
                    y_pred,
                    labels,
                    y_score,
                    "binary",
                    sample_hours_test,
                )
                rows.append({
                    "dataset": "network_only",
                    "feature_profile": args.feature_profile,
                    "model": model_name,
                    "model_label": MODEL_LABELS.get(model_name, model_name),
                    "seed": seed,
                    "threshold_mode": threshold_mode,
                    "threshold": threshold,
                    "threshold_beta": args.binary_threshold_beta if threshold_mode == "fbeta_oof_f2" else np.nan,
                    "train_sessions": ",".join(args.train_sessions),
                    "test_sessions": ",".join(args.test_sessions),
                    "n_train": int(train_mask.sum()),
                    "n_test": int(test_mask.sum()),
                    "n_features_selected": len(feature_cols),
                    "n_features_after_filter": X_train.shape[1],
                    "n_dropped_safe_selector": len(dropped),
                    "n_removed_filter_columns": len(removed_cols),
                    **metrics,
                })

    results = pd.DataFrame(rows)
    if results.empty:
        raise RuntimeError("no threshold sensitivity rows were produced")

    metric_cols = [
        "macro_f1",
        "attack_precision",
        "attack_recall",
        "attack_f1",
        "mcc",
        "balanced_accuracy",
        "pr_auc",
        "fpr_per_hour",
        "tn",
        "fp",
        "fn",
        "tp",
    ]
    summary = results.groupby(["model", "model_label", "threshold_mode"])[metric_cols].agg(["mean", "std"])
    summary.columns = ["_".join(part for part in column if part) for column in summary.columns.to_flat_index()]
    summary = summary.reset_index()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    results.to_csv(output_dir / "threshold_sensitivity.csv", index=False)
    summary.to_csv(output_dir / "threshold_sensitivity_summary_mean_std.csv", index=False)
    return results, summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Day-6 binary threshold sensitivity for network-only models")
    parser.add_argument("--network-data", default="SemanticAware-S7comm-Dataset/processed/network.csv")
    parser.add_argument("--output-dir", default="ml_results/day6_binary_extra")
    parser.add_argument("--feature-profile", choices=train_ml.FEATURE_PROFILES, default="hybrid")
    parser.add_argument("--train-sessions", nargs="+", default=["day1", "day2", "day3", "day4", "day5"])
    parser.add_argument("--test-sessions", nargs="+", default=["day6"])
    parser.add_argument("--models", nargs="+", default=["catboost", "logistic_regression", "xgboost", "random_forest"])
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
