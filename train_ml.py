#!/usr/bin/env python3
"""Grouped, leakage-aware ML evaluation for ICS/PLC IDS datasets.

This script is intentionally conservative: metadata, timestamps, capture roles,
IP/MAC/port identity columns, rule flags, and hand-written anomaly outputs are
dropped from ML feature matrices unless the dataset is passed as an explicit
leakage-ablation input.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import warnings
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_recall_curve,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, label_binarize

try:
    from sklearn.model_selection import StratifiedGroupKFold
except Exception:  # pragma: no cover - older sklearn fallback
    StratifiedGroupKFold = None

warnings.filterwarnings("ignore")

try:
    import seaborn as sns  # type: ignore
except Exception:  # pragma: no cover - optional plotting dependency
    sns = None


# ---------------------------------------------------------------------------
# Leakage policy
# ---------------------------------------------------------------------------

ALWAYS_DROP = {
    "label",
    "label_network",
    "label_system",
    "plc_under_attack",
    "extractor_label",
}

SAFE_DROP_EXACT = {
    # metadata / grouping / time
    "window_start_ms", "window_end_ms", "window_start", "window_end",
    "timestamp_ms", "timestamp", "frame.time_epoch",
    "session_id", "episode_id", "host_id", "scenario_id", "day", "dataset_view",
    "capture_role", "capture_source", "source_file", "plc_ip", "decode_level", "mitre_technique",
    "poll_seq", "_window_mid_ms",

    # raw identity / endpoint columns
    "src_ip", "dst_ip", "src_mac", "dst_mac", "src_port", "dst_port",
    "src_id", "dst_id", "protocol", "top_src_ip", "top_dst_ip", "top_protocol", "top_dst_port",

    # raw dumps / hashes
    "q_raw_hex", "m_raw_hex", "q0_raw_hex", "i0_raw_hex",

    # identity/stack proxy features: acceptable for forensics, unsafe for paper ML
    "unique_src_ip_count", "unique_dst_ip_count",
    "unique_src_mac_count", "unique_dst_mac_count",
    "arp_unique_sender_mac_count",
    "dcp_unique_scanner_mac_count", "dcp_unique_device_mac_count",
    "fwd_init_win_bytes", "bwd_init_win_bytes",
}

RULE_SUBSTRINGS = (
    "scan_detected",
    "green_conflict",
    "red_green",
    "multi_light",
    "no_light",
    "timer_out_of_range",
    "setpoint_corrupted",
    "q_output_unexpected",
    "belt_stopped_unexpectedly",
    "stop_flag_unexpected",
    "all_sensors_active",
    "sensor_vs_belt_conflict",
    "cd_timer_out_of_range",
    "cd_timer_corrupted",
)

RULE_EXACT = {
    "scan_detected_rule",
    "dcp_scan_detected_rule",
    "dcp_scan_detected",
}

UNSAFE_SUFFIXES = ("_score",)

DEFAULT_GROUP_COLUMNS = ("session_id", "host_id", "episode_id")
AUDIT_METADATA_COLUMNS = (
    "session_id", "host_id", "episode_id", "scenario_id", "dataset_view",
    "capture_source", "capture_role", "dataset_file",
)


def is_benign_label(value: object) -> bool:
    label = str(value).strip().upper()
    return label in {"BENIGN", "BENIGN_NORMAL", "NORMAL", ""} or label.startswith("BENIGN")


def is_rule_column(col: str) -> bool:
    c = col.lower()
    return col in RULE_EXACT or any(token in c for token in RULE_SUBSTRINGS)


def is_unsafe_safe_ml_column(col: str) -> bool:
    c = col.lower()
    return (
        col in SAFE_DROP_EXACT
        or is_rule_column(col)
        or any(c.endswith(suffix) for suffix in UNSAFE_SUFFIXES)
    )


def slug(value: object) -> str:
    text = str(value)
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", text)
    return text.strip("_") or "unknown"


def expand_paths(patterns: Optional[Sequence[str]]) -> List[str]:
    paths: List[str] = []
    for pattern in patterns or []:
        matches = glob.glob(pattern)
        paths.extend(matches if matches else [pattern])
    seen = set()
    out = []
    for path in paths:
        if path not in seen and os.path.exists(path):
            out.append(path)
            seen.add(path)
        elif path not in seen:
            print(f"[WARN] Dataset path not found: {path}")
            seen.add(path)
    return out


def load_dataset(paths: Sequence[str], dataset_name: str) -> pd.DataFrame:
    frames = []
    for path in paths:
        df = pd.read_csv(path, low_memory=False)
        df["dataset_file"] = os.path.basename(path)
        frames.append(df)
        print(f"[LOAD] {dataset_name}: {path} shape={df.shape}")
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True, sort=False)


def select_feature_matrix(df: pd.DataFrame, leakage_mode: bool) -> Tuple[pd.DataFrame, List[str], List[str]]:
    dropped: List[str] = []
    kept: List[str] = []
    for col in df.columns:
        if col in ALWAYS_DROP:
            dropped.append(col)
            continue
        if not leakage_mode and is_unsafe_safe_ml_column(col):
            dropped.append(col)
            continue
        kept.append(col)

    X = df[kept].copy()
    # Convert numeric-looking object columns; nonnumeric IDs become NaN and are dropped.
    converted = {}
    nonnumeric = []
    for col in X.columns:
        numeric = pd.to_numeric(X[col], errors="coerce")
        if numeric.notna().any():
            converted[col] = numeric
        else:
            nonnumeric.append(col)
    if nonnumeric:
        dropped.extend(nonnumeric)
    X = pd.DataFrame(converted, index=df.index)
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return X, list(X.columns), dropped


def parse_group_columns(requested: str) -> List[str]:
    return [part.strip() for part in re.split(r"[,/;+\s]+", requested) if part.strip()]


def composite_group_series(df: pd.DataFrame, columns: Sequence[str]) -> pd.Series:
    values = df[list(columns)].astype(str).fillna("unknown_group")
    return values.agg("|".join, axis=1)


def choose_group_series(df: pd.DataFrame, requested: str) -> pd.Series:
    requested = (requested or "auto").strip()
    if requested != "auto":
        requested_cols = parse_group_columns(requested)
        missing = [col for col in requested_cols if col not in df.columns]
        if requested_cols and not missing:
            print(f"[INFO] Using requested group columns: {', '.join(requested_cols)}")
            return composite_group_series(df, requested_cols)
        print(f"[WARN] Requested group column(s) unavailable: {', '.join(missing or requested_cols)}")

    composite_cols = [col for col in DEFAULT_GROUP_COLUMNS if col in df.columns]
    if composite_cols:
        groups = composite_group_series(df, composite_cols)
        if groups.nunique(dropna=True) >= 2:
            print(f"[INFO] Using composite group columns: {', '.join(composite_cols)}")
            return groups

    for col in ["episode_id", "session_id", "host_id", "dataset_file", "scenario_id"]:
        if col in df.columns and df[col].nunique(dropna=True) >= 2:
            print(f"[INFO] Using fallback group column: {col}")
            return df[col].astype(str).fillna("unknown_group")

    print("[WARN] No usable group column found; assigning one group per row. This is not publication-grade.")
    return pd.Series([f"row_{i}" for i in range(len(df))], index=df.index)


def make_splits(y: pd.Series, groups: pd.Series, n_splits: int, seed: int):
    n_groups = groups.nunique()
    if n_groups < 2:
        raise ValueError("Need at least two groups for grouped evaluation")
    splits = min(n_splits, n_groups)
    if StratifiedGroupKFold is not None and splits >= 2:
        splitter = StratifiedGroupKFold(n_splits=splits, shuffle=True, random_state=seed)
        return splitter.split(np.zeros(len(y)), y, groups)
    splitter = GroupKFold(n_splits=splits)
    return splitter.split(np.zeros(len(y)), y, groups)


def fold_filter_features(
    X_train: pd.DataFrame,
    X_test: pd.DataFrame,
    corr_threshold: float,
) -> Tuple[pd.DataFrame, pd.DataFrame, List[str]]:
    constant_cols = [c for c in X_train.columns if X_train[c].nunique(dropna=False) <= 1]
    X_train = X_train.drop(columns=constant_cols)
    X_test = X_test.drop(columns=[c for c in constant_cols if c in X_test.columns])

    corr_drop: List[str] = []
    if X_train.shape[1] > 1:
        corr = X_train.corr().abs()
        upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
        corr_drop = [col for col in upper.columns if any(upper[col] > corr_threshold)]
        X_train = X_train.drop(columns=corr_drop)
        X_test = X_test.drop(columns=[c for c in corr_drop if c in X_test.columns])

    X_test = X_test.reindex(columns=X_train.columns, fill_value=0.0)
    return X_train, X_test, constant_cols + corr_drop


def make_models(seed: int) -> Dict[str, object]:
    return {
        "random_forest": RandomForestClassifier(
            n_estimators=300,
            random_state=seed,
            n_jobs=-1,
            class_weight="balanced_subsample",
            min_samples_leaf=2,
        ),
        "logistic_regression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", n_jobs=-1)),
        ]),
    }


def macro_false_positive_rate(y_true: np.ndarray, y_pred: np.ndarray, labels: Sequence[object]) -> float:
    rates = []
    for label in labels:
        true_pos = y_true == label
        pred_pos = y_pred == label
        fp = int((~true_pos & pred_pos).sum())
        tn = int((~true_pos & ~pred_pos).sum())
        rates.append(fp / max(fp + tn, 1))
    return float(np.mean(rates)) if rates else float("nan")


def infer_sample_hours(df: pd.DataFrame, default_window_seconds: float) -> pd.Series:
    default_hours = max(float(default_window_seconds), 0.0) / 3600.0
    if {"window_start_ms", "window_end_ms"}.issubset(df.columns):
        start = pd.to_numeric(df["window_start_ms"], errors="coerce")
        end = pd.to_numeric(df["window_end_ms"], errors="coerce")
        hours = (end - start) / 3_600_000.0
        hours = hours.where(hours > 0, default_hours)
        return hours.fillna(default_hours)
    return pd.Series(default_hours, index=df.index, dtype="float64")


def compute_metrics(
    y_true: pd.Series,
    y_pred: np.ndarray,
    labels: Sequence[object],
    y_score: Optional[np.ndarray],
    task: str,
    sample_hours: Optional[pd.Series] = None,
) -> Dict[str, float]:
    y_true_array = np.asarray(y_true)
    y_pred_array = np.asarray(y_pred)
    if task == "binary":
        benign_mask = y_true_array == 0
        false_positive_mask = benign_mask & (y_pred_array == 1)
    else:
        benign_mask = np.array([is_benign_label(v) for v in y_true_array])
        false_positive_mask = benign_mask & np.array([not is_benign_label(v) for v in y_pred_array])

    benign_hours = float("nan")
    false_positives_per_hour = float("nan")
    if sample_hours is not None:
        hours = pd.to_numeric(sample_hours, errors="coerce").fillna(0.0).to_numpy()
        benign_hours = float(hours[benign_mask].sum())
        if benign_hours > 0:
            false_positives_per_hour = float(false_positive_mask.sum() / benign_hours)

    out = {
        "balanced_accuracy": balanced_accuracy_score(y_true, y_pred),
        "macro_f1": f1_score(y_true, y_pred, average="macro", zero_division=0),
        "macro_precision": precision_score(y_true, y_pred, average="macro", zero_division=0),
        "macro_recall": recall_score(y_true, y_pred, average="macro", zero_division=0),
        "mcc": matthews_corrcoef(y_true, y_pred),
        "false_positive_rate_macro": macro_false_positive_rate(np.asarray(y_true), np.asarray(y_pred), labels),
        "false_positive_count": float(false_positive_mask.sum()),
        "benign_hours": benign_hours,
        "fpr_per_hour": false_positives_per_hour,
        "pr_auc_macro": float("nan"),
    }
    if y_score is not None:
        try:
            if task == "binary":
                score = y_score[:, 1] if y_score.ndim == 2 and y_score.shape[1] > 1 else y_score.ravel()
                out["pr_auc_macro"] = average_precision_score(y_true, score)
            else:
                y_bin = label_binarize(y_true, classes=list(labels))
                out["pr_auc_macro"] = average_precision_score(y_bin, y_score, average="macro")
        except Exception:
            pass
    return out


def predict_scores(model: object, X_test: pd.DataFrame, labels: Sequence[object]) -> Optional[np.ndarray]:
    if not hasattr(model, "predict_proba"):
        return None
    try:
        probs = model.predict_proba(X_test)
        model_classes = list(getattr(model, "classes_", labels))
        aligned = np.zeros((len(X_test), len(labels)))
        for idx, cls in enumerate(model_classes):
            if cls in labels:
                aligned[:, list(labels).index(cls)] = probs[:, idx]
        return aligned
    except Exception:
        return None


def save_confusion_matrix(
    y_true: pd.Series,
    y_pred: np.ndarray,
    labels: Sequence[object],
    path_base: str,
) -> None:
    cm = confusion_matrix(y_true, y_pred, labels=list(labels))
    pd.DataFrame(cm, index=labels, columns=labels).to_csv(path_base + ".csv")
    plt.figure(figsize=(max(6, len(labels) * 0.8), max(5, len(labels) * 0.7)))
    if sns is not None:
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=labels, yticklabels=labels)
    else:
        plt.imshow(cm, interpolation="nearest", cmap="Blues")
        plt.colorbar()
        plt.xticks(range(len(labels)), labels, rotation=45, ha="right")
        plt.yticks(range(len(labels)), labels)
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                plt.text(j, i, str(cm[i, j]), ha="center", va="center", color="black")
    plt.xlabel("Predicted")
    plt.ylabel("True")
    plt.tight_layout()
    plt.savefig(path_base + ".png", dpi=180)
    plt.close()


def save_pr_curve(y_true: pd.Series, y_score: Optional[np.ndarray], path: str) -> None:
    if y_score is None:
        return
    try:
        score = y_score[:, 1] if y_score.ndim == 2 and y_score.shape[1] > 1 else y_score.ravel()
        precision, recall, _ = precision_recall_curve(y_true, score)
        plt.figure(figsize=(6, 5))
        plt.plot(recall, precision)
        plt.xlabel("Recall")
        plt.ylabel("Precision")
        plt.tight_layout()
        plt.savefig(path, dpi=180)
        plt.close()
    except Exception:
        return


def save_feature_importance(model: object, features: Sequence[str], path: str, top_n: int = 25) -> None:
    importances = None
    if hasattr(model, "feature_importances_"):
        importances = np.asarray(model.feature_importances_)
    elif isinstance(model, Pipeline):
        clf = model.named_steps.get("clf")
        if hasattr(clf, "coef_"):
            importances = np.mean(np.abs(clf.coef_), axis=0)
    if importances is None or len(importances) != len(features):
        return
    series = pd.Series(importances, index=features).sort_values(ascending=False).head(top_n)
    series.to_csv(path + ".csv", header=["importance"])
    plt.figure(figsize=(9, max(5, len(series) * 0.32)))
    if sns is not None:
        sns.barplot(x=series.values, y=series.index, color="#3b82f6")
    else:
        plt.barh(range(len(series)), series.values, color="#3b82f6")
        plt.yticks(range(len(series)), series.index)
        plt.gca().invert_yaxis()
    plt.xlabel("Importance")
    plt.ylabel("Feature")
    plt.tight_layout()
    plt.savefig(path + ".png", dpi=180)
    plt.close()


def run_ml_experiment(
    df: pd.DataFrame,
    experiment: str,
    output_dir: str,
    leakage_mode: bool,
    n_splits: int,
    seeds: Sequence[int],
    group_col: str,
    tasks: Sequence[str],
    corr_threshold: float,
    default_window_seconds: float,
) -> List[Dict[str, object]]:
    if df.empty or "label" not in df.columns:
        print(f"[SKIP] {experiment}: no rows or no label column")
        return []

    exp_dir = os.path.join(output_dir, slug(experiment))
    os.makedirs(exp_dir, exist_ok=True)
    rows: List[Dict[str, object]] = []

    for task in tasks:
        y = (~df["label"].map(is_benign_label)).astype(int) if task == "binary" else df["label"].astype(str)
        valid = y.notna()
        y = y[valid]
        data = df.loc[valid].reset_index(drop=True)
        y = y.reset_index(drop=True)
        if y.nunique() < 2:
            print(f"[SKIP] {experiment}/{task}: only one class")
            continue

        X_all, feature_cols, dropped = select_feature_matrix(data, leakage_mode=leakage_mode)
        if X_all.empty:
            print(f"[SKIP] {experiment}/{task}: no usable features")
            continue
        groups = choose_group_series(data, group_col).reset_index(drop=True)
        sample_hours = infer_sample_hours(data, default_window_seconds).reset_index(drop=True)
        labels = sorted(y.unique().tolist())
        print(
            f"[EXP] {experiment}/{task}: rows={len(data)} features={len(feature_cols)} "
            f"groups={groups.nunique()} dropped={len(dropped)} leakage_mode={leakage_mode}"
        )

        for seed in seeds:
            try:
                split_iter = list(make_splits(y, groups, n_splits, seed))
            except ValueError as exc:
                print(f"[SKIP] {experiment}/{task}: {exc}")
                continue

            for fold_idx, (train_idx, test_idx) in enumerate(split_iter, start=1):
                X_train = X_all.iloc[train_idx].copy()
                X_test = X_all.iloc[test_idx].copy()
                y_train = y.iloc[train_idx]
                y_test = y.iloc[test_idx]
                X_train, X_test, removed_fold_cols = fold_filter_features(X_train, X_test, corr_threshold)
                if X_train.empty:
                    continue

                for model_name, model in make_models(seed).items():
                    model.fit(X_train, y_train)
                    y_pred = model.predict(X_test)
                    y_score = predict_scores(model, X_test, labels)
                    metrics = compute_metrics(y_test, y_pred, labels, y_score, task, sample_hours.iloc[test_idx])
                    row = {
                        "experiment": experiment,
                        "validation_type": "group_cv",
                        "task": task,
                        "model": model_name,
                        "seed": seed,
                        "fold": fold_idx,
                        "n_train": len(train_idx),
                        "n_test": len(test_idx),
                        "n_features": X_train.shape[1],
                        "n_groups_train": groups.iloc[train_idx].nunique(),
                        "n_groups_test": groups.iloc[test_idx].nunique(),
                        "removed_fold_columns": len(removed_fold_cols),
                        **metrics,
                    }
                    rows.append(row)

                    base = os.path.join(exp_dir, f"{task}_{model_name}_seed{seed}_fold{fold_idx}")
                    save_confusion_matrix(y_test, y_pred, labels, base + "_confusion")
                    if task == "binary":
                        save_pr_curve(y_test, y_score, base + "_pr_curve.png")
                    with open(base + "_report.json", "w", encoding="utf-8") as f:
                        json.dump(classification_report(y_test, y_pred, output_dict=True, zero_division=0), f, indent=2)
                    save_feature_importance(model, list(X_train.columns), base + "_feature_importance")

    return rows


def run_rule_baseline(
    df: pd.DataFrame,
    experiment: str,
    output_dir: str,
    n_splits: int,
    seeds: Sequence[int],
    group_col: str,
    default_window_seconds: float,
) -> List[Dict[str, object]]:
    if df.empty or "label" not in df.columns:
        return []
    rule_cols = [c for c in df.columns if is_rule_column(c)]
    if not rule_cols:
        print(f"[RULE] {experiment}: no rule columns found")
        return []

    y = (~df["label"].map(is_benign_label)).astype(int).reset_index(drop=True)
    if y.nunique() < 2:
        return []
    data = df.reset_index(drop=True)
    X_rule = data[rule_cols].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    pred_all = (X_rule.gt(0).any(axis=1)).astype(int)
    groups = choose_group_series(data, group_col).reset_index(drop=True)
    sample_hours = infer_sample_hours(data, default_window_seconds).reset_index(drop=True)
    labels = [0, 1]
    rows: List[Dict[str, object]] = []

    exp_dir = os.path.join(output_dir, slug(experiment + "_rule_baseline"))
    os.makedirs(exp_dir, exist_ok=True)
    for seed in seeds:
        try:
            split_iter = list(make_splits(y, groups, n_splits, seed))
        except ValueError:
            continue
        for fold_idx, (_, test_idx) in enumerate(split_iter, start=1):
            y_test = y.iloc[test_idx]
            y_pred = pred_all.iloc[test_idx].to_numpy()
            y_score = y_pred.reshape(-1, 1)
            metrics = compute_metrics(y_test, y_pred, labels, y_score, "binary", sample_hours.iloc[test_idx])
            row = {
                "experiment": experiment,
                "validation_type": "group_cv",
                "task": "binary",
                "model": "rule_baseline",
                "seed": seed,
                "fold": fold_idx,
                "n_train": 0,
                "n_test": len(test_idx),
                "n_features": len(rule_cols),
                "n_groups_train": 0,
                "n_groups_test": groups.iloc[test_idx].nunique(),
                "removed_fold_columns": 0,
                **metrics,
            }
            rows.append(row)
            base = os.path.join(exp_dir, f"binary_rule_seed{seed}_fold{fold_idx}")
            save_confusion_matrix(y_test, y_pred, labels, base + "_confusion")
    return rows


def build_validation_mask(
    df: pd.DataFrame,
    validation_host_ids: Sequence[str],
    validation_session_ids: Sequence[str],
) -> pd.Series:
    mask = pd.Series(True, index=df.index)
    if validation_host_ids:
        if "host_id" not in df.columns:
            return pd.Series(False, index=df.index)
        host_set = {str(v) for v in validation_host_ids}
        mask &= df["host_id"].astype(str).isin(host_set)
    if validation_session_ids:
        if "session_id" not in df.columns:
            return pd.Series(False, index=df.index)
        session_set = {str(v) for v in validation_session_ids}
        mask &= df["session_id"].astype(str).isin(session_set)
    return mask


def run_holdout_experiment(
    df: pd.DataFrame,
    experiment: str,
    output_dir: str,
    leakage_mode: bool,
    validation_host_ids: Sequence[str],
    validation_session_ids: Sequence[str],
    seeds: Sequence[int],
    tasks: Sequence[str],
    corr_threshold: float,
    default_window_seconds: float,
) -> List[Dict[str, object]]:
    if df.empty or "label" not in df.columns:
        return []
    if not validation_host_ids and not validation_session_ids:
        return []

    validation_mask = build_validation_mask(df, validation_host_ids, validation_session_ids)
    if not validation_mask.any():
        print(f"[HOLDOUT] {experiment}: requested validation host/session not present")
        return []
    if validation_mask.all():
        print(f"[HOLDOUT] {experiment}: validation selection leaves no training rows")
        return []

    exp_dir = os.path.join(output_dir, slug(experiment + "_host_holdout"))
    os.makedirs(exp_dir, exist_ok=True)
    rows: List[Dict[str, object]] = []

    for task in tasks:
        y = (~df["label"].map(is_benign_label)).astype(int) if task == "binary" else df["label"].astype(str)
        valid = y.notna()
        data = df.loc[valid].reset_index(drop=True)
        y = y.loc[valid].reset_index(drop=True)
        holdout_mask = validation_mask.loc[valid].reset_index(drop=True)
        if y.nunique() < 2:
            continue

        train_idx = np.flatnonzero(~holdout_mask.to_numpy())
        test_idx = np.flatnonzero(holdout_mask.to_numpy())
        y_train = y.iloc[train_idx]
        y_test = y.iloc[test_idx]
        if y_train.nunique() < 2:
            print(f"[HOLDOUT] {experiment}/{task}: training split has one class")
            continue
        if y_test.empty:
            continue

        X_all, feature_cols, dropped = select_feature_matrix(data, leakage_mode=leakage_mode)
        if X_all.empty:
            continue
        sample_hours = infer_sample_hours(data, default_window_seconds).reset_index(drop=True)
        labels = sorted(y.unique().tolist())
        print(
            f"[HOLDOUT] {experiment}/{task}: train={len(train_idx)} test={len(test_idx)} "
            f"features={len(feature_cols)} dropped={len(dropped)} hosts={list(validation_host_ids)} "
            f"sessions={list(validation_session_ids)}"
        )

        for seed in seeds:
            X_train = X_all.iloc[train_idx].copy()
            X_test = X_all.iloc[test_idx].copy()
            X_train, X_test, removed_fold_cols = fold_filter_features(X_train, X_test, corr_threshold)
            if X_train.empty:
                continue

            for model_name, model in make_models(seed).items():
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)
                y_score = predict_scores(model, X_test, labels)
                metrics = compute_metrics(y_test, y_pred, labels, y_score, task, sample_hours.iloc[test_idx])
                row = {
                    "experiment": experiment,
                    "validation_type": "host_holdout",
                    "task": task,
                    "model": model_name,
                    "seed": seed,
                    "fold": 0,
                    "n_train": len(train_idx),
                    "n_test": len(test_idx),
                    "n_features": X_train.shape[1],
                    "n_groups_train": np.nan,
                    "n_groups_test": np.nan,
                    "removed_fold_columns": len(removed_fold_cols),
                    "validation_host_ids": ",".join(map(str, validation_host_ids)),
                    "validation_session_ids": ",".join(map(str, validation_session_ids)),
                    **metrics,
                }
                rows.append(row)

                base = os.path.join(exp_dir, f"{task}_{model_name}_seed{seed}_holdout")
                save_confusion_matrix(y_test, y_pred, labels, base + "_confusion")
                if task == "binary":
                    save_pr_curve(y_test, y_score, base + "_pr_curve.png")
                with open(base + "_report.json", "w", encoding="utf-8") as f:
                    json.dump(classification_report(y_test, y_pred, output_dict=True, zero_division=0), f, indent=2)
                save_feature_importance(model, list(X_train.columns), base + "_feature_importance")

    return rows


def write_metric_tables(rows: List[Dict[str, object]], output_dir: str) -> None:
    if not rows:
        print("[WARN] No metrics produced")
        return
    metrics = pd.DataFrame(rows)
    os.makedirs(output_dir, exist_ok=True)
    metrics.to_csv(os.path.join(output_dir, "all_fold_metrics.csv"), index=False)
    metric_cols = [
        "balanced_accuracy", "macro_f1", "macro_precision", "macro_recall",
        "mcc", "false_positive_rate_macro", "false_positive_count",
        "benign_hours", "fpr_per_hour", "pr_auc_macro",
    ]
    summary = metrics.groupby(["experiment", "validation_type", "task", "model"])[metric_cols].agg(["mean", "std"])
    summary.to_csv(os.path.join(output_dir, "summary_mean_std.csv"))
    print("\n[SUMMARY]")
    print(summary.to_string())


def value_counts_dict(df: pd.DataFrame, col: str) -> Dict[str, int]:
    if col not in df.columns:
        return {}
    return {str(k): int(v) for k, v in df[col].fillna("NA").astype(str).value_counts().items()}


def audit_dataset(name: str, df: pd.DataFrame, leakage_mode: bool) -> Dict[str, Any]:
    if df.empty:
        return {"name": name, "rows": 0, "leakage_mode": leakage_mode}
    _, kept, dropped = select_feature_matrix(df, leakage_mode=leakage_mode)
    return {
        "name": name,
        "rows": int(len(df)),
        "columns": int(len(df.columns)),
        "leakage_mode": leakage_mode,
        "label_counts": value_counts_dict(df, "label"),
        "dataset_view_counts": value_counts_dict(df, "dataset_view"),
        "session_counts": value_counts_dict(df, "session_id"),
        "host_counts": value_counts_dict(df, "host_id"),
        "episode_count": int(df["episode_id"].nunique(dropna=True)) if "episode_id" in df.columns else 0,
        "kept_feature_count": int(len(kept)),
        "dropped_feature_count": int(len(dropped)),
        "dropped_columns": sorted(set(map(str, dropped))),
        "metadata_columns_present": [col for col in AUDIT_METADATA_COLUMNS if col in df.columns],
    }


def write_leakage_control_report(
    datasets: Sequence[Tuple[str, pd.DataFrame, bool]],
    output_dir: str,
    args: argparse.Namespace,
) -> None:
    os.makedirs(output_dir, exist_ok=True)
    dataset_reports = [audit_dataset(name, df, leakage_mode) for name, df, leakage_mode in datasets]
    validation_configured = bool(args.validation_host_id or args.validation_session_id)
    report = {
        "view_separation": {
            "network_only": "--network-data inputs only",
            "process_only": "--process-data inputs only",
            "fusion": "--fusion-data inputs only",
            "leakage_ablation": "--leakage-data inputs only and leakage_mode=true",
        },
        "split_policy": {
            "group_col_argument": args.group_col,
            "auto_grouping": "composite session_id|host_id|episode_id when available; otherwise episode/session/host/file fallback",
            "row_shuffle": False,
            "fold_feature_filtering": "constant/correlation filtering is fit on train fold only",
            "validation_host_id": list(args.validation_host_id),
            "validation_session_id": list(args.validation_session_id),
            "host_holdout_configured": validation_configured,
        },
        "leakage_policy": {
            "always_drop": sorted(ALWAYS_DROP),
            "safe_drop_exact": sorted(SAFE_DROP_EXACT),
            "rule_exact": sorted(RULE_EXACT),
            "rule_substrings": list(RULE_SUBSTRINGS),
            "unsafe_suffixes": list(UNSAFE_SUFFIXES),
            "note": "Metadata, identity, rule/anomaly outputs, timestamps, labels, and process context are excluded from safe ML views.",
        },
        "metrics": [
            "macro_f1", "mcc", "pr_auc_macro", "fpr_per_hour", "confusion_matrix",
            "balanced_accuracy", "macro_precision", "macro_recall",
        ],
        "datasets": dataset_reports,
    }

    json_path = os.path.join(output_dir, "leakage_control_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    md_path = os.path.join(output_dir, "leakage_control_report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# Leakage Control Report\n\n")
        f.write("## Split Policy\n\n")
        f.write(f"- Grouping: `{report['split_policy']['auto_grouping']}`\n")
        f.write(f"- Requested group setting: `{args.group_col}`\n")
        f.write("- Row-level random split: disabled\n")
        if validation_configured:
            f.write(f"- Host/session holdout: host={list(args.validation_host_id)} session={list(args.validation_session_id)}\n")
        else:
            f.write("- Host/session holdout: not configured; do not claim attacker-host generalization\n")
        f.write("\n## Feature Leakage Controls\n\n")
        f.write("- Labels and target-state columns are always dropped from ML features.\n")
        f.write("- Metadata, timestamps, host/session/episode IDs, endpoint identity, stack proxy, and rule/anomaly outputs are dropped in safe views.\n")
        f.write("- Leakage ablation is isolated under `--leakage-data` and is marked `leakage_mode=true`.\n")
        f.write("\n## Dataset Views\n\n")
        for item in dataset_reports:
            f.write(
                f"- {item['name']}: rows={item.get('rows', 0)} "
                f"kept_features={item.get('kept_feature_count', 0)} "
                f"dropped_features={item.get('dropped_feature_count', 0)} "
                f"hosts={len(item.get('host_counts', {}))} episodes={item.get('episode_count', 0)} "
                f"leakage_mode={item.get('leakage_mode')}\n"
            )
        f.write("\n## Required Metrics\n\n")
        f.write("- Report `macro_f1`, `mcc`, `pr_auc_macro`, `fpr_per_hour`, and confusion matrices from the generated files.\n")
    print(f"[AUDIT] Wrote leakage control reports: {json_path}, {md_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Grouped leakage-aware ICS/PLC IDS ML evaluation")
    parser.add_argument("--network-data", nargs="*", default=[], help="Network-only dataset CSV(s), supports glob patterns")
    parser.add_argument("--process-data", nargs="*", default=[], help="Process-monitor dataset CSV(s), supports glob patterns")
    parser.add_argument("--fusion-data", nargs="*", default=[], help="Fusion dataset CSV(s), supports glob patterns")
    parser.add_argument("--leakage-data", nargs="*", default=[], help="Explicit leakage-ablation dataset CSV(s), supports glob patterns")
    parser.add_argument("--output-dir", default="ml_results", help="Directory for metrics and figures")
    parser.add_argument("--group-col", default="auto", help="Group column for CV: episode_id/session_id/host_id/auto")
    parser.add_argument("--n-splits", type=int, default=5)
    parser.add_argument("--seeds", nargs="*", type=int, default=[42, 43, 44, 45, 46])
    parser.add_argument("--tasks", nargs="*", choices=["binary", "multiclass"], default=["binary", "multiclass"])
    parser.add_argument("--corr-threshold", type=float, default=0.98)
    parser.add_argument("--default-window-seconds", type=float, default=5.0, help="Fallback window duration for FPR/hour when window_end_ms is absent")
    parser.add_argument("--validation-host-id", nargs="*", default=[], help="Host ID(s) reserved for attacker-host holdout validation")
    parser.add_argument("--validation-session-id", nargs="*", default=[], help="Session ID(s) reserved for holdout validation")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    all_rows: List[Dict[str, object]] = []

    datasets = [
        ("network_only", load_dataset(expand_paths(args.network_data), "network_only"), False),
        ("process_only", load_dataset(expand_paths(args.process_data), "process_only"), False),
        ("fusion", load_dataset(expand_paths(args.fusion_data), "fusion"), False),
        ("leakage_ablation", load_dataset(expand_paths(args.leakage_data), "leakage_ablation"), True),
    ]

    write_leakage_control_report(datasets, args.output_dir, args)

    for name, df, leakage_mode in datasets:
        if df.empty:
            continue
        all_rows.extend(run_ml_experiment(
            df=df,
            experiment=name,
            output_dir=args.output_dir,
            leakage_mode=leakage_mode,
            n_splits=args.n_splits,
            seeds=args.seeds,
            group_col=args.group_col,
            tasks=args.tasks,
            corr_threshold=args.corr_threshold,
            default_window_seconds=args.default_window_seconds,
        ))
        all_rows.extend(run_holdout_experiment(
            df=df,
            experiment=name,
            output_dir=args.output_dir,
            leakage_mode=leakage_mode,
            validation_host_ids=args.validation_host_id,
            validation_session_ids=args.validation_session_id,
            seeds=args.seeds,
            tasks=args.tasks,
            corr_threshold=args.corr_threshold,
            default_window_seconds=args.default_window_seconds,
        ))
        if not leakage_mode:
            all_rows.extend(run_rule_baseline(
                df=df,
                experiment=name,
                output_dir=args.output_dir,
                n_splits=args.n_splits,
                seeds=args.seeds,
                group_col=args.group_col,
                default_window_seconds=args.default_window_seconds,
            ))

    write_metric_tables(all_rows, args.output_dir)


if __name__ == "__main__":
    main()
