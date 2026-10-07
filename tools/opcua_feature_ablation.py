#!/usr/bin/env python3
"""Run reproducible OPC UA feature ablation without overwriting legacy artifacts.

The script trains only inside the requested output directory. It evaluates:
all recorded features, a profile without client/source identity proxies, a
service-only profile, and a simple threshold baseline derived from training
benign windows.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
)
from sklearn.model_selection import GroupKFold, cross_val_predict


IDENTITY_PROXY_FEATURES = {
    "opcua_unique_src_ip_count",
    "opcua_unique_dst_ip_count",
    "opcua_client_src_count",
    "opcua_max_pkts_by_client",
    "opcua_max_bytes_by_client",
    "opcua_max_services_by_client",
    "opcua_busiest_client_pkt_frac",
    "opcua_max_opn_by_single_src",
    "opcua_max_read_by_single_src",
    "opcua_max_create_session_by_single_src",
    "opcua_max_browse_by_single_src",
}

SERVICE_PREFIXES = (
    "opcua_hel_count",
    "opcua_opn_count",
    "opcua_msg_count",
    "opcua_clo_count",
    "opcua_err_count",
    "opcua_transport_error_count",
    "opcua_status_",
    "opcua_distinct_status_count",
    "opcua_get_endpoints_count",
    "opcua_create_session_count",
    "opcua_activate_session_count",
    "opcua_close_session_count",
    "opcua_browse_count",
    "opcua_browse_next_count",
    "opcua_read_count",
    "opcua_write_count",
    "opcua_create_subscription_count",
    "opcua_modify_subscription_count",
    "opcua_delete_subscriptions_count",
    "opcua_create_monitored_items_count",
    "opcua_modify_monitored_items_count",
    "opcua_delete_monitored_items_count",
    "opcua_publish_count",
    "opcua_republish_count",
    "opcua_set_publishing_mode_count",
    "opcua_register_nodes_count",
    "opcua_unregister_nodes_count",
    "opcua_translate_browse_paths_count",
    "opcua_call_count",
)

BASELINE_FEATURES = (
    "opcua_hel_count",
    "opcua_opn_count",
    "opcua_create_session_count",
    "opcua_browse_count",
    "opcua_read_count",
    "opcua_write_count",
    "opcua_create_subscription_count",
    "opcua_create_monitored_items_count",
    "opcua_unique_tcp_stream_count",
    "opcua_client_src_count",
    "opcua_max_pkts_per_sec",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", default="data_opc/day8_out/opcua_harvest_ext_aa.csv")
    parser.add_argument("--ood", default="data_opc/day8_out/opcua_ood2_ext_aa.csv")
    parser.add_argument(
        "--testclean", default="data_opc/day8_out/opcua_testclean_ext_aa.csv"
    )
    parser.add_argument("--features", default="model_opcua/features.json")
    parser.add_argument(
        "--output-dir", default="experiments/opcua_research_v2/feature_ablation"
    )
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--baseline-quantile", type=float, default=0.99)
    return parser.parse_args()


def normalize_label(value: object) -> str:
    label = str(value).strip()
    upper = label.upper()
    if upper.startswith("BENIGN") or upper == "NORMAL":
        return "benign"
    if upper in {"OPCUA_INVALID_WRITE", "OPCUA_WRITE_DENIED"}:
        return "OPCUA_MALICIOUS_WRITE"
    return label


def load_frame(path: str) -> pd.DataFrame:
    frame = pd.read_csv(path)
    if "label" not in frame:
        raise ValueError(f"Missing label column: {path}")
    frame = frame.copy()
    frame["label_eval"] = frame["label"].map(normalize_label)
    return frame


def matrix(frame: pd.DataFrame, feature_names: list[str]) -> pd.DataFrame:
    result = pd.DataFrame(index=frame.index)
    for name in feature_names:
        if name in frame:
            result[name] = pd.to_numeric(frame[name], errors="coerce").fillna(0.0)
        else:
            result[name] = 0.0
    return result


def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float]:
    true_binary = np.where(y_true == "benign", "benign", "attack")
    pred_binary = np.where(y_pred == "benign", "benign", "attack")
    precision, recall, f1, _ = precision_recall_fscore_support(
        true_binary,
        pred_binary,
        labels=["attack"],
        average="binary",
        pos_label="attack",
        zero_division=0,
    )
    tn, fp, fn, tp = confusion_matrix(
        true_binary, pred_binary, labels=["benign", "attack"]
    ).ravel()
    return {
        "binary_precision": float(precision),
        "binary_recall": float(recall),
        "binary_f1": float(f1),
        "binary_fpr": float(fp / (fp + tn)) if fp + tn else 0.0,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def result_row(
    profile: str,
    dataset: str,
    mode: str,
    n_features: int,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    notes: str = "",
) -> dict[str, object]:
    row: dict[str, object] = {
        "profile": profile,
        "dataset": dataset,
        "mode": mode,
        "n_features": n_features,
        "n_rows": len(y_true),
        "multiclass_macro_f1": float(
            f1_score(y_true, y_pred, average="macro", zero_division=0)
        ),
        "notes": notes,
    }
    row.update(binary_metrics(y_true, y_pred))
    return row


def write_report(
    output_dir: Path,
    profile: str,
    dataset: str,
    y_true: np.ndarray,
    y_pred: np.ndarray,
) -> None:
    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    report_path = output_dir / f"classification_{profile}_{dataset}.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    labels = sorted(set(y_true) | set(y_pred))
    matrix_values = confusion_matrix(y_true, y_pred, labels=labels)
    confusion_path = output_dir / f"confusion_{profile}_{dataset}.csv"
    with confusion_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["true/pred", *labels])
        for label, values in zip(labels, matrix_values):
            writer.writerow([label, *values.tolist()])


def new_model(seed: int) -> ExtraTreesClassifier:
    return ExtraTreesClassifier(
        n_estimators=400,
        max_depth=10,
        random_state=seed,
        n_jobs=-1,
    )


def baseline_thresholds(
    train: pd.DataFrame, features: list[str], quantile: float
) -> dict[str, float]:
    benign = train[train["label_eval"] == "benign"]
    values = matrix(benign, features)
    return {name: float(values[name].quantile(quantile)) for name in features}


def baseline_predict(
    frame: pd.DataFrame, features: list[str], thresholds: dict[str, float]
) -> np.ndarray:
    values = matrix(frame, features)
    triggered = np.zeros(len(frame), dtype=bool)
    for feature in features:
        triggered |= values[feature].to_numpy() > thresholds[feature]
    return np.where(triggered, "attack", "benign")


def baseline_row(
    profile: str,
    dataset: str,
    frame: pd.DataFrame,
    predictions: np.ndarray,
    n_features: int,
    notes: str,
) -> dict[str, object]:
    y_true = frame["label_eval"].to_numpy(dtype=object)
    true_binary = np.where(y_true == "benign", "benign", "attack")
    row: dict[str, object] = {
        "profile": profile,
        "dataset": dataset,
        "mode": "fixed_threshold",
        "n_features": n_features,
        "n_rows": len(frame),
        "multiclass_macro_f1": "",
        "notes": notes,
    }
    row.update(binary_metrics(true_binary, predictions))
    return row


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    all_features = list(json.loads(Path(args.features).read_text(encoding="utf-8")))
    train = load_frame(args.train)
    evaluation_sets = {
        "ood2": load_frame(args.ood),
        "testclean": load_frame(args.testclean),
    }

    profiles = {
        "all_61": all_features,
        "no_client_identity_proxy": [
            name for name in all_features if name not in IDENTITY_PROXY_FEATURES
        ],
        "service_only": [
            name for name in all_features if name.startswith(SERVICE_PREFIXES)
        ],
    }
    if not profiles["service_only"]:
        raise ValueError("No service-only features matched the recorded feature list")

    (output_dir / "feature_groups.json").write_text(
        json.dumps(
            {
                "profiles": profiles,
                "removed_identity_proxy_features": sorted(IDENTITY_PROXY_FEATURES),
                "baseline_features": list(BASELINE_FEATURES),
                "rationale": (
                    "Identity-proxy features aggregate by source/client and may encode "
                    "fixed testbed identity or attacker concurrency. Service-only features "
                    "retain protocol semantics while removing packet-volume shortcuts."
                ),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    y_train = train["label_eval"].to_numpy(dtype=object)
    groups = (
        train["episode_id"].fillna("").astype(str)
        if "episode_id" in train
        else pd.Series(np.arange(len(train)).astype(str), index=train.index)
    )
    n_groups = groups.nunique()
    n_folds = min(args.folds, n_groups)
    if n_folds < 2:
        raise ValueError("At least two episode groups are required for grouped CV")

    results: list[dict[str, object]] = []
    for profile, feature_names in profiles.items():
        train_matrix = matrix(train, feature_names)
        cv_predictions = cross_val_predict(
            new_model(args.seed),
            train_matrix,
            y_train,
            groups=groups,
            cv=GroupKFold(n_splits=n_folds),
            n_jobs=-1,
            method="predict",
        )
        results.append(
            result_row(
                profile,
                "train",
                f"group_{n_folds}_fold_cv",
                len(feature_names),
                y_train,
                np.asarray(cv_predictions, dtype=object),
                "Groups are episode_id; no random-window split.",
            )
        )
        write_report(
            output_dir,
            profile,
            "train_group_cv",
            y_train,
            np.asarray(cv_predictions, dtype=object),
        )

        model = new_model(args.seed)
        model.fit(train_matrix, y_train)
        profile_dir = output_dir / "models" / profile
        profile_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, profile_dir / "classifier.joblib")
        (profile_dir / "features.json").write_text(
            json.dumps(feature_names, indent=2), encoding="utf-8"
        )
        for dataset_name, frame in evaluation_sets.items():
            true_labels = frame["label_eval"].to_numpy(dtype=object)
            predictions = np.asarray(
                model.predict(matrix(frame, feature_names)), dtype=object
            )
            results.append(
                result_row(
                    profile,
                    dataset_name,
                    "train_fit_external_eval",
                    len(feature_names),
                    true_labels,
                    predictions,
                )
            )
            write_report(
                output_dir, profile, dataset_name, true_labels, predictions
            )

    baseline_features = [name for name in BASELINE_FEATURES if name in all_features]
    thresholds = baseline_thresholds(train, baseline_features, args.baseline_quantile)
    (output_dir / "simple_baseline_thresholds.json").write_text(
        json.dumps(
            {
                "quantile": args.baseline_quantile,
                "derived_from": "training benign windows only",
                "thresholds": thresholds,
                "rule": "attack if any selected feature is greater than its threshold",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    for dataset_name, frame in evaluation_sets.items():
        predictions = baseline_predict(frame, baseline_features, thresholds)
        results.append(
            baseline_row(
                "simple_protocol_threshold",
                dataset_name,
                frame,
                predictions,
                len(baseline_features),
                f"Thresholds are benign-training quantile {args.baseline_quantile}.",
            )
        )

    result_path = output_dir / "ablation_results.csv"
    with result_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(results[0]))
        writer.writeheader()
        writer.writerows(results)
    run_config = {
        "train": args.train,
        "ood": args.ood,
        "testclean": args.testclean,
        "feature_source": args.features,
        "seed": args.seed,
        "folds": n_folds,
        "model": {
            "class": "ExtraTreesClassifier",
            "n_estimators": 400,
            "max_depth": 10,
            "class_weight": None,
        },
    }
    (output_dir / "run_config.json").write_text(
        json.dumps(run_config, indent=2), encoding="utf-8"
    )
    print(f"Wrote {len(results)} result rows to {result_path}")


if __name__ == "__main__":
    main()
