#!/usr/bin/env python3
"""Verify internal consistency of OPC UA research-v2 artifacts.

This script does not train a model or create new experimental observations. It
recomputes counts and metrics already represented in the saved artifacts and
writes a machine-readable pass/fail report.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="experiments/opcua_research_v2")
    parser.add_argument(
        "--output",
        default="experiments/opcua_research_v2/scientific_verification.json",
    )
    return parser.parse_args()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def close(actual: float, expected: float, tolerance: float = 1e-12) -> bool:
    return math.isclose(actual, expected, rel_tol=tolerance, abs_tol=tolerance)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    args = parse_args()
    root = Path(args.root)
    checks: dict[str, bool] = {}
    details: dict[str, object] = {}

    label_dir = root / "label_audit"
    manifest = read_csv(label_dir / "label_manifest.csv")
    changed = read_csv(label_dir / "changed_windows.csv")
    label_summary = read_json(label_dir / "summary.json")
    assert isinstance(label_summary, dict)
    manifest_keys = [
        (row["window_start_ms"], row["window_end_ms"]) for row in manifest
    ]
    raw_counts = Counter(row["raw_label"] for row in manifest)
    aa_counts = Counter(row["activity_aware_label"] for row in manifest)
    change_counts = Counter(
        f"{row['raw_label']} -> {row['activity_aware_label']}"
        for row in manifest
        if row["changed"] == "true"
    )
    checks["label_manifest_row_count"] = len(manifest) == label_summary["n_windows"]
    checks["label_manifest_unique_windows"] = len(manifest_keys) == len(set(manifest_keys))
    checks["label_changed_row_count"] = (
        len(changed)
        == label_summary["n_changed"]
        == sum(row["changed"] == "true" for row in manifest)
    )
    checks["label_raw_counts"] = dict(sorted(raw_counts.items())) == label_summary["raw_label_counts"]
    checks["label_activity_aware_counts"] = dict(sorted(aa_counts.items())) == label_summary["activity_aware_label_counts"]
    checks["label_change_breakdown"] = dict(sorted(change_counts.items())) == label_summary["changes"]
    checks["label_changed_file_matches_manifest"] = {
        (row["window_start_ms"], row["window_end_ms"]) for row in changed
    } == {
        (row["window_start_ms"], row["window_end_ms"])
        for row in manifest
        if row["changed"] == "true"
    }
    details["label_audit"] = {
        "n_windows": len(manifest),
        "n_changed": len(changed),
        "raw_attack_windows": len(manifest) - raw_counts["benign"],
        "activity_aware_attack_windows": len(manifest) - aa_counts["benign"],
        "attacker_packet_count_persisted": any(
            row.get("attacker_packet_count", "") for row in manifest
        ),
    }

    ablation_dir = root / "feature_ablation"
    ablation_rows = read_csv(ablation_dir / "ablation_results.csv")
    feature_groups = read_json(ablation_dir / "feature_groups.json")
    run_config = read_json(ablation_dir / "run_config.json")
    assert isinstance(feature_groups, dict) and isinstance(run_config, dict)
    profiles = feature_groups["profiles"]
    removed = set(feature_groups["removed_identity_proxy_features"])
    checks["feature_group_sizes"] = (
        len(profiles["all_61"]) == 61
        and len(profiles["no_client_identity_proxy"]) == 50
        and len(profiles["service_only"]) == 24
        and len(removed) == 11
    )
    checks["feature_ablation_is_exact_removal"] = (
        set(profiles["all_61"]) - removed
        == set(profiles["no_client_identity_proxy"])
    )
    checks["ablation_fixed_recipe"] = run_config["model"] == {
        "class": "ExtraTreesClassifier",
        "n_estimators": 400,
        "max_depth": 10,
        "class_weight": None,
    }

    binary_rows_ok = True
    report_rows_ok = True
    for row in ablation_rows:
        tp, fp = int(row["tp"]), int(row["fp"])
        tn, fn = int(row["tn"]), int(row["fn"])
        n_rows = int(row["n_rows"])
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        binary_rows_ok &= (
            tp + fp + tn + fn == n_rows
            and close(float(row["binary_precision"]), precision)
            and close(float(row["binary_recall"]), recall)
            and close(float(row["binary_f1"]), f1)
            and close(float(row["binary_fpr"]), fpr)
        )
        if row["profile"] == "simple_protocol_threshold":
            continue
        suffix = "train_group_cv" if row["dataset"] == "train" else row["dataset"]
        report = read_json(
            ablation_dir / f"classification_{row['profile']}_{suffix}.json"
        )
        confusion_path = ablation_dir / f"confusion_{row['profile']}_{suffix}.csv"
        with confusion_path.open(newline="", encoding="utf-8-sig") as handle:
            matrix_reader = csv.reader(handle)
            header = next(matrix_reader)
            matrix = [[int(value) for value in matrix_row[1:]] for matrix_row in matrix_reader]
        matrix_total = sum(sum(values) for values in matrix)
        diagonal = sum(matrix[index][index] for index in range(len(matrix)))
        report_rows_ok &= (
            len(header) - 1 == len(matrix)
            and matrix_total == n_rows
            and close(report["accuracy"], diagonal / matrix_total)
            and close(report["macro avg"]["f1-score"], float(row["multiclass_macro_f1"]))
        )
    checks["ablation_binary_metrics_recomputed"] = binary_rows_ok
    checks["ablation_reports_match_confusions"] = report_rows_ok

    legacy_ood = read_json(Path("eval_ood2_extratrees/ood_report.json"))
    legacy_test = read_json(Path("eval_testclean_extratrees/ood_report.json"))
    assert isinstance(legacy_ood, dict) and isinstance(legacy_test, dict)
    all_ood = next(
        row for row in ablation_rows
        if row["profile"] == "all_61" and row["dataset"] == "ood2"
    )
    all_test = next(
        row for row in ablation_rows
        if row["profile"] == "all_61" and row["dataset"] == "testclean"
    )
    checks["all61_ood_matches_legacy"] = (
        [int(all_ood[key]) for key in ("tp", "fp", "tn", "fn")]
        == [
            legacy_ood["binary_benign_vs_attack"][key]
            for key in ("tp", "fp", "tn", "fn")
        ]
        and close(
            float(all_ood["multiclass_macro_f1"]),
            legacy_ood["multiclass"]["macro_f1_raw"],
            tolerance=5e-5,
        )
    )
    checks["all61_testclean_matches_legacy"] = (
        [int(all_test[key]) for key in ("tp", "fp", "tn", "fn")]
        == [
            legacy_test["binary_benign_vs_attack"][key]
            for key in ("tp", "fp", "tn", "fn")
        ]
        and close(
            float(all_test["multiclass_macro_f1"]),
            legacy_test["multiclass"]["macro_f1_raw"],
            tolerance=5e-5,
        )
    )
    details["ablation"] = {
        "n_result_rows": len(ablation_rows),
        "feature_group_sizes": {name: len(values) for name, values in profiles.items()},
        "n_removed_source_structure_features": len(removed),
    }

    warmup_dir = root / "warmup_ood"
    predictions = read_csv(warmup_dir / "ood2_predictions.csv")
    error_summary = read_json(warmup_dir / "error_summary.json")
    episode_summary = read_json(warmup_dir / "ood2_episode_summary.json")
    negative_episodes = read_csv(warmup_dir / "ood2_negative_episode_results.csv")
    assert isinstance(error_summary, dict) and isinstance(episode_summary, dict)
    true_attack = [row["true_binary"] == "attack" for row in predictions]
    pred_attack = [row["pred_binary"] == "attack" for row in predictions]
    score_alert = [float(row["pred_attack_score"]) >= 0.5 for row in predictions]
    tp = sum(truth and pred for truth, pred in zip(true_attack, pred_attack))
    fp = sum(not truth and pred for truth, pred in zip(true_attack, pred_attack))
    tn = sum(not truth and not pred for truth, pred in zip(true_attack, pred_attack))
    fn = sum(truth and not pred for truth, pred in zip(true_attack, pred_attack))
    phase_counts = Counter(
        "attack" if row["true_binary"] == "attack"
        else f"benign_{row['benign_phase']}"
        for row in predictions
    )
    fp_phases = Counter(
        f"benign_{row['benign_phase']}"
        for row in predictions
        if row["is_fp"] == "True"
    )
    fn_phases = Counter(
        "attack" for row in predictions if row["is_fn"] == "True"
    )
    checks["ood2_prediction_confusion"] = (tp, fp, tn, fn) == (124, 23, 457, 1)
    checks["ood2_attack_score_matches_argmax_binary"] = score_alert == pred_attack
    checks["warmup_phase_counts"] = dict(sorted(phase_counts.items())) == error_summary["phase_counts"]
    checks["warmup_fp_counts"] = dict(sorted(fp_phases.items())) == error_summary["false_positives"]
    checks["warmup_fn_counts"] = dict(sorted(fn_phases.items())) == error_summary["false_negatives"]

    episode_groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for index, row in enumerate(predictions):
        episode_groups[row.get("episode_id") or f"row_without_episode_{index}"].append(row)
    mixed = {
        key for key, group in episode_groups.items()
        if len({row["true_binary"] for row in group}) > 1
    }
    positive = {
        key: group for key, group in episode_groups.items()
        if group[0]["true_binary"] == "attack"
    }
    negative = {
        key: group for key, group in episode_groups.items()
        if group[0]["true_binary"] == "benign"
    }
    alerted = {
        key for key, group in episode_groups.items()
        if any(float(row["pred_attack_score"]) >= 0.5 for row in group)
    }
    episode_tp = len(set(positive) & alerted)
    episode_fp = len(set(negative) & alerted)
    episode_tn = len(set(negative) - alerted)
    episode_fn = len(set(positive) - alerted)
    checks["episode_ids_do_not_mix_labels"] = not mixed
    checks["episode_confusion_recomputed"] = (
        episode_tp,
        episode_fp,
        episode_tn,
        episode_fn,
    ) == (
        episode_summary["episode_tp"],
        episode_summary["episode_fp"],
        episode_summary["episode_tn"],
        episode_summary["episode_fn"],
    )
    checks["episode_precision_recomputed"] = close(
        episode_summary["episode_precision"],
        episode_tp / (episode_tp + episode_fp),
    )
    checks["negative_episode_artifact_complete"] = (
        len(negative_episodes) == len(negative)
        and sum(row["false_positive"] == "true" for row in negative_episodes)
        == episode_fp
    )
    details["ood2"] = {
        "n_windows": len(predictions),
        "window_confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "n_episode_ids": len(episode_groups),
        "episode_confusion": {
            "tp": episode_tp,
            "fp": episode_fp,
            "tn": episode_tn,
            "fn": episode_fn,
        },
        "episode_precision": episode_tp / (episode_tp + episode_fp),
        "episode_recall": episode_tp / (episode_tp + episode_fn),
    }

    model_bytes = Path("model_opcua/classifier.joblib").read_bytes()
    new_model_bytes = (
        root / "feature_ablation/models/all_61/classifier.joblib"
    ).read_bytes()
    checks["model_version_markers_present"] = (
        b"1.8.0" in model_bytes and b"1.9.1" in new_model_bytes
    )
    details["runtime_versions"] = {
        "persisted_model_marker": "1.8.0",
        "ablation_model_marker": "1.9.1",
    }

    checksum_paths = [
        Path("model_opcua/classifier.joblib"),
        label_dir / "summary.json",
        label_dir / "label_manifest.csv",
        ablation_dir / "ablation_results.csv",
        warmup_dir / "ood2_predictions.csv",
        warmup_dir / "ood2_episode_summary.json",
        warmup_dir / "ood2_negative_episode_results.csv",
    ]
    report = {
        "all_checks_passed": all(checks.values()),
        "n_checks": len(checks),
        "checks": checks,
        "details": details,
        "sha256": {str(path): sha256(path) for path in checksum_paths},
    }
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    if not report["all_checks_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
