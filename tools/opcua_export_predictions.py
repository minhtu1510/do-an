#!/usr/bin/env python3
"""Export row-level OPC UA predictions with warmup and error annotations."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", default="model_opcua")
    parser.add_argument("--input", default="data_opc/day8_out/opcua_ood2_ext_aa.csv")
    parser.add_argument(
        "--output",
        default="experiments/opcua_research_v2/warmup_ood/ood2_predictions.csv",
    )
    return parser.parse_args()


def normalize_label(value: object) -> str:
    label = str(value).strip()
    upper = label.upper()
    if upper.startswith("BENIGN") or upper == "NORMAL":
        return "benign"
    if upper in {"OPCUA_INVALID_WRITE", "OPCUA_WRITE_DENIED"}:
        return "OPCUA_MALICIOUS_WRITE"
    return label


def main() -> None:
    args = parse_args()
    model_dir = Path(args.model_dir)
    feature_names = json.loads((model_dir / "features.json").read_text(encoding="utf-8"))
    model = joblib.load(model_dir / "classifier.joblib")
    frame = pd.read_csv(args.input)
    if "label" not in frame:
        raise ValueError("Input CSV must contain a label column")

    for feature in feature_names:
        if feature not in frame:
            frame[feature] = 0.0
    matrix = frame.loc[:, feature_names].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    predictions = np.asarray(model.predict(matrix), dtype=object)

    confidence = np.full(len(frame), np.nan)
    attack_score = np.full(len(frame), np.nan)
    if hasattr(model, "predict_proba"):
        probabilities = np.asarray(model.predict_proba(matrix), dtype=float)
        confidence = probabilities.max(axis=1)
        classes = [str(item) for item in model.classes_]
        benign_indexes = [i for i, item in enumerate(classes) if normalize_label(item) == "benign"]
        if benign_indexes:
            attack_score = 1.0 - probabilities[:, benign_indexes].sum(axis=1)
        else:
            attack_score = probabilities.sum(axis=1)

    original = frame["label"].astype(str)
    true_eval = original.map(normalize_label)
    pred_eval = pd.Series(predictions).map(normalize_label)
    true_binary = np.where(true_eval == "benign", "benign", "attack")
    pred_binary = np.where(pred_eval == "benign", "benign", "attack")
    is_warmup = original.str.upper().str.startswith("BENIGN") & (
        original.str.lower() != "benign"
    )

    output = frame.copy()
    output["label_original"] = original
    output["label_eval"] = true_eval
    output["pred_label"] = predictions
    output["pred_label_eval"] = pred_eval
    output["pred_confidence"] = confidence
    output["pred_attack_score"] = attack_score
    output["true_binary"] = true_binary
    output["pred_binary"] = pred_binary
    output["is_correct"] = true_eval.to_numpy() == pred_eval.to_numpy()
    output["is_fp"] = (true_binary == "benign") & (pred_binary == "attack")
    output["is_fn"] = (true_binary == "attack") & (pred_binary == "benign")
    output["benign_phase"] = np.where(
        true_binary == "benign", np.where(is_warmup, "warmup", "steady"), ""
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output.to_csv(output_path, index=False)
    print(f"Wrote {len(output)} predictions to {output_path}")


if __name__ == "__main__":
    main()
