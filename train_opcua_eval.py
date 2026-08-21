#!/usr/bin/env python3
"""Train & persist a deployable OPC UA classifier for the Web-SCADA IDS Upload page.

This is the OPC UA counterpart to train_eval.py (which only covers S7comm
traffic). tests/day8/evaluate_opcua.py already validated the recipe used here
via GroupKFold cross-validation (see that file's docstring for the reasoning
behind merging OPCUA_INVALID_WRITE/OPCUA_WRITE_DENIED and *not* using
class_weight="balanced") — this script reuses the same recipe but fits on the
full dataset once and persists the result, since evaluate_opcua.py itself
never saves a model (it's benchmark-only, in-memory, cross-validated and
discarded).

Usage:
  python train_opcua_eval.py --dataset data_opc/day8_out/opcua_harvest_features.csv --output model_opcua/
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold, cross_val_predict
from sklearn.metrics import f1_score

WRITE_MERGE = {
    "OPCUA_INVALID_WRITE": "OPCUA_MALICIOUS_WRITE",
    "OPCUA_WRITE_DENIED": "OPCUA_MALICIOUS_WRITE",
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", required=True, help="Feature CSV from extract_opcua_features.py (e.g. opcua_harvest_features.csv)")
    ap.add_argument("--output", required=True, help="Output directory for the persisted model")
    args = ap.parse_args()

    df = pd.read_csv(args.dataset)
    feat = [c for c in df.columns if c.startswith("opcua_")]
    df = df.copy()
    df["label"] = df["label"].replace(WRITE_MERGE)

    X = df[feat].fillna(0).values
    y = df["label"].values
    groups = df["episode_id"].values if "episode_id" in df.columns else None

    # Honest cross-validated estimate before fitting on everything — this is
    # what the web app will show as the model's expected accuracy, not a
    # training-set score that would look artificially perfect.
    cv_macro_f1 = None
    if groups is not None and pd.Series(groups).nunique() >= 5:
        clf_cv = RandomForestClassifier(n_estimators=400, random_state=0, n_jobs=-1)
        pred = cross_val_predict(clf_cv, X, y, groups=groups, cv=GroupKFold(5), n_jobs=-1)
        cv_macro_f1 = float(f1_score(y, pred, average="macro"))
        print(f"[*] Grouped 5-fold CV macro-F1 (honest estimate): {cv_macro_f1:.3f}")
    else:
        print("[!] Not enough distinct episode_id groups for 5-fold CV — skipping CV estimate.")

    print(f"[*] Fitting final classifier on all {len(df)} windows, {len(feat)} features, {df['label'].nunique()} labels...")
    clf = RandomForestClassifier(n_estimators=400, random_state=0, n_jobs=-1)
    clf.fit(X, y)

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, out_dir / "classifier.joblib")
    (out_dir / "features.json").write_text(json.dumps(feat, indent=2))
    (out_dir / "meta.json").write_text(json.dumps({
        "labels": sorted(df["label"].unique().tolist()),
        "n_windows": len(df),
        "n_features": len(feat),
        "cv_macro_f1": cv_macro_f1,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "source_dataset": str(Path(args.dataset).resolve()),
    }, indent=2, ensure_ascii=False))

    print(f"[OK] Saved classifier.joblib, features.json, meta.json -> {out_dir}")


if __name__ == "__main__":
    main()
