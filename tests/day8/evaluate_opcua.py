#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/day8/evaluate_opcua.py

Danh gia dataset OPC UA da trich xuat boi extract_opcua_features.py.

Muc tieu (xem review trong bao-cao/opcua_bao_cao_chi_tiet.md):
  1. Danh gia PHAT HIEN nhi phan benign-vs-attack (GroupKFold theo episode_id).
  2. Danh gia PHAN LOAI da lop, co 2 xu ly da duoc kiem chung tren du lieu:
       a) Gop INVALID_WRITE + WRITE_DENIED -> OPCUA_WRITE_REJECTED (wire-identical:
          deu la 1 lenh Write bi server tu choi -> khong the tach o muc feature).
          CHU Y: nhan gop nay KHONG duoc dat trung ten voi scenario that
          "OPCUA_MALICIOUS_WRITE" trong run_day8.py/scenarios.yaml -- do la
          kich ban RIENG, thuc su ghi thanh cong 1 gia tri sai roi rollback,
          can DAY8_ALLOW_PROCESS_IMPACT=1, va KHONG nam trong DEFAULT_POOL cua
          collect_opcua.py nen chua tung duoc thu thap. Dung trung ten se lam
          nguoi doc hieu nham la da kiem chung phat hien ghi-thanh-cong-co-tac-dong
          that, trong khi du lieu o day chi la ghi-bi-tu-choi.
       b) KHONG dung class_weight='balanced': benign co create_session=0 tuyet doi
          nen feature da tach benign/session_burst; balanced weighting (upweight
          lop hiem ~50x) chi tao false-positive benign->session_burst gia tao.
  3. In feature-importance + confusion cho cac lop de dua vao bao cao.

Chay:
  python tests/day8/evaluate_opcua.py \
    --features data_opc/day8_out/opcua_harvest_features.csv \
    --out-dir data_opc/day8_out/eval
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold, cross_val_predict
from sklearn.metrics import classification_report, confusion_matrix, f1_score

# Hai lop Write giong het nhau tren wire (1 Write bi tu choi) -> gop lam 1.
# ID gop KHONG duoc trung "OPCUA_MALICIOUS_WRITE" -- do la 1 scenario THAT
# KHAC (ghi thanh cong + rollback, can opt-in, chua thu thap). Xem docstring.
WRITE_MERGE = {"OPCUA_INVALID_WRITE": "OPCUA_WRITE_REJECTED",
               "OPCUA_WRITE_DENIED": "OPCUA_WRITE_REJECTED"}


def load(features_csv: str):
    df = pd.read_csv(features_csv)
    feat = [c for c in df.columns if c.startswith("opcua_")]
    return df, feat


def eval_binary(df, feat):
    X = df[feat].fillna(0).values
    y = (df["label"] != "benign").astype(int).values
    g = df["episode_id"].values
    clf = RandomForestClassifier(n_estimators=400, random_state=0, n_jobs=-1)
    pred = cross_val_predict(clf, X, y, groups=g, cv=GroupKFold(5), n_jobs=-1)
    rep = classification_report(y, pred, target_names=["benign", "attack"],
                                digits=3, output_dict=True)
    txt = classification_report(y, pred, target_names=["benign", "attack"], digits=3)
    return rep, txt


def eval_multiclass(df, feat, merge_write=True, balanced=False):
    d = df.copy()
    if merge_write:
        d["label"] = d["label"].replace(WRITE_MERGE)
    X = d[feat].fillna(0).values
    y = d["label"].values
    g = d["episode_id"].values
    cw = "balanced" if balanced else None
    clf = RandomForestClassifier(n_estimators=400, random_state=0, n_jobs=-1,
                                 class_weight=cw)
    pred = cross_val_predict(clf, X, y, groups=g, cv=GroupKFold(5), n_jobs=-1)
    macro = f1_score(y, pred, average="macro")
    rep = classification_report(y, pred, digits=3, output_dict=True)
    labels = sorted(set(y))
    cm = confusion_matrix(y, pred, labels=labels)
    return macro, rep, labels, cm, y, pred


def feature_importance(df, feat, merge_write=True):
    d = df.copy()
    if merge_write:
        d["label"] = d["label"].replace(WRITE_MERGE)
    X = d[feat].fillna(0).values
    y = d["label"].values
    clf = RandomForestClassifier(n_estimators=400, random_state=0, n_jobs=-1)
    clf.fit(X, y)
    imp = sorted(zip(feat, clf.feature_importances_), key=lambda t: -t[1])
    return imp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", required=True)
    ap.add_argument("--out-dir", default=None)
    args = ap.parse_args()

    df, feat = load(args.features)
    print(f"[*] {len(df)} window, {len(feat)} feature, "
          f"{df['label'].nunique()} lop, {df['episode_id'].nunique()} episode")

    print("\n" + "=" * 60)
    print("A. PHAT HIEN NHI PHAN (benign vs attack)")
    print("=" * 60)
    brep, btxt = eval_binary(df, feat)
    print(btxt)

    print("=" * 60)
    print("B. DA LOP — so sanh 4 cau hinh (chung minh 2 xu ly)")
    print("=" * 60)
    configs = [
        ("raw + balanced (baseline ban dau)", False, True),
        ("raw + no-weight", False, False),
        ("merge-write + balanced", True, True),
        ("merge-write + no-weight (KHUYEN NGHI)", True, False),
    ]
    summary = []
    best = None
    for name, mw, bal in configs:
        macro, rep, labels, cm, y, pred = eval_multiclass(df, feat, mw, bal)
        summary.append((name, macro))
        print(f"  macro-F1 = {macro:.3f}   [{name}]")
        if name.startswith("merge-write + no-weight"):
            best = (rep, labels, cm, y, pred)

    print("\n--- Chi tiet cau hinh KHUYEN NGHI (merge-write + no-weight) ---")
    rep, labels, cm, y, pred = best
    print(f"{'label':32s} {'prec':>6s} {'rec':>6s} {'f1':>6s} {'n':>5s}")
    for k in sorted(rep):
        if k in ("accuracy", "macro avg", "weighted avg"):
            continue
        r = rep[k]
        print(f"{k:32s} {r['precision']:6.3f} {r['recall']:6.3f} "
              f"{r['f1-score']:6.3f} {int(r['support']):5d}")

    print("\n--- Confusion (chi in o != 0) ---")
    for i, l in enumerate(labels):
        dests = [(labels[j], cm[i][j]) for j in range(len(labels)) if cm[i][j] > 0]
        line = "  ".join(f"{n.replace('OPCUA_','')}={c}" for n, c in
                         sorted(dests, key=lambda t: -t[1]))
        print(f"  {l.replace('OPCUA_',''):26s} -> {line}")

    print("\n" + "=" * 60)
    print("C. FEATURE IMPORTANCE (top 15)")
    print("=" * 60)
    imp = feature_importance(df, feat)
    for name, val in imp[:15]:
        print(f"  {val:6.3f}  {name}")

    if args.out_dir:
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        macro_best = dict(summary)["merge-write + no-weight (KHUYEN NGHI)"]
        result = {
            "n_windows": len(df),
            "n_features": len(feat),
            "n_episodes": int(df["episode_id"].nunique()),
            "binary": {"attack_f1": brep["attack"]["f1-score"],
                       "attack_precision": brep["attack"]["precision"],
                       "attack_recall": brep["attack"]["recall"],
                       "benign_f1": brep["benign"]["f1-score"],
                       "accuracy": brep["accuracy"]},
            "multiclass_macro_f1": dict(summary),
            "multiclass_best_per_class": {
                k: {"precision": rep[k]["precision"], "recall": rep[k]["recall"],
                    "f1": rep[k]["f1-score"], "support": rep[k]["support"]}
                for k in rep if k not in ("accuracy", "macro avg", "weighted avg")},
            "top_features": [{"feature": n, "importance": float(v)} for n, v in imp[:15]],
        }
        (out / "eval_results.json").write_text(json.dumps(result, indent=2, ensure_ascii=False))
        pd.DataFrame(cm, index=labels, columns=labels).to_csv(out / "confusion_matrix.csv")
        print(f"\n[OK] Ket qua -> {out}/eval_results.json, confusion_matrix.csv")


if __name__ == "__main__":
    main()
