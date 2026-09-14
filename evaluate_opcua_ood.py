#!/usr/bin/env python3
"""
evaluate_opcua_ood.py -- Danh gia OOD (out-of-distribution) cho model OPC UA:
nap model DA TRAIN tren 1 phien (harvest) va test tren 1 phien THU THAP KHAC
(cross-session holdout), dung vai tro giong Day 6 ben S7comm. train_opcua_eval.py
chi lam GroupKFold TRONG 1 file -> khong tra loi duoc "model co generalize ra
ngoai 1 buoi thu khong". Script nay tra loi dung cau hoi do.

Bao cao 2 goc nhin:
  1. NHI PHAN benign-vs-attack (con so van hanh, khop slide S7): recall, FPR,
     precision, F1, va FPR/gio (dua tren window 5s).
  2. DA LOP: macro-F1 + per-class + confusion matrix. Cac dong co nhan mà model
     KHONG biet (vd WRITE_DENIED/INVALID_WRITE bi loai luc train) duoc dem rieng
     va bao ro -- trong da-lop chung luon sai, nhung trong nhi phan van la
     'attack' hop le.

Vi du:
  python evaluate_opcua_ood.py \
      --model-dir model_opcua \
      --test data_opc/day8_out/opcua_testclean_ext_aa.csv \
      --output eval_ood_opcua
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    f1_score, precision_score, recall_score, confusion_matrix, classification_report,
)

WINDOW_SECONDS = 5.0  # OPC UA feature window (xac nhan tu window_end-window_start)
META_COLS = {"window_start_ms", "window_end_ms", "label", "capture_role",
             "plc_ip", "session_id", "host_id", "scenario_id", "episode_id"}
BENIGN = "benign"

# PHAI khop y het train_opcua_eval.py: 3 bien the write gan nhu khong phan biet
# duoc o tang traffic nen duoc gop thanh 1 lop khi TRAIN. Bat buoc ap dung cung
# phep gop len nhan TEST, neu khong model doan dung "MALICIOUS_WRITE" cho 1
# WRITE_DENIED se bi tinh sai oan.
WRITE_MERGE = {
    "OPCUA_INVALID_WRITE": "OPCUA_MALICIOUS_WRITE",
    "OPCUA_WRITE_DENIED": "OPCUA_MALICIOUS_WRITE",
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model-dir", default="model_opcua", help="Thu muc chua classifier.joblib + features.json + meta.json")
    ap.add_argument("--test", required=True, help="CSV feature cua PHIEN test (khac phien train)")
    ap.add_argument("--output", default="eval_ood_opcua", help="Thu muc luu report")
    args = ap.parse_args()

    model_dir = Path(args.model_dir)
    clf = joblib.load(model_dir / "classifier.joblib")
    features = json.loads((model_dir / "features.json").read_text())
    meta = {}
    meta_path = model_dir / "meta.json"
    if meta_path.exists():
        meta = json.loads(meta_path.read_text())
    known_classes = list(getattr(clf, "classes_", meta.get("labels", [])))

    df = pd.read_csv(args.test)
    if "label" not in df.columns:
        raise SystemExit("[ERR] CSV test khong co cot 'label'")
    # Chuan hoa nhan benign: cac phien thu khac nhau co the ghi baseline warmup
    # la 'BENIGN_NORMAL' thay vi 'benign' (train dung 'benign'). Bat ky nhan nao
    # bat dau bang BENIGN deu la benign -> gop ve 'benign', neu khong 36 window
    # warmup se bi tinh nham la 'attack' o ground-truth, lam sai het recall/FPR.
    benign_alias_mask = df["label"].astype(str).str.upper().str.startswith("BENIGN") & (df["label"] != BENIGN)
    n_benign_alias = int(benign_alias_mask.sum())
    # Giu lai co "transient/warmup" (benign nhung o giai doan khoi dong phien,
    # nhan goc BENIGN_* thay vi 'benign') de tach FPR steady-state vs transient.
    is_transient_benign = benign_alias_mask.values.copy()
    df.loc[benign_alias_mask, "label"] = BENIGN
    # Ap dung cung phep gop label nhu luc train (bat buoc de cham diem cong bang).
    n_merged = int(df["label"].isin(WRITE_MERGE).sum())
    df["label"] = df["label"].replace(WRITE_MERGE)

    # Canh feature dung thu tu model mong doi; thieu -> 0, thua -> bo.
    missing = [f for f in features if f not in df.columns]
    for f in missing:
        df[f] = 0.0
    X = df[features].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    y_true = df["label"].astype(str).values
    y_pred = clf.predict(X)

    # --- Kiem tra nhan test co nam trong lop model biet khong ---
    test_labels = set(y_true.tolist())
    unseen_labels = sorted(l for l in test_labels if l not in set(known_classes) and l != BENIGN)
    n_unseen_rows = int(np.isin(y_true, list(unseen_labels)).sum()) if unseen_labels else 0

    # --- Goc nhin 1: NHI PHAN benign vs attack ---
    yt_bin = np.where(y_true == BENIGN, 0, 1)          # 1 = attack
    yp_bin = np.where(y_pred == BENIGN, 0, 1)
    tn = int(((yt_bin == 0) & (yp_bin == 0)).sum())
    fp = int(((yt_bin == 0) & (yp_bin == 1)).sum())
    fn = int(((yt_bin == 1) & (yp_bin == 0)).sum())
    tp = int(((yt_bin == 1) & (yp_bin == 1)).sum())
    n_benign = tn + fp
    recall_bin = tp / max(tp + fn, 1)
    precision_bin = tp / max(tp + fp, 1)
    fpr = fp / max(n_benign, 1)
    f1_bin = 2 * precision_bin * recall_bin / max(precision_bin + recall_bin, 1e-9)
    benign_hours = (n_benign * WINDOW_SECONDS) / 3600.0
    fpr_per_hour = fp / max(benign_hours, 1e-9)

    # Tach FPR theo loai benign: steady-state (van hanh on dinh) vs transient
    # (warmup/khoi dong phien). FP o transient la trang thai bootstrap da biet,
    # khac ban chat voi FP o van hanh on dinh -> bao rieng cho trung thuc.
    benign_gt = (yt_bin == 0)
    steady_mask = benign_gt & (~is_transient_benign)
    transient_mask = benign_gt & is_transient_benign
    n_steady = int(steady_mask.sum())
    n_transient = int(transient_mask.sum())
    fp_steady = int((steady_mask & (yp_bin == 1)).sum())
    fp_transient = int((transient_mask & (yp_bin == 1)).sum())
    fpr_steady_per_hour = fp_steady / max((n_steady * WINDOW_SECONDS) / 3600.0, 1e-9)

    # --- Goc nhin 2: DA LOP ---
    # macro-F1 THÔ tren TAT CA nhan xuat hien (bi phat mechanically boi cac lop
    # model khong the emit -- WRITE_DENIED/INVALID_WRITE -- va cac lop khong co
    # trong phien test: chung deu F1=0, keo macro xuong). Bao ca 2 de trung thuc.
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    macro_prec = precision_score(y_true, y_pred, average="macro", zero_division=0)
    macro_rec = recall_score(y_true, y_pred, average="macro", zero_division=0)
    accuracy = float((y_true == y_pred).mean())
    # macro-F1 CONG BANG: chi tren cac dong co nhan model THUC SU biet
    # (loai dong nhan la) -> phan anh dung nang luc phan loai da-lop cua model.
    fair_mask = np.isin(y_true, list(known_classes))
    macro_f1_fair = float(f1_score(y_true[fair_mask], y_pred[fair_mask],
                                   average="macro", zero_division=0)) if fair_mask.any() else 0.0
    report_txt = classification_report(y_true, y_pred, zero_division=0)
    cm_labels = sorted(set(y_true.tolist()) | set(y_pred.tolist()))
    cm = confusion_matrix(y_true, y_pred, labels=cm_labels)

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    result = {
        "model_dir": str(model_dir),
        "model_trained_on": meta.get("source_dataset"),
        "model_cv_macro_f1_in_distribution": meta.get("cv_macro_f1"),
        "test_dataset": args.test,
        "n_test_windows": int(len(df)),
        "n_benign_windows": n_benign,
        "n_attack_windows": int(tp + fn),
        "window_seconds": WINDOW_SECONDS,
        "labels_unseen_by_model": unseen_labels,
        "n_rows_with_unseen_label": n_unseen_rows,
        "binary_benign_vs_attack": {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "recall": round(recall_bin, 4),
            "precision": round(precision_bin, 4),
            "fpr": round(fpr, 4),
            "f1": round(f1_bin, 4),
            "fpr_per_hour": round(fpr_per_hour, 3),
            "fpr_steady_state": {
                "fp": fp_steady, "n_benign": n_steady,
                "fpr_per_hour": round(fpr_steady_per_hour, 3),
                "note": "benign van hanh on dinh (poll co dinh) -- con so van hanh nen dan",
            },
            "fpr_transient_warmup": {
                "fp": fp_transient, "n_benign": n_transient,
                "pct_flagged": round(100 * fp_transient / max(n_transient, 1), 1),
                "note": "benign warmup/khoi dong phien -- trang thai bootstrap, FP o day la han che da biet",
            },
        },
        "multiclass": {
            "accuracy": round(accuracy, 4),
            "macro_f1_raw": round(float(macro_f1), 4),
            "macro_f1_fair_known_classes": round(macro_f1_fair, 4),
            "macro_precision": round(float(macro_prec), 4),
            "macro_recall": round(float(macro_rec), 4),
            "note": "macro_f1_raw bi phat boi lop model khong emit duoc + lop vang mat trong test; "
                    "macro_f1_fair chi tinh tren lop model that su biet -> con so nen dung khi so voi in-distribution CV.",
        },
    }
    (out_dir / "ood_report.json").write_text(json.dumps(result, indent=2, ensure_ascii=False))
    (out_dir / "classification_report.txt").write_text(report_txt)
    cm_df = pd.DataFrame(cm, index=cm_labels, columns=cm_labels)
    cm_df.to_csv(out_dir / "confusion_matrix.csv")

    # --- In tom tat ---
    print("=" * 66)
    print("  OOD CROSS-SESSION EVALUATION -- OPC UA")
    print("=" * 66)
    print(f"  Model train tren : {meta.get('source_dataset', '?')}")
    print(f"    (in-distribution CV macro-F1 = {meta.get('cv_macro_f1', '?')})")
    print(f"  Test phien khac  : {args.test}")
    print(f"  Windows test     : {len(df)}  (benign={n_benign}, attack={tp+fn})")
    if n_benign_alias:
        print(f"  [i] Da chuan hoa {n_benign_alias} dong BENIGN_* -> benign (khop train).")
    if n_merged:
        print(f"  [i] Da gop {n_merged} dong WRITE_DENIED/INVALID_WRITE -> MALICIOUS_WRITE (khop train).")
    if unseen_labels:
        print(f"  [!] {n_unseen_rows} dong co nhan model KHONG biet ({unseen_labels}) "
              f"-> luon sai o da-lop, van tinh la 'attack' o nhi phan.")
    print("-" * 66)
    print("  [NHI PHAN benign-vs-attack]  (con so van hanh)")
    print(f"    Recall (bat duoc % attack) : {recall_bin*100:.1f}%   ({tp}/{tp+fn})")
    print(f"    Precision                  : {precision_bin*100:.1f}%")
    print(f"    FPR (gop)                  : {fpr*100:.2f}%   ({fp}/{n_benign})  -> {fpr_per_hour:.2f}/gio")
    if n_transient > 0:
        print(f"      - benign steady-state    : {fp_steady}/{n_steady} FP  -> {fpr_steady_per_hour:.2f}/gio  (SO VAN HANH)")
        print(f"      - benign warmup/transient: {fp_transient}/{n_transient} FP  ({100*fp_transient/max(n_transient,1):.0f}% bi gan co, han che da biet)")
    print(f"    F1                         : {f1_bin:.4f}")
    print("-" * 66)
    print("  [DA LOP]")
    print(f"    Accuracy                   : {accuracy*100:.2f}%")
    print(f"    Macro-F1 (cong bang)       : {macro_f1_fair:.4f}   (in-dist CV: {meta.get('cv_macro_f1','?')})")
    print(f"    Macro-F1 (tho, co artifact): {macro_f1:.4f}   <- bi phat boi lop model khong emit / lop vang")
    print("=" * 66)
    print(f"  Da luu: {out_dir}/ood_report.json, classification_report.txt, confusion_matrix.csv")


if __name__ == "__main__":
    main()
