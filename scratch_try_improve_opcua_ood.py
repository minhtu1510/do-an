#!/usr/bin/env python3
"""Thu nghiem nhanh: co cach nao (doi model / regularize / feature selection)
cai thien macro-F1 OOD (phien cach 1 thang) khong -- khong thu them data,
chi thay doi phia model. Dung cung train/test split va cung xu ly nhan
(write-merge, benign-alias) nhu evaluate_opcua_ood.py de so sanh cong bang."""

import json
import numpy as np
import pandas as pd
from sklearn.ensemble import (
    RandomForestClassifier, GradientBoostingClassifier,
    ExtraTreesClassifier, HistGradientBoostingClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score

WRITE_MERGE = {"OPCUA_INVALID_WRITE": "OPCUA_MALICIOUS_WRITE", "OPCUA_WRITE_DENIED": "OPCUA_MALICIOUS_WRITE"}
BENIGN = "benign"


def prep(path, feats):
    df = pd.read_csv(path)
    lab = df["label"].astype(str)
    lab[lab.str.upper().str.startswith("BENIGN")] = BENIGN
    lab = lab.replace(WRITE_MERGE)
    for f in feats:
        if f not in df.columns:
            df[f] = 0.0
    X = df[feats].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    return X, lab.values


feats = json.load(open("model_opcua/features.json"))
Xtr, ytr = prep("data_opc/day8_out/opcua_harvest_ext_aa.csv", feats)
Xte, yte = prep("data_opc/day8_out/opcua_ood2_ext_aa.csv", feats)

print(f"train: {len(Xtr)} rows, {ytr.dtype}; test: {len(Xte)} rows")
print(f"train labels: {sorted(set(ytr))}")
print("=" * 70)

configs = []

# 0. Baseline dung y het model da luu (doi chieu)
configs.append(("Baseline (RF 400, khong gioi han sau -- nhu model_opcua/)",
                 RandomForestClassifier(n_estimators=400, random_state=0, n_jobs=-1), False))

# 1. RF regularized (gioi han do sau + min_samples_leaf -- giam overfit phien train)
configs.append(("RF regularized (max_depth=8, min_samples_leaf=5)",
                 RandomForestClassifier(n_estimators=400, max_depth=8, min_samples_leaf=5,
                                        random_state=0, n_jobs=-1), False))

# 2. RF + class_weight balanced
configs.append(("RF class_weight=balanced",
                 RandomForestClassifier(n_estimators=400, class_weight="balanced",
                                        random_state=0, n_jobs=-1), False))

# 3. ExtraTrees (thuong robust hon RF tren OOD do randomize split diem cat)
configs.append(("ExtraTrees (400, max_depth=10)",
                 ExtraTreesClassifier(n_estimators=400, max_depth=10, random_state=0, n_jobs=-1), False))

# 4. GradientBoosting (regularize tu nhien qua shrinkage)
configs.append(("GradientBoosting (n=200, max_depth=3, lr=0.05)",
                 GradientBoostingClassifier(n_estimators=200, max_depth=3, learning_rate=0.05,
                                            random_state=0), False))

# 5. HistGradientBoosting (regularize qua l2 + early stopping ngam)
configs.append(("HistGradientBoosting (max_depth=6)",
                 HistGradientBoostingClassifier(max_depth=6, random_state=0), False))

# 6. Logistic Regression (tuyen tinh, it kha nang overfit fingerprint phien) + scale
configs.append(("LogisticRegression (scaled, C=1.0, max_iter=2000)",
                 LogisticRegression(max_iter=2000, C=1.0), True))

results = []
for name, clf, need_scale in configs:
    if need_scale:
        scaler = StandardScaler().fit(Xtr)
        Xtr_, Xte_ = scaler.transform(Xtr), scaler.transform(Xte)
    else:
        Xtr_, Xte_ = Xtr.values, Xte.values
    clf.fit(Xtr_, ytr)
    pred = clf.predict(Xte_)
    macro_f1 = f1_score(yte, pred, average="macro", zero_division=0)
    acc = (yte == pred).mean()
    results.append((name, macro_f1, acc))
    print(f"{name:55s} macro-F1={macro_f1:.4f}  acc={acc:.4f}")

print("=" * 70)
best = max(results, key=lambda r: r[1])
print(f"TOT NHAT: {best[0]} -> macro-F1={best[1]:.4f} (baseline=0.462)")
