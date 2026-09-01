"""RF-only vs XGBoost-only vs soft-voting Ensemble (RF+XGB), on the exact
same 82 features / hyperparameters as the deployed Layer 3 AttackClassifier
(train_eval.py), evaluated with grouped CV (no leakage) on the real S7comm
dataset (SemanticAware-S7comm-Dataset/processed/network.csv). One-off
ablation script, not part of the product.
"""
import re
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold
from sklearn.metrics import f1_score
from xgboost import XGBClassifier

text = open("/home/sus/do-an/train_eval.py").read()
m = re.search(r"FEATURE_COLUMNS\s*=\s*\[(.*?)\]", text, re.S)
FEATURE_COLUMNS = re.findall(r"\"([a-zA-Z0-9_]+)\"", m.group(1))

LABEL_MAP = {
    "BENIGN": "BENIGN",
    "SCAN_PORT": "SCAN",
    "ENUM_TAGS": "ENUMERATION",
    "SENSOR_SPOOF": "SPOOF",
    "RWRITE_BURST": "RWRITE",
    "SETPOINT_ATTACK": "RWRITE",
    "STEALTHY_WRITE": "STEALTHY",
    "S7_FLOOD": "FLOOD",
    "SYN_FLOOD": "FLOOD",
    "PROTOCOL_FUZZ": "FUZZ",
}

DATA_PATH = "/home/sus/do-an/SemanticAware-S7comm-Dataset/processed/network.csv"
usecols = [c for c in FEATURE_COLUMNS] + ["scenario_id", "session_id", "host_id", "episode_id"]
df = pd.read_csv(DATA_PATH, low_memory=False)
usecols = [c for c in usecols if c in df.columns]
df = df[usecols].copy()

for c in FEATURE_COLUMNS:
    if c not in df.columns:
        df[c] = 0.0

df["label"] = df["scenario_id"].map(LABEL_MAP)
df = df.dropna(subset=["label"])
# The real training run for the deployed model used only day1-day5 (each day
# isolates a different attack subset); day6 is the mixed-attack day kept
# aside for scenario demos/testing, not folded into this CV.
df = df[df["session_id"].astype(str) != "day6"].copy()
X_all = df[FEATURE_COLUMNS].fillna(0.0)
y_all = df["label"].values
groups = (df["session_id"].astype(str) + "|" + df["host_id"].astype(str) + "|" + df["episode_id"].astype(str)).values

print(f"[DATA] rows={len(df)}  classes={sorted(set(y_all))}  groups={len(set(groups))}")

N_SPLITS = 5
gkf = GroupKFold(n_splits=N_SPLITS)

fold_f1 = {"random_forest": [], "xgboost": [], "ensemble": []}
all_y_true, all_y_pred_ens = [], []

from collections import Counter
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import SMOTE

for fold, (train_idx, test_idx) in enumerate(gkf.split(X_all, y_all, groups), 1):
    X_train, X_test = X_all.iloc[train_idx], X_all.iloc[test_idx]
    y_train, y_test = y_all[train_idx], y_all[test_idx]

    # Exactly mirror AttackClassifier.fit() in train_eval.py: inverse-frequency
    # class weights (CPU_CONTROL x5, not present in this label set) fed only
    # to RF, and SMOTE oversampling applied to the training fold before
    # fitting *both* RF and XGB (XGB gets no class_weight of its own — only
    # benefits from SMOTE, same as production).
    classes_ = sorted(set(y_train))
    dist = Counter(y_train)
    total = len(y_train)
    class_weight_map = {}
    for cls in classes_:
        cnt = dist.get(cls, 1)
        w = total / (len(classes_) * cnt)
        if cls == "CPU_CONTROL":
            w *= 5.0
        class_weight_map[cls] = round(w, 2)

    le = LabelEncoder()
    y_train_enc = le.fit_transform(y_train)
    class_weight_int = {le.transform([cls])[0]: w for cls, w in class_weight_map.items()}

    X_train_res, y_train_enc_res = X_train.values, y_train_enc
    try:
        smote = SMOTE(random_state=42, k_neighbors=min(3, min(dist.values()) - 1))
        X_train_res, y_train_enc_res = smote.fit_resample(X_train.values, y_train_enc)
    except Exception as e:
        print(f"[fold {fold}] SMOTE skipped: {e}")

    rf = RandomForestClassifier(
        n_estimators=300, max_depth=None, min_samples_leaf=2,
        class_weight=class_weight_int, random_state=42, n_jobs=-1,
    )
    rf.fit(X_train_res, y_train_enc_res)
    rf_proba_enc = rf.predict_proba(X_test)
    rf_classes_labels = le.inverse_transform(rf.classes_)
    # Re-express rf_proba in a fixed, alphabetically sorted class order so it
    # can be averaged column-for-column with xgb_proba below.
    rf_proba = np.zeros((len(X_test), len(classes_)))
    for i, cls in enumerate(rf_classes_labels):
        j = classes_.index(cls)
        rf_proba[:, j] = rf_proba_enc[:, i]
    rf.classes_ = np.array(classes_)
    rf_pred = rf.classes_[np.argmax(rf_proba, axis=1)]

    xgb = XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8, eval_metric="mlogloss",
        random_state=42, n_jobs=-1, verbosity=0,
    )
    xgb.fit(X_train_res, y_train_enc_res)
    xgb_proba_raw = xgb.predict_proba(X_test)
    # Realign XGB's proba columns (ordered by LabelEncoder) to RF's class order
    xgb_classes = le.classes_
    xgb_proba = np.zeros_like(rf_proba)
    for i, cls in enumerate(rf.classes_):
        j = np.where(xgb_classes == cls)[0]
        if len(j):
            xgb_proba[:, i] = xgb_proba_raw[:, j[0]]
    xgb_pred = rf.classes_[np.argmax(xgb_proba, axis=1)]

    ens_proba = (rf_proba + xgb_proba) / 2.0
    ens_pred = rf.classes_[np.argmax(ens_proba, axis=1)]

    # BUG (found after the first two runs looked suspiciously low, esp. fold
    # 5's exact 0.5000): using set(y_test) | set(y_train) as `labels` counts
    # every class that's in the *training* set but happens to have zero real
    # samples in this fold's *test* set as an automatic F1=0 for that fold
    # (sklearn's zero_division=0 convention) — that's not a real error, the
    # class was just never asked about, but it drags the fold's macro
    # average down hard when several of the 8 classes are missing from a
    # given fold's test split (single-attack-per-day dataset means a rare
    # class's episodes can cluster into 1-2 folds). Scoring only labels that
    # actually occur in y_test is the correct macro-F1 for that fold.
    labels = sorted(set(y_test))
    f1_rf = f1_score(y_test, rf_pred, labels=labels, average="macro", zero_division=0)
    f1_xgb = f1_score(y_test, xgb_pred, labels=labels, average="macro", zero_division=0)
    f1_ens = f1_score(y_test, ens_pred, labels=labels, average="macro", zero_division=0)

    fold_f1["random_forest"].append(f1_rf)
    fold_f1["xgboost"].append(f1_xgb)
    fold_f1["ensemble"].append(f1_ens)
    print(f"[fold {fold}] test_rows={len(test_idx)}  RF={f1_rf:.4f}  XGB={f1_xgb:.4f}  Ensemble={f1_ens:.4f}  test_classes={sorted(set(y_test))}")

    all_y_true.extend(list(y_test))
    all_y_pred_ens.extend(list(ens_pred))

print()
print("=== Macro-F1 (multiclass, grouped CV, mean +/- std) ===")
for name, scores in fold_f1.items():
    arr = np.array(scores)
    print(f"{name:16s} {arr.mean():.4f} +/- {arr.std():.4f}")

print()
print("=== Per-class report, ensemble, out-of-fold predictions pooled across all 5 folds ===")
from sklearn.metrics import classification_report, confusion_matrix
all_labels = sorted(set(all_y_true))
print(classification_report(all_y_true, all_y_pred_ens, labels=all_labels, zero_division=0))
print("Confusion matrix (rows=true, cols=pred), label order:", all_labels)
cm = confusion_matrix(all_y_true, all_y_pred_ens, labels=all_labels)
print(pd.DataFrame(cm, index=all_labels, columns=all_labels))
