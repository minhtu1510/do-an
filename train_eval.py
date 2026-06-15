#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
train_eval.py – 3-Layer IDS for Siemens S7 / Profinet ICS Networks
====================================================================

Kiến trúc 3 lớp:
  Layer 1 – Rule-based detector  : Phát hiện tức thì (SCAN, CPU_CTRL, FUZZ nghiêm trọng)
  Layer 2 – Anomaly detection    : IsolationForest, phát hiện bất thường thống kê
  Layer 3 – ML Classifier        : Random Forest + XGBoost ensemble, phân loại chi tiết

Labels (9 lớp):
  BENIGN, SCAN, FLOOD, ENUM(ERATION), RWRITE, SPOOF, REPLAY, CPU_CONTROL, FUZZ

Cách dùng:
  python train_eval.py --dataset labeled_dataset.csv --mode train --output model/
  python train_eval.py --dataset labeled_dataset.csv --mode eval  --model model/
  python train_eval.py --input features.csv           --mode predict --model model/

Requirements:
  pip install pandas numpy scikit-learn xgboost imbalanced-learn joblib shap matplotlib
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import warnings
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")


# ============================================================
# Constants
# ============================================================

LABEL_COL = "label"

# 9 attack labels (chuẩn hóa về uppercase)
ALL_LABELS = ["BENIGN", "SCAN", "FLOOD", "ENUMERATION", "RWRITE",
              "SPOOF", "REPLAY", "CPU_CONTROL", "FUZZ"]

# Map nhãn thô → nhãn chuẩn (xử lý các biến thể trong merge_dataset.py)
LABEL_NORMALIZE = {
    "BENIGN": "BENIGN", "NORMAL": "BENIGN", "BENIGN_NORMAL": "BENIGN",
    "SCAN": "SCAN", "DISCOVERY": "SCAN", "S7_DISCOVERY": "SCAN",
    "FLOOD": "FLOOD", "S7_FLOOD_LOW": "FLOOD", "S7_FLOOD_HIGH": "FLOOD",
    "ENUM": "ENUMERATION", "ENUMERATION": "ENUMERATION", "ENUM_TAGS": "ENUMERATION",
    "RWRITE": "RWRITE", "RWRITE_TAG": "RWRITE", "SETPOINT_ATTACK": "RWRITE",
    "SPOOF": "SPOOF", "SPOOF_TAG": "SPOOF",
    "REPLAY": "REPLAY", "COMMAND_REPLAY_STOP": "REPLAY", "COMMAND_REPLAY_START": "REPLAY",
    "CPU_CONTROL": "CPU_CONTROL", "CPU_CTRL": "CPU_CONTROL",
    "FUZZ": "FUZZ", "FUZZ_S7": "FUZZ",
}

# Features mới dùng cho DCP scan (cần có trong dataset)
DCP_FEATURES = [
    "dcp_identify_request_count",
    "dcp_identify_response_count",
    "dcp_total_frame_count",
    "dcp_scan_detected",
]

# Features S7 I/Q write cho SPOOF detection
SPOOF_FEATURES = [
    "s7_input_write_count",
    "s7_output_write_count",
]

# Feature set đầy đủ (85+ features) – lấy từ extract_s7_features.py header
FEATURE_COLUMNS = [
    # Network/session
    "packet_count", "byte_count", "packet_rate",
    "tcp_syn_count", "tcp_rst_count", "tcp_ack_count", "tcp_psh_count", "tcp_fin_count",
    # TCP analysis
    "tcp_active_streams", "tcp_time_delta_mean", "tcp_time_delta_std",
    "tcp_retransmit_count", "tcp_out_of_order_count", "tcp_prev_seg_lost_count",
    "packet_len_mean", "packet_len_std",
    "tcp_payload_len_mean", "tcp_payload_len_std",
    # Industrial protocol
    "tcp_102_packet_count", "tpkt_count", "cotp_count",
    "cotp_cr_count", "cotp_cc_count", "cotp_dt_count", "cotp_dr_count",
    "cotp_fragment_count", "pres_data_transfer_count",
    "s7comm_packet_count", "s7comm_plus_packet_count",
    # Directional
    "to_plc_packet_count", "to_plc_byte_count",
    "from_plc_packet_count", "from_plc_byte_count",
    # S7 semantic
    "s7_read_count", "s7_write_count", "s7_setup_count",
    "s7_cpu_control_count", "s7_error_count",
    "s7_pdu_job_count", "s7_pdu_ack_count", "s7_pdu_ack_data_count", "s7_pdu_userdata_count",
    "s7_unique_db_count", "s7_unique_area_count", "s7_unique_offset_count",
    "s7_transport_size_count", "s7_repeated_command_count",
    # DPI payload
    "s7_db_area_count", "s7_merker_area_count",
    "s7_input_area_count", "s7_output_area_count", "s7_other_area_count",
    "s7_write_payload_bytes_total", "s7_write_payload_bytes_mean",
    "s7_max_item_count", "s7_write_read_ratio", "s7_unique_commands_count",
    # Payload stats
    "raw_payload_len_mean", "raw_payload_len_std",
    "raw_payload_len_min", "raw_payload_len_max",
    "payload_entropy_mean", "payload_entropy_max",
    "payload_hash_unique_count", "payload_repeated_hash_count",
    # Background
    "arp_count", "icmp_count", "other_packet_count", "non_s7_packet_ratio",
    # === 13 NEW FEATURES ===
    "dcp_identify_request_count", "dcp_identify_response_count",
    "dcp_total_frame_count", "dcp_scan_detected",
    "s7_input_write_count", "s7_output_write_count",
    "tcp_conn_churn_rate",
    "s7_sequential_offset_score",
    "payload_entropy_std", "payload_hash_unique_ratio",
    "plc_response_gap_max_ms",
    "from_plc_packet_ratio",
    "s7_negotiation_only_ratio",
]


# ============================================================
# Layer 1: Rule-based Detector
# ============================================================

class RuleBasedDetector:
    """
    Phát hiện tức thì các tấn công có dấu hiệu rõ ràng.
    100% recall cho CPU_CONTROL và SCAN – không cần training.
    """

    def predict(self, df: pd.DataFrame) -> pd.Series:
        """
        Returns Series với nhãn rule-based hoặc None nếu không match rule.
        None → chuyển sang Layer 2/3 để phân loại.
        """
        result = pd.Series([None] * len(df), index=df.index, dtype=object)

        for idx, row in df.iterrows():
            label = self._apply_rules(row)
            result[idx] = label

        return result

    def _apply_rules(self, row: pd.Series) -> Optional[str]:
        """Apply priority-ordered rules to a single row."""

        # Rule 1: CPU_CONTROL – Phát hiện gửi lệnh STOP/START PLC
        # s7_cpu_control_count > 0 → 100% recall, rule đơn giản nhất
        if row.get("s7_cpu_control_count", 0) > 0:
            return "CPU_CONTROL"

        # Rule 2: DCP SCAN – Profinet Discovery scan
        # Cần ≥ 2 Identify Request (1 có thể là normal probe)
        if row.get("dcp_identify_request_count", 0) >= 2:
            return "SCAN"

        # Rule 3: FUZZ nghiêm trọng – TCP RST rất cao + S7 error rất cao
        # Dấu hiệu: PLC liên tục reject malformed PDU
        tcp_rst = row.get("tcp_rst_count", 0)
        s7_err = row.get("s7_error_count", 0)
        pkt_count = max(row.get("packet_count", 1), 1)
        if tcp_rst / pkt_count > 0.4 and s7_err > 30:
            return "FUZZ"

        # Rule 4: FLOOD cực đoan – hàng trăm SYN trong 1 window
        syn_count = row.get("tcp_syn_count", 0)
        pkt_rate = row.get("packet_rate", 0)
        cotp_cr = row.get("cotp_cr_count", 0)
        read_write_total = row.get("s7_read_count", 0) + row.get("s7_write_count", 0)
        if syn_count > 40 and cotp_cr > 40 and read_write_total == 0:
            return "FLOOD"

        # Không match rule nào → return None
        return None


# ============================================================
# Layer 2: Anomaly Detection
# ============================================================

class AnomalyDetector:
    """
    IsolationForest-based anomaly detection.
    Được train trên dữ liệu BENIGN để phát hiện bất thường.
    """

    def __init__(self, contamination: float = 0.05):
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        self.scaler = StandardScaler()
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=200,
            random_state=42,
            n_jobs=-1,
        )
        self.feature_cols: List[str] = []
        self.trained = False

    def fit(self, df_benign: pd.DataFrame, feature_cols: List[str]) -> None:
        """Train chỉ trên BENIGN data."""
        self.feature_cols = feature_cols
        X = df_benign[feature_cols].fillna(0).values
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.trained = True
        print(f"[Layer 2] IsolationForest trained on {len(df_benign)} BENIGN samples")

    def predict(self, df: pd.DataFrame) -> pd.Series:
        """Returns 1 (normal) hoặc -1 (anomaly)."""
        if not self.trained:
            return pd.Series([1] * len(df), index=df.index)

        X = df[self.feature_cols].fillna(0).values
        X_scaled = self.scaler.transform(X)
        preds = self.model.predict(X_scaled)  # 1=normal, -1=anomaly
        return pd.Series(preds, index=df.index)

    def save(self, path: str) -> None:
        import joblib
        joblib.dump({"scaler": self.scaler, "model": self.model,
                     "feature_cols": self.feature_cols}, path)
        print(f"[Layer 2] Saved to {path}")

    def load(self, path: str) -> None:
        import joblib
        obj = joblib.load(path)
        self.scaler = obj["scaler"]
        self.model = obj["model"]
        self.feature_cols = obj["feature_cols"]
        self.trained = True
        print(f"[Layer 2] Loaded from {path}")


# ============================================================
# Layer 3: ML Classifier (Ensemble)
# ============================================================

class AttackClassifier:
    """
    Ensemble classifier: Random Forest + XGBoost (soft voting).
    Handles class imbalance với SMOTE + class weights.
    """

    def __init__(self):
        self.rf = None
        self.xgb = None
        self.label_encoder = None
        self.feature_cols: List[str] = []
        self.classes_: List[str] = []
        self.trained = False

    def fit(
        self,
        df: pd.DataFrame,
        feature_cols: List[str],
        label_col: str = LABEL_COL,
    ) -> None:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import LabelEncoder

        try:
            from xgboost import XGBClassifier
            has_xgb = True
        except ImportError:
            has_xgb = False
            print("[Layer 3] XGBoost không available – chỉ dùng Random Forest")

        try:
            from imblearn.over_sampling import SMOTE
            has_smote = True
        except ImportError:
            has_smote = False
            print("[Layer 3] imbalanced-learn không available – bỏ qua SMOTE")

        self.feature_cols = feature_cols

        # Encode labels
        le = LabelEncoder()
        y = le.fit_transform(df[label_col].fillna("BENIGN"))
        self.label_encoder = le
        self.classes_ = list(le.classes_)

        X = df[feature_cols].fillna(0).values

        print(f"\n[Layer 3] Training trên {len(df)} samples")
        print(f"[Layer 3] Classes: {self.classes_}")
        print(f"[Layer 3] Features: {len(feature_cols)}")

        # Class distribution
        from collections import Counter
        dist = Counter(df[label_col].fillna("BENIGN"))
        print("[Layer 3] Class distribution:")
        for cls, cnt in sorted(dist.items()):
            print(f"  {cls:<20} {cnt:>6} ({cnt/len(df)*100:.1f}%)")

        # Class weights (đặc biệt nặng cho CPU_CONTROL vì rất ít samples)
        class_weight_map = {}
        total = len(df)
        n_classes = len(self.classes_)
        for cls in self.classes_:
            cnt = dist.get(cls, 1)
            weight = total / (n_classes * cnt)
            # CPU_CONTROL cần recall cao → tăng weight thêm
            if cls == "CPU_CONTROL":
                weight *= 5.0
            class_weight_map[cls] = round(weight, 2)
        print(f"[Layer 3] Class weights: {class_weight_map}")

        # Map class names to encoded indices
        class_weight_int = {
            le.transform([cls])[0]: w
            for cls, w in class_weight_map.items()
            if cls in le.classes_
        }

        # SMOTE oversampling
        if has_smote:
            try:
                smote = SMOTE(random_state=42, k_neighbors=min(3, min(dist.values()) - 1))
                X, y = smote.fit_resample(X, y)
                print(f"[Layer 3] After SMOTE: {len(X)} samples")
            except Exception as e:
                print(f"[Layer 3] SMOTE failed ({e}), continuing without oversampling")

        # Random Forest
        print("[Layer 3] Training Random Forest...")
        self.rf = RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_leaf=2,
            class_weight=class_weight_int,
            random_state=42,
            n_jobs=-1,
        )
        self.rf.fit(X, y)
        print("[Layer 3] Random Forest done.")

        # XGBoost
        if has_xgb:
            print("[Layer 3] Training XGBoost...")
            # Tính sample_weight từ class_weight_int
            sample_weight = np.array([class_weight_int.get(yi, 1.0) for yi in y])
            self.xgb = XGBClassifier(
                n_estimators=300,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                use_label_encoder=False,
                eval_metric="mlogloss",
                random_state=42,
                n_jobs=-1,
                verbosity=0,
            )
            self.xgb.fit(X, y, sample_weight=sample_weight)
            print("[Layer 3] XGBoost done.")

        self.trained = True

    def predict_proba(self, df: pd.DataFrame) -> np.ndarray:
        """Returns class probabilities (n_samples, n_classes)."""
        if not self.trained:
            raise RuntimeError("Model chưa được train")

        X = df[self.feature_cols].fillna(0).values
        proba_rf = self.rf.predict_proba(X)

        if self.xgb is not None:
            proba_xgb = self.xgb.predict_proba(X)
            # Soft voting: trung bình xác suất
            return (proba_rf + proba_xgb) / 2.0
        return proba_rf

    def predict(self, df: pd.DataFrame) -> np.ndarray:
        proba = self.predict_proba(df)
        idx = np.argmax(proba, axis=1)
        return self.label_encoder.inverse_transform(idx)

    def feature_importance_report(self) -> pd.DataFrame:
        """Top features theo Random Forest importance."""
        if self.rf is None:
            return pd.DataFrame()
        imp = self.rf.feature_importances_
        df_imp = pd.DataFrame({
            "feature": self.feature_cols,
            "importance": imp,
        }).sort_values("importance", ascending=False)
        return df_imp

    def save(self, path: str) -> None:
        import joblib
        joblib.dump({
            "rf": self.rf,
            "xgb": self.xgb,
            "label_encoder": self.label_encoder,
            "feature_cols": self.feature_cols,
            "classes_": self.classes_,
        }, path)
        print(f"[Layer 3] Saved to {path}")

    def load(self, path: str) -> None:
        import joblib
        obj = joblib.load(path)
        self.rf = obj["rf"]
        self.xgb = obj.get("xgb")
        self.label_encoder = obj["label_encoder"]
        self.feature_cols = obj["feature_cols"]
        self.classes_ = obj["classes_"]
        self.trained = True
        print(f"[Layer 3] Loaded from {path}")


# ============================================================
# 3-Layer IDS Pipeline
# ============================================================

class IDSPipeline:
    """Kết hợp 3 lớp thành một pipeline hoàn chỉnh."""

    def __init__(self):
        self.layer1 = RuleBasedDetector()
        self.layer2 = AnomalyDetector()
        self.layer3 = AttackClassifier()
        self.feature_cols: List[str] = []

    def fit(self, df: pd.DataFrame, feature_cols: List[str]) -> None:
        self.feature_cols = feature_cols

        # Normalize labels
        df = df.copy()
        df[LABEL_COL] = df[LABEL_COL].str.upper().map(
            lambda x: LABEL_NORMALIZE.get(x, x)
        )

        # Layer 2: train trên BENIGN data
        df_benign = df[df[LABEL_COL] == "BENIGN"]
        if len(df_benign) > 0:
            self.layer2.fit(df_benign, feature_cols)
        else:
            print("[WARNING] Không có BENIGN samples để train Layer 2")

        # Layer 3: train trên toàn bộ data
        self.layer3.fit(df, feature_cols)

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Returns DataFrame với các cột:
            prediction, layer_used, confidence
        """
        results = []

        # Layer 1: Rule-based
        l1_preds = self.layer1.predict(df)

        # Layer 2: Anomaly
        l2_preds = self.layer2.predict(df)

        # Layer 3: ML Classifier
        l3_preds = self.layer3.predict(df)
        l3_proba = self.layer3.predict_proba(df)

        for i in range(len(df)):
            if l1_preds.iloc[i] is not None:
                # Layer 1 đã phát hiện → dùng kết quả rule-based
                results.append({
                    "prediction": l1_preds.iloc[i],
                    "layer_used": 1,
                    "confidence": 1.0,
                })
            elif l2_preds.iloc[i] == -1:
                # Layer 2 phát hiện anomaly → dùng Layer 3 để classify
                pred = l3_preds[i]
                conf = float(np.max(l3_proba[i]))
                results.append({
                    "prediction": pred if pred != "BENIGN" else "ANOMALY",
                    "layer_used": 2,
                    "confidence": conf,
                })
            else:
                # Bình thường → Layer 3 classify
                pred = l3_preds[i]
                conf = float(np.max(l3_proba[i]))
                results.append({
                    "prediction": pred,
                    "layer_used": 3,
                    "confidence": conf,
                })

        return pd.DataFrame(results, index=df.index)

    def save(self, model_dir: str) -> None:
        os.makedirs(model_dir, exist_ok=True)
        self.layer2.save(os.path.join(model_dir, "layer2_anomaly.joblib"))
        self.layer3.save(os.path.join(model_dir, "layer3_classifier.joblib"))
        # Save feature list
        with open(os.path.join(model_dir, "features.json"), "w") as f:
            json.dump(self.feature_cols, f, indent=2)
        print(f"[IDS] Pipeline saved to {model_dir}/")

    def load(self, model_dir: str) -> None:
        self.layer2.load(os.path.join(model_dir, "layer2_anomaly.joblib"))
        self.layer3.load(os.path.join(model_dir, "layer3_classifier.joblib"))
        with open(os.path.join(model_dir, "features.json")) as f:
            self.feature_cols = json.load(f)
        print(f"[IDS] Pipeline loaded from {model_dir}/")


# ============================================================
# Data Loading & Preprocessing
# ============================================================

def load_and_preprocess(csv_path: str, available_features: List[str]) -> Tuple[pd.DataFrame, List[str]]:
    """Load CSV, chọn features có sẵn, fill NaN."""
    print(f"[DATA] Loading: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)
    print(f"[DATA] Shape: {df.shape}")

    # Normalize labels
    if LABEL_COL in df.columns:
        df[LABEL_COL] = df[LABEL_COL].str.upper().map(
            lambda x: LABEL_NORMALIZE.get(x, x) if isinstance(x, str) else x
        )
        print(f"[DATA] Label distribution:\n{df[LABEL_COL].value_counts()}")

    # Chọn features có sẵn trong file
    existing_features = [f for f in available_features if f in df.columns]
    missing = [f for f in available_features if f not in df.columns]

    if missing:
        print(f"[DATA] {len(missing)} features thiếu – sẽ được fill bằng 0:")
        for m in missing[:10]:
            print(f"  - {m}")
        if len(missing) > 10:
            print(f"  ... và {len(missing)-10} feature khác")
        # Thêm cột 0 cho features thiếu
        for m in missing:
            df[m] = 0
        existing_features = available_features  # Bây giờ đủ hết

    # Ép kiểu số & fill NaN
    for col in existing_features:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    # Drop decode_level (string column, không phải feature số)
    existing_features = [f for f in existing_features if f != "decode_level"]

    print(f"[DATA] Using {len(existing_features)} numeric features")
    return df, existing_features


# ============================================================
# Evaluation
# ============================================================

def evaluate(y_true: pd.Series, y_pred: pd.Series, labels: List[str]) -> None:
    """In classification report chi tiết theo từng class."""
    from sklearn.metrics import (
        classification_report, confusion_matrix, f1_score
    )

    print("\n" + "="*70)
    print("EVALUATION REPORT")
    print("="*70)

    # Lọc labels thực sự có trong dữ liệu
    present_labels = sorted(set(y_true) | set(y_pred))

    print("\n📊 Per-Class Metrics:")
    print(classification_report(
        y_true, y_pred,
        labels=[l for l in labels if l in present_labels],
        target_names=[l for l in labels if l in present_labels],
        zero_division=0,
    ))

    # Macro F1
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    print(f"🎯 Macro F1:    {macro_f1:.4f}")
    print(f"🎯 Weighted F1: {weighted_f1:.4f}")

    # Critical check: CPU_CONTROL recall
    if "CPU_CONTROL" in set(y_true):
        from sklearn.metrics import recall_score
        cpu_mask = y_true == "CPU_CONTROL"
        if cpu_mask.sum() > 0:
            cpu_recall = recall_score(
                y_true[cpu_mask], y_pred[cpu_mask],
                labels=["CPU_CONTROL"], average="macro", zero_division=0
            )
            status = "✅" if cpu_recall >= 0.99 else "⚠️"
            print(f"\n{status} CPU_CONTROL Recall: {cpu_recall:.4f} (target: ≥0.99)")

    # DCP/SCAN check
    if "SCAN" in set(y_true):
        from sklearn.metrics import recall_score, precision_score
        scan_mask = y_true == "SCAN"
        if scan_mask.sum() > 0:
            scan_recall = recall_score(y_true, y_pred, labels=["SCAN"], average="macro", zero_division=0)
            print(f"{'✅' if scan_recall >= 0.90 else '⚠️'} SCAN Recall: {scan_recall:.4f} (target: ≥0.90)")


def feature_importance_analysis(classifier: AttackClassifier, top_n: int = 20) -> None:
    """In top-N features by importance."""
    df_imp = classifier.feature_importance_report()
    if df_imp.empty:
        return

    print(f"\n📈 Top {top_n} Most Important Features (Random Forest):")
    print(f"{'Rank':<5} {'Feature':<45} {'Importance':>10}")
    print("-" * 62)
    for rank, (_, row) in enumerate(df_imp.head(top_n).iterrows(), 1):
        bar = "█" * int(row["importance"] * 500)
        print(f"{rank:<5} {row['feature']:<45} {row['importance']:>10.4f}  {bar}")

    # Highlight critical features
    critical = ["s7_cpu_control_count", "dcp_identify_request_count",
                "tcp_rst_count", "s7_write_read_ratio", "s7_sequential_offset_score"]
    print("\n⭐ Critical Feature Rankings:")
    for feat in critical:
        mask = df_imp["feature"] == feat
        if mask.any():
            rank = df_imp[mask].index[0] + 1
            imp = df_imp[mask]["importance"].values[0]
            print(f"   {feat:<45} rank={rank:<3} imp={imp:.4f}")


def try_shap_analysis(classifier: AttackClassifier, df_sample: pd.DataFrame) -> None:
    """SHAP analysis nếu shap được cài."""
    try:
        import shap
        import matplotlib.pyplot as plt

        print("\n[SHAP] Generating feature importance plot...")
        X = df_sample[classifier.feature_cols].fillna(0).values
        explainer = shap.TreeExplainer(classifier.rf)
        shap_values = explainer.shap_values(X[:min(200, len(X))])

        plt.figure(figsize=(12, 8))
        if isinstance(shap_values, list):
            # Multi-class: show mean |SHAP| across all classes
            mean_shap = np.mean([np.abs(sv) for sv in shap_values], axis=0)
            shap.summary_plot(
                mean_shap,
                X[:min(200, len(X))],
                feature_names=classifier.feature_cols,
                plot_type="bar",
                show=False,
            )
        else:
            shap.summary_plot(
                shap_values, X[:min(200, len(X))],
                feature_names=classifier.feature_cols,
                show=False,
            )
        plt.tight_layout()
        plt.savefig("shap_importance.png", dpi=150, bbox_inches="tight")
        print("[SHAP] Saved: shap_importance.png")

    except ImportError:
        print("[SHAP] shap không được cài – bỏ qua. (pip install shap)")
    except Exception as e:
        print(f"[SHAP] Lỗi: {e}")


# ============================================================
# CLI
# ============================================================

def mode_train(args) -> None:
    """Train full pipeline và save model."""
    df, features = load_and_preprocess(args.dataset, FEATURE_COLUMNS)

    if LABEL_COL not in df.columns:
        print(f"[ERROR] Column '{LABEL_COL}' không tìm thấy trong dataset!")
        sys.exit(1)

    # Train-test split
    from sklearn.model_selection import train_test_split
    df_train, df_test = train_test_split(
        df, test_size=0.2, random_state=42,
        stratify=df[LABEL_COL] if df[LABEL_COL].nunique() > 1 else None
    )
    print(f"\n[DATA] Train: {len(df_train)}, Test: {len(df_test)}")

    # Train pipeline
    pipeline = IDSPipeline()
    pipeline.fit(df_train, features)

    # Save
    os.makedirs(args.output, exist_ok=True)
    pipeline.save(args.output)

    # Evaluate on test set
    print("\n[EVAL] Evaluating on test set...")
    test_results = pipeline.predict(df_test[features])
    y_true = df_test[LABEL_COL]
    y_pred = test_results["prediction"]

    evaluate(y_true, y_pred, ALL_LABELS)
    feature_importance_analysis(pipeline.layer3, top_n=25)
    try_shap_analysis(pipeline.layer3, df_test)

    # Layer breakdown
    layer_counts = test_results["layer_used"].value_counts()
    print(f"\n[PIPELINE] Phân phối quyết định theo layer:")
    for layer, cnt in layer_counts.items():
        pct = cnt / len(test_results) * 100
        print(f"   Layer {layer}: {cnt:>5} ({pct:.1f}%)")

    print("\n✅ Training hoàn tất!")
    print(f"   Model lưu tại: {args.output}/")


def mode_eval(args) -> None:
    """Load model đã train và evaluate trên dataset."""
    pipeline = IDSPipeline()
    pipeline.load(args.model)

    df, features = load_and_preprocess(args.dataset, pipeline.feature_cols)

    if LABEL_COL not in df.columns:
        print(f"[ERROR] Column '{LABEL_COL}' không tìm thấy!")
        sys.exit(1)

    results = pipeline.predict(df[features])
    evaluate(df[LABEL_COL], results["prediction"], ALL_LABELS)
    feature_importance_analysis(pipeline.layer3, top_n=25)


def mode_predict(args) -> None:
    """Predict trên file input không có label."""
    pipeline = IDSPipeline()
    pipeline.load(args.model)

    df, features = load_and_preprocess(args.input, pipeline.feature_cols)
    results = pipeline.predict(df[features])

    # Merge results với metadata
    output_df = df.copy()
    output_df["prediction"] = results["prediction"]
    output_df["layer_used"] = results["layer_used"]
    output_df["confidence"] = results["confidence"]

    output_path = args.output or args.input.replace(".csv", "_predictions.csv")
    output_df.to_csv(output_path, index=False)
    print(f"\n[OK] Predictions saved to: {output_path}")

    # Summary
    pred_dist = results["prediction"].value_counts()
    print("\n📊 Prediction Summary:")
    for label, cnt in pred_dist.items():
        alert = " ⚠️ ATTACK DETECTED" if label != "BENIGN" else ""
        print(f"   {label:<20} {cnt:>6}{alert}")

    # Rule-based alerts (Layer 1)
    l1_alerts = results[results["layer_used"] == 1]
    if len(l1_alerts) > 0:
        print(f"\n🚨 Layer 1 Rule-based ALERTS: {len(l1_alerts)} windows")
        for pred, cnt in l1_alerts["prediction"].value_counts().items():
            print(f"   {pred}: {cnt} windows")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="3-Layer IDS for Siemens S7/Profinet ICS Networks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  train    - Train model từ labeled dataset và lưu model
  eval     - Evaluate model đã train trên labeled dataset
  predict  - Dự đoán nhãn cho dữ liệu mới (không cần label)

Examples:
  python train_eval.py --dataset data/labeled.csv --mode train --output model/
  python train_eval.py --dataset data/test.csv    --mode eval  --model model/
  python train_eval.py --input data/live.csv      --mode predict --model model/
""",
    )

    parser.add_argument(
        "--mode", required=True,
        choices=["train", "eval", "predict"],
        help="Chế độ hoạt động",
    )
    parser.add_argument(
        "--dataset",
        help="[train/eval] Path đến labeled CSV dataset",
    )
    parser.add_argument(
        "--input",
        help="[predict] Path đến CSV input không có label",
    )
    parser.add_argument(
        "--output",
        default="model/",
        help="[train] Thư mục lưu model (default: model/). [predict] Output file path",
    )
    parser.add_argument(
        "--model",
        default="model/",
        help="[eval/predict] Thư mục chứa model đã train",
    )

    args = parser.parse_args()

    if args.mode == "train":
        if not args.dataset:
            parser.error("--dataset required for train mode")
        mode_train(args)
    elif args.mode == "eval":
        if not args.dataset or not args.model:
            parser.error("--dataset và --model required for eval mode")
        mode_eval(args)
    elif args.mode == "predict":
        if not args.input or not args.model:
            parser.error("--input và --model required for predict mode")
        mode_predict(args)


if __name__ == "__main__":
    main()
