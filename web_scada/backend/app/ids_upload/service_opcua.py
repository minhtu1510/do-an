"""Pcap -> feature extraction -> OPC UA classifier, wired for the web.

Counterpart to service.py, which only handles S7comm pcaps. A pcap captured
from OPC UA traffic (e.g. the Day 8 scenario suite) has none of the S7comm
fields service.py's model was trained on — running it through that pipeline
would silently produce a meaningless result instead of a real prediction.
This module is a separate model + separate feature extractor for that reason.

Reuses:
  - extract_opcua_features.py  (needs tshark on PATH) -> feature CSV
  - model_opcua/classifier.joblib, trained by train_opcua_eval.py using the
    exact recipe tests/day8/evaluate_opcua.py validated via grouped CV
    (merge OPCUA_INVALID_WRITE/OPCUA_WRITE_DENIED, no class_weight balancing)

No fake data: if model_opcua/ isn't there yet (nobody has run
train_opcua_eval.py on real OPC UA capture data), this reports "not
configured" instead of inventing a result.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[4]
EXTRACT_SCRIPT = REPO_ROOT / "extract_opcua_features.py"
MODEL_DIR = Path(os.getenv("IDS_MODEL_OPCUA_DIR", str(REPO_ROOT / "model_opcua")))

UPLOAD_SCRATCH = Path(__file__).resolve().parents[2] / "data" / "ids_uploads"
UPLOAD_SCRATCH.mkdir(parents=True, exist_ok=True)

CONFIDENCE_BINS = [0.0, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.0]


class IdsUploadOpcuaError(RuntimeError):
    """Raised for conditions the caller should show as a clear error, not a 500."""


def model_configured() -> bool:
    return (
        MODEL_DIR.is_dir()
        and (MODEL_DIR / "classifier.joblib").is_file()
        and (MODEL_DIR / "features.json").is_file()
        and (MODEL_DIR / "meta.json").is_file()
    )


def _load_model() -> tuple[Any, list[str], dict[str, Any]]:
    if not model_configured():
        raise IdsUploadOpcuaError(
            f"Chưa có model OPC UA đã train tại {MODEL_DIR}. Chạy "
            f"'python train_opcua_eval.py --dataset <opcua_features.csv> --output {MODEL_DIR}' "
            f"trên dữ liệu OPC UA thật (Day 8) trước, hoặc set IDS_MODEL_OPCUA_DIR trỏ đúng thư mục model."
        )
    classifier = joblib.load(MODEL_DIR / "classifier.joblib")
    features = json.loads((MODEL_DIR / "features.json").read_text())
    meta = json.loads((MODEL_DIR / "meta.json").read_text())
    return classifier, features, meta


def _extract_features(pcap_path: Path, plc_ip: str, window: float) -> Path:
    if not EXTRACT_SCRIPT.is_file():
        raise IdsUploadOpcuaError(f"Không tìm thấy {EXTRACT_SCRIPT.name} ở repo root.")

    csv_path = pcap_path.with_suffix(".opcua_features.csv")
    cmd = [
        sys.executable, str(EXTRACT_SCRIPT),
        "--pcap", str(pcap_path),
        "--output", str(csv_path),
        "--window", str(window),
        "--plc-ip", plc_ip,
        "--label", "unknown",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0 or not csv_path.is_file():
        raise IdsUploadOpcuaError(
            f"Trích xuất đặc trưng OPC UA thất bại (tshark cần có trong PATH). "
            f"stderr: {proc.stderr[-1000:] if proc.stderr else '(empty)'}"
        )
    return csv_path


def _to_native(value: Any) -> Any:
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, dict):
        return {k: _to_native(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_native(v) for v in value]
    return value


def _feature_importance(classifier, features: list[str], top_n: int = 10) -> list[dict[str, Any]]:
    """Top-N features by importance — classifier here is a single fitted
    RandomForestClassifier (see train_opcua_eval.py), so feature_importances_
    is available directly, no wrapper needed like the S7comm ensemble."""
    try:
        importances = classifier.feature_importances_
    except AttributeError:
        return []
    pairs = sorted(zip(features, importances), key=lambda t: -t[1])[:top_n]
    return [{"feature": f, "importance": float(v)} for f, v in pairs]


def _summarize(df: pd.DataFrame, predictions: np.ndarray, confidences: np.ndarray, meta: dict[str, Any]) -> dict[str, Any]:
    prediction_counts = pd.Series(predictions).value_counts().to_dict()

    confidence_hist = []
    for lo, hi in zip(CONFIDENCE_BINS[:-1], CONFIDENCE_BINS[1:]):
        mask = (confidences >= lo) & (confidences < hi if hi < 1.0 else confidences <= hi)
        confidence_hist.append({"range": f"{lo:.2f}-{hi:.2f}", "count": int(mask.sum())})

    ts_col = "window_start_ms" if "window_start_ms" in df.columns else None
    timeline = []
    if ts_col:
        merged = pd.DataFrame({
            "timestamp_ms": df[ts_col],
            "prediction": predictions,
            "confidence": confidences,
        }).sort_values("timestamp_ms")
        timeline = merged.to_dict(orient="records")

    non_benign_mask = predictions != "benign"
    flow_cols = [c for c in (
        "window_start_ms", "window_end_ms", "opcua_create_session_count",
        "opcua_write_count", "opcua_browse_count", "opcua_read_count",
    ) if c in df.columns]
    flow_table = []
    order = np.argsort(-confidences)
    for idx in order:
        if not non_benign_mask[idx]:
            continue
        entry = {"prediction": str(predictions[idx]), "confidence": float(confidences[idx])}
        for col in flow_cols:
            entry[col] = df.iloc[idx][col]
        flow_table.append(entry)
        if len(flow_table) >= 200:
            break

    total = len(predictions)
    attack_total = int(non_benign_mask.sum())

    return _to_native({
        "total_flows": total,
        "attack_flows": attack_total,
        "attack_ratio": round(attack_total / total, 4) if total else 0.0,
        "prediction_counts": prediction_counts,
        "confidence_histogram": confidence_hist,
        "timeline": timeline,
        "flow_table": flow_table,
        "model_cv_macro_f1": meta.get("cv_macro_f1"),
    })


def analyze_pcap(pcap_bytes: bytes, filename: str, plc_ip: str, window: float = 5.0) -> dict[str, Any]:
    classifier, features, meta = _load_model()  # fail fast before writing any temp file if model missing

    job_id = uuid.uuid4().hex[:12]
    pcap_path = UPLOAD_SCRATCH / f"{job_id}_{Path(filename).name}"
    csv_path = None
    try:
        pcap_path.write_bytes(pcap_bytes)
        csv_path = _extract_features(pcap_path, plc_ip, window)

        df = pd.read_csv(csv_path, low_memory=False)
        if df.empty:
            raise IdsUploadOpcuaError("File pcap không trích xuất được flow OPC UA nào (kiểm tra lại --plc-ip có đúng không).")

        missing = [f for f in features if f not in df.columns]
        for f in missing:
            df[f] = 0
        X = df[features].fillna(0).values

        predictions = classifier.predict(X)
        proba = classifier.predict_proba(X)
        confidences = proba.max(axis=1)

        summary = _summarize(df, predictions, confidences, meta)
        summary["feature_count"] = len(features)
        summary["feature_importance"] = _feature_importance(classifier, features)
        summary["job_id"] = job_id
        summary["source_file"] = filename
        summary["model_dir"] = str(MODEL_DIR)
        return summary
    finally:
        pcap_path.unlink(missing_ok=True)
        if csv_path:
            csv_path.unlink(missing_ok=True)
