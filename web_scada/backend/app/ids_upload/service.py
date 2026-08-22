"""Pcap -> feature extraction -> 3-layer IDS pipeline (train_eval.py), wired for the web.

Reuses two existing repo-root scripts rather than reimplementing them:
  - extract_s7_features.py  (needs tshark on PATH) -> feature CSV
  - train_eval.py's IDSPipeline                    -> prediction, layer_used, confidence

No fake data: if the model directory isn't there yet (nobody has run
`python train_eval.py --mode train ...` on real Day 1-6 data), this reports
"not configured" instead of inventing a result.
"""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[4]
EXTRACT_SCRIPT = REPO_ROOT / "extract_s7_features.py"
MODEL_DIR = Path(os.getenv("IDS_MODEL_DIR", str(REPO_ROOT / "model")))

UPLOAD_SCRATCH = Path(__file__).resolve().parents[2] / "data" / "ids_uploads"
UPLOAD_SCRATCH.mkdir(parents=True, exist_ok=True)

CONFIDENCE_BINS = [0.0, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.0]


class IdsUploadError(RuntimeError):
    """Raised for conditions the caller should show as a clear error, not a 500."""


def model_configured() -> bool:
    return (
        MODEL_DIR.is_dir()
        and (MODEL_DIR / "layer2_anomaly.joblib").is_file()
        and (MODEL_DIR / "layer3_classifier.joblib").is_file()
        and (MODEL_DIR / "features.json").is_file()
    )


def _load_pipeline():
    if not model_configured():
        raise IdsUploadError(
            f"Chưa có model đã train tại {MODEL_DIR}. Chạy "
            f"'python train_eval.py --dataset <labeled_day1_6.csv> --mode train --output {MODEL_DIR}' "
            f"trên dữ liệu Day 1-6 thật trước, hoặc set IDS_MODEL_DIR trỏ đúng thư mục model."
        )
    sys.path.insert(0, str(REPO_ROOT))
    from train_eval import IDSPipeline  # noqa: PLC0415 -- repo-root script, imported lazily on purpose

    pipeline = IDSPipeline()
    pipeline.load(str(MODEL_DIR))
    return pipeline


def _extract_features(pcap_path: Path, plc_ip: str, window: float) -> Path:
    if not EXTRACT_SCRIPT.is_file():
        raise IdsUploadError(f"Không tìm thấy {EXTRACT_SCRIPT.name} ở repo root.")

    csv_path = pcap_path.with_suffix(".features.csv")
    cmd = [
        sys.executable, str(EXTRACT_SCRIPT),
        "--pcap", str(pcap_path),
        "--output", str(csv_path),
        "--window", str(window),
        "--plc-ip", plc_ip,
        "--label", "unknown",
        "--standalone-labeling",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0 or not csv_path.is_file():
        raise IdsUploadError(
            f"Trích xuất đặc trưng thất bại (tshark cần có trong PATH). "
            f"stderr: {proc.stderr[-1000:] if proc.stderr else '(empty)'}"
        )
    return csv_path


def _feature_importance(pipeline, top_n: int = 10) -> list[dict[str, Any]]:
    """Top-N features by Random Forest importance — pipeline.layer3.rf is a
    real fitted RandomForestClassifier loaded from layer3_classifier.joblib,
    feature_importance_report() already exists on AttackClassifier (used by
    train_eval.py's own CLI report), just reusing it here for the web result.
    """
    try:
        df_imp = pipeline.layer3.feature_importance_report()
    except Exception:
        return []
    if df_imp is None or df_imp.empty:
        return []
    return [
        {"feature": row["feature"], "importance": float(row["importance"])}
        for _, row in df_imp.head(top_n).iterrows()
    ]


def _summarize(df: pd.DataFrame, results: pd.DataFrame) -> dict[str, Any]:
    prediction_counts = results["prediction"].value_counts().to_dict()
    layer_counts = {str(k): int(v) for k, v in results["layer_used"].value_counts().to_dict().items()}

    confidence_hist = []
    for lo, hi in zip(CONFIDENCE_BINS[:-1], CONFIDENCE_BINS[1:]):
        mask = (results["confidence"] >= lo) & (results["confidence"] < hi if hi < 1.0 else results["confidence"] <= hi)
        confidence_hist.append({"range": f"{lo:.2f}-{hi:.2f}", "count": int(mask.sum())})

    ts_col = "window_start_ms" if "window_start_ms" in df.columns else None
    timeline = []
    if ts_col:
        merged = pd.DataFrame({
            "timestamp_ms": df[ts_col],
            "prediction": results["prediction"].values,
            "confidence": results["confidence"].values,
            "layer_used": results["layer_used"].values,
        }).sort_values("timestamp_ms")
        timeline = merged.to_dict(orient="records")

    non_benign = results[results["prediction"] != "BENIGN"].copy()
    non_benign["row_index"] = non_benign.index
    top_flows = non_benign.sort_values("confidence", ascending=False).head(200)
    # src_ip/dst_ip were listed here before but extract_s7_features.py never
    # emits per-window IP columns (only aggregate counts) — dropped so this
    # doesn't silently promise a "Flow" column that's always empty.
    flow_cols = [c for c in ("window_start_ms", "window_end_ms", "s7_input_write_count", "s7_output_write_count") if c in df.columns]
    flow_table = []
    for idx, row in top_flows.iterrows():
        entry = {"prediction": row["prediction"], "confidence": float(row["confidence"]), "layer_used": int(row["layer_used"])}
        for col in flow_cols:
            entry[col] = df.loc[idx, col]
        flow_table.append(entry)

    total = len(results)
    attack_total = int((results["prediction"] != "BENIGN").sum())

    return _to_native({
        "total_flows": total,
        "attack_flows": attack_total,
        "attack_ratio": round(attack_total / total, 4) if total else 0.0,
        "prediction_counts": prediction_counts,
        "layer_counts": layer_counts,
        "confidence_histogram": confidence_hist,
        "timeline": timeline,
        "flow_table": flow_table,
    })


def _to_native(value: Any) -> Any:
    """Recursively convert numpy scalar types (int64/float64/bool_...) to native
    Python types — pandas/numpy leak these into dicts built from DataFrames,
    and the stdlib json encoder FastAPI uses cannot serialize np.int64.
    """
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, dict):
        return {k: _to_native(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_native(v) for v in value]
    return value


def analyze_pcap(pcap_bytes: bytes, filename: str, plc_ip: str, window: float = 5.0) -> dict[str, Any]:
    pipeline = _load_pipeline()  # fail fast before writing any temp file if model missing

    job_id = uuid.uuid4().hex[:12]
    pcap_path = UPLOAD_SCRATCH / f"{job_id}_{Path(filename).name}"
    csv_path = None
    try:
        pcap_path.write_bytes(pcap_bytes)
        csv_path = _extract_features(pcap_path, plc_ip, window)

        df = pd.read_csv(csv_path, low_memory=False)
        if df.empty:
            raise IdsUploadError("File pcap không trích xuất được flow nào (kiểm tra lại --plc-ip có đúng không).")

        from train_eval import load_and_preprocess  # noqa: PLC0415

        df, features = load_and_preprocess(str(csv_path), pipeline.feature_cols)
        results = pipeline.predict(df[features])

        summary = _summarize(df, results)
        summary["feature_count"] = len(pipeline.feature_cols)
        summary["feature_importance"] = _feature_importance(pipeline)
        summary["job_id"] = job_id
        summary["source_file"] = filename
        summary["model_dir"] = str(MODEL_DIR)
        return summary
    finally:
        pcap_path.unlink(missing_ok=True)
        if csv_path:
            csv_path.unlink(missing_ok=True)
