"""Runs a loaded model over an extracted feature CSV and builds a report.

Column alignment is the main hazard here: the extractor's CSV column order
has no guaranteed relationship to what the model was trained on. We trust
`ModelBundle.feature_columns` (sklearn's `feature_names_in_` when available)
as the source of truth, reindex onto it, and surface any mismatch instead of
silently mispredicting on shifted columns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional

import pandas as pd

from .feature_extraction import ExtractionResult
from .model_registry import ModelBundle

BENIGN_LOOKALIKES = {"benign", "normal", "0", "false", "clean"}


@dataclass
class InferenceReport:
    total_windows: int
    benign_count: int
    malicious_count: int
    malicious_ratio: float
    feature_source: str
    missing_feature_columns: List[str]
    extra_feature_columns: List[str]
    rows: List[dict]
    top_alerts: List[dict]
    warnings: List[str] = field(default_factory=list)


def _is_malicious(predicted_label: Any, positive_class: Optional[Any]) -> bool:
    if positive_class is not None:
        return predicted_label == positive_class
    return str(predicted_label).strip().lower() not in BENIGN_LOOKALIKES


def run_inference(extraction: ExtractionResult, bundle: ModelBundle) -> InferenceReport:
    df_raw = pd.read_csv(extraction.raw_csv)
    df_feat = pd.read_csv(extraction.ml_safe_csv)
    warnings: List[str] = []

    feature_source = bundle.feature_source
    x_input = df_feat.drop(columns=["label"], errors="ignore")

    if bundle.feature_columns is None:
        warnings.append(
            "Model không có feature_names_in_ và không có feature_columns.json đi kèm — "
            "dùng nguyên thứ tự cột do extractor sinh ra, KHÔNG đảm bảo khớp với lúc train."
        )
        feature_columns = list(x_input.columns)
    else:
        feature_columns = bundle.feature_columns

    missing = [c for c in feature_columns if c not in x_input.columns]
    extra = [c for c in x_input.columns if c not in feature_columns]

    x = x_input.reindex(columns=feature_columns, fill_value=0.0)
    x = x.apply(pd.to_numeric, errors="coerce").fillna(0.0)

    total = len(x)
    if total == 0:
        return InferenceReport(
            total_windows=0, benign_count=0, malicious_count=0, malicious_ratio=0.0,
            feature_source=feature_source, missing_feature_columns=missing,
            extra_feature_columns=extra, rows=[], top_alerts=[],
            warnings=warnings + ["Không có window nào được trích xuất từ pcap này."],
        )

    predictions = bundle.model.predict(x)

    confidence: Optional[List[float]] = None
    if hasattr(bundle.model, "predict_proba"):
        proba = bundle.model.predict_proba(x)
        classes = list(getattr(bundle.model, "classes_", []))
        if bundle.positive_class is not None and bundle.positive_class in classes:
            pos_idx = classes.index(bundle.positive_class)
            confidence = [float(p[pos_idx]) for p in proba]
        else:
            confidence = [float(p.max()) for p in proba]

    rows = []
    malicious_count = 0
    for i in range(total):
        pred = predictions[i]
        malicious = _is_malicious(pred, bundle.positive_class)
        malicious_count += int(malicious)
        raw = df_raw.iloc[i] if i < len(df_raw) else None
        rows.append({
            "window_start_ms": int(raw["window_start_ms"]) if raw is not None and "window_start_ms" in raw else i,
            "window_end_ms": int(raw["window_end_ms"]) if raw is not None and "window_end_ms" in raw else None,
            "predicted_label": str(pred),
            "is_malicious": malicious,
            "confidence": confidence[i] if confidence is not None else None,
        })

    top_alerts = sorted(
        (r for r in rows if r["is_malicious"]),
        key=lambda r: r["confidence"] if r["confidence"] is not None else 0.0,
        reverse=True,
    )[:20]

    if missing:
        warnings.append(f"{len(missing)} cột model cần nhưng extractor không sinh ra (đã điền 0): {missing[:10]}")
    if extra:
        warnings.append(f"{len(extra)} cột do extractor sinh ra nhưng model không dùng (đã bỏ qua): {extra[:10]}")

    return InferenceReport(
        total_windows=total,
        benign_count=total - malicious_count,
        malicious_count=malicious_count,
        malicious_ratio=malicious_count / total,
        feature_source=feature_source,
        missing_feature_columns=missing,
        extra_feature_columns=extra,
        rows=rows,
        top_alerts=top_alerts,
        warnings=warnings,
    )
