"""Loads trained IDS models from disk, one per protocol.

Convention (see models/README.md):
    models/<protocol>/model.pkl  (or .joblib)
    models/<protocol>/feature_columns.json   [optional]
    models/<protocol>/label_map.json         [optional]

No model is bundled with this repo -- train_ml.py only produces evaluation
reports, not a deployable artifact. This module just defines where an
external artifact is expected and how it's loaded; until someone drops a
file at that path, is_available() returns False and callers must not fake a
prediction.
"""

from __future__ import annotations

import json
import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[3]
MODELS_DIR = REPO_ROOT / "models"

_MODEL_FILENAMES = ("model.pkl", "model.joblib")


class ModelLoadError(RuntimeError):
    pass


@dataclass
class ModelBundle:
    protocol: str
    model: Any
    model_path: Path
    feature_columns: Optional[List[str]]
    positive_class: Optional[Any]
    feature_source: str  # "model.feature_names_in_" | "feature_columns.json" | "extracted_csv (unverified)"


_cache: dict[str, tuple[float, ModelBundle]] = {}


def _protocol_dir(protocol: str) -> Path:
    return MODELS_DIR / protocol


def _find_model_file(protocol: str) -> Optional[Path]:
    d = _protocol_dir(protocol)
    for name in _MODEL_FILENAMES:
        p = d / name
        if p.is_file():
            return p
    return None


def is_available(protocol: str) -> bool:
    return _find_model_file(protocol) is not None


def _load_raw_model(path: Path) -> Any:
    try:
        import joblib
        return joblib.load(path)
    except Exception:
        pass
    with path.open("rb") as f:
        return pickle.load(f)


def _resolve_feature_columns(model: Any, protocol: str) -> tuple[Optional[List[str]], str]:
    names = getattr(model, "feature_names_in_", None)
    if names is not None:
        return list(names), "model.feature_names_in_"

    side_file = _protocol_dir(protocol) / "feature_columns.json"
    if side_file.is_file():
        with side_file.open("r", encoding="utf-8") as f:
            cols = json.load(f)
        if isinstance(cols, list):
            return cols, "feature_columns.json"

    return None, "extracted_csv (unverified)"


def _resolve_positive_class(model: Any, protocol: str) -> Optional[Any]:
    side_file = _protocol_dir(protocol) / "label_map.json"
    if side_file.is_file():
        with side_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if "positive_class" in data:
            return data["positive_class"]

    classes = getattr(model, "classes_", None)
    if classes is None:
        return None
    classes = list(classes)
    for candidate in classes:
        if str(candidate).strip().lower() in ("attack", "malicious", "anomaly", "1", "true"):
            return candidate
    if set(classes) == {0, 1}:
        return 1
    if len(classes) == 2:
        return classes[1]
    return None


def load_model(protocol: str) -> Optional[ModelBundle]:
    path = _find_model_file(protocol)
    if path is None:
        _cache.pop(protocol, None)
        return None

    mtime = path.stat().st_mtime
    cached = _cache.get(protocol)
    if cached and cached[0] == mtime:
        return cached[1]

    try:
        model = _load_raw_model(path)
    except Exception as e:
        raise ModelLoadError(f"Không load được model tại {path}: {e}") from e

    feature_columns, feature_source = _resolve_feature_columns(model, protocol)
    positive_class = _resolve_positive_class(model, protocol)

    bundle = ModelBundle(
        protocol=protocol,
        model=model,
        model_path=path,
        feature_columns=feature_columns,
        positive_class=positive_class,
        feature_source=feature_source,
    )
    _cache[protocol] = (mtime, bundle)
    return bundle
