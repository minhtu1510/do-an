"""Persists admin-edited tag safety thresholds (minimum/maximum) across
backend restarts, separately from config/opcua_tags.yaml. The YAML stays the
"factory default" that ships with the repo; overrides an admin makes at
runtime live in this small JSON file instead, so editing a threshold from
the UI never rewrites (and risks corrupting the formatting/comments of) the
YAML config.
"""

from __future__ import annotations

import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
OVERRIDES_PATH = DATA_DIR / "tag_threshold_overrides.json"


def load_overrides() -> dict[str, dict]:
    if not OVERRIDES_PATH.exists():
        return {}
    try:
        return json.loads(OVERRIDES_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_override(key: str, minimum: float | None, maximum: float | None) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    data = load_overrides()
    data[key] = {"minimum": minimum, "maximum": maximum}
    OVERRIDES_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
