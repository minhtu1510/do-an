"""Reads the CSV produced by attacks_ext/../attack_event_logger.py during S7comm
attack runs (run_day_bangtruyen.sh Day 3/4), so the Trends chart can overlay a
marker at the exact moment RWRITE_BURST/SETPOINT_ATTACK wrote to the PLC.

The attack script and this backend usually run on different machines (attack
machine vs. controller machine) — there is no live network sync here. Copy or
mount the CSV so it is readable from wherever this backend runs, then point
ATTACK_EVENT_FILE at it. Returns an empty list (not fake data) if unset or
missing, exactly like the rest of this codebase's "no fake data" convention.
"""

from __future__ import annotations

import csv
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

TZ = timezone(timedelta(hours=7))


def _path() -> Path | None:
    raw = os.getenv("ATTACK_EVENT_FILE")
    if not raw:
        return None
    path = Path(raw)
    return path if path.is_file() else None


def configured() -> bool:
    return _path() is not None


def list_attack_events(start: str | None = None, end: str | None = None) -> list[dict]:
    path = _path()
    if path is None:
        return []

    start_dt = datetime.fromisoformat(start) if start else None
    end_dt = datetime.fromisoformat(end) if end else None

    events = []
    with path.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            try:
                ts = datetime.fromtimestamp(int(row["timestamp_ms"]) / 1000, tz=TZ)
            except (KeyError, ValueError):
                continue
            if start_dt and ts < start_dt:
                continue
            if end_dt and ts > end_dt:
                continue
            events.append({
                "timestamp": ts.isoformat(),
                "scenario_label": row.get("scenario_label", ""),
                "signal": row.get("signal", ""),
                "old_value": row.get("old_value", ""),
                "new_value": row.get("new_value", ""),
                "day": row.get("day", ""),
                "note": row.get("note", ""),
            })
    return events
