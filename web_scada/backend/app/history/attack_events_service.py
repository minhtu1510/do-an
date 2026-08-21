"""Live in-memory store for attack-write events, pushed by attack_event_logger.py
during S7comm attack runs (RWRITE_BURST/SETPOINT_ATTACK/SENSOR_SPOOF/etc).

Same pattern as scenarios/store.py's ScenarioStore for tests/day8/run_day8.py:
the attack script and this backend usually run on different machines (attack
machine vs. controller machine), so instead of requiring a manual file copy +
ATTACK_EVENT_FILE env var, the logger POSTs each event straight to this
backend over the lab network (see WEB_SCADA_API in attack_event_logger.py).
No fake data — configured() is always True, list_attack_events() returns
exactly what was pushed, empty until something real arrives.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any

TZ = timezone(timedelta(hours=7))
MAX_EVENTS = 5000

_events: deque[dict] = deque(maxlen=MAX_EVENTS)


def configured() -> bool:
    return True


def add_event(body: dict[str, Any]) -> dict:
    timestamp_ms = body.get("timestamp_ms")
    try:
        ts = datetime.fromtimestamp(int(timestamp_ms) / 1000, tz=TZ)
    except (TypeError, ValueError):
        ts = datetime.now(TZ)

    event = {
        "timestamp": ts.isoformat(),
        "scenario_label": body.get("scenario_label", ""),
        "signal": body.get("signal", ""),
        "old_value": body.get("old_value", ""),
        "new_value": body.get("new_value", ""),
        "day": body.get("day", ""),
        "note": body.get("note", ""),
    }
    _events.appendleft(event)
    return event


def list_attack_events(start: str | None = None, end: str | None = None) -> list[dict]:
    start_dt = datetime.fromisoformat(start) if start else None
    end_dt = datetime.fromisoformat(end) if end else None

    events = []
    for event in reversed(_events):  # chronological order, oldest first
        ts = datetime.fromisoformat(event["timestamp"])
        if start_dt and ts < start_dt:
            continue
        if end_dt and ts > end_dt:
            continue
        events.append(event)
    return events
