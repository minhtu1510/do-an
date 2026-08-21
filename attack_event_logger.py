#!/usr/bin/env python3
"""Append attack write/event records during dataset collection.

Pushes each event live to the Web-SCADA backend (same WEB_SCADA_API env var
and best-effort urllib POST pattern as tests/day8/run_day8.py) so it appears
on the Trends attack-marker overlay immediately, without copying a CSV by
hand from the attack machine to the controller machine. Set
WEB_SCADA_API=http://<controller-ip>:8000/api if the backend isn't on
localhost. Local CSV logging via ATTACK_EVENT_FILE is still available
alongside the push (e.g. for offline archival) but is no longer required.
"""

from __future__ import annotations

import csv
import json
import os
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

WEB_SCADA_API = os.environ.get("WEB_SCADA_API", "http://127.0.0.1:8000/api").rstrip("/")

HEADER = [
    "timestamp_ms",
    "scenario_label",
    "action",
    "session_id",
    "host_id",
    "episode_id",
    "day",
    "signal",
    "area",
    "db_number",
    "byte_offset",
    "bit_offset",
    "data_type",
    "old_value",
    "new_value",
    "status",
    "note",
]


def _env(name: str) -> str:
    return os.environ.get(name, "")


def _push_event(row: dict[str, Any]) -> None:
    body = json.dumps(row).encode("utf-8")
    req = Request(f"{WEB_SCADA_API}/history/attack-events", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        urlopen(req, timeout=2)
    except (HTTPError, URLError, OSError):
        # Best-effort — an attack script must never stall or crash because the
        # controller machine is unreachable. ATTACK_EVENT_FILE (if set) below
        # still captures the event locally either way.
        pass


def log_attack_event(
    signal: str,
    area: str = "",
    db_number: Any = "",
    byte_offset: Any = "",
    bit_offset: Any = "",
    data_type: str = "",
    old_value: Any = "",
    new_value: Any = "",
    status: str = "write_sent",
    note: str = "",
) -> None:
    row = {
        "timestamp_ms": int(time.time() * 1000),
        "scenario_label": _env("ATTACK_SCENARIO"),
        "action": "EVENT",
        "session_id": _env("SESSION_ID"),
        "host_id": _env("HOST_ID"),
        "episode_id": _env("ATTACK_EPISODE_ID"),
        "day": _env("ATTACK_DAY"),
        "signal": signal,
        "area": area,
        "db_number": db_number,
        "byte_offset": byte_offset,
        "bit_offset": bit_offset,
        "data_type": data_type,
        "old_value": old_value,
        "new_value": new_value,
        "status": status,
        "note": note,
    }

    _push_event(row)

    path = _env("ATTACK_EVENT_FILE")
    if not path:
        return

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    needs_header = not os.path.exists(path) or os.path.getsize(path) == 0
    with open(path, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if needs_header:
            writer.writerow(HEADER)
        writer.writerow([row[col] for col in HEADER])
