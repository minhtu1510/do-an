#!/usr/bin/env python3
"""Append attack write/event records during dataset collection.

Writes each event to a local CSV via ATTACK_EVENT_FILE — set that env var to
enable logging. (An earlier version also pushed each event live to the
Web-SCADA backend for a Trends chart overlay; that overlay was never fed by
real attack runs in practice, so both the overlay and this push were
removed.)
"""

from __future__ import annotations

import csv
import os
import time
from typing import Any

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
