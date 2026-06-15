#!/usr/bin/env python3
"""Append attack write/event records during dataset collection."""

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
    path = _env("ATTACK_EVENT_FILE")
    if not path:
        return

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    needs_header = not os.path.exists(path) or os.path.getsize(path) == 0
    with open(path, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if needs_header:
            writer.writerow(HEADER)
        writer.writerow([
            int(time.time() * 1000),
            _env("ATTACK_SCENARIO"),
            "EVENT",
            _env("SESSION_ID"),
            _env("HOST_ID"),
            _env("ATTACK_EPISODE_ID"),
            _env("ATTACK_DAY"),
            signal,
            area,
            db_number,
            byte_offset,
            bit_offset,
            data_type,
            old_value,
            new_value,
            status,
            note,
        ])
