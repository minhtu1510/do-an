"""Admin-managed list of IP addresses considered legitimate on the PLC
network (engineering workstations, the PLC itself, etc.) — a real ICS
security practice (CISA/NIST recommend IP allowlisting for OT networks),
not previously present anywhere in this app. Same JSON-file-in-data/
persistence pattern as opcua/threshold_store.py: simple, survives restarts,
no new DB table needed for a handful of entries.

Currently used to flag unexpected source IPs in the packet detail view for
flagged pcap windows (ids_upload) — a source IP outside this list showing
up in attack-flagged traffic is a stronger signal than one already known.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
ALLOWLIST_PATH = DATA_DIR / "ip_allowlist.json"
TZ = timezone(timedelta(hours=7))


def list_entries() -> list[dict]:
    if not ALLOWLIST_PATH.exists():
        return []
    try:
        return json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def _save(entries: list[dict]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ALLOWLIST_PATH.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")


def add_entry(ip: str, label: str, added_by: str) -> dict:
    entries = list_entries()
    if any(e["ip"] == ip for e in entries):
        raise ValueError(f"IP {ip} đã có trong danh sách")
    entry = {"ip": ip, "label": label, "added_by": added_by, "added_at": datetime.now(TZ).isoformat()}
    entries.append(entry)
    _save(entries)
    return entry


def remove_entry(ip: str) -> bool:
    entries = list_entries()
    remaining = [e for e in entries if e["ip"] != ip]
    if len(remaining) == len(entries):
        return False
    _save(remaining)
    return True


def is_allowed(ip: str | None) -> bool:
    if not ip:
        return True  # nothing to flag if the field wasn't populated (e.g. ARP frames)
    return any(e["ip"] == ip for e in list_entries())
