"""PLC write-lock switch — persisted to a small JSON file (same pattern as
opcua/threshold_store.py and ip_allowlist.py), loaded back at import time.

Was previously a bare in-memory dict, matching the write rate limiter's
"in-memory is fine, only needs to survive one process's uptime" precedent —
but that precedent doesn't hold here: the rate limiter's state (a handful of
recent write timestamps) is cheap to lose on restart, whereas losing an
engaged lock silently re-opens PLC writes at exactly the moment a real
write-tampering attack was detected. A backend restart (crash, deploy) while
locked used to mean the lock just vanished. Persisting it closes that gap.

Engaged automatically when a PCAP analysis finds a high-confidence
write-tampering attack (RWRITE/SPOOF for S7comm, OPCUA_MALICIOUS_WRITE for
OPC UA); only an admin can release it (see /control/unlock).

Scope, important to state plainly: this blocks writes made through this
app's own POST /tags/{key}/write endpoint only. It has no reach over other
software that talks to the PLC directly (e.g. TIA Portal on the engineering
workstation) — this app is not a network-level enforcement point, it can
only refuse to forward the commands that come through it.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

TZ = timezone(timedelta(hours=7))

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
STATE_PATH = DATA_DIR / "control_lock_state.json"

_DEFAULT_STATE: dict = {"locked": False, "reason": None, "locked_by": None, "locked_at": None}


def _load() -> dict:
    if not STATE_PATH.exists():
        return dict(_DEFAULT_STATE)
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        return {**_DEFAULT_STATE, **data}
    except (json.JSONDecodeError, OSError):
        # Corrupt/unreadable state file: fail toward the safer state (locked)
        # rather than silently defaulting to open, since this file existing
        # at all means a lock was engaged at some point.
        return {**_DEFAULT_STATE, "locked": True, "reason": "Không đọc được trạng thái khoá cũ (file lỗi) — tự khoá theo hướng an toàn, admin kiểm tra lại."}


def _save() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(_state, indent=2, ensure_ascii=False), encoding="utf-8")


_state: dict = _load()


def engage(reason: str, locked_by: str) -> None:
    _state.update(locked=True, reason=reason, locked_by=locked_by, locked_at=datetime.now(TZ).isoformat())
    _save()


def release() -> None:
    _state.update(locked=False, reason=None, locked_by=None, locked_at=None)
    _save()


def status() -> dict:
    return dict(_state)


def is_locked() -> bool:
    return bool(_state["locked"])
