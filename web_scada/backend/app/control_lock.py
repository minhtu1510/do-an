"""In-memory PLC write-lock switch — same "in-memory is fine, only needs to
survive one backend process's uptime, not a restart" precedent already used
by the write rate limiter in api/router.py.

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

from datetime import datetime, timedelta, timezone

TZ = timezone(timedelta(hours=7))

_state: dict = {"locked": False, "reason": None, "locked_by": None, "locked_at": None}


def engage(reason: str, locked_by: str) -> None:
    _state.update(locked=True, reason=reason, locked_by=locked_by, locked_at=datetime.now(TZ).isoformat())


def release() -> None:
    _state.update(locked=False, reason=None, locked_by=None, locked_at=None)


def status() -> dict:
    return dict(_state)


def is_locked() -> bool:
    return bool(_state["locked"])
