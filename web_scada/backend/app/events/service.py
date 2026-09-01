"""Event store — an in-memory deque for fast reads by the live UI, backed by
a real SQLite table (see database/models.py::EventRow) so the audit trail
actually survives a backend restart. Earlier this was in-memory only; a
committee asking "show me the persisted log" would have found nothing after
a restart. Every add()/ack() writes through to the DB; load_from_db() at
startup rebuilds the in-memory cache from it.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Iterable

from .models import EventRecord

TZ = timezone(timedelta(hours=7))

# When the event on the left is added, the ACTIVE event type(s) on the right
# auto-close to CLEARED — these are the "recovered" counterpart of a
# condition-based alarm (alarms/engine.py) or the lock-release path. Without
# this, e.g. PLC_DISCONNECTED stayed ACTIVE (needing manual "Xác nhận")
# forever after a routine reconnect, even though PLC_CONNECTED already fired
# right after it — a dev/test restart cycle produced dozens of stuck
# "needs ack" rows that had nothing to do with an attack. The bool says
# whether to scope the match to the same tag_key (needed for per-tag alarms
# like the stage timers, where cd1 recovering must not clear cd2's alarm).
AUTO_CLEAR_MAP: dict[str, list[tuple[str, bool]]] = {
    "PLC_CONNECTED": [("PLC_DISCONNECTED", False)],
    "OPCUA_RECONNECTED": [("OPCUA_STALE", True)],
    "STAGE_TIMER_RANGE_CLEARED": [("STAGE_TIMER_OUT_OF_RANGE", True)],
    "ATTACK_SENSOR_SPOOF_CLEARED": [("ATTACK_SENSOR_SPOOF_SUSPECTED", False)],
    "WRITE_LOCK_RELEASED": [("WRITE_LOCK_ENGAGED", False)],
}


class EventService:
    def __init__(self, max_events: int = 1000):
        self._events: deque[EventRecord] = deque(maxlen=max_events)

    def load_from_db(self) -> None:
        """Rebuild the in-memory cache from the persistent table — called
        once at backend startup so history from before a restart is not
        silently gone.
        """
        from ..database import query_recent_events

        try:
            rows = query_recent_events(self._events.maxlen or 1000)
        except Exception:
            return
        records = [
            EventRecord(
                id=row["id"], event_type=row["event_type"], message=row["message"],
                severity=row["severity"], tag_key=row["tag_key"], old_value=row["old_value"],
                new_value=row["new_value"], status=row["status"], timestamp=row["timestamp"],
                acked_by=row["acked_by"], acked_at=row["acked_at"],
                disposition=row.get("disposition"), note=row.get("note"), labels=row.get("labels"),
            )
            for row in rows
        ]
        self._events = deque(records, maxlen=self._events.maxlen)

    def add(self, event: EventRecord) -> EventRecord:
        self._events.appendleft(event)
        try:
            from ..database import insert_event
            insert_event(event.to_dict())
        except Exception:
            pass  # live alarm pipeline must keep working even if the DB write fails

        for closed_type, scope_by_tag in AUTO_CLEAR_MAP.get(event.event_type, []):
            if scope_by_tag and event.tag_key is None:
                continue  # this instance doesn't carry the scoping info needed to clear safely
            self.clear_active(closed_type, tag_key=event.tag_key if scope_by_tag else None)

        return event

    def add_many(self, events: Iterable[EventRecord]) -> list[EventRecord]:
        stored = []
        for event in events:
            stored.append(self.add(event))
        return stored

    def list(self, limit: int = 100) -> list[dict]:
        safe_limit = max(1, min(limit, 1000))
        return [event.to_dict() for event in list(self._events)[:safe_limit]]

    def active_count(self) -> int:
        return sum(1 for event in self._events if event.status == "ACTIVE")

    def clear_active(self, event_type: str, tag_key: str | None = None) -> EventRecord | None:
        """Flip the newest still-ACTIVE event of this type (and, if given,
        same tag_key) to CLEARED. Called both directly (releasing the write
        lock) and automatically from add() via AUTO_CLEAR_MAP above."""
        for event in self._events:
            if event.event_type != event_type or event.status != "ACTIVE":
                continue
            if tag_key is not None and event.tag_key != tag_key:
                continue
            event.status = "CLEARED"
            try:
                from ..database import update_event_status
                update_event_status(event.id, "CLEARED")
            except Exception:
                pass
            return event
        return None

    def ack(
        self, event_id: str, username: str,
        disposition: str | None = None, note: str | None = None,
    ) -> EventRecord | None:
        for event in self._events:
            if event.id == event_id:
                event.acked_by = username
                event.acked_at = datetime.now(TZ).isoformat()
                event.disposition = disposition
                event.note = note
                try:
                    from ..database import update_event_ack
                    update_event_ack(event_id, username, event.acked_at, event.status, disposition, note)
                except Exception:
                    pass
                return event
        return None

    def due_for_escalation(self, severity: str, schedule_minutes: list[int]) -> list[EventRecord]:
        """ACTIVE events of the given severity, unacked, that have crossed
        their NEXT escalation rung in `schedule_minutes` (e.g. [5, 15, 30,
        120, 600, 1440] — 5m, 15m, 30m, 2h, 10h, 24h since the event fired,
        like an alarm clock's snooze schedule rather than one single
        reminder). Each event escalates through the ladder one rung at a
        time as the loop ticks; once past the last rung, it stops — a
        24h-old unacked alarm doesn't need a reminder every 60s forever."""
        now = datetime.now(TZ)
        due = []
        for event in self._events:
            if event.status != "ACTIVE" or event.acked_by or event.severity != severity:
                continue
            if event.escalation_level >= len(schedule_minutes):
                continue
            try:
                ts = datetime.fromisoformat(event.timestamp)
            except ValueError:
                continue
            elapsed_minutes = (now - ts).total_seconds() / 60
            if elapsed_minutes >= schedule_minutes[event.escalation_level]:
                due.append(event)
        return due


event_service = EventService()
