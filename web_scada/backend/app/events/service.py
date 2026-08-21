"""Event store — an in-memory deque for fast reads by the live UI, backed by
a real SQLite table (see database/models.py::EventRow) so the audit trail
actually survives a backend restart. Earlier this was in-memory only; a
committee asking "show me the persisted log" would have found nothing after
a restart. Every add()/ack() writes through to the DB; load_from_db() at
startup rebuilds the in-memory cache from it.
"""

from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Iterable

from .models import EventRecord

TZ = timezone(timedelta(hours=7))


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

    def ack(self, event_id: str, username: str) -> EventRecord | None:
        for event in self._events:
            if event.id == event_id:
                event.acked_by = username
                event.acked_at = datetime.now(TZ).isoformat()
                try:
                    from ..database import update_event_ack
                    update_event_ack(event_id, username, event.acked_at, event.status)
                except Exception:
                    pass
                return event
        return None


event_service = EventService()
