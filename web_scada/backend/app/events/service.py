"""In-memory event store.

This keeps the first alarm/event implementation lightweight. PostgreSQL can
replace this service later without changing the current OPC UA gateway flow.
"""

from collections import deque
from typing import Iterable

from .models import EventRecord


class EventService:
    def __init__(self, max_events: int = 1000):
        self._events: deque[EventRecord] = deque(maxlen=max_events)

    def add(self, event: EventRecord) -> EventRecord:
        self._events.appendleft(event)
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


event_service = EventService()
