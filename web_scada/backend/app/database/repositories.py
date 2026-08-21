"""Historian read/write access.

insert_sample only writes a row when the value actually changed since the
last stored sample for that tag_key — this is what keeps the table
proportional to real process activity instead of growing with wall-clock
time (the gateway polls every tag every ~1s regardless of change).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, func, select

from .connection import get_session
from .models import EventRow, TagSample

TZ = timezone(timedelta(hours=7))
MAX_ROWS_PER_TAG = 20000

_last_value: dict[str, Any] = {}


class HistoryRepositoryUnavailable(RuntimeError):
    pass


def _to_numeric(value: Any) -> float | None:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    return None


def insert_sample(tag_key: str, value: Any, quality: str, stale: bool, timestamp: str | None = None) -> None:
    if not stale and tag_key in _last_value and _last_value[tag_key] == value:
        return
    _last_value[tag_key] = value

    ts = datetime.fromisoformat(timestamp) if timestamp else datetime.now(TZ)
    session = get_session()
    try:
        session.add(TagSample(
            tag_key=tag_key,
            value_numeric=_to_numeric(value),
            value_raw=str(value),
            quality=quality,
            stale=stale,
            timestamp=ts,
        ))
        session.commit()

        count = session.scalar(select(func.count()).select_from(TagSample).where(TagSample.tag_key == tag_key))
        if count and count > MAX_ROWS_PER_TAG:
            oldest_ids = session.scalars(
                select(TagSample.id).where(TagSample.tag_key == tag_key)
                .order_by(TagSample.timestamp).limit(count - MAX_ROWS_PER_TAG)
            ).all()
            if oldest_ids:
                session.execute(delete(TagSample).where(TagSample.id.in_(oldest_ids)))
                session.commit()
    finally:
        session.close()


def query_tag_history(tag_key: str, start: str | None, end: str | None) -> list[dict]:
    session = get_session()
    try:
        stmt = select(TagSample).where(TagSample.tag_key == tag_key)
        if start:
            stmt = stmt.where(TagSample.timestamp >= datetime.fromisoformat(start))
        if end:
            stmt = stmt.where(TagSample.timestamp <= datetime.fromisoformat(end))
        stmt = stmt.order_by(TagSample.timestamp)
        return [row.to_dict() for row in session.scalars(stmt).all()]
    finally:
        session.close()


def query_process_history(tag_keys: list[str], start: str | None, end: str | None) -> dict[str, list[dict]]:
    return {key: query_tag_history(key, start, end) for key in tag_keys}


MAX_EVENT_ROWS = 20000


def insert_event(event: dict) -> None:
    session = get_session()
    try:
        session.add(EventRow(
            id=event["id"],
            event_type=event["event_type"],
            message=event["message"],
            severity=event["severity"],
            tag_key=event.get("tag_key"),
            old_value=None if event.get("old_value") is None else str(event["old_value"]),
            new_value=None if event.get("new_value") is None else str(event["new_value"]),
            status=event["status"],
            timestamp=datetime.fromisoformat(event["timestamp"]),
            acked_by=event.get("acked_by"),
            acked_at=datetime.fromisoformat(event["acked_at"]) if event.get("acked_at") else None,
        ))
        session.commit()

        # Same retention pattern as TagSample (see MAX_ROWS_PER_TAG above):
        # routine INFO events (e.g. PRODUCT_COUNT_CHANGED firing every
        # production cycle) have no natural upper bound like a tag's value
        # does, so without a cap this table grows forever. Capping keeps the
        # durable audit trail proportional to recent activity instead of
        # unbounded disk growth over a long-running demo/lab session.
        count = session.scalar(select(func.count()).select_from(EventRow))
        if count and count > MAX_EVENT_ROWS:
            oldest_ids = session.scalars(
                select(EventRow.id).order_by(EventRow.timestamp).limit(count - MAX_EVENT_ROWS)
            ).all()
            if oldest_ids:
                session.execute(delete(EventRow).where(EventRow.id.in_(oldest_ids)))
                session.commit()
    finally:
        session.close()


def update_event_ack(event_id: str, acked_by: str, acked_at: str, status: str) -> None:
    session = get_session()
    try:
        row = session.get(EventRow, event_id)
        if row is not None:
            row.acked_by = acked_by
            row.acked_at = datetime.fromisoformat(acked_at)
            row.status = status
            session.commit()
    finally:
        session.close()


def query_recent_events(limit: int = 1000) -> list[dict]:
    session = get_session()
    try:
        stmt = select(EventRow).order_by(EventRow.timestamp.desc()).limit(limit)
        return [row.to_dict() for row in session.scalars(stmt).all()]
    finally:
        session.close()
