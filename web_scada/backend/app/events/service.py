"""Event store — an in-memory deque for fast reads by the live UI, backed by
a real SQLite table (see database/models.py::EventRow) so the audit trail
actually survives a backend restart. Earlier this was in-memory only; a
committee asking "show me the persisted log" would have found nothing after
a restart. Every add()/ack() writes through to the DB; load_from_db() at
startup rebuilds the in-memory cache from it.
"""

from __future__ import annotations

import asyncio
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

# Event types with a real physical "recovered" signal (the left-hand side of
# AUTO_CLEAR_MAP above eventually flips them CLEARED). "Đóng vụ" on one of
# these must wait for that to happen — closing the human ticket while the
# underlying condition (PLC still disconnected, write-lock still engaged...)
# is literally still true would hide an ongoing problem. Derived from
# AUTO_CLEAR_MAP instead of hand-duplicated so the two can't drift apart.
#
# Forensic/one-shot event types (ATTACK_PCAP_DETECTED, IDS_ANOMALY_DETECTED,
# COMMAND_* ...) are NOT in here on purpose: they have no future physical
# event that will ever clear them (a pcap analysis is a fact about the past,
# not a live condition), so for those "Đóng vụ" IS the terminal state —
# gating them on status=="CLEARED" would make them permanently unclosable.
CONDITION_BASED_EVENT_TYPES: set[str] = {
    closed_type for pairs in AUTO_CLEAR_MAP.values() for closed_type, _ in pairs
}


class ResolveBlockedError(Exception):
    """Raised by resolve() when the event is a condition-based alarm still
    ACTIVE — see CONDITION_BASED_EVENT_TYPES above."""

    def __init__(self, event_type: str):
        self.event_type = event_type
        super().__init__(
            f"Không thể đóng vụ khi sự cố '{event_type}' vẫn đang tiếp diễn (status=ACTIVE)."
        )


class EventService:
    def __init__(self, max_events: int = 1000):
        self._events: deque[EventRecord] = deque(maxlen=max_events)

    @staticmethod
    def _record_from_row(row: dict) -> EventRecord:
        return EventRecord(
            id=row["id"], event_type=row["event_type"], message=row["message"],
            severity=row["severity"], tag_key=row["tag_key"], old_value=row["old_value"],
            new_value=row["new_value"], status=row["status"], timestamp=row["timestamp"],
            acked_by=row["acked_by"], acked_at=row["acked_at"],
            disposition=row.get("disposition"), note=row.get("note"), labels=row.get("labels"),
            escalation_level=row.get("escalation_level") or 0,
            assignee=row.get("assignee"), resolved_by=row.get("resolved_by"),
            resolved_at=row.get("resolved_at"),
            support_requested_by=row.get("support_requested_by"),
            support_requested_at=row.get("support_requested_at"),
            audit=row.get("audit") or [],
        )

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
        records = [self._record_from_row(row) for row in rows]
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

    def _find(self, event_id: str) -> EventRecord | None:
        for event in self._events:
            if event.id == event_id:
                return event
        # Not in the bounded in-memory cache (max_events, default 1000) —
        # could just be a stale/unknown id, but could also be a genuinely
        # real, still-open event that aged out because enough newer events
        # (e.g. OPC UA reconnect noise, which fires often in this lab) piled
        # up after it. A browser tab open since before that eviction would
        # still show the row and let someone click "Xác nhận"/"Giao"/"Yêu
        # cầu hỗ trợ" on it — that used to 404 even though the record was
        # still perfectly intact in the DB. Fall back to a direct DB lookup
        # and re-admit it into the cache so it isn't lost again immediately.
        try:
            from ..database import get_event_by_id
            row = get_event_by_id(event_id)
        except Exception:
            return None
        if row is None:
            return None
        event = self._record_from_row(row)
        self._events.appendleft(event)
        return event

    def get(self, event_id: str) -> EventRecord | None:
        """Public read-only lookup — for callers (e.g. Telegram's on_ack)
        that need to check current state before deciding whether to act,
        without going through the mutating ack()/assign()/resolve() calls."""
        return self._find(event_id)

    def _audit(self, event: EventRecord, action: str, by: str,
               frm: str | None = None, to: str | None = None,
               note: str | None = None) -> None:
        entry = {"action": action, "by": by, "at": datetime.now(TZ).isoformat()}
        if frm is not None or to is not None:
            entry["from"] = frm
            entry["to"] = to
        if note:
            entry["note"] = note
        event.audit.append(entry)

    def _persist(self, event: EventRecord) -> None:
        try:
            from ..database import update_event_workflow
            update_event_workflow(event.to_dict())
        except Exception:
            pass  # live UI must keep working even if the DB write fails

    def _clear_telegram_buttons(self, event_id: str, acked_by: str) -> None:
        """Fire-and-forget: an event was just acked by something OTHER than
        a Telegram tap (web claim, bulk ack, resolve()'s own auto-ack) — any
        "Xác nhận" button still live on a Telegram message for this event
        must be removed now, or a later tap on that stale button would
        silently overwrite acked_by back to "telegram-bot". Scheduled on the
        running loop since this method itself is sync (called from plain
        request handlers, not awaited) — same pattern as main.py's
        on_tag_update. Best-effort: no running loop / Telegram not
        configured must never break the ack that triggered this.
        """
        try:
            from ..notify import TELEGRAM_ACK_USERNAME, clear_pending_buttons
            if acked_by == TELEGRAM_ACK_USERNAME:
                return  # Telegram's own poll loop already clears its buttons after this tap
            asyncio.get_event_loop().create_task(clear_pending_buttons(event_id))
        except Exception:
            pass

    def ack(
        self, event_id: str, username: str,
        disposition: str | None = None, note: str | None = None,
    ) -> EventRecord | None:
        """Acknowledge an event, or re-classify an already-acked one. Calling
        again with a different disposition is allowed and records the change in
        the audit trail (old → new) instead of silently overwriting — this is
        how "đổi phân loại sau khi ack" works end to end. acked_by/acked_at are
        set ONCE, on the first ack, and never touched again — they record who
        first saw it, not who most recently re-classified it (assignee tracks
        current ownership separately, see assign())."""
        from .. import notify as _notify  # lazy: avoids a module-load-order cycle

        event = self._find(event_id)
        if event is None:
            return None
        first_ack = event.acked_by is None
        if not first_ack and username == _notify.TELEGRAM_ACK_USERNAME:
            # A stale phone button, tapped after this was already acked some
            # other way (web claim, a different Telegram message for the same
            # event, ...) — silently do nothing rather than let a late tap
            # revert a human's disposition or steal the "who acked" credit.
            return event
        prev_disp = event.disposition
        if first_ack:
            event.acked_by = username
            event.acked_at = datetime.now(TZ).isoformat()
        event.disposition = disposition
        event.note = note
        if first_ack:
            self._audit(event, "ack", username, to=disposition, note=note)
            self._clear_telegram_buttons(event_id, username)
        elif prev_disp != disposition:
            self._audit(event, "disposition", username, frm=prev_disp, to=disposition, note=note)
        else:
            self._audit(event, "note", username, note=note)
        self._persist(event)
        return event

    def claim(
        self, event_id: str, username: str,
        disposition: str | None = None, note: str | None = None,
    ) -> EventRecord | None:
        """Web "Xác nhận" button on a NEW event: ACK + auto-assign to the
        clicking engineer in one action (the "claim the alert" pattern —
        PagerDuty/Opsgenie do the same, so nobody has to separately "giao
        việc" cho chính mình right after acking it). Only sets assignee if
        nobody already has it, so re-classifying an already-claimed event
        (or one already handed to someone else) never silently reassigns it.

        Telegram's ack (notify/telegram.py -> main.py's on_ack) deliberately
        calls ack() directly instead of this — a phone tap should silence
        the nagging, but a bot pseudo-identity ("telegram-bot") must never
        become the recorded incident owner. A real engineer claims it on
        the web afterwards (assign() below, used by the "Tiếp nhận vụ này"
        quick action when an event is already acked but still unassigned).
        """
        event = self.ack(event_id, username, disposition, note)
        if event is not None and event.assignee is None:
            self.assign(event_id, username, username)
        return event

    def assign(self, event_id: str, username: str, assignee: str | None) -> EventRecord | None:
        """Set (or clear, with assignee=None) who is officially handling this
        incident. Recorded in the audit trail. No-op (no audit entry, no DB
        write) if the target is already the current assignee — otherwise
        re-confirming the same person in the UI would spam the audit trail
        with pointless "assign: X -> X" entries."""
        event = self._find(event_id)
        if event is None:
            return None
        prev = event.assignee
        normalized = assignee or None
        if normalized == prev:
            return event
        event.assignee = normalized
        self._audit(event, "assign", username, frm=prev, to=event.assignee)
        self._persist(event)
        return event

    def request_support(self, event_id: str, username: str, requested: bool) -> EventRecord | None:
        """Flag (or un-flag) this event as needing admin attention — WITHOUT
        transferring ownership the way assign() does. Kept deliberately
        separate from assign(): handing an incident straight to an admin
        account reads as "cấp dưới chỉ đạo cấp trên" (see the rank check on
        /events/{id}/assign in api/router.py), whereas this is just a plain
        request an admin can notice (StatusBar badge) and choose to act on —
        the operator keeps ownership of their own case the whole time."""
        event = self._find(event_id)
        if event is None:
            return None
        if requested:
            event.support_requested_by = username
            event.support_requested_at = datetime.now(TZ).isoformat()
            self._audit(event, "request_support", username)
        else:
            event.support_requested_by = None
            event.support_requested_at = None
            self._audit(event, "cancel_support", username)
        self._persist(event)
        return event

    def resolve(self, event_id: str, username: str, note: str | None = None) -> EventRecord | None:
        """Mark the incident as handled/closed by a human — the terminal state
        of the handling workflow, separate from `status` (condition-driven).
        Auto-acks first if nobody had, since resolving implies you've seen it."""
        event = self._find(event_id)
        if event is None:
            return None
        if event.event_type in CONDITION_BASED_EVENT_TYPES and event.status != "CLEARED":
            raise ResolveBlockedError(event.event_type)
        if event.acked_by is None:
            event.acked_by = username
            event.acked_at = datetime.now(TZ).isoformat()
            self._audit(event, "ack", username, to=event.disposition)
            self._clear_telegram_buttons(event_id, username)
        event.resolved_by = username
        event.resolved_at = datetime.now(TZ).isoformat()
        # A resolved case has nothing left to "need help with" — clear any
        # standing support request so it doesn't linger in the StatusBar badge.
        event.support_requested_by = None
        event.support_requested_at = None
        self._audit(event, "resolve", username, note=note)
        self._persist(event)
        return event

    def reopen(self, event_id: str, username: str, note: str | None = None) -> EventRecord | None:
        """Undo a resolve (mis-click, or the incident came back). Keeps the
        audit trail — the resolve entry stays, a reopen entry is appended."""
        event = self._find(event_id)
        if event is None:
            return None
        event.resolved_by = None
        event.resolved_at = None
        self._audit(event, "reopen", username, note=note)
        self._persist(event)
        return event

    def due_for_escalation(
        self,
        severity: str | None,
        schedule_minutes: list[int],
        event_types: set[str] | None = None,
    ) -> list[EventRecord]:
        """ACTIVE events, unacked, that have crossed their NEXT escalation
        rung in `schedule_minutes` (e.g. [5, 15, 30, 120, 600, 1440] — 5m,
        15m, 30m, 2h, 10h, 24h since the event fired, like an alarm clock's
        snooze schedule rather than one single reminder). Each event
        escalates through the ladder one rung at a time as the loop ticks;
        once past the last rung, it stops — a 24h-old unacked alarm doesn't
        need a reminder every 60s forever.

        Matched by `event_types` (a specific set of event_type strings) when
        given, by `severity` otherwise. event_types exists because
        "needs re-nagging" isn't really a function of severity: a real
        detected attack (ATTACK_PCAP_DETECTED/IDS_ANOMALY_DETECTED) is
        WARNING-severity for UI coloring, but if nobody acks it, it should
        escalate just as hard as an ERROR — while most other WARNING events
        (a single rejected/rate-limited command, a routine admin action)
        are one-shot notices that would just be noise if nagged on a timer.
        """
        now = datetime.now(TZ)
        due = []
        for event in self._events:
            if event.status != "ACTIVE" or event.acked_by:
                continue
            if event_types is not None:
                if event.event_type not in event_types:
                    continue
            elif event.severity != severity:
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
