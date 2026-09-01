"""Event models for alarm and process events."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4


TZ = timezone(timedelta(hours=7))


@dataclass(slots=True)
class EventRecord:
    event_type: str
    message: str
    severity: str = "INFO"
    tag_key: str | None = None
    old_value: Any = None
    new_value: Any = None
    status: str = "CLEARED"
    timestamp: str = field(default_factory=lambda: datetime.now(TZ).isoformat())
    id: str = field(default_factory=lambda: str(uuid4()))
    acked_by: str | None = None
    acked_at: str | None = None
    # disposition: human-assigned handling state, separate from `status`
    # (which alarms/engine.py flips ACTIVE<->CLEARED based on the real
    # physical condition for condition-based alarms). None = chưa xử lý,
    # "investigating" = đang xử lý, "false_positive" = xác nhận không phải
    # sự cố thật. Kept independent so a manual disposition on a one-shot
    # event (PCAP attack, rate-limited, etc.) is never silently overwritten.
    disposition: str | None = None
    note: str | None = None
    # Structured attack labels (e.g. ["RWRITE", "SPOOF"]) for
    # ATTACK_PCAP_DETECTED events — lets the UI show a runbook suggestion
    # per label without regex-parsing the free-text `message`.
    labels: list[str] | None = None
    # In-memory only (not persisted, not in to_dict) — how many rungs of the
    # escalation ladder (ESCALATION_SCHEDULE_MINUTES in main.py) have
    # already fired for this still-unacked event, so each rung notifies
    # exactly once instead of every 60s tick past its threshold.
    escalation_level: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "event_type": self.event_type,
            "message": self.message,
            "tag_key": self.tag_key,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "status": self.status,
            "acked_by": self.acked_by,
            "acked_at": self.acked_at,
            "disposition": self.disposition,
            "note": self.note,
            "labels": self.labels,
        }
