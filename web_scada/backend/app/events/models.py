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
    # disposition: human CONCLUSION about the event, separate from `status`
    # (which alarms/engine.py flips ACTIVE<->CLEARED based on the real
    # physical condition) and separate from assignee ("đang xử lý" is
    # derived from assignee being set, not a disposition value — see
    # ALLOWED_DISPOSITIONS in api/router.py). None = chưa kết luận gì,
    # "false_positive" = xác nhận không phải sự cố thật, "confirmed_new_
    # pattern" = xác nhận đúng là 1 kiểu tấn công/lỗi thật (admin only).
    # May still be "investigating" on rows persisted before that value was
    # retired as a selectable disposition — kept displayable, not writable.
    disposition: str | None = None
    note: str | None = None
    # Structured attack labels (e.g. ["RWRITE", "SPOOF"]) for
    # ATTACK_PCAP_DETECTED events — lets the UI show a runbook suggestion
    # per label without regex-parsing the free-text `message`.
    labels: list[str] | None = None
    # How many rungs of the escalation ladder (ESCALATION_SCHEDULE_MINUTES in
    # main.py) have already fired for this still-unacked event, so each rung
    # notifies exactly once instead of every 60s tick past its threshold.
    # Persisted (database/models.py::EventRow.escalation_level) — used to be
    # in-memory only, which reset this to 0 on every backend restart even
    # for events that had already escalated several rungs, causing a burst
    # of re-notifications right after each restart.
    escalation_level: int = 0
    # Human incident-handling workflow (see database/models.py::EventRow for the
    # durable side). assignee = ai đang lo vụ này; resolved_by/at = ai đã đóng
    # vụ, lúc nào; audit = nhật ký mọi thao tác xử lý (append-only) để đổi
    # disposition sau khi ack mà vẫn giữ được giá trị cũ.
    assignee: str | None = None
    resolved_by: str | None = None
    resolved_at: str | None = None
    # "Yêu cầu hỗ trợ" — the assignee (or anyone operator+) flags this needs
    # admin eyes, WITHOUT handing over ownership the way assign() would.
    # Deliberately separate from assignee: assigning to admin directly reads
    # as "cấp dưới chỉ đạo cấp trên" (see assign()'s rank check below), while
    # this is a plain request an admin can notice and choose to act on.
    # Auto-cleared when the event is resolved (see resolve()).
    support_requested_by: str | None = None
    support_requested_at: str | None = None
    audit: list[dict[str, Any]] = field(default_factory=list)

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
            "escalation_level": self.escalation_level,
            "assignee": self.assignee,
            "resolved_by": self.resolved_by,
            "resolved_at": self.resolved_at,
            "support_requested_by": self.support_requested_by,
            "support_requested_at": self.support_requested_at,
            "audit": self.audit,
        }
