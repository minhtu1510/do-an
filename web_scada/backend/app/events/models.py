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
        }
