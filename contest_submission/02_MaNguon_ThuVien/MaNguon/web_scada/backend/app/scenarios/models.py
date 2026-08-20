"""Scenario result model — mirrors the JSON shape written by tests/day8/run_day8.py."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4


TZ = timezone(timedelta(hours=7))


@dataclass(slots=True)
class ScenarioResult:
    scenario_id: str
    group: str
    status: str
    label: str = ""
    duration_s: float | None = None
    preconditions: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    mitre_technique: str | None = None
    mitre_technique_name: str | None = None
    security_mode: str | None = None
    received_at: str = field(default_factory=lambda: datetime.now(TZ).isoformat())
    id: str = field(default_factory=lambda: str(uuid4()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scenario_id": self.scenario_id,
            "label": self.label or self.scenario_id,
            "group": self.group,
            "status": self.status,
            "duration_s": self.duration_s,
            "preconditions": self.preconditions,
            "evidence": self.evidence,
            "notes": self.notes,
            "mitre_technique": self.mitre_technique,
            "mitre_technique_name": self.mitre_technique_name,
            "security_mode": self.security_mode,
            "received_at": self.received_at,
        }
