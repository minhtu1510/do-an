"""Historian tables — one row per real value change per tag (not fixed-interval
polling), so the DB stays proportional to how often the process actually
changes, not to how long the backend has been running.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import DateTime, Float, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .connection import Base

TZ = timezone(timedelta(hours=7))


class TagSample(Base):
    __tablename__ = "tag_samples"
    __table_args__ = (Index("ix_tag_samples_key_time", "tag_key", "timestamp"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tag_key: Mapped[str] = mapped_column(String(64))
    value_numeric: Mapped[float | None] = mapped_column(Float, nullable=True)
    value_raw: Mapped[str] = mapped_column(String(255))
    quality: Mapped[str] = mapped_column(String(16))
    stale: Mapped[bool] = mapped_column(default=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(TZ))

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "value": self.value_numeric if self.value_numeric is not None else self.value_raw,
            "quality": self.quality,
            "stale": self.stale,
        }


class EventRow(Base):
    """Persistent copy of every alarm/audit event — event_service also keeps
    a fast in-memory deque for the live UI, but that deque is lost on
    restart. This table is the real, durable audit trail: it survives a
    backend restart, which the in-memory-only version could not honestly
    claim to be.
    """

    __tablename__ = "events"
    __table_args__ = (Index("ix_events_timestamp", "timestamp"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64))
    message: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(16))
    tag_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    old_value: Mapped[str | None] = mapped_column(String(255), nullable=True)
    new_value: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(16))
    timestamp: Mapped[datetime] = mapped_column(DateTime)
    acked_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    acked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event_type": self.event_type,
            "message": self.message,
            "severity": self.severity,
            "tag_key": self.tag_key,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "status": self.status,
            "timestamp": self.timestamp.isoformat(),
            "acked_by": self.acked_by,
            "acked_at": self.acked_at.isoformat() if self.acked_at else None,
        }


class PcapAnalysisRow(Base):
    """One row per pcap uploaded to IDS Upload — the page itself only ever
    held the most recent result in browser memory, so a page refresh or a
    second analyst lost every earlier run. This table is what backs the
    "Lịch sử phân tích PCAP" page.
    """

    __tablename__ = "pcap_analyses"
    __table_args__ = (Index("ix_pcap_analyses_timestamp", "timestamp"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime)
    protocol: Mapped[str] = mapped_column(String(16))
    source_file: Mapped[str] = mapped_column(String(255))
    analyzed_by: Mapped[str] = mapped_column(String(64))
    total_flows: Mapped[int] = mapped_column(Integer)
    attack_flows: Mapped[int] = mapped_column(Integer)
    attack_ratio: Mapped[float] = mapped_column(Float)
    prediction_counts_json: Mapped[str] = mapped_column(String(1024))
    model_dir: Mapped[str] = mapped_column(String(255))

    def to_dict(self) -> dict:
        import json

        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "protocol": self.protocol,
            "source_file": self.source_file,
            "analyzed_by": self.analyzed_by,
            "total_flows": self.total_flows,
            "attack_flows": self.attack_flows,
            "attack_ratio": self.attack_ratio,
            "prediction_counts": json.loads(self.prediction_counts_json),
            "model_dir": self.model_dir,
        }
