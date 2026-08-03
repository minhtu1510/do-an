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
