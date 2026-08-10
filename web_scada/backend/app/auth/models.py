"""User model — SQLite-backed, persists across backend restarts.

A small file-based DB is enough here: a handful of lab accounts, not a
production user base. No need to stand up PostgreSQL just for this.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base

TZ = timezone(timedelta(hours=7))

ROLES = ("admin", "operator", "viewer")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[str] = mapped_column(DateTime, default=lambda: datetime.now(TZ))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
