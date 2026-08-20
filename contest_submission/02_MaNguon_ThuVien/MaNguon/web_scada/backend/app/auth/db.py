"""SQLite engine for auth data. Separate from the (still unconfigured) PostgreSQL
historian in app/database/ — auth needs to work even before that is wired up.
"""

from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = os.getenv("AUTH_DB_PATH", str(DATA_DIR / "auth.db"))

engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    from . import models  # noqa: F401 — register models on Base before create_all

    Base.metadata.create_all(engine)


def get_session() -> Session:
    return SessionLocal()
