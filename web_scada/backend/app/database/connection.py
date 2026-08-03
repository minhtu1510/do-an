"""Historian database connection.

Defaults to a local SQLite file — zero setup, works out of the box on the
lab machine. Set DATABASE_URL in .env to point at a real PostgreSQL instance
instead (e.g. postgresql+psycopg2://user:pass@host/dbname) if you want a
shared/production historian; the schema is identical either way.
"""

from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_SQLITE_URL = f"sqlite:///{DATA_DIR / 'historian.db'}"

DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_SQLITE_URL)
_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    from . import models  # noqa: F401 — register models on Base before create_all

    Base.metadata.create_all(engine)


def get_session() -> Session:
    return SessionLocal()


def database_configured() -> bool:
    return True
