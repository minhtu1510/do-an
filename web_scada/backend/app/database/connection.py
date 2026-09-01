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
    _migrate_pcap_analyses_result_json()
    _migrate_events_disposition_note()


def _migrate_pcap_analyses_result_json() -> None:
    """create_all() only creates missing tables, it never alters an existing
    one — a pcap_analyses table from before result_json existed (this repo
    has no formal migration tool) would otherwise make every query against
    that column fail. Nullable column, so old rows just get NULL and are
    reported as not reopenable (see get_pcap_analysis)."""
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    if "pcap_analyses" not in inspector.get_table_names():
        return
    columns = {c["name"] for c in inspector.get_columns("pcap_analyses")}
    if "result_json" in columns:
        return
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE pcap_analyses ADD COLUMN result_json TEXT"))


def _migrate_events_disposition_note() -> None:
    """Same reasoning as _migrate_pcap_analyses_result_json — an events
    table from before disposition/note/labels_json existed needs these
    columns added in place, not recreated (would lose the audit trail)."""
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    if "events" not in inspector.get_table_names():
        return
    columns = {c["name"] for c in inspector.get_columns("events")}
    with engine.begin() as conn:
        if "disposition" not in columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN disposition VARCHAR(24)"))
        if "note" not in columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN note TEXT"))
        if "labels_json" not in columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN labels_json TEXT"))


def get_session() -> Session:
    return SessionLocal()


def database_configured() -> bool:
    return True
