"""Database connection placeholder.

PostgreSQL is not configured in the current live-data MVP. The historian can
wire an async SQLAlchemy engine here when database settings are available.
"""


def database_configured() -> bool:
    return False
