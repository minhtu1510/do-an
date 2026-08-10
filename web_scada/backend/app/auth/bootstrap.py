"""Seed the first admin account on startup, only if the users table is empty.

Solves the chicken-and-egg problem: user management requires an admin, but
the first admin can't be created through the admin-only API. Reads
ADMIN_USERNAME / ADMIN_PASSWORD from .env; does nothing if either is unset
or if any user already exists (never overwrites existing accounts).
"""

from __future__ import annotations

import logging
import os

from sqlalchemy import select

from .db import get_session, init_db
from .models import User
from .security import hash_password

logger = logging.getLogger("web_scada.auth")


def bootstrap_admin() -> None:
    init_db()

    session = get_session()
    try:
        if session.scalar(select(User).limit(1)) is not None:
            return

        username = os.getenv("ADMIN_USERNAME")
        password = os.getenv("ADMIN_PASSWORD")
        if not username or not password:
            logger.warning(
                "No users exist yet and ADMIN_USERNAME/ADMIN_PASSWORD are not set in .env — "
                "no one can log in until you set them and restart, or insert a user manually."
            )
            return

        session.add(User(username=username, password_hash=hash_password(password), role="admin"))
        session.commit()
        logger.info(f"Bootstrapped first admin account: {username}")
    finally:
        session.close()
