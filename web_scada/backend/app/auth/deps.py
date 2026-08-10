"""FastAPI dependencies for authentication and role-based access control.

Role hierarchy (each level includes everything the level below can do):
  viewer   -> read-only operational pages (Overview, Process Monitor, Alarms, Trends, System Status)
  operator -> viewer + Security/IDS, Dataset & Model Stats
  admin    -> operator + user management
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError

from .db import get_session
from .models import User
from .security import decode_access_token

_bearer = HTTPBearer(auto_error=False)

ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}


def _load_user(user_id: int) -> User | None:
    session = get_session()
    try:
        return session.get(User, user_id)
    finally:
        session.close()


def _user_from_token(token: str | None) -> User:
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing credentials")
    try:
        payload = decode_access_token(token)
    except PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    user = _load_user(int(payload["sub"]))
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User no longer exists")
    return user


def get_current_user(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> User:
    return _user_from_token(creds.credentials if creds else None)


def get_ws_user(token: str | None = Query(default=None)) -> User:
    """Same check as get_current_user, but for WebSocket connections — browsers
    cannot set an Authorization header on a native WebSocket handshake, so the
    token travels as a query parameter instead: /ws/process?token=...
    """
    return _user_from_token(token)


def require_role(minimum: str):
    if minimum not in ROLE_RANK:
        raise ValueError(f"Unknown role {minimum!r}")

    def _check(user: User = Depends(get_current_user)) -> User:
        if ROLE_RANK[user.role] < ROLE_RANK[minimum]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Requires {minimum} role or higher")
        return user

    return _check
