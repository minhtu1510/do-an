import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .db import get_session
from .deps import get_current_user, require_role
from .models import ROLES, User
from .schemas import ChangeRoleRequest, CreateUserRequest, LoginRequest, TokenResponse, UserOut
from .security import create_access_token, hash_password, verify_password

auth_router = APIRouter()
TZ = timezone(timedelta(hours=7))


def _event_service():
    from ..events import event_service
    return event_service


def _event_record_cls():
    from ..events.models import EventRecord
    return EventRecord


# Brute-force protection for login — the write endpoint already had a rate
# limit (api/router.py), but login itself had none: any number of wrong
# passwords was allowed, unlimited. Same in-memory-is-fine precedent as that
# rate limiter (only needs to survive one process's uptime). Keyed by
# username, not IP: this is a small lab deployment behind one gateway IP in
# most setups, so an IP-keyed limit would lock out everyone together.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_S = 600  # 10 minutes to accumulate failures
LOGIN_LOCKOUT_S = 300  # 5 minute lockout once the threshold is crossed
_login_failures: dict[str, list[float]] = defaultdict(list)
_login_lockout_until: dict[str, float] = {}


def _login_lockout_remaining(username: str) -> float:
    now = time.monotonic()
    until = _login_lockout_until.get(username, 0.0)
    return max(0.0, until - now)


def _record_login_failure(username: str) -> None:
    now = time.monotonic()
    attempts = _login_failures[username]
    attempts[:] = [t for t in attempts if now - t < LOGIN_WINDOW_S]
    attempts.append(now)
    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        _login_lockout_until[username] = now + LOGIN_LOCKOUT_S
        attempts.clear()
        try:
            _event_service().add(_event_record_cls()(
                event_type="ACCOUNT_LOCKED",
                severity="ERROR",
                message=f"Tài khoản '{username}' bị khoá tạm {LOGIN_LOCKOUT_S // 60} phút — sai mật khẩu {LOGIN_MAX_ATTEMPTS} lần liên tiếp.",
                status="CLEARED",
            ))
        except Exception:
            pass
    else:
        try:
            _event_service().add(_event_record_cls()(
                event_type="LOGIN_FAILED",
                severity="WARNING",
                message=f"Đăng nhập sai cho tài khoản '{username}' (lần {len(attempts)}/{LOGIN_MAX_ATTEMPTS}).",
                status="CLEARED",
            ))
        except Exception:
            pass


def _record_login_success(username: str) -> None:
    _login_failures.pop(username, None)
    _login_lockout_until.pop(username, None)


@auth_router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest):
    remaining = _login_lockout_remaining(body.username)
    if remaining > 0:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Tài khoản tạm khoá do đăng nhập sai quá nhiều lần — thử lại sau {int(remaining) + 1}s.",
        )

    session = get_session()
    try:
        user = session.scalar(select(User).where(User.username == body.username))
    finally:
        session.close()

    if user is None or not verify_password(body.password, user.password_hash):
        # Same message and same failure-recording call whether the username
        # doesn't exist or the password is wrong — no leak of which case it was.
        _record_login_failure(body.username)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")

    _record_login_success(body.username)
    token = create_access_token(user.id, user.username, user.role)
    return TokenResponse(access_token=token, id=user.id, role=user.role, username=user.username)


@auth_router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return UserOut(**user.to_dict())


@auth_router.get("/users", response_model=list[UserOut])
def list_users(_admin: User = Depends(require_role("admin"))):
    session = get_session()
    try:
        users = session.scalars(select(User).order_by(User.id)).all()
        return [UserOut(**u.to_dict()) for u in users]
    finally:
        session.close()


@auth_router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: CreateUserRequest, admin: User = Depends(require_role("admin"))):
    if body.role not in ROLES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"role must be one of {ROLES}")

    session = get_session()
    try:
        user = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
        session.add(user)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            raise HTTPException(status.HTTP_409_CONFLICT, "Username already exists")
        session.refresh(user)
        try:
            _event_service().add(_event_record_cls()(
                event_type="USER_CREATED",
                severity="WARNING",
                message=f"{admin.username} đã tạo tài khoản '{user.username}' với quyền {user.role}.",
                status="CLEARED",
            ))
        except Exception:
            pass
        return UserOut(**user.to_dict())
    finally:
        session.close()


@auth_router.patch("/users/{user_id}/role", response_model=UserOut)
def change_role(user_id: int, body: ChangeRoleRequest, admin: User = Depends(require_role("admin"))):
    if body.role not in ROLES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"role must be one of {ROLES}")
    if user_id == admin.id and body.role != "admin":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot demote your own account")

    session = get_session()
    try:
        user = session.get(User, user_id)
        if user is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
        old_role = user.role
        user.role = body.role
        session.commit()
        session.refresh(user)
        if old_role != user.role:
            try:
                _event_service().add(_event_record_cls()(
                    event_type="USER_ROLE_CHANGED",
                    severity="WARNING",
                    message=f"{admin.username} đã đổi quyền '{user.username}': {old_role} -> {user.role}.",
                    status="CLEARED",
                ))
            except Exception:
                pass
        return UserOut(**user.to_dict())
    finally:
        session.close()


@auth_router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, admin: User = Depends(require_role("admin"))):
    if user_id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot delete your own account")

    session = get_session()
    try:
        user = session.get(User, user_id)
        if user is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
        deleted_username = user.username
        session.delete(user)
        session.commit()
        try:
            _event_service().add(_event_record_cls()(
                event_type="USER_DELETED",
                severity="WARNING",
                message=f"{admin.username} đã xoá tài khoản '{deleted_username}'.",
                status="CLEARED",
            ))
        except Exception:
            pass
    finally:
        session.close()
