from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .db import get_session
from .deps import get_current_user, require_role
from .models import ROLES, User
from .schemas import ChangeRoleRequest, CreateUserRequest, LoginRequest, TokenResponse, UserOut
from .security import create_access_token, hash_password, verify_password

auth_router = APIRouter()


@auth_router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest):
    session = get_session()
    try:
        user = session.scalar(select(User).where(User.username == body.username))
    finally:
        session.close()

    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")

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
def create_user(body: CreateUserRequest, _admin: User = Depends(require_role("admin"))):
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
        user.role = body.role
        session.commit()
        session.refresh(user)
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
        session.delete(user)
        session.commit()
    finally:
        session.close()
