from pydantic import BaseModel, Field

from .models import ROLES


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    id: int
    role: str
    username: str


class UserOut(BaseModel):
    id: int
    username: str
    role: str
    created_at: str | None = None


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)
    role: str

    def validate_role(self) -> None:
        if self.role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")


class ChangeRoleRequest(BaseModel):
    role: str
