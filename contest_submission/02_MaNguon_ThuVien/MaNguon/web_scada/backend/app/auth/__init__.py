"""JWT auth + role-based access control (admin / operator / viewer), SQLite-backed."""

from .bootstrap import bootstrap_admin
from .deps import get_current_user, get_ws_user, require_role
from .router import auth_router

__all__ = ["auth_router", "bootstrap_admin", "get_current_user", "get_ws_user", "require_role"]
