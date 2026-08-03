"""History endpoints — real historian data (see database/repositories.py)."""

from fastapi import APIRouter, Depends

from ..auth import require_role
from . import attack_events_service
from .service import history_service

history_router = APIRouter()

DEFAULT_PROCESS_TAGS = ["bang_tai", "cd1", "cd2", "cd3", "nhap", "hien_thi"]


@history_router.get("/tags/{key}")
async def tag_history(key: str, start: str | None = None, end: str | None = None, _user=Depends(require_role("viewer"))):
    return {"key": key, "points": history_service.tag_history(key, start, end)}


@history_router.get("/process")
async def process_history(
    start: str | None = None,
    end: str | None = None,
    tags: str | None = None,
    _user=Depends(require_role("viewer")),
):
    tag_keys = tags.split(",") if tags else DEFAULT_PROCESS_TAGS
    return {"tags": history_service.process_history(tag_keys, start, end)}


@history_router.get("/attack-events")
async def attack_events(start: str | None = None, end: str | None = None, _user=Depends(require_role("viewer"))):
    return {
        "configured": attack_events_service.configured(),
        "events": attack_events_service.list_attack_events(start, end),
    }
