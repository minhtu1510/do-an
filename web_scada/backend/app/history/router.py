"""History endpoints — real historian data (see database/repositories.py)."""

from fastapi import APIRouter, Depends
from starlette.concurrency import run_in_threadpool

from ..auth import require_role
from .service import history_service

history_router = APIRouter()

DEFAULT_PROCESS_TAGS = ["bang_tai", "cd1", "cd2", "cd3", "nhap", "hien_thi"]


@history_router.get("/tags/{key}")
async def tag_history(key: str, start: str | None = None, end: str | None = None, _user=Depends(require_role("viewer"))):
    # query_tag_history is a blocking SQLAlchemy sync call over a table that
    # can hold tens of thousands of rows per tag — run it off the event loop
    # so it can't stall the OPC UA gateway's poll/keep-alive loop the same
    # way the pcap-analyze endpoint used to (see ids_upload/router.py).
    points = await run_in_threadpool(history_service.tag_history, key, start, end)
    return {"key": key, "points": points}


@history_router.get("/process")
async def process_history(
    start: str | None = None,
    end: str | None = None,
    tags: str | None = None,
    _user=Depends(require_role("viewer")),
):
    tag_keys = tags.split(",") if tags else DEFAULT_PROCESS_TAGS
    result = await run_in_threadpool(history_service.process_history, tag_keys, start, end)
    return {"tags": result}
