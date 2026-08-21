"""History endpoints — real historian data (see database/repositories.py)."""

from fastapi import APIRouter, Depends, Request
from starlette.concurrency import run_in_threadpool

from ..auth import require_role
from . import attack_events_service
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


@history_router.get("/attack-events")
async def attack_events(start: str | None = None, end: str | None = None, _user=Depends(require_role("viewer"))):
    return {
        "configured": attack_events_service.configured(),
        "events": attack_events_service.list_attack_events(start, end),
    }


@history_router.post("/attack-events")
async def push_attack_event(request: Request):
    """Ingestion endpoint for attack_event_logger.py — one POST per PLC write
    during an attack run, so the marker appears on the Trends overlay live.

    Deliberately left without require_role, same rationale as
    /security/scenario-result in api/router.py: a machine-to-machine push
    from the attack machine over the lab network, not a browser call, and it
    only ever *adds* an event to an in-memory demo feed — it cannot read or
    change anything else. This replaces the old ATTACK_EVENT_FILE workflow
    (copy a CSV by hand from the attack machine to this one), which was the
    only manual-copy step left in an otherwise fully live demo.
    """
    body = await request.json()
    event = attack_events_service.add_event(body)
    return {"stored": True, "event": event}
