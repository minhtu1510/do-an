"""History endpoints.

These endpoints reserve the public API shape while making it explicit that no
historian database has been configured yet.
"""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from .service import history_service


history_router = APIRouter()


@history_router.get("/tags/{key}")
async def tag_history(key: str, start: str | None = None, end: str | None = None):
    if not history_service.configured():
        return JSONResponse(
            status_code=501,
            content={
                "error": "history_unavailable",
                "message": "PostgreSQL historian is not configured",
                "key": key,
                "start": start,
                "end": end,
            },
        )
    return {"key": key, "points": []}


@history_router.get("/process")
async def process_history(start: str | None = None, end: str | None = None):
    if not history_service.configured():
        return JSONResponse(
            status_code=501,
            content={
                "error": "history_unavailable",
                "message": "PostgreSQL historian is not configured",
                "start": start,
                "end": end,
            },
        )
    return {"points": []}
