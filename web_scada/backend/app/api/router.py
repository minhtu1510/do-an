"""API routes — read-only OPC UA tags. No Write endpoints."""

import os
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta

load_dotenv()

TZ = timezone(timedelta(hours=7))
api_router = APIRouter()


def _gateway():
    from ..main import gateway
    return gateway


def _tag_registry():
    from ..opcua.tag_registry import get_tag_registry
    return get_tag_registry()


@api_router.get("/plc/status")
async def plc_status():
    g = _gateway()
    return {**g.status, "timestamp": datetime.now(TZ).isoformat()}


@api_router.get("/tags")
async def get_all_tags():
    g = _gateway()
    values = g.get_all_values()
    return {
        "tags": values,
        "count": len(values),
        "timestamp": datetime.now(TZ).isoformat(),
    }


@api_router.get("/tags/{tag_key}")
async def get_tag(tag_key: str):
    g = _gateway()
    reg = _tag_registry()
    cfg = reg.get_by_key(tag_key)
    if cfg is None:
        return JSONResponse(
            status_code=404,
            content={"error": "tag_not_found", "key": tag_key, "message": f"Tag '{tag_key}' does not exist in registry"}
        )
    value = g.get_value(tag_key)
    if value is None:
        return {
            "key": tag_key,
            "value": None,
            "quality": "Bad",
            "stale": True,
            "message": "Tag configured but not yet subscribed",
        }
    return value
