"""API routes — read-only OPC UA tags. No Write endpoints."""

import os
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta

from ..alarms import alarm_engine
from ..events import event_service

load_dotenv()

TZ = timezone(timedelta(hours=7))
api_router = APIRouter()


def _gateway():
    from ..main import gateway
    return gateway


def _backend_status():
    from ..main import get_backend_status
    return get_backend_status()


def _tag_registry():
    from ..opcua.tag_registry import get_tag_registry
    return get_tag_registry()


@api_router.get("/plc/status")
async def plc_status():
    status = {**_backend_status(), "timestamp": datetime.now(TZ).isoformat()}
    event_service.add_many(alarm_engine.process_gateway_status(status))
    return status


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


@api_router.get("/events")
async def get_events(limit: int = 100):
    return {
        "events": event_service.list(limit),
        "active_count": alarm_engine.active_alarm_count(),
        "timestamp": datetime.now(TZ).isoformat(),
    }


@api_router.get("/security/status")
async def security_status():
    g = _gateway()
    metrics = alarm_engine.security_metrics()
    return {
        "plc_connection": "CONNECTED" if g.status.get("connected") else "DISCONNECTED",
        "opcua_connection": "CONNECTED" if g.status.get("connected") else "DISCONNECTED",
        "reconnect_count": g.status.get("reconnect_count", 0),
        "active_alarm_count": metrics["active_alarm_count"],
        "stale_event_count": metrics["stale_event_count"],
        "rejected_operation_count": metrics["rejected_operation_count"],
        "capture_status": "Not configured",
        "dataset_session_id": "No active collection",
        "scenario_id": "Not configured",
        "current_label": "Not configured",
        "ids_module": "IDS module unavailable",
        "timestamp": datetime.now(TZ).isoformat(),
    }
