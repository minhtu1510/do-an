"""API routes — read-only OPC UA tags. No Write endpoints."""

import csv
import io
import os
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from dotenv import load_dotenv
from pydantic import BaseModel
from datetime import datetime, timezone, timedelta

from ..alarms import alarm_engine
from ..auth import require_role
from ..events import event_service
from ..events.models import EventRecord
from ..opcua.gateway import TagWriteError
from ..scenarios import scenario_catalog, scenario_store
from ..scenarios.models import ScenarioResult
from ..system import sample as sample_system_resources

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
async def plc_status(_user=Depends(require_role("viewer"))):
    status = {**_backend_status(), "timestamp": datetime.now(TZ).isoformat()}
    event_service.add_many(alarm_engine.process_gateway_status(status))
    return status


@api_router.get("/system/resources")
async def system_resources(_user=Depends(require_role("viewer"))):
    """CPU/RAM/disk/network of the machine running this backend (the gateway
    host) — not the PLC, which has no general-purpose OS to sample.
    See app/system/service.py."""
    from ..websocket.manager import ws_manager

    return {
        **sample_system_resources(),
        "ws_connections": ws_manager.count,
        "timestamp": datetime.now(TZ).isoformat(),
    }


@api_router.get("/tags")
async def get_all_tags(_user=Depends(require_role("viewer"))):
    g = _gateway()
    values = g.get_all_values()
    return {
        "tags": values,
        "count": len(values),
        "timestamp": datetime.now(TZ).isoformat(),
    }


@api_router.get("/tags/{tag_key}")
async def get_tag(tag_key: str, _user=Depends(require_role("viewer"))):
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


class TagWriteRequest(BaseModel):
    value: bool | int | float


@api_router.post("/tags/{tag_key}/write")
async def write_tag(tag_key: str, body: TagWriteRequest, user=Depends(require_role("controller"))):
    """Write a value to a whitelisted PLC tag (see `writable` in opcua_tags.yaml).
    Every call is logged as an event, whether it succeeds or fails validation,
    so there is always an audit trail of who issued which command.
    """
    from ..websocket.manager import ws_manager

    g = _gateway()
    old_value = g.get_value(tag_key)
    old = old_value["value"] if old_value else None

    try:
        new_tag_value = await g.write_value(tag_key, body.value)
    except TagWriteError as e:
        event_service.add(EventRecord(
            event_type="COMMAND_REJECTED",
            severity="WARNING",
            message=f"{user.username} tried to write {tag_key}={body.value!r}: {e}",
            tag_key=tag_key,
            old_value=old,
            new_value=body.value,
            status="CLEARED",
        ))
        return JSONResponse(status_code=422, content={"error": "invalid_write", "message": str(e)})
    except RuntimeError as e:
        event_service.add(EventRecord(
            event_type="COMMAND_FAILED",
            severity="ERROR",
            message=f"{user.username} tried to write {tag_key}={body.value!r}: {e}",
            tag_key=tag_key,
            old_value=old,
            new_value=body.value,
            status="CLEARED",
        ))
        return JSONResponse(status_code=503, content={"error": "write_failed", "message": str(e)})

    result = new_tag_value.to_dict()
    event = event_service.add(EventRecord(
        event_type="COMMAND_WRITE",
        severity="WARNING",
        message=f"{user.username} set {tag_key}: {old!r} -> {result['value']!r}",
        tag_key=tag_key,
        old_value=old,
        new_value=result["value"],
        status="CLEARED",
    ))
    payload = event.to_dict()
    payload["active_count"] = alarm_engine.active_alarm_count()
    await ws_manager.broadcast_event(payload)
    await ws_manager.broadcast_tag_update(tag_key, result)
    return {"written": True, "tag": result}


@api_router.get("/events")
async def get_events(limit: int = 100, _user=Depends(require_role("viewer"))):
    return {
        "events": event_service.list(limit),
        "active_count": alarm_engine.active_alarm_count(),
        "timestamp": datetime.now(TZ).isoformat(),
    }


@api_router.post("/events/{event_id}/ack")
async def ack_event(event_id: str, user=Depends(require_role("operator"))):
    from ..websocket.manager import ws_manager

    event = event_service.ack(event_id, user.username)
    if event is None:
        return JSONResponse(status_code=404, content={"error": "event_not_found", "id": event_id})

    payload = event.to_dict()
    payload["active_count"] = alarm_engine.active_alarm_count()
    await ws_manager.broadcast_event(payload)
    return payload


@api_router.get("/events/export/csv")
async def export_events_csv(
    limit: int = 1000,
    severity: str | None = None,
    status: str | None = None,
    event_types: str | None = None,
    exclude_event_types: str | None = None,
    _user=Depends(require_role("viewer")),
):
    events = event_service.list(limit)
    if severity:
        events = [e for e in events if e["severity"] == severity.upper()]
    if status:
        events = [e for e in events if e["status"] == status.upper()]
    if event_types:
        allowed = {t.strip().upper() for t in event_types.split(",") if t.strip()}
        events = [e for e in events if e["event_type"] in allowed]
    if exclude_event_types:
        excluded = {t.strip().upper() for t in exclude_event_types.split(",") if t.strip()}
        events = [e for e in events if e["event_type"] not in excluded]

    fieldnames = ["timestamp", "severity", "event_type", "message", "tag_key", "old_value", "new_value", "status", "acked_by", "acked_at"]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for event in events:
        writer.writerow({key: event.get(key) for key in fieldnames})

    filename = f"web_scada_events_{datetime.now(TZ).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@api_router.get("/security/status")
async def security_status(_user=Depends(require_role("operator"))):
    g = _gateway()
    metrics = alarm_engine.security_metrics()
    scenario_summary = scenario_store.summary()
    return {
        "plc_connection": "CONNECTED" if g.status.get("connected") else "DISCONNECTED",
        "opcua_connection": "CONNECTED" if g.status.get("connected") else "DISCONNECTED",
        "reconnect_count": g.status.get("reconnect_count", 0),
        "active_alarm_count": metrics["active_alarm_count"],
        "stale_event_count": metrics["stale_event_count"],
        "rejected_operation_count": metrics["rejected_operation_count"],
        "capture_status": "Not configured",
        "dataset_session_id": "No active collection",
        "scenario_id": scenario_summary["latest_scenario_id"] or "Not configured",
        "current_label": scenario_summary["latest_status"] or "Not configured",
        "ids_module": "IDS module unavailable",
        "scenario_runs_total": scenario_summary["total_runs"],
        "scenario_runs_executed": scenario_summary["executed_count"],
        "timestamp": datetime.now(TZ).isoformat(),
    }


@api_router.get("/security/scenarios")
async def list_scenario_results(limit: int = 50, _user=Depends(require_role("operator"))):
    return {
        "results": scenario_store.list(limit),
        "summary": scenario_store.summary(),
        "timestamp": datetime.now(TZ).isoformat(),
    }


@api_router.get("/security/comparator")
async def security_mode_comparator(group: str = "opcua", _user=Depends(require_role("operator"))):
    return {
        **scenario_store.security_mode_comparator(group),
        "timestamp": datetime.now(TZ).isoformat(),
    }


@api_router.post("/security/scenario-result")
async def ingest_scenario_result(request: Request):
    """Ingestion endpoint for tests/day8/run_day8.py — one POST per finished scenario.

    This is what turns a day8 scenario run into a live demo: run the scenario
    runner while this backend is up and the result appears here immediately.

    Deliberately left without require_role: this is a machine-to-machine push
    from a Python script on the attack machine, not a browser call, and it
    only ever *adds* a row to an in-memory demo feed (see scenarios/store.py)
    — it cannot read or change anything else. Making the runner authenticate
    as a user just to post a status ping was judged not worth the complexity
    for a same-lab-network ingestion channel. The read side (GET
    /security/scenarios, /security/status) is protected at operator role.
    """
    from ..websocket.manager import ws_manager

    body = await request.json()
    scenario_id = body.get("scenario_id", "UNKNOWN")
    mitre = scenario_catalog.lookup(scenario_id)
    result = ScenarioResult(
        scenario_id=scenario_id,
        group=body.get("group", "unknown"),
        status=body.get("status", "UNKNOWN"),
        label=body.get("label", ""),
        duration_s=body.get("duration_s"),
        preconditions=body.get("preconditions", []),
        evidence=body.get("evidence", []),
        notes=body.get("notes", []),
        mitre_technique=mitre["mitre_technique"],
        mitre_technique_name=mitre["mitre_technique_name"],
        security_mode=body.get("security_mode"),
    )
    scenario_store.add(result)
    payload = result.to_dict()
    await ws_manager.broadcast_scenario_result(payload)
    return {"stored": True, "result": payload}
