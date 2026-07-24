"""API routes — read-only OPC UA tags. No Write endpoints."""

import csv
import io
import os
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta

from ..alarms import alarm_engine
from ..events import event_service
from ..scenarios import scenario_catalog, scenario_store
from ..scenarios.models import ScenarioResult

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


@api_router.get("/events/export/csv")
async def export_events_csv(limit: int = 1000, severity: str | None = None, status: str | None = None):
    events = event_service.list(limit)
    if severity:
        events = [e for e in events if e["severity"] == severity.upper()]
    if status:
        events = [e for e in events if e["status"] == status.upper()]

    fieldnames = ["timestamp", "severity", "event_type", "message", "tag_key", "old_value", "new_value", "status"]
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
async def security_status():
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
async def list_scenario_results(limit: int = 50):
    return {
        "results": scenario_store.list(limit),
        "summary": scenario_store.summary(),
        "timestamp": datetime.now(TZ).isoformat(),
    }


@api_router.get("/security/comparator")
async def security_mode_comparator(group: str = "opcua"):
    return {
        **scenario_store.security_mode_comparator(group),
        "timestamp": datetime.now(TZ).isoformat(),
    }


@api_router.post("/security/scenario-result")
async def ingest_scenario_result(request: Request):
    """Ingestion endpoint for tests/day8/run_day8.py — one POST per finished scenario.

    This is what turns a day8 scenario run into a live demo: run the scenario
    runner while this backend is up and the result appears here immediately.
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
