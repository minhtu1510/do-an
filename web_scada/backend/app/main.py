"""FastAPI Web-SCADA Backend — OPC UA Gateway + REST API + WebSocket"""

import asyncio
import os
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta

from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

from .opcua.gateway import OPCUAGateway
from .opcua.tag_registry import get_tag_registry
from .api.router import api_router
from .alarms import alarm_engine
from .auth import auth_router, bootstrap_admin, get_ws_user
from .database import init_db, insert_sample
from .events import event_service
from .history.router import history_router
from .ids_upload.router import ids_upload_router
from .ml_results.router import ml_results_router
from .system import sample as sample_system_resources, warm_up as warm_up_system_resources
from .websocket.manager import ws_manager

logger = logging.getLogger("web_scada")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

TZ = timezone(timedelta(hours=7))
OPCUA_ENDPOINT = os.getenv("OPCUA_ENDPOINT", "opc.tcp://192.168.210.211:4840")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")

gateway: OPCUAGateway = None
backend_started_at: datetime | None = None


def get_backend_status() -> dict:
    now = datetime.now(TZ)
    started_at = backend_started_at or now
    base_status = gateway.status if gateway else {"connected": False, "endpoint": OPCUA_ENDPOINT}
    return {
        **base_status,
        "backend_started_at": started_at.isoformat(),
        "uptime_seconds": int((now - started_at).total_seconds()),
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    global gateway, backend_started_at
    logger.info("Web-SCADA backend starting...")
    backend_started_at = datetime.now(TZ)

    bootstrap_admin()
    init_db()

    tag_registry = get_tag_registry()
    logger.info(f"Loaded {len(tag_registry.tags)} tags from registry")

    def on_tag_update(key: str, data: dict):
        try:
            cfg = tag_registry.get_by_key(key)
            if cfg and cfg.history_enabled:
                insert_sample(key, data.get("value"), data.get("quality", "Bad"), data.get("stale", True), data.get("received_timestamp"))

            loop = asyncio.get_event_loop()
            events = event_service.add_many(alarm_engine.process_tag_update(key, data))
            loop.create_task(ws_manager.broadcast_tag_update(key, data))
            for event in events:
                payload = event.to_dict()
                payload["active_count"] = alarm_engine.active_alarm_count()
                loop.create_task(ws_manager.broadcast_event(payload))
        except Exception:
            pass

    gateway = OPCUAGateway(OPCUA_ENDPOINT, tag_registry)

    gateway.on_value_change(on_tag_update)

    task = asyncio.create_task(gateway.start())
    logger.info(f"OPC UA gateway connecting to {OPCUA_ENDPOINT}...")

    warm_up_system_resources()

    async def system_resources_loop():
        while True:
            await asyncio.sleep(2)
            try:
                await ws_manager.broadcast_system_resources({
                    **sample_system_resources(),
                    "ws_connections": ws_manager.count,
                })
            except Exception:
                pass

    resources_task = asyncio.create_task(system_resources_loop())

    yield

    logger.info("Web-SCADA backend shutting down...")
    await gateway.stop()
    task.cancel()
    resources_task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    try:
        await resources_task
    except asyncio.CancelledError:
        pass
    logger.info("Web-SCADA backend stopped cleanly")


app = FastAPI(
    title="Web-SCADA Backend",
    description="FastAPI OPC UA Gateway — Read-only monitoring for ICS Security Testbed",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/api/auth")
app.include_router(api_router, prefix="/api")
app.include_router(history_router, prefix="/api/history")
app.include_router(ml_results_router, prefix="/api/ml")
app.include_router(ids_upload_router, prefix="/api/ids")


@app.websocket("/ws/process")
async def websocket_endpoint(ws: WebSocket, _user=Depends(get_ws_user)):
    await ws_manager.connect(ws)
    try:
        # Send full snapshot on connect
        await ws.send_json({
            "type": "full_state",
            "tags": gateway.get_all_values(),
            "status": get_backend_status(),
            "timestamp": datetime.now(TZ).isoformat(),
        })
        events = event_service.add_many(alarm_engine.process_gateway_status(get_backend_status()))
        for event in events:
            payload = event.to_dict()
            payload["active_count"] = alarm_engine.active_alarm_count()
            await ws.send_json({"type": "event", "event": payload, "active_count": payload["active_count"]})
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
    except Exception:
        ws_manager.disconnect(ws)
