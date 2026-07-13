"""FastAPI Web-SCADA Backend — OPC UA Gateway + REST API + WebSocket"""

import asyncio
import os
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

from .opcua.gateway import OPCUAGateway
from .opcua.tag_registry import get_tag_registry
from .api.router import api_router
from .websocket.manager import ws_manager

logger = logging.getLogger("web_scada")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

TZ = timezone(timedelta(hours=7))
OPCUA_ENDPOINT = os.getenv("OPCUA_ENDPOINT", "opc.tcp://192.168.210.211:4840")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")

gateway: OPCUAGateway = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global gateway
    logger.info("Web-SCADA backend starting...")

    tag_registry = get_tag_registry()
    logger.info(f"Loaded {len(tag_registry.tags)} tags from registry")

    gateway = OPCUAGateway(OPCUA_ENDPOINT, tag_registry)

    def on_tag_update(key: str, data: dict):
        try:
            loop = asyncio.get_event_loop()
            loop.create_task(ws_manager.broadcast_tag_update(key, data))
        except Exception:
            pass

    gateway.on_value_change(on_tag_update)

    task = asyncio.create_task(gateway.start())
    logger.info(f"OPC UA gateway connecting to {OPCUA_ENDPOINT}...")

    yield

    logger.info("Web-SCADA backend shutting down...")
    await gateway.stop()
    task.cancel()
    try:
        await task
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
    allow_methods=["GET"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")


@app.websocket("/ws/process")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        # Send full snapshot on connect
        await ws.send_json({
            "type": "full_state",
            "tags": gateway.get_all_values(),
            "status": gateway.status,
            "timestamp": datetime.now(TZ).isoformat(),
        })
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
    except Exception:
        ws_manager.disconnect(ws)
