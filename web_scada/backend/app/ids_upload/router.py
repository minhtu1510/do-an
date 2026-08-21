from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, Form, UploadFile
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from ..auth import require_role
from ..events import event_service
from ..events.models import EventRecord
from .service import IdsUploadError, MODEL_DIR, analyze_pcap, model_configured
from .service_opcua import (
    IdsUploadOpcuaError,
    MODEL_DIR as MODEL_DIR_OPCUA,
    analyze_pcap as analyze_pcap_opcua,
    model_configured as model_configured_opcua,
)

ids_upload_router = APIRouter()

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB — a few hours of ICS traffic, generous but bounded
TZ = timezone(timedelta(hours=7))


def _record_analysis(result: dict, protocol: str, username: str) -> None:
    """Persist the analysis to history, and raise a real alarm if it found
    anything non-benign. Both steps are best-effort — a DB/event write must
    never turn a completed analysis into a 500 for the user who just waited
    on it.
    """
    from ..database import insert_pcap_analysis

    try:
        insert_pcap_analysis({
            "id": result["job_id"],
            "timestamp": datetime.now(TZ).isoformat(),
            "protocol": protocol,
            "source_file": result["source_file"],
            "analyzed_by": username,
            "total_flows": result["total_flows"],
            "attack_flows": result["attack_flows"],
            "attack_ratio": result["attack_ratio"],
            "prediction_counts": result["prediction_counts"],
            "model_dir": result["model_dir"],
        })
    except Exception:
        pass

    if result["attack_flows"] > 0:
        top_labels = sorted(
            ((k, v) for k, v in result["prediction_counts"].items() if k not in ("BENIGN", "benign")),
            key=lambda kv: -kv[1],
        )
        labels_text = ", ".join(f"{k} x{v}" for k, v in top_labels[:3])
        try:
            event_service.add(EventRecord(
                event_type="ATTACK_PCAP_DETECTED",
                severity="WARNING",
                message=(
                    f"{username} phân tích pcap '{result['source_file']}' ({protocol}): "
                    f"{result['attack_flows']}/{result['total_flows']} flow bị gắn nhãn tấn công — {labels_text}"
                ),
                status="ACTIVE",
            ))
        except Exception:
            pass


@ids_upload_router.get("/status")
async def ids_status(_user=Depends(require_role("operator"))):
    return {"configured": model_configured(), "model_dir": str(MODEL_DIR)}


@ids_upload_router.post("/analyze")
async def ids_analyze(
    file: UploadFile = File(...),
    plc_ip: str = Form("192.168.210.211"),
    window: float = Form(5.0),
    user=Depends(require_role("operator")),
):
    body = await file.read()
    if len(body) > MAX_UPLOAD_BYTES:
        return JSONResponse(status_code=413, content={"error": "file_too_large", "max_bytes": MAX_UPLOAD_BYTES})
    if not body:
        return JSONResponse(status_code=400, content={"error": "empty_file"})

    try:
        # analyze_pcap shells out to tshark (subprocess.run, blocking) and runs
        # the model on the extracted CSV — both can take seconds to a couple
        # minutes on a large pcap. Running it inline on the event loop would
        # stall every other coroutine, including the OPC UA gateway's poll
        # loop and keep-alive traffic, long enough for the PLC/OPC UA server
        # to time out and drop the session. Run it in a worker thread instead
        # so the gateway keeps ticking while this request is in flight.
        result = await run_in_threadpool(analyze_pcap, body, file.filename or "upload.pcap", plc_ip, window)
    except IdsUploadError as exc:
        return JSONResponse(status_code=422, content={"error": "ids_upload_failed", "message": str(exc)})

    _record_analysis(result, "s7comm", user.username)
    return result


@ids_upload_router.get("/opcua/status")
async def ids_status_opcua(_user=Depends(require_role("operator"))):
    return {"configured": model_configured_opcua(), "model_dir": str(MODEL_DIR_OPCUA)}


@ids_upload_router.post("/opcua/analyze")
async def ids_analyze_opcua(
    file: UploadFile = File(...),
    plc_ip: str = Form("192.168.210.211"),
    window: float = Form(5.0),
    user=Depends(require_role("operator")),
):
    body = await file.read()
    if len(body) > MAX_UPLOAD_BYTES:
        return JSONResponse(status_code=413, content={"error": "file_too_large", "max_bytes": MAX_UPLOAD_BYTES})
    if not body:
        return JSONResponse(status_code=400, content={"error": "empty_file"})

    try:
        result = await run_in_threadpool(analyze_pcap_opcua, body, file.filename or "upload.pcap", plc_ip, window)
    except IdsUploadOpcuaError as exc:
        return JSONResponse(status_code=422, content={"error": "ids_upload_opcua_failed", "message": str(exc)})

    _record_analysis(result, "opcua", user.username)
    return result


@ids_upload_router.get("/history")
async def ids_history(limit: int = 100, _user=Depends(require_role("operator"))):
    from ..database import query_recent_pcap_analyses

    return {"analyses": query_recent_pcap_analyses(limit)}
