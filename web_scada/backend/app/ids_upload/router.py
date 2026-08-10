from fastapi import APIRouter, Depends, File, Form, UploadFile
from fastapi.responses import JSONResponse

from ..auth import require_role
from .service import IdsUploadError, MODEL_DIR, analyze_pcap, model_configured

ids_upload_router = APIRouter()

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB — a few hours of ICS traffic, generous but bounded


@ids_upload_router.get("/status")
async def ids_status(_user=Depends(require_role("operator"))):
    return {"configured": model_configured(), "model_dir": str(MODEL_DIR)}


@ids_upload_router.post("/analyze")
async def ids_analyze(
    file: UploadFile = File(...),
    plc_ip: str = Form("192.168.210.211"),
    window: float = Form(5.0),
    _user=Depends(require_role("operator")),
):
    body = await file.read()
    if len(body) > MAX_UPLOAD_BYTES:
        return JSONResponse(status_code=413, content={"error": "file_too_large", "max_bytes": MAX_UPLOAD_BYTES})
    if not body:
        return JSONResponse(status_code=400, content={"error": "empty_file"})

    try:
        result = analyze_pcap(body, file.filename or "upload.pcap", plc_ip, window)
    except IdsUploadError as exc:
        return JSONResponse(status_code=422, content={"error": "ids_upload_failed", "message": str(exc)})

    return result
