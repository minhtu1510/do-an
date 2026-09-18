import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, Form, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from .. import control_lock, ip_allowlist
from ..auth import require_role
from ..events import event_service
from ..events.models import EventRecord
from .service import UPLOAD_SCRATCH, IdsUploadError, MODEL_DIR, analyze_pcap, model_configured
from .service_opcua import (
    IdsUploadOpcuaError,
    MODEL_DIR as MODEL_DIR_OPCUA,
    analyze_pcap as analyze_pcap_opcua,
    model_configured as model_configured_opcua,
)

ids_upload_router = APIRouter()

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB — a few hours of ICS traffic, generous but bounded
TZ = timezone(timedelta(hours=7))
JOB_ID_RE = re.compile(r"^[0-9a-f]{12}$")  # matches uuid.uuid4().hex[:12] from service.py/service_opcua.py


def _without_packet_detail(result: dict) -> dict:
    """Full Wireshark-style detail (packet_capture.py's `detail`/`hex`) is
    fine in the live HTTP response for the analysis you just ran (~1-3MB),
    but keeping that in every history row would bloat the SQLite historian
    (500 rows x that easily reaches gigabytes) for a feature that's only
    useful right after analyzing, while the context is still fresh. History
    keeps the lightweight per-packet fields (time/IP/port/protocol/info),
    just not the full layer tree — a shallow copy, does not mutate `result`
    (the caller still returns the full version to the current request).
    """
    flow_table = result.get("flow_table")
    if not flow_table:
        return result
    trimmed_flow_table = []
    for row in flow_table:
        if not row.get("packets"):
            trimmed_flow_table.append(row)
            continue
        trimmed_packets = [{k: v for k, v in p.items() if k not in ("detail", "hex")} for p in row["packets"]]
        trimmed_flow_table.append({**row, "packets": trimmed_packets})
    return {**result, "flow_table": trimmed_flow_table}


async def _record_analysis(result: dict, protocol: str, username: str) -> None:
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
            "result": {**_without_packet_detail(result), "protocol": protocol},
        })
    except Exception:
        pass

    if result["attack_flows"] > 0:
        # ANOMALY (Layer 2 IsolationForest disagreeing with Layer 3 on an
        # otherwise-BENIGN window — see IDSPipeline.predict, train_eval.py)
        # is NOT a confirmed attack, just "unusual, unseen in training" —
        # calling it out under ATTACK_PCAP_DETECTED would overclaim. It gets
        # its own event below instead.
        top_labels = sorted(
            ((k, v) for k, v in result["prediction_counts"].items() if k not in ("BENIGN", "benign", "ANOMALY")),
            key=lambda kv: -kv[1],
        )
        if top_labels:
            labels_text = ", ".join(f"{k} x{v}" for k, v in top_labels[:3])
            try:
                from ..alarms import alarm_engine
                from ..websocket.manager import ws_manager

                event = event_service.add(EventRecord(
                    event_type="ATTACK_PCAP_DETECTED",
                    severity="WARNING",
                    message=(
                        f"{username} phân tích pcap '{result['source_file']}' ({protocol}): "
                        f"{result['attack_flows']}/{result['total_flows']} cửa sổ bị model dự đoán là tấn công — {labels_text}"
                    ),
                    status="ACTIVE",
                    labels=[k for k, _ in top_labels[:3]],
                ))
                payload = event.to_dict()
                payload["active_count"] = alarm_engine.active_alarm_count()
                await ws_manager.broadcast_event(payload)
            except Exception:
                pass

            await _maybe_engage_write_lock(result, protocol, username)

        anomaly_count = result["prediction_counts"].get("ANOMALY", 0)
        if anomaly_count > 0:
            try:
                from ..alarms import alarm_engine
                from ..websocket.manager import ws_manager

                event = event_service.add(EventRecord(
                    event_type="IDS_ANOMALY_DETECTED",
                    severity="WARNING",
                    message=(
                        f"{username} phân tích pcap '{result['source_file']}' ({protocol}): "
                        f"{anomaly_count}/{result['total_flows']} cửa sổ BENIGN nhưng bị Layer 2 (Anomaly Detector) đánh dấu khác thường — "
                        f"dữ liệu lạ, mô hình chưa từng thấy dạng này lúc train. Cần operator trở lên xem xét."
                    ),
                    status="ACTIVE",
                    labels=["ANOMALY"],
                ))
                payload = event.to_dict()
                payload["active_count"] = alarm_engine.active_alarm_count()
                await ws_manager.broadcast_event(payload)
            except Exception:
                pass


# Labels that represent tampered/forged PLC writes — the one class of attack
# this app can actually do something about (it's the write path this app
# itself exposes), unlike scan/flood/enumeration which the app can only
# report on. Auto-lock is intentionally scoped to just these.
WRITE_TAMPER_LABELS = {
    "s7comm": {"RWRITE", "SPOOF"},
    "opcua": {"OPCUA_MALICIOUS_WRITE"},
}

# Checked against real out-of-fold predictions (grouped CV, Day1-5,
# 48,614 windows, same RF+XGBoost ensemble recipe as AttackClassifier),
# not picked by feel. Swept 50%-99%: false-lock rate stayed ~0% across the
# whole range (1 false lock out of 45,976 non-tamper windows, only at the
# 50% end) — confidence is a much stronger signal here than expected, so
# the threshold mostly trades recall, not false-lock risk. At 90%: 97.3%
# recall (RWRITE 100%, the SPOOF misses mostly confused with STEALTHY).
# 80% would recover to 97.8% recall at the same ~0% false-lock rate, so
# there's headroom to go lower — 90% is kept for now as a safety-first
# round number, not because 80% was shown to be worse.
WRITE_LOCK_CONFIDENCE_THRESHOLD = 0.9


async def _maybe_engage_write_lock(result: dict, protocol: str, username: str) -> None:
    """Auto-containment adapted to what this app can actually enforce: it
    has no control over the network (can't isolate a host / block an IP
    like a real SOC playbook), but it IS the thing PLC write commands go
    through — so a high-confidence tampered-write detection engages a lock
    on that one path. Only an admin can release it (POST /control/unlock).
    """
    if control_lock.is_locked():
        return  # already engaged, don't spam another lock event

    tamper_labels = WRITE_TAMPER_LABELS.get(protocol, set())
    hits = [
        row for row in result.get("flow_table", [])
        if row.get("prediction") in tamper_labels and row.get("confidence", 0) >= WRITE_LOCK_CONFIDENCE_THRESHOLD
    ]
    if not hits:
        return

    worst = max(hits, key=lambda r: r["confidence"])
    reason = (
        f"Phát hiện {worst['prediction']} độ tin cậy {worst['confidence']*100:.0f}% "
        f"trong pcap '{result['source_file']}' — tự động khóa lệnh ghi PLC qua web."
    )
    control_lock.engage(reason=reason, locked_by="system")
    try:
        from ..alarms import alarm_engine
        from ..websocket.manager import ws_manager

        event = event_service.add(EventRecord(
            event_type="WRITE_LOCK_ENGAGED",
            severity="ERROR",
            message=f"{reason} Chỉ admin mở khóa lại được (trang Cảnh báo & Sự kiện).",
            status="ACTIVE",
            labels=[worst["prediction"]],
        ))
        payload = event.to_dict()
        payload["active_count"] = alarm_engine.active_alarm_count()
        await ws_manager.broadcast_event(payload)
    except Exception:
        pass


@ids_upload_router.get("/status")
async def ids_status(_user=Depends(require_role("operator"))):
    return {"configured": model_configured(), "model_dir": str(MODEL_DIR)}


@ids_upload_router.post("/detect-protocol")
async def ids_detect_protocol(file: UploadFile = File(...), _user=Depends(require_role("operator"))):
    """Fast pre-check (tshark protocol hierarchy, not a model) so the upload
    UI can tell the operator which pipeline (S7comm/OPC UA) a pcap belongs to
    before they have to pick one themselves — see packet_capture.detect_protocol
    for why this doesn't need AI. Re-uploads/re-parses the file independently
    of the real /analyze call that follows (no shared state to clean up),
    which is a fine tradeoff for pcaps this size (IDS Upload caps at 200MB,
    typical analysis files are small slices)."""
    import uuid
    from .packet_capture import detect_protocol

    body = await file.read()
    if len(body) > MAX_UPLOAD_BYTES:
        return JSONResponse(status_code=413, content={"error": "file_too_large", "max_bytes": MAX_UPLOAD_BYTES})
    if not body:
        return JSONResponse(status_code=400, content={"error": "empty_file"})

    tmp_path = UPLOAD_SCRATCH / f"{uuid.uuid4().hex[:12]}_{file.filename or 'upload.pcap'}"
    try:
        tmp_path.write_bytes(body)
        result = await run_in_threadpool(detect_protocol, tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)
    return result


@ids_upload_router.post("/analyze")
async def ids_analyze(
    file: UploadFile = File(...),
    plc_ip: str = Form("192.168.210.211"),
    window: float = Form(2.0),
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

    await _record_analysis(result, "s7comm", user.username)
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

    await _record_analysis(result, "opcua", user.username)
    return result


@ids_upload_router.get("/evidence/{job_id}")
async def ids_evidence(job_id: str, _user=Depends(require_role("operator"))):
    """Download the standalone .pcap packet_capture.extract_evidence_pcap()
    cut from the sampled frames of a just-run analysis — real DFIR practice
    is pivoting from an alert to the underlying capture, not just an
    on-screen summary. Only available shortly after analysis (see
    sweep_old_evidence, EVIDENCE_MAX_AGE_S in packet_capture.py) — reopening
    an old row from Lịch sử phân tích PCAP won't have it anymore, same
    tradeoff already made for the full Wireshark-style packet detail.
    """
    if not JOB_ID_RE.match(job_id):
        return JSONResponse(status_code=400, content={"error": "invalid_job_id"})
    path = UPLOAD_SCRATCH / f"{job_id}_evidence.pcap"
    if not path.is_file():
        return JSONResponse(
            status_code=404,
            content={
                "error": "evidence_not_found",
                "message": "Bằng chứng pcap đã hết hạn hoặc chưa từng được tạo — chỉ giữ trong 2 giờ sau khi phân tích, không lưu vĩnh viễn.",
            },
        )
    return FileResponse(path, media_type="application/vnd.tcpdump.pcap", filename=f"evidence_{job_id}.pcap")


@ids_upload_router.get("/asset-inventory")
async def ids_asset_inventory(_user=Depends(require_role("operator"))):
    """IP addresses seen across recent pcap analyses' packet samples, cross-
    referenced against the admin-managed allowlist (ip_allowlist.py) — see
    list_ip_asset_inventory()'s docstring for the honest scope: this is what
    read-only pcap analysis happened to sample, not a network-wide asset scan.
    """
    from ..database import list_ip_asset_inventory

    known_ips = {e["ip"] for e in ip_allowlist.list_entries()}
    inventory = list_ip_asset_inventory()
    for entry in inventory:
        entry["known"] = entry["ip"] in known_ips
    return {"entries": inventory}


@ids_upload_router.get("/history")
async def ids_history(limit: int = 100, _user=Depends(require_role("operator"))):
    from ..database import query_recent_pcap_analyses

    return {"analyses": query_recent_pcap_analyses(limit)}


@ids_upload_router.get("/history/{analysis_id}")
async def ids_history_detail(analysis_id: str, _user=Depends(require_role("operator"))):
    from ..database import get_pcap_analysis

    result = get_pcap_analysis(analysis_id)
    if result is None:
        return JSONResponse(status_code=404, content={"error": "analysis_not_found", "id": analysis_id})
    return result
