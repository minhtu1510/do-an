"""Offline IDS routes: upload a pcap, run feature extraction, run inference.

No live capture involved -- the dataset can't be streamed online yet, so
this is a batch "upload -> analyze -> report" flow. Follows the same
`setup_..._routes(app)` pattern as risk_assessment_routes.py rather than a
Blueprint, since s7_routes.py is the only place in this app using Blueprint
objects and it needed a url_prefix; this module doesn't.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path

from flask import jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

from icsscout.core.ids import feature_extraction, inference, model_registry

JOBS_DIR = feature_extraction.REPO_ROOT / "var" / "ids_offline_jobs"
ALLOWED_EXTENSIONS = (".pcap", ".pcapng")
JOB_ID_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_ROWS_IN_RESPONSE = 2000


def _bad_request(message: str, **extra):
    return jsonify({"success": False, "error": message, **extra}), 400


def setup_ids_offline_routes(app):

    @app.route("/ids-offline")
    def ids_offline_page():
        return render_template("ids_offline.html")

    @app.route("/api/ids-offline/protocols", methods=["GET"])
    def api_ids_offline_protocols():
        protocols = []
        for protocol in feature_extraction.SUPPORTED_PROTOCOLS:
            protocols.append({
                "id": protocol,
                "model_available": model_registry.is_available(protocol),
            })
        return jsonify({"success": True, "protocols": protocols})

    @app.route("/api/ids-offline/analyze", methods=["POST"])
    def api_ids_offline_analyze():
        if "pcap" not in request.files:
            return _bad_request("Thiếu file pcap (field 'pcap').")
        file = request.files["pcap"]
        if not file.filename:
            return _bad_request("File pcap rỗng.")
        filename = secure_filename(file.filename)
        if not filename.lower().endswith(ALLOWED_EXTENSIONS):
            return _bad_request("Chỉ chấp nhận file .pcap hoặc .pcapng.")

        protocol = request.form.get("protocol", "").strip().lower()
        if protocol not in feature_extraction.SUPPORTED_PROTOCOLS:
            return _bad_request(
                f"Giao thức không hợp lệ, chỉ hỗ trợ: {', '.join(feature_extraction.SUPPORTED_PROTOCOLS)}"
            )

        try:
            window = float(request.form.get("window", 5.0))
        except ValueError:
            return _bad_request("Tham số window phải là số.")
        plc_ip = request.form.get("plc_ip", "").strip() or None

        job_id = uuid.uuid4().hex
        job_dir = JOBS_DIR / job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        pcap_path = job_dir / f"capture{Path(filename).suffix.lower()}"
        file.save(pcap_path)

        try:
            extraction = feature_extraction.run_extraction(
                pcap_path=pcap_path, protocol=protocol, workdir=job_dir,
                window=window, plc_ip=plc_ip,
            )
        except feature_extraction.FeatureExtractionError as e:
            return jsonify({"success": False, "job_id": job_id, "stage": "feature_extraction", "error": str(e)}), 422
        finally:
            pcap_path.unlink(missing_ok=True)

        response = {
            "success": True,
            "job_id": job_id,
            "protocol": protocol,
            "extraction": {
                "window_count": extraction.window_count,
                "raw_csv": f"/api/ids-offline/jobs/{job_id}/download/raw",
                "ml_safe_csv": f"/api/ids-offline/jobs/{job_id}/download/ml_safe",
            },
        }

        try:
            bundle = model_registry.load_model(protocol)
        except model_registry.ModelLoadError as e:
            response["model_available"] = False
            response["model_error"] = str(e)
            return jsonify(response)

        if bundle is None:
            response["model_available"] = False
            response["message"] = (
                f"Model chưa được nạp cho giao thức '{protocol}'. "
                f"Đặt file model.pkl vào models/{protocol}/ rồi phân tích lại "
                f"(feature extraction ở trên đã chạy thành công, chỉ thiếu bước suy luận)."
            )
            return jsonify(response)

        report = inference.run_inference(extraction, bundle)
        response["model_available"] = True
        response["model_path"] = str(bundle.model_path.relative_to(feature_extraction.REPO_ROOT))
        response["feature_source"] = bundle.feature_source
        response["summary"] = {
            "total_windows": report.total_windows,
            "benign_count": report.benign_count,
            "malicious_count": report.malicious_count,
            "malicious_ratio": report.malicious_ratio,
        }
        response["warnings"] = report.warnings
        response["top_alerts"] = report.top_alerts
        response["rows"] = report.rows[:MAX_ROWS_IN_RESPONSE]
        if len(report.rows) > MAX_ROWS_IN_RESPONSE:
            response["warnings"].append(
                f"Chỉ hiển thị {MAX_ROWS_IN_RESPONSE}/{len(report.rows)} window trong response "
                f"(tải file CSV đầy đủ qua extraction.ml_safe_csv để xem hết)."
            )
        return jsonify(response)

    @app.route("/api/ids-offline/jobs/<job_id>/download/<kind>", methods=["GET"])
    def api_ids_offline_download(job_id, kind):
        if not JOB_ID_RE.match(job_id):
            return _bad_request("job_id không hợp lệ.")
        if kind not in ("raw", "ml_safe"):
            return _bad_request("kind phải là 'raw' hoặc 'ml_safe'.")
        job_dir = JOBS_DIR / job_id
        suffix = "raw" if kind == "raw" else "ml_safe"
        matches = list(job_dir.glob(f"*_features_{suffix}.csv"))
        if not matches:
            return jsonify({"success": False, "error": "Không tìm thấy file kết quả cho job này."}), 404
        return send_file(matches[0], as_attachment=True, download_name=matches[0].name)

    print("[OK] Offline IDS (pcap upload) routes registered")
