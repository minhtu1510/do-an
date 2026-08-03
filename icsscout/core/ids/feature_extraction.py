"""Runs the existing batch feature extractors against an uploaded pcap.

Both extract_opcua_features.py and extract_s7_features.py live at the repo
root and share the same CLI shape (--pcap/--output/--window/--plc-ip/...,
plus --ml-safe-copy to drop metadata columns that must never reach the
model). This module just shells out to them so the offline IDS upload flow
reuses the exact same, already-validated parsing logic instead of
reimplementing tshark dissection here.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple, Optional

REPO_ROOT = Path(__file__).resolve().parents[3]

EXTRACTOR_SCRIPTS = {
    "opcua": REPO_ROOT / "extract_opcua_features.py",
    "s7": REPO_ROOT / "extract_s7_features.py",
}

SUPPORTED_PROTOCOLS = tuple(EXTRACTOR_SCRIPTS.keys())


class FeatureExtractionError(RuntimeError):
    pass


class ExtractionResult(NamedTuple):
    raw_csv: Path
    ml_safe_csv: Path
    window_count: int
    log: str


def _require_tshark() -> None:
    if shutil.which("tshark") is None:
        raise FeatureExtractionError(
            "tshark không có trong PATH — cần cài Wireshark/tshark trên máy chạy server để trích xuất đặc trưng."
        )


def run_extraction(
    pcap_path: Path,
    protocol: str,
    workdir: Path,
    window: float = 5.0,
    plc_ip: Optional[str] = None,
) -> ExtractionResult:
    """Extract windowed features from `pcap_path` using the extractor for `protocol`.

    Returns paths to the raw feature CSV (has metadata columns, useful for
    debugging/inspection) and the ml-safe CSV (metadata columns dropped,
    ready to feed to a model).
    """
    if protocol not in EXTRACTOR_SCRIPTS:
        raise FeatureExtractionError(
            f"Giao thức '{protocol}' chưa được hỗ trợ (chỉ hỗ trợ: {', '.join(SUPPORTED_PROTOCOLS)})."
        )
    script = EXTRACTOR_SCRIPTS[protocol]
    if not script.is_file():
        raise FeatureExtractionError(f"Không tìm thấy script trích xuất đặc trưng: {script}")

    _require_tshark()

    workdir.mkdir(parents=True, exist_ok=True)
    raw_csv = workdir / f"{protocol}_features_raw.csv"
    ml_safe_csv = workdir / f"{protocol}_features_ml_safe.csv"

    cmd = [
        sys.executable, str(script),
        "--pcap", str(pcap_path),
        "--output", str(raw_csv),
        "--window", str(window),
        "--label", "unknown",
        "--session-id", "offline_upload",
        "--host-id", "offline_upload",
        "--ml-safe-copy", str(ml_safe_csv),
    ]
    if plc_ip:
        cmd.extend(["--plc-ip", plc_ip])

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    log = (proc.stdout or "") + (proc.stderr or "")

    if proc.returncode != 0:
        raise FeatureExtractionError(
            f"Trích xuất đặc trưng thất bại (exit code {proc.returncode}):\n{log.strip()}"
        )
    if not ml_safe_csv.is_file():
        raise FeatureExtractionError(f"Extractor chạy xong nhưng không thấy file output:\n{log.strip()}")

    window_count = max(0, sum(1 for _ in ml_safe_csv.open("r", encoding="utf-8")) - 1)
    return ExtractionResult(raw_csv=raw_csv, ml_safe_csv=ml_safe_csv, window_count=window_count, log=log)
