import csv
import os
import sys
import time
from typing import Optional

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


DEFAULT_LABEL_CSV_PATH = os.path.join(os.getcwd(), "labels", "legacy_timeline.csv")
HEADER = [
    "attacker_timestamp_ms",
    "scenario_label",
    "action",
    "session_id",
    "host_id",
    "episode_id",
    "day",
    "note",
]


def _label_path() -> str:
    return os.getenv("LABEL_CSV_PATH", DEFAULT_LABEL_CSV_PATH)


def log_event(
    label_type: str,
    action_detail: str,
    *,
    action: str = "EVENT",
    session_id: Optional[str] = None,
    host_id: Optional[str] = None,
    episode_id: Optional[str] = None,
    day: Optional[str] = None,
    note: Optional[str] = None,
) -> None:
    """Append one event to the unified timeline CSV schema.

    Older standalone scripts call this with only label_type/action_detail. Those
    rows are kept as EVENT records and should not be used as the main dataset
    timeline. The publication collection path is run_day_bangtruyen.sh.
    """
    path = _label_path()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    write_header = not os.path.exists(path)

    row = {
        "attacker_timestamp_ms": int(time.time() * 1000),
        "scenario_label": str(label_type).strip().upper(),
        "action": action.strip().upper(),
        "session_id": session_id or os.getenv("SESSION_ID", "legacy_session"),
        "host_id": host_id or os.getenv("HOST_ID", "legacy_host"),
        "episode_id": episode_id or "",
        "day": day or os.getenv("DAY", "legacy"),
        "note": note if note is not None else action_detail,
    }

    try:
        with open(path, "a", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=HEADER)
            if write_header:
                writer.writeheader()
            writer.writerow(row)
    except Exception as exc:
        print(f"Lỗi khi ghi timeline CSV: {exc}")
