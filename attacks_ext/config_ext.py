"""
Parser chuẩn cho tất cả attack modules trong attacks_ext/
Đảm bảo tương thích với cách gọi từ run_day_bangtruyen.sh / run_day_bangtruyen_ext.sh
"""

import argparse
import csv
import os
import time
from datetime import datetime


def base_parser(description: str) -> argparse.ArgumentParser:
    """Parser dùng chung cho tất cả attack modules."""
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--duration", type=int, default=300,
                   help="Thời gian chạy (giây)")
    p.add_argument("--session-id", default="ext_session",
                   help="Session ID (khớp với bash)")
    p.add_argument("--host-id", default="attacker_host",
                   help="Host ID")
    p.add_argument("--label-file", default="labels/ext_timeline.csv",
                   help="Đường dẫn file CSV label")
    p.add_argument("--episode-id", default="",
                   help="Episode ID (tùy chọn)")
    p.add_argument("--day", type=int, default=7,
                   help="Day number (mặc định 7)")
    return p


def write_label(label_file, scenario, action,
                session_id, host_id,
                episode_id="", day=7, note=""):
    """Ghi label vào CSV — cùng schema với run_day_bangtruyen.sh."""
    os.makedirs(os.path.dirname(label_file) or ".", exist_ok=True)
    ts_ms = int(time.time() * 1000)
    file_exists = os.path.isfile(label_file)

    with open(label_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "attacker_timestamp_ms", "scenario_label", "action",
            "session_id", "host_id", "episode_id", "day", "note"
        ])
        if not file_exists:
            writer.writeheader()
        writer.writerow({
            "attacker_timestamp_ms": ts_ms,
            "scenario_label":        scenario,
            "action":                action,
            "session_id":            session_id,
            "host_id":               host_id,
            "episode_id":            episode_id,
            "day":                   day,
            "note":                  str(note).replace(",", ";"),
        })
    print(f"[{datetime.now().strftime('%H:%M:%S')}] label {scenario} {action}")
