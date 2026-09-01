"""Real packet-level detail for flagged windows — captured from the
uploaded pcap via tshark before analyze_pcap()'s finally block deletes it,
since that's the only point where the raw pcap still exists. Shared by both
service.py (S7comm) and service_opcua.py (OPC UA): both build a flow_table
of the same shape (window_start_ms/window_end_ms/prediction/confidence), so
one implementation covers both protocols.

Scope, deliberately kept small: only the highest-confidence non-BENIGN
windows get packet samples (not every flagged window — some uploads have
hundreds), and only a handful of packets per window. This is meant to let
an analyst SEE what a flagged window's real traffic actually looked like,
not to be a full packet-capture export tool.

Deliberately NOT filtered via tshark's own `-Y "frame.time_epoch>=..."` —
verified against a real capture that this comparison silently returns zero
matches for a range that demonstrably contains packets (a real tshark/
Wireshark float-precision quirk on frame.time_epoch relational filters, not
a bug in this code). Dumping every packet's fields and matching windows in
Python side-steps it entirely and is simple enough to be worth the extra
tshark output for pcaps this size (IDS Upload caps at 200MB, but a typical
analysis file is a small slice, not a full day's capture).
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

MAX_PACKET_WINDOWS = 20
MAX_PACKETS_PER_WINDOW = 8
TSHARK_TIMEOUT_S = 120


def attach_attack_packets(pcap_path: Path, flow_table: list[dict[str, Any]]) -> None:
    """Mutates flow_table in place, adding a `packets` list to the entries
    tshark actually found packets for. Best-effort: any failure here (no
    tshark, malformed pcap, timeout) must not fail an analysis that already
    succeeded — the caller wraps this in try/except.
    """
    candidates = [
        row for row in flow_table
        if row.get("window_start_ms") is not None and row.get("window_end_ms") is not None
    ]
    candidates.sort(key=lambda r: -r.get("confidence", 0))
    candidates = candidates[:MAX_PACKET_WINDOWS]
    if not candidates:
        return

    ranges = [(row["window_start_ms"], row["window_end_ms"]) for row in candidates]  # ms
    remaining = [MAX_PACKETS_PER_WINDOW] * len(candidates)

    cmd = [
        "tshark", "-r", str(pcap_path),
        "-T", "fields",
        "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
        "-e", "frame.len", "-e", "_ws.col.Protocol", "-e", "_ws.col.Info",
        "-E", "separator=/t", "-E", "quote=n",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TSHARK_TIMEOUT_S)
    if proc.returncode != 0:
        return

    packets_by_window: dict[int, list[dict[str, Any]]] = {i: [] for i in range(len(candidates))}
    for line in proc.stdout.splitlines():
        if sum(remaining) == 0:
            break
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        try:
            ts_ms = float(parts[0]) * 1000.0
        except ValueError:
            continue
        for i, (start_ms, end_ms) in enumerate(ranges):
            if remaining[i] > 0 and start_ms <= ts_ms < end_ms:
                packets_by_window[i].append({
                    "time_epoch": ts_ms / 1000.0,
                    "src_ip": parts[1] or None,
                    "dst_ip": parts[2] or None,
                    "length": int(parts[3]) if parts[3].isdigit() else None,
                    "protocol": parts[4] or None,
                    "info": "\t".join(parts[5:]).strip() if len(parts) > 5 else "",
                })
                remaining[i] -= 1
                break

    for i, row in enumerate(candidates):
        pkts = packets_by_window.get(i, [])
        if pkts:
            row["packets"] = pkts
