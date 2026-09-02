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

Two levels of detail, on purpose:
  - `packets[]` (this module's original scope): time/IPs/ports/len/protocol/
    info per packet — small, safe to persist into pcap_analyses.result_json
    (history), same as any other analysis field.
  - `packets[].detail` / `.hex`: full Wireshark-style protocol layer tree +
    raw hex, one `tshark -T json -x` pass over just the already-selected
    frame numbers. ~15-20KB per packet — fine in the live HTTP response for
    the analysis you just ran, but too heavy to keep in the historian
    forever (500 rows x that would bloat a SQLite file meant to "just
    work"). Callers (ids_upload/router.py) strip this field before writing
    to pcap_analyses — reopening an old analysis later still shows the
    summary row, just not the full tree.

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

import json
import subprocess
from pathlib import Path
from typing import Any

MAX_PACKET_WINDOWS = 20
MAX_PACKETS_PER_WINDOW = 8
TSHARK_TIMEOUT_S = 120


def attach_attack_packets(pcap_path: Path, flow_table: list[dict[str, Any]]) -> None:
    """Mutates flow_table in place, adding a `packets` list (each with a
    `detail`/`hex` field for the full Wireshark-style view) to the entries
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
        "-e", "frame.number", "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport", "-e", "udp.dstport",
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
        if len(parts) < 9:
            continue
        try:
            frame_no = int(parts[0])
            ts_ms = float(parts[1]) * 1000.0
        except ValueError:
            continue
        for i, (start_ms, end_ms) in enumerate(ranges):
            if remaining[i] > 0 and start_ms <= ts_ms < end_ms:
                src_port = parts[4] or parts[6] or None
                dst_port = parts[5] or parts[7] or None
                packets_by_window[i].append({
                    "frame_number": frame_no,
                    "time_epoch": ts_ms / 1000.0,
                    "src_ip": parts[2] or None,
                    "dst_ip": parts[3] or None,
                    "src_port": int(src_port) if src_port else None,
                    "dst_port": int(dst_port) if dst_port else None,
                    "length": int(parts[8]) if parts[8].isdigit() else None,
                    "protocol": parts[9] if len(parts) > 9 else None,
                    "info": "\t".join(parts[10:]).strip() if len(parts) > 10 else "",
                })
                remaining[i] -= 1
                break

    all_packets: list[dict[str, Any]] = []
    for i, row in enumerate(candidates):
        pkts = packets_by_window.get(i, [])
        if pkts:
            row["packets"] = pkts
            all_packets.extend(pkts)

    if all_packets:
        _attach_full_detail(pcap_path, all_packets)


def _attach_full_detail(pcap_path: Path, packets: list[dict[str, Any]]) -> None:
    """One batched `tshark -T json -x` pass over exactly the frame numbers
    already selected above — full protocol layer tree (every field
    Wireshark's packet detail pane would show) plus raw hex bytes, keyed
    back onto each packet dict by frame number. Best-effort, same as the
    caller: on any failure the packets just keep their lightweight fields.
    """
    frame_numbers = [p["frame_number"] for p in packets if p.get("frame_number")]
    if not frame_numbers:
        return

    display_filter = "frame.number in {" + ",".join(str(n) for n in frame_numbers) + "}"
    cmd = ["tshark", "-r", str(pcap_path), "-Y", display_filter, "-T", "json", "-x"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TSHARK_TIMEOUT_S)
    except Exception:
        return
    if proc.returncode != 0 or not proc.stdout.strip():
        return

    try:
        records = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return

    detail_by_frame: dict[int, dict[str, Any]] = {}
    for rec in records:
        layers = rec.get("_source", {}).get("layers", {})
        frame = layers.get("frame", {})
        try:
            frame_no = int(frame.get("frame.number", 0))
        except (TypeError, ValueError):
            continue
        if not frame_no:
            continue
        frame_raw = layers.pop("frame_raw", None)
        hex_bytes = frame_raw[0] if isinstance(frame_raw, list) and frame_raw else None
        # Drop every other `<layer>_raw` sibling (byte-offset arrays used by
        # Wireshark's GUI to highlight bytes on hover) — not useful without
        # that GUI, and they roughly double the payload for no benefit here.
        cleaned = {k: v for k, v in layers.items() if not k.endswith("_raw")}
        detail_by_frame[frame_no] = {"layers": cleaned, "hex": hex_bytes}

    for p in packets:
        d = detail_by_frame.get(p.get("frame_number"))
        if d:
            p["detail"] = d["layers"]
            p["hex"] = d["hex"]
