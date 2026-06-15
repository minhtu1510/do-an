#!/usr/bin/env python3
"""
Build scientifically separated ICS/PLC IDS datasets.

Outputs:
  1. Network IDS dataset: PCAP/window features only. PLC tag/process columns are
     not joined into this view.
  2. Process Monitor dataset: PLC tag poll rows labeled by system state.
  3. Fusion dataset: optional, explicit network + process context view.
  4. Leakage-ablation dataset: optional, intentionally unsafe view for measuring
     how much performance is inflated by process/context/rule/identity leakage.

The final supervised label is assigned here from timeline START/END events or
intervals. Labels emitted by extract_s7_features.py are kept only as
`extractor_label` audit metadata and are never authoritative.
"""

from __future__ import annotations

import argparse
import os
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# Label normalization
# ---------------------------------------------------------------------------

SCENARIO_TO_LABEL = {
    # benign
    "BENIGN": "BENIGN",
    "BENIGN_NORMAL": "BENIGN",
    "BENIGN_PROCESS": "BENIGN",
    "BENIGN_ENGINEERING": "BENIGN",
    "BENIGN_RECOVERY": "BENIGN",
    "NORMAL": "BENIGN",

    # reconnaissance
    "SCAN": "SCAN",
    "SCAN_PORT": "SCAN",
    "SLOW_SCAN": "SCAN",
    "FAST_SCAN": "SCAN",
    "S7_DISCOVERY": "SCAN",
    "AUTH_BRUTE": "SCAN",
    "DCP_PASSIVE_IDENTIFY": "SCAN",
    "MITM_ARP_POISON": "SCAN",
    "SLOW_SCAN_PORT": "SCAN",
    "FAST_SCAN_PORT": "SCAN",
    "ENUM_TAGS": "ENUMERATION",
    "ENUMERATION": "ENUMERATION",
    "ENUM_TAGS_SLOW": "ENUMERATION",
    "ENUM_TAGS_FAST": "ENUMERATION",

    # integrity / process manipulation
    "CPU_STOP": "CPU_CONTROL",
    "CPU_CONTROL": "CPU_CONTROL",
    "CPU_CONTROL_ATTEMPT": "CPU_CONTROL",
    "RWRITE": "RWRITE",
    "RWRITE_BURST": "RWRITE",
    "RWRITE_TAG": "RWRITE",
    "SETPOINT_ATTACK": "SETPOINT_ATTACK",
    "SENSOR_SPOOF": "SPOOF",
    "SPOOF": "SPOOF",
    "SPOOF_TAG": "SPOOF",
    "STEALTHY_WRITE": "STEALTHY",
    "STEALTHY_START": "STEALTHY",
    "STEALTHY_STOP": "STEALTHY",
    "COMMAND_REPLAY": "REPLAY",
    "COMMAND_REPLAY_STOP": "REPLAY",
    "COMMAND_REPLAY_START": "REPLAY",
    "REPLAY": "REPLAY",

    # availability / malformed protocol
    "S7_FLOOD": "FLOOD",
    "S7_FLOOD_LOW": "FLOOD",
    "S7_FLOOD_HIGH": "FLOOD",
    "SYN_FLOOD": "FLOOD",
    "SYN_FLOOD_PORT_102": "FLOOD",
    "FLOOD": "FLOOD",
    "PROTOCOL_FUZZ": "FUZZ",
    "FUZZ_S7": "FUZZ",
    "FUZZ": "FUZZ",
}


def map_label(scenario: object) -> str:
    key = str(scenario).strip().upper()
    return SCENARIO_TO_LABEL.get(key, key if key else "BENIGN")


def is_benign_label(value: object) -> bool:
    label = str(value).strip().upper()
    return label in {"", "BENIGN", "BENIGN_NORMAL", "NORMAL"} or label.startswith("BENIGN")


def normalize_epoch_ms(value: object) -> int:
    try:
        v = float(str(value).strip())
    except Exception:
        return -1
    if v < 0:
        return -1
    if v > 10_000_000_000:
        return int(v)
    return int(v * 1000)


def slug(value: object, default: str = "unknown") -> str:
    text = str(value).strip() if value is not None else ""
    if not text or text.lower() == "nan":
        text = default
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", text)
    return text.strip("_") or default


def lower_col_map(df: pd.DataFrame) -> Dict[str, str]:
    return {str(c).lower().strip(): c for c in df.columns}


def first_col(df: pd.DataFrame, candidates: Sequence[str]) -> Optional[str]:
    lower = lower_col_map(df)
    for c in candidates:
        found = lower.get(c.lower())
        if found is not None:
            return found
    return None


@dataclass(frozen=True)
class AttackInterval:
    start_ms: int
    end_ms: int
    scenario_id: str
    label: str
    episode_id: str
    day: str = "unknown_day"
    note: str = ""


@dataclass(frozen=True)
class LabelInfo:
    label: str
    scenario_id: str
    episode_id: str
    under_attack: int


def load_timeline(files: Iterable[str]) -> pd.DataFrame:
    frames = []
    for path in files:
        if path and os.path.exists(path):
            frames.append(pd.read_csv(path, low_memory=False))
        elif path:
            print(f"[WARN] Timeline not found: {path}")
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True, sort=False)


def build_intervals(timeline: pd.DataFrame, session_id: str) -> List[AttackInterval]:
    if timeline.empty:
        return []

    start_col = first_col(timeline, ["start", "start_time", "start_timestamp", "start_ms"])
    end_col = first_col(timeline, ["end", "end_time", "end_timestamp", "end_ms"])
    label_col = first_col(timeline, ["scenario_label", "label", "attack", "class", "scenario"])
    day_col = first_col(timeline, ["day"])
    note_col = first_col(timeline, ["note", "episode", "run", "repeat"])

    intervals: List[AttackInterval] = []

    # Interval CSV format: start,end,label.
    if start_col and end_col and label_col:
        for idx, row in timeline.iterrows():
            start_ms = normalize_epoch_ms(row.get(start_col))
            end_ms = normalize_epoch_ms(row.get(end_col))
            scenario = slug(row.get(label_col), "BENIGN").upper()
            label = map_label(scenario)
            if start_ms >= 0 and end_ms > start_ms and not is_benign_label(label):
                day = slug(row.get(day_col), "unknown_day") if day_col else "unknown_day"
                note = slug(row.get(note_col), f"ep{idx + 1}") if note_col else f"ep{idx + 1}"
                episode = f"{slug(session_id)}:{day}:{scenario}:{note}:{idx + 1}"
                intervals.append(AttackInterval(start_ms, end_ms, scenario, label, episode, day, note))
        return sorted(intervals, key=lambda x: x.start_ms)

    # Event timeline format: timestamp,label/scenario_label,action START/END.
    ts_col = first_col(timeline, ["attacker_timestamp_ms", "timestamp_ms", "timestamp", "time", "ts"])
    action_col = first_col(timeline, ["action", "event"])
    if not ts_col or not label_col or not action_col:
        raise ValueError(
            "Timeline must contain either start,end,label or timestamp,label,action columns."
        )

    data = timeline.copy()
    data["__ts_ms"] = data[ts_col].map(normalize_epoch_ms)
    data = data[data["__ts_ms"] >= 0].sort_values("__ts_ms")

    active: Dict[str, Deque[Tuple[int, str, str]]] = defaultdict(deque)
    counters: Dict[str, int] = defaultdict(int)

    for _, row in data.iterrows():
        scenario = slug(row.get(label_col), "BENIGN").upper()
        action = str(row.get(action_col, "")).strip().upper()
        ts_ms = int(row["__ts_ms"])
        day = slug(row.get(day_col), "unknown_day") if day_col else "unknown_day"
        note = slug(row.get(note_col), "") if note_col else ""

        if action == "START":
            active[scenario].append((ts_ms, day, note))
        elif action == "END" and active[scenario]:
            start_ms, start_day, start_note = active[scenario].popleft()
            if ts_ms <= start_ms:
                continue
            label = map_label(scenario)
            if is_benign_label(label):
                continue
            counters[scenario] += 1
            ep_note = start_note or note or f"r{counters[scenario]}"
            episode = f"{slug(session_id)}:{start_day}:{scenario}:{ep_note}:{counters[scenario]}"
            intervals.append(AttackInterval(start_ms, ts_ms, scenario, label, episode, start_day, ep_note))

    return sorted(intervals, key=lambda x: x.start_ms)


def timeline_bounds(timeline: pd.DataFrame) -> Optional[Tuple[int, int]]:
    if timeline.empty:
        return None
    cols = [
        first_col(timeline, ["attacker_timestamp_ms", "timestamp_ms", "timestamp", "time", "ts"]),
        first_col(timeline, ["start", "start_time", "start_timestamp", "start_ms"]),
        first_col(timeline, ["end", "end_time", "end_timestamp", "end_ms"]),
    ]
    values: List[int] = []
    for col in [c for c in cols if c]:
        values.extend([normalize_epoch_ms(v) for v in timeline[col].dropna().tolist()])
    values = [v for v in values if v >= 0]
    if not values:
        return None
    return min(values), max(values)


def label_for_time(ts_ms: int, intervals: Sequence[AttackInterval], session_id: str) -> LabelInfo:
    for item in intervals:
        if item.start_ms <= ts_ms <= item.end_ms:
            return LabelInfo(item.label, item.scenario_id, item.episode_id, 1)
    benign_chunk = int(ts_ms // (10 * 60 * 1000)) if ts_ms >= 0 else 0
    return LabelInfo("BENIGN", "BENIGN", f"{slug(session_id)}:BENIGN:{benign_chunk}", 0)


def drop_transition_rows(
    df: pd.DataFrame,
    intervals: Sequence[AttackInterval],
    time_col: str,
    drop_seconds: int,
) -> pd.DataFrame:
    if df.empty or not intervals or drop_seconds <= 0 or time_col not in df.columns:
        return df
    drop_ms = drop_seconds * 1000
    ts = pd.to_numeric(df[time_col], errors="coerce")
    keep = pd.Series(True, index=df.index)
    for item in intervals:
        keep &= (ts - item.start_ms).abs() > drop_ms
        keep &= (ts - item.end_ms).abs() > drop_ms
    dropped = int((~keep).sum())
    if dropped:
        print(f"[INFO] Dropped {dropped} transition rows (±{drop_seconds}s around attack boundaries)")
    return df[keep].copy()


# ---------------------------------------------------------------------------
# Leakage control
# ---------------------------------------------------------------------------

GROUP_META_COLS = {
    "session_id", "host_id", "scenario_id", "episode_id", "day", "dataset_view",
    "capture_source", "capture_role", "plc_ip", "extractor_label",
    "label_network", "label_system", "plc_under_attack",
}

IDENTITY_OR_STACK_PROXY_COLS = {
    "top_src_ip", "top_dst_ip", "top_protocol", "top_dst_port",
    "unique_src_ip_count", "unique_dst_ip_count",
    "unique_src_mac_count", "unique_dst_mac_count",
    "arp_unique_sender_mac_count",
    "dcp_unique_scanner_mac_count", "dcp_unique_device_mac_count",
    "fwd_init_win_bytes", "bwd_init_win_bytes",
}

PROCESS_CONTEXT_PREFIXES = ("tag_", "proc__")


def drop_network_leakage_columns(df: pd.DataFrame, keep_unsafe: bool = False) -> pd.DataFrame:
    if keep_unsafe:
        return df.copy()
    drop_cols = []
    for col in df.columns:
        c = str(col)
        if c in IDENTITY_OR_STACK_PROXY_COLS:
            drop_cols.append(c)
        elif c.startswith(PROCESS_CONTEXT_PREFIXES):
            drop_cols.append(c)
    if drop_cols:
        print(f"[INFO] Network view: dropped {len(drop_cols)} identity/process-context leakage columns")
    return df.drop(columns=[c for c in drop_cols if c in df.columns])


def normalize_feature_frame(path: str, source: str, session_id: str, host_id: str) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)
    if "label" in df.columns:
        df = df.rename(columns={"label": "extractor_label"})
    if "window_start_ms" not in df.columns:
        raise ValueError(f"Feature file missing window_start_ms: {path}")
    df["window_start_ms"] = pd.to_numeric(df["window_start_ms"], errors="coerce").fillna(-1).astype("int64")
    df = df[df["window_start_ms"] >= 0].copy()
    df["capture_source"] = source
    if "capture_role" not in df.columns:
        df["capture_role"] = source
    df["session_id"] = session_id
    df["host_id"] = host_id
    df["source_file"] = os.path.basename(path)
    return df


def assign_network_labels(
    df: pd.DataFrame,
    intervals: Sequence[AttackInterval],
    session_id: str,
    window_ms: int,
    label_all_traffic_by_system: bool = False,
) -> pd.DataFrame:
    if df.empty:
        return df
    rows = []
    for _, row in df.iterrows():
        w_start = int(row["window_start_ms"])
        mid = w_start + int(window_ms / 2)
        system_info = label_for_time(mid, intervals, session_id)
        source = str(row.get("capture_source", row.get("capture_role", ""))).lower()
        role = str(row.get("capture_role", "")).lower()
        is_attacker_capture = source == "attacker" or role == "attacker"

        if label_all_traffic_by_system or is_attacker_capture:
            network_info = system_info
        else:
            network_info = label_for_time(-1, [], session_id)

        out = row.to_dict()
        out["label"] = network_info.label
        out["label_network"] = network_info.label
        out["label_system"] = system_info.label
        out["scenario_id"] = network_info.scenario_id
        out["episode_id"] = network_info.episode_id
        out["plc_under_attack"] = system_info.under_attack
        out["dataset_view"] = "network"
        rows.append(out)
    return pd.DataFrame(rows)


def filter_timeline_bounds(df: pd.DataFrame, bounds: Optional[Tuple[int, int]], window_ms: int) -> pd.DataFrame:
    if df.empty or bounds is None or "window_start_ms" not in df.columns:
        return df
    start, end = bounds
    before = len(df)
    out = df[(df["window_start_ms"] >= start - window_ms) & (df["window_start_ms"] <= end + window_ms)].copy()
    print(f"[INFO] Timeline-bound filter: {before} -> {len(out)} rows")
    return out


def filter_plc_rows(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    mask = pd.Series(False, index=df.index)
    if "to_plc_packet_count" in df.columns:
        mask |= pd.to_numeric(df["to_plc_packet_count"], errors="coerce").fillna(0) > 0
    if "from_plc_packet_count" in df.columns:
        mask |= pd.to_numeric(df["from_plc_packet_count"], errors="coerce").fillna(0) > 0
    if mask.any():
        before = len(df)
        df = df[mask].copy()
        print(f"[INFO] PLC-traffic filter: {before} -> {len(df)} rows")
    return df


# ---------------------------------------------------------------------------
# Process and fusion views
# ---------------------------------------------------------------------------

def load_process_tags(path: str) -> pd.DataFrame:
    tags = pd.read_csv(path, low_memory=False)
    ts_col = first_col(tags, ["timestamp_ms", "timestamp", "time", "ts"])
    if not ts_col:
        raise ValueError("PLC tags CSV must contain timestamp_ms/timestamp/time/ts")
    if ts_col != "timestamp_ms":
        tags["timestamp_ms"] = tags[ts_col].map(normalize_epoch_ms)
    else:
        tags["timestamp_ms"] = tags["timestamp_ms"].map(normalize_epoch_ms)
    tags = tags[tags["timestamp_ms"] >= 0].copy()
    return tags


def build_process_dataset(
    tags: pd.DataFrame,
    intervals: Sequence[AttackInterval],
    session_id: str,
    host_id: str,
    window_ms: int,
    drop_transition_seconds: int,
) -> pd.DataFrame:
    proc = tags.copy()
    proc["window_start_ms"] = (proc["timestamp_ms"] // window_ms * window_ms).astype("int64")
    labels = [label_for_time(int(ts), intervals, session_id) for ts in proc["timestamp_ms"]]
    proc["label"] = [x.label for x in labels]
    proc["label_system"] = proc["label"]
    proc["label_network"] = "NA_PROCESS_VIEW"
    proc["scenario_id"] = [x.scenario_id for x in labels]
    proc["episode_id"] = [x.episode_id for x in labels]
    proc["plc_under_attack"] = [x.under_attack for x in labels]
    proc["session_id"] = session_id
    proc["host_id"] = host_id
    proc["capture_source"] = "process_logger"
    proc["dataset_view"] = "process"
    proc = drop_transition_rows(proc, intervals, "timestamp_ms", drop_transition_seconds)
    return proc


def process_window_snapshot(process_df: pd.DataFrame, window_ms: int) -> pd.DataFrame:
    if process_df.empty:
        return pd.DataFrame(columns=["window_start_ms"])

    exclude = set(GROUP_META_COLS) | {"label", "timestamp_ms", "window_start_ms", "poll_seq"}
    numeric_cols = []
    for col in process_df.columns:
        if col in exclude:
            continue
        if pd.api.types.is_numeric_dtype(process_df[col]):
            numeric_cols.append(col)
        else:
            converted = pd.to_numeric(process_df[col], errors="coerce")
            if converted.notna().any():
                process_df[col] = converted
                numeric_cols.append(col)

    if not numeric_cols:
        return process_df[["window_start_ms"]].drop_duplicates().copy()

    grouped = process_df.groupby("window_start_ms", sort=True)[numeric_cols].agg(["mean", "std", "min", "max"])
    grouped.columns = [f"proc__{col}_{stat}" for col, stat in grouped.columns]
    grouped = grouped.reset_index()
    std_cols = [c for c in grouped.columns if c.endswith("_std")]
    grouped[std_cols] = grouped[std_cols].fillna(0.0)
    return grouped


def build_fusion_dataset(
    network_df: pd.DataFrame,
    process_df: pd.DataFrame,
    intervals: Sequence[AttackInterval],
    session_id: str,
    window_ms: int,
    drop_transition_seconds: int,
    keep_unsafe_network: bool,
) -> pd.DataFrame:
    if network_df.empty or process_df.empty:
        return pd.DataFrame()

    net = drop_network_leakage_columns(network_df, keep_unsafe=keep_unsafe_network).copy()
    proc_win = process_window_snapshot(process_df.copy(), window_ms)
    fusion = pd.merge(net, proc_win, on="window_start_ms", how="left")
    proc_cols = [c for c in proc_win.columns if c != "window_start_ms"]
    fusion[proc_cols] = fusion[proc_cols].fillna(0)

    labels = [label_for_time(int(w + window_ms / 2), intervals, session_id) for w in fusion["window_start_ms"]]
    fusion["label"] = [x.label for x in labels]
    fusion["label_system"] = fusion["label"]
    fusion["scenario_id"] = [x.scenario_id for x in labels]
    fusion["episode_id"] = [x.episode_id for x in labels]
    fusion["plc_under_attack"] = [x.under_attack for x in labels]
    fusion["dataset_view"] = "fusion_leakage_ablation" if keep_unsafe_network else "fusion"
    fusion["_window_mid_ms"] = fusion["window_start_ms"] + int(window_ms / 2)
    fusion = drop_transition_rows(fusion, intervals, "_window_mid_ms", drop_transition_seconds)
    return fusion.drop(columns=["_window_mid_ms"], errors="ignore")


def write_dataset(path: Optional[str], df: pd.DataFrame, name: str) -> None:
    if not path:
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    df.to_csv(path, index=False)
    print(f"\n[OK] {name}: {path}")
    print(f"     rows={len(df)} cols={len(df.columns)}")
    if "label" in df.columns and len(df):
        print(df["label"].value_counts().to_string())


def print_intervals(intervals: Sequence[AttackInterval]) -> None:
    print(f"[Timeline] non-benign attack intervals: {len(intervals)}")
    for item in intervals:
        dur = (item.end_ms - item.start_ms) / 1000.0
        print(f"  - {item.scenario_id:20s} -> {item.label:14s} {dur:8.1f}s  episode={item.episode_id}")


def infer_session_id(args: argparse.Namespace, timeline: pd.DataFrame) -> str:
    if args.session_id:
        return args.session_id
    session_col = first_col(timeline, ["session_id"]) if not timeline.empty else None
    if session_col and timeline[session_col].notna().any():
        return slug(timeline[session_col].dropna().iloc[0], "unknown_session")
    return slug(os.path.splitext(os.path.basename(args.output))[0], "unknown_session")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Merge ICS/PLC features into network, process, fusion, and leakage-ablation datasets.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--attacker-features", default=None, help="CSV from extract_s7_features.py for attacker capture")
    parser.add_argument("--controller-features", default=None, help="CSV from extract_s7_features.py for controller capture")
    parser.add_argument("--plc-tags", default=None, help="CSV from log_tags*.py")
    parser.add_argument("--timeline-files", nargs="+", default=[], help="Timeline CSV(s), START/END or start/end interval format")
    parser.add_argument("--output", required=True, help="Network-only dataset output CSV")
    parser.add_argument("--process-output", default=None, help="Process-monitor dataset output CSV")
    parser.add_argument("--export-process-dataset", default=None, help="Backward-compatible alias for --process-output")
    parser.add_argument("--fusion-output", default=None, help="Optional fusion dataset output CSV")
    parser.add_argument("--leakage-ablation-output", default=None, help="Optional intentionally unsafe ablation dataset output CSV")
    parser.add_argument("--window", type=float, default=5.0, help="Window size in seconds; must match extract_s7_features.py")
    parser.add_argument("--drop-transition-seconds", type=int, default=10, help="Drop rows near attack boundaries")
    parser.add_argument("--session-id", default=None, help="Session/run metadata for grouped splitting")
    parser.add_argument("--attacker-host-id", default="attacker_host", help="Attacker capture host metadata")
    parser.add_argument("--controller-host-id", default="controller_host", help="Controller capture host metadata")
    parser.add_argument("--process-host-id", default="process_logger", help="PLC tag logger host metadata")
    parser.add_argument("--plc-ip", default=None, help="If set, keep only rows with to/from PLC packet counts")
    parser.add_argument("--timeline-bound-filter", action="store_true", help="Trim feature rows to timeline min/max bounds; off by default to preserve benign warmup/cooldown")
    parser.add_argument("--keep-unsafe-network", action="store_true", help="Keep identity/process leakage columns in network output (debug only)")
    parser.add_argument("--label-all-traffic-by-system", action="store_true", help="Label controller rows by system attack state; normally false for network IDS")
    args = parser.parse_args()

    window_ms = int(args.window * 1000)
    timeline = load_timeline(args.timeline_files)
    session_id = infer_session_id(args, timeline)
    intervals = build_intervals(timeline, session_id)
    bounds = timeline_bounds(timeline) if args.timeline_bound_filter else None
    print_intervals(intervals)

    frames = []
    if args.attacker_features and os.path.exists(args.attacker_features):
        frames.append(normalize_feature_frame(args.attacker_features, "attacker", session_id, args.attacker_host_id))
    elif args.attacker_features:
        print(f"[WARN] Attacker features not found: {args.attacker_features}")

    if args.controller_features and os.path.exists(args.controller_features):
        frames.append(normalize_feature_frame(args.controller_features, "controller", session_id, args.controller_host_id))
    elif args.controller_features:
        print(f"[WARN] Controller features not found: {args.controller_features}")

    network_df = pd.DataFrame()
    if frames:
        raw_network = pd.concat(frames, ignore_index=True, sort=False)
        raw_network = filter_timeline_bounds(raw_network, bounds, window_ms)
        raw_network = assign_network_labels(
            raw_network,
            intervals,
            session_id,
            window_ms,
            label_all_traffic_by_system=args.label_all_traffic_by_system,
        )
        if args.plc_ip:
            raw_network = filter_plc_rows(raw_network)
        raw_network["_window_mid_ms"] = raw_network["window_start_ms"] + int(window_ms / 2)
        raw_network = drop_transition_rows(raw_network, intervals, "_window_mid_ms", args.drop_transition_seconds)
        raw_network = raw_network.drop(columns=["_window_mid_ms"], errors="ignore")
        network_df = drop_network_leakage_columns(raw_network, keep_unsafe=args.keep_unsafe_network)
        write_dataset(args.output, network_df, "Network-only dataset")
    else:
        print("[WARN] No network feature CSVs provided; network output will be empty.")
        write_dataset(args.output, network_df, "Network-only dataset")

    process_output = args.process_output or args.export_process_dataset
    process_df = pd.DataFrame()
    if args.plc_tags and os.path.exists(args.plc_tags):
        tags = load_process_tags(args.plc_tags)
        process_df = build_process_dataset(
            tags,
            intervals,
            session_id,
            args.process_host_id,
            window_ms,
            args.drop_transition_seconds,
        )
        if process_output:
            write_dataset(process_output, process_df, "Process-monitor dataset")
    elif args.plc_tags:
        print(f"[WARN] PLC tags not found: {args.plc_tags}")
    elif process_output or args.fusion_output or args.leakage_ablation_output:
        print("[WARN] Process/fusion output requested but --plc-tags was not provided.")

    if args.fusion_output:
        fusion_df = build_fusion_dataset(
            network_df,
            process_df,
            intervals,
            session_id,
            window_ms,
            args.drop_transition_seconds,
            keep_unsafe_network=False,
        )
        write_dataset(args.fusion_output, fusion_df, "Fusion dataset")

    if args.leakage_ablation_output:
        # Rebuild from the raw-ish network view if available so process context and
        # identity/rule outputs remain visible to train_ml.py's leakage experiment.
        source_net = raw_network if frames else network_df
        leakage_df = build_fusion_dataset(
            source_net,
            process_df,
            intervals,
            session_id,
            window_ms,
            args.drop_transition_seconds,
            keep_unsafe_network=True,
        )
        write_dataset(args.leakage_ablation_output, leakage_df, "Leakage-ablation dataset")


if __name__ == "__main__":
    main()
