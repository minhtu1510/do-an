#!/usr/bin/env python3
"""Create a network-friendly attack timeline from START/END labels plus attack events.

For sparse write/process attacks, labeling the full START..END interval can mark many
normal polling windows as attack. This utility keeps continuous traffic attacks from
the original timeline, but replaces selected sparse scenarios with short windows
around the actual attacker EVENT timestamps. The attack-event file is used only to
build ground-truth labels, not as model input features.
"""

from __future__ import annotations

import argparse
import csv
import os
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Iterable, List, Optional, Sequence


DEFAULT_EVENT_SCENARIOS = {
    "RWRITE",
    "RWRITE_BURST",
    "RWRITE_TAG",
    "SETPOINT_ATTACK",
    "SENSOR_SPOOF",
    "SPOOF",
    "SPOOF_TAG",
    "STEALTHY",
    "STEALTHY_WRITE",
    "STEALTHY_START",
    "STEALTHY_STOP",
}

BENIGN_LABELS = {"BENIGN", "BENIGN_NORMAL", "NORMAL", "BENIGN_PROCESS", "BENIGN_READER"}


@dataclass
class Interval:
    start_ms: int
    end_ms: int
    scenario: str
    day: str
    note: str
    event_count: int = 0


@dataclass
class AttackEvent:
    timestamp_ms: int
    scenario: str
    note: str


def normalize_epoch_ms(value: object) -> int:
    if value is None:
        return -1
    text = str(value).strip()
    if not text:
        return -1
    try:
        raw = float(text)
    except ValueError:
        return -1
    if raw < 0:
        return -1
    return int(raw * 1000) if raw < 10_000_000_000 else int(raw)


def first_col(fieldnames: Sequence[str], candidates: Iterable[str]) -> Optional[str]:
    lower = {name.lower().strip(): name for name in fieldnames}
    for candidate in candidates:
        found = lower.get(candidate.lower())
        if found:
            return found
    return None


def norm_label(value: object) -> str:
    return str(value or "").strip().upper()


def is_benign(value: object) -> bool:
    label = norm_label(value)
    return not label or label in BENIGN_LABELS or label.startswith("BENIGN")


def load_timeline(path: str) -> List[Interval]:
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return []
        fields = reader.fieldnames
        start_col = first_col(fields, ["start", "start_time", "start_timestamp", "start_ms"])
        end_col = first_col(fields, ["end", "end_time", "end_timestamp", "end_ms"])
        label_col = first_col(fields, ["scenario_label", "label", "attack", "class", "scenario"])
        day_col = first_col(fields, ["day"])
        note_col = first_col(fields, ["note", "episode", "run", "repeat"])

        if start_col and end_col and label_col:
            intervals = []
            for row in reader:
                scenario = norm_label(row.get(label_col))
                if is_benign(scenario):
                    continue
                start_ms = normalize_epoch_ms(row.get(start_col))
                end_ms = normalize_epoch_ms(row.get(end_col))
                if end_ms > start_ms >= 0:
                    intervals.append(Interval(
                        start_ms,
                        end_ms,
                        scenario,
                        str(row.get(day_col, "") if day_col else ""),
                        str(row.get(note_col, "") if note_col else ""),
                    ))
            return sorted(intervals, key=lambda x: x.start_ms)

        ts_col = first_col(fields, ["attacker_timestamp_ms", "timestamp_ms", "timestamp", "time", "ts"])
        action_col = first_col(fields, ["action", "event"])
        episode_col = first_col(fields, ["episode_id", "episode"])
        if not ts_col or not label_col or not action_col:
            raise ValueError("Timeline must contain start,end,label or timestamp,label,action columns")

        active: Dict[tuple[str, str], Deque[tuple[int, str, str]]] = defaultdict(deque)
        intervals: List[Interval] = []
        for row in sorted(reader, key=lambda r: normalize_epoch_ms(r.get(ts_col))):
            scenario = norm_label(row.get(label_col))
            if is_benign(scenario):
                continue
            action = str(row.get(action_col, "")).strip().upper()
            ts_ms = normalize_epoch_ms(row.get(ts_col))
            if ts_ms < 0:
                continue
            episode = str(row.get(episode_col, "") if episode_col else "").strip()
            key = (scenario, episode or scenario)
            day = str(row.get(day_col, "") if day_col else "")
            note = str(row.get(note_col, "") if note_col else "")
            if action == "START":
                active[key].append((ts_ms, day, note))
            elif action == "END" and active[key]:
                start_ms, start_day, start_note = active[key].popleft()
                if ts_ms > start_ms:
                    intervals.append(Interval(start_ms, ts_ms, scenario, start_day or day, start_note or note))
        return sorted(intervals, key=lambda x: x.start_ms)


def load_attack_events(path: Optional[str]) -> List[AttackEvent]:
    if not path:
        return []
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return []
        fields = reader.fieldnames
        ts_col = first_col(fields, ["timestamp_ms", "attacker_timestamp_ms", "timestamp", "time", "ts"])
        label_col = first_col(fields, ["scenario_label", "label", "attack", "class", "scenario"])
        signal_col = first_col(fields, ["signal", "tag", "address"])
        status_col = first_col(fields, ["status", "result"])
        if not ts_col or not label_col:
            raise ValueError("Attack events must contain timestamp_ms and scenario_label columns")
        events = []
        for row in reader:
            ts_ms = normalize_epoch_ms(row.get(ts_col))
            scenario = norm_label(row.get(label_col))
            if ts_ms < 0 or is_benign(scenario):
                continue
            parts = []
            if signal_col and row.get(signal_col):
                parts.append(f"signal={row.get(signal_col)}")
            if status_col and row.get(status_col):
                parts.append(f"status={row.get(status_col)}")
            events.append(AttackEvent(ts_ms, scenario, ";".join(parts)))
        return sorted(events, key=lambda x: x.timestamp_ms)


def merge_intervals(intervals: List[Interval]) -> List[Interval]:
    out: List[Interval] = []
    for item in sorted(intervals, key=lambda x: (x.scenario, x.start_ms, x.end_ms)):
        if out and out[-1].scenario == item.scenario and item.start_ms <= out[-1].end_ms:
            out[-1].end_ms = max(out[-1].end_ms, item.end_ms)
            out[-1].event_count += item.event_count
            if item.note and item.note not in out[-1].note:
                out[-1].note = f"{out[-1].note};{item.note}" if out[-1].note else item.note
        else:
            out.append(item)
    return sorted(out, key=lambda x: x.start_ms)


def refine_timeline(
    intervals: Sequence[Interval],
    events: Sequence[AttackEvent],
    event_scenarios: set[str],
    event_window_ms: int,
    fallback_full_interval: bool,
) -> List[Interval]:
    events_by_scenario: Dict[str, List[AttackEvent]] = defaultdict(list)
    for event in events:
        events_by_scenario[event.scenario].append(event)

    refined: List[Interval] = []
    for interval in intervals:
        if interval.scenario not in event_scenarios:
            refined.append(interval)
            continue

        matched = [
            event for event in events_by_scenario.get(interval.scenario, [])
            if interval.start_ms <= event.timestamp_ms <= interval.end_ms
        ]
        if not matched:
            if fallback_full_interval:
                refined.append(interval)
            continue

        for event in matched:
            start_ms = max(interval.start_ms, event.timestamp_ms - event_window_ms)
            end_ms = min(interval.end_ms, event.timestamp_ms + event_window_ms)
            if end_ms > start_ms:
                note = f"event_refined;{event.note}" if event.note else "event_refined"
                refined.append(Interval(start_ms, end_ms, interval.scenario, interval.day, note, event_count=1))

    return merge_intervals(refined)


def write_intervals(path: str, intervals: Sequence[Interval]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["start", "end", "scenario_label", "day", "note", "event_count"])
        writer.writeheader()
        for item in sorted(intervals, key=lambda x: x.start_ms):
            writer.writerow({
                "start": item.start_ms,
                "end": item.end_ms,
                "scenario_label": item.scenario,
                "day": item.day,
                "note": item.note,
                "event_count": item.event_count,
            })


def parse_scenarios(value: str) -> set[str]:
    if not value.strip():
        return set(DEFAULT_EVENT_SCENARIOS)
    return {norm_label(part) for part in value.replace(";", ",").split(",") if part.strip()}


def main() -> None:
    parser = argparse.ArgumentParser(description="Refine sparse attack labels using attacker event timestamps")
    parser.add_argument("--timeline", required=True, help="Original START/END timeline CSV")
    parser.add_argument("--attack-events", default=None, help="Optional attacker EVENT CSV")
    parser.add_argument("--output", required=True, help="Refined interval timeline CSV")
    parser.add_argument("--event-window-seconds", type=float, default=2.0, help="Seconds before/after each event to label as attack")
    parser.add_argument("--event-scenarios", default=",".join(sorted(DEFAULT_EVENT_SCENARIOS)), help="Comma-separated sparse scenarios to refine from events")
    parser.add_argument("--fallback-full-interval", action="store_true", help="Keep full START/END interval when a sparse scenario has no matching events")
    args = parser.parse_args()

    intervals = load_timeline(args.timeline)
    events = load_attack_events(args.attack_events)
    refined = refine_timeline(
        intervals,
        events,
        parse_scenarios(args.event_scenarios),
        int(args.event_window_seconds * 1000),
        fallback_full_interval=args.fallback_full_interval,
    )
    write_intervals(args.output, refined)

    print(f"[OK] Original non-benign intervals: {len(intervals)}")
    print(f"[OK] Attack events: {len(events)}")
    print(f"[OK] Refined intervals: {len(refined)}")
    counts: Dict[str, int] = defaultdict(int)
    for item in refined:
        counts[item.scenario] += 1
    for scenario, count in sorted(counts.items()):
        print(f"  {scenario}: {count}")
    print(f"[OK] Saved: {args.output}")


if __name__ == "__main__":
    main()
