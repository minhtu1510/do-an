#!/usr/bin/env python3
"""Regenerate robust ICS IDS datasets and train selected feature profiles.

Outputs are written with a suffix, so existing extract/network/process/fusion
CSV files are not overwritten unless you choose an existing suffix.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PLC_IP = "192.168.210.211"
FEATURE_PROFILES = ("safe", "hybrid", "frequency_robust")
DAYS = ("day1", "day2", "day3", "day4", "day5", "day6")


def run(cmd: list[str], dry_run: bool) -> None:
    line = "\n$ " + " ".join(f'"{part}"' if " " in part else part for part in cmd)
    encoding = sys.stdout.encoding or "utf-8"
    print(line.encode(encoding, errors="backslashreplace").decode(encoding))
    if not dry_run:
        subprocess.run(cmd, cwd=ROOT, check=True)


def as_arg(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def session_id_for_day(day: str, args: argparse.Namespace) -> str:
    day_num = day[3:] if day.startswith("day") else day
    return args.session_template.format(day=day, n=day_num)


def timeline_for_day(day: str, args: argparse.Namespace) -> Path | None:
    if day == "day1":
        return None
    session_id = session_id_for_day(day, args)
    base = ROOT / "labels" / f"{day}_{session_id}_{args.attacker_host_id}_timeline.csv"
    refined = ROOT / "labels" / f"{day}_{session_id}_{args.attacker_host_id}_timeline_refined.csv"
    if args.prefer_refined_timelines and refined.exists():
        return refined
    return base


def day_paths(day: str, args: argparse.Namespace) -> dict[str, Path]:
    session_id = session_id_for_day(day, args)
    capture_dir = ROOT / "captures" / day
    return {
        "pcap": capture_dir / args.pcap_name,
        "extract": capture_dir / f"extract_{args.suffix}.csv",
        "network": capture_dir / f"network_{args.suffix}.csv",
        "process": capture_dir / f"process_{args.suffix}.csv",
        "fusion": capture_dir / f"fusion_{args.suffix}.csv",
        "tags": ROOT / "logs" / f"{day}_{session_id}_{args.controller_host_id}_tags.csv",
    }


def build_extract_cmd(day: str, paths: dict[str, Path], args: argparse.Namespace) -> list[str]:
    return [
        sys.executable,
        "extract_s7_features.py",
        "--pcap", as_arg(paths["pcap"]),
        "--output", as_arg(paths["extract"]),
        "--window", str(args.window),
        "--plc-ip", args.plc_ip,
        "--role", "mirror",
        "--label", "BENIGN",
        "--session-id", day,
        "--host-id", "mirror_capture",
    ]


def build_merge_cmd(day: str, paths: dict[str, Path], args: argparse.Namespace) -> list[str]:
    cmd = [
        sys.executable,
        "merge_dataset.py",
        "--mirror-features", as_arg(paths["extract"]),
        "--plc-tags", as_arg(paths["tags"]),
        "--output", as_arg(paths["network"]),
        "--process-output", as_arg(paths["process"]),
        "--fusion-output", as_arg(paths["fusion"]),
        "--window", str(args.window),
        "--drop-transition-seconds", str(args.drop_transition_seconds),
        "--session-id", day,
        "--mirror-host-id", "mirror_capture",
        "--process-host-id", "process_logger",
        "--plc-ip", args.plc_ip,
    ]
    timeline = timeline_for_day(day, args)
    if timeline:
        cmd.extend(["--timeline-files", as_arg(timeline)])
    return cmd


def build_train_cmd(args: argparse.Namespace) -> list[str]:
    network_paths = [as_arg(day_paths(day, args)["network"]) for day in DAYS]
    process_paths = [as_arg(day_paths(day, args)["process"]) for day in DAYS]
    fusion_paths = [as_arg(day_paths(day, args)["fusion"]) for day in DAYS]
    cmd = [
        sys.executable,
        "train_ml.py",
        "--network-data", *network_paths,
        "--process-data", *process_paths,
        "--fusion-data", *fusion_paths,
        "--output-dir", as_arg(ROOT / "ml_results" / f"{args.suffix}_{args.feature_profile}"),
        "--feature-profile", args.feature_profile,
        "--binary-threshold-mode", args.binary_threshold_mode,
        "--binary-threshold-beta", str(args.binary_threshold_beta),
        "--validation-session-id", args.validation_session_id,
        "--default-window-seconds", str(args.window),
        "--tasks", "binary", "multiclass",
        "--seeds", *[str(seed) for seed in args.seeds],
    ]
    if args.binary_threshold_value is not None:
        cmd.extend(["--binary-threshold-value", str(args.binary_threshold_value)])
    if args.quick_holdout:
        cmd.append("--skip-group-cv")
    return cmd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Regenerate robust features/datasets and train ICS IDS models")
    parser.add_argument("--window", type=float, default=2.0, help="Window size in seconds; must match train default-window-seconds")
    parser.add_argument("--plc-ip", default=PLC_IP)
    parser.add_argument("--suffix", default="robust", help="Output suffix for regenerated CSV files")
    parser.add_argument("--session-template", default="{day}_bt_s1", help="Session id template used by collection, e.g. '{day}_bt_s1_ext300k'. Supports {day}=day1 and {n}=1")
    parser.add_argument("--controller-host-id", default="controller_host", help="Host id used in controller tag log filenames")
    parser.add_argument("--attacker-host-id", default="attacker_host", help="Host id used in attacker timeline filenames")
    parser.add_argument("--pcap-name", default="merged_all.pcapng", help="Merged PCAP filename inside each captures/day* directory")
    parser.set_defaults(prefer_refined_timelines=True)
    parser.add_argument("--prefer-refined-timelines", dest="prefer_refined_timelines", action="store_true", help="Use *_timeline_refined.csv when present")
    parser.add_argument("--no-prefer-refined-timelines", dest="prefer_refined_timelines", action="store_false", help="Use raw timeline CSV even when a refined timeline exists")
    parser.add_argument("--drop-transition-seconds", type=int, default=0, help="0 preserves sparse event-refined attack windows")
    parser.add_argument("--validation-session-id", default="day6")
    parser.add_argument("--feature-profile", choices=FEATURE_PROFILES, default="hybrid", help="hybrid is recommended for mixed scan/flood and sparse PLC-logic attacks")
    parser.add_argument("--binary-threshold-mode", choices=["default", "fbeta", "fixed"], default="fbeta", help="fbeta tunes binary threshold on train folds; fixed uses --binary-threshold-value")
    parser.add_argument("--binary-threshold-beta", type=float, default=2.0)
    parser.add_argument("--binary-threshold-value", type=float, default=None)
    parser.add_argument("--seeds", nargs="*", type=int, default=[42, 43, 44])
    parser.add_argument("--skip-extract", action="store_true", help="Reuse captures/day*/extract_<suffix>.csv")
    parser.add_argument("--skip-merge", action="store_true", help="Reuse captures/day*/network/process/fusion_<suffix>.csv")
    parser.add_argument("--skip-train", action="store_true")
    parser.add_argument("--quick-holdout", action="store_true", help="Train only day/session holdout, skip grouped CV")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without running them")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    for day in DAYS:
        paths = day_paths(day, args)
        for key in ["pcap", "tags"]:
            if not paths[key].exists():
                raise FileNotFoundError(paths[key])
        timeline = timeline_for_day(day, args)
        if timeline is not None and not timeline.exists():
            raise FileNotFoundError(timeline)
        if not args.skip_extract:
            run(build_extract_cmd(day, paths, args), args.dry_run)
        if not args.skip_merge:
            run(build_merge_cmd(day, paths, args), args.dry_run)
    if not args.skip_train:
        run(build_train_cmd(args), args.dry_run)


if __name__ == "__main__":
    main()
