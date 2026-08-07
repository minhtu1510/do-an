#!/usr/bin/env python3
"""
tests/day8/collect_opcua.py

Orchestrator thu thap dataset OPC UA (Day 8) -- tu dong hoa vong doi
warmup -> attack -> cooldown giong run_day_bangtruyen.sh cua Day 1-6, nhung
cho be mat OPC UA.

Thiet ke:
- Goi lai chinh run_day8.py bang subprocess (process isolation): mot kich ban
  DoS treo/loi khong lam chet tien trinh thu thap chinh.
- Chi dung cac kich ban LAP LAI DUOC (ket noi truc tiep, khong MITM/ARP) --
  MITM bi switch chan chap chon nen KHONG dung de thu dataset.
- Ghi timeline CSV dinh dang epoch (start,end,label) tuong thich truc tiep voi
  extract_opcua_features.py (--timeline). Label = TEN kich ban (multiclass).

Luong van hanh:
  1. Web-SCADA (.31) dang chay -> sinh traffic OPC UA benign (baseline).
  2. Bat Capture o cong mirror cua switch (trang cua thay) -> ghi PCAP.
  3. Chay script nay tren may attacker (.32).
  4. Xong -> Stop Capture, tai PCAP; chay extract_opcua_features.py voi PCAP +
     file timeline vua sinh.

Vi du:
  # PoC 25 phut (test pipeline)
  python tests/day8/collect_opcua.py --cycles 15 --warmup 40 --attack 20 --cooldown 40

  # Thu hoach lon theo thoi luong
  python tests/day8/collect_opcua.py --duration 10800 --warmup 60 --attack 25 --cooldown 45
"""

from __future__ import annotations

import argparse
import csv
import os
import random
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

RUN_DAY8 = Path(__file__).with_name("run_day8.py")
REPO_ROOT = Path(__file__).resolve().parents[2]
TZ = timezone(timedelta(hours=7))

# Chi cac kich ban LAP LAI DUOC (khong can quyen Ghi, khong MITM, khong
# NOT_CONFIGURED). Loai OPCUA_MALICIOUS_WRITE (can impact opt-in), cac benign
# (dung lam warmup), va UNAUTHORIZED_SESSION/CERTIFICATE_REJECTED (NOT_CONFIGURED).
DEFAULT_POOL = [
    # safe
    "OPCUA_ENDPOINT_DISCOVERY",
    "OPCUA_NODE_BROWSE",
    "OPCUA_READ_SCRAPING",
    "OPCUA_BEHAVIORAL_PROFILING",
    # gated (khong can impact opt-in)
    "OPCUA_WRITE_DENIED",
    "OPCUA_INVALID_WRITE",
    "OPCUA_SESSION_BURST",
    "OPCUA_SUBSCRIPTION_FLOOD",
    "OPCUA_PROTOCOL_FUZZ",
    "OPCUA_SLOWLORIS",
    "OPCUA_RECURSIVE_BROWSE",
]

_stop = {"flag": False}


def _handle_sigint(signum, frame):
    _stop["flag"] = True
    print("\n[!] Nhan Ctrl+C -- se dung sau chu ky hien tai, timeline da luu duoc giu nguyen.")


def now_epoch() -> float:
    return time.time()


def human(ts: float) -> str:
    return datetime.fromtimestamp(ts, TZ).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def run_one_scenario(scenario: str, max_seconds: int, env: dict) -> str:
    """Chay 1 kich ban qua run_day8.py subprocess. Tra ve trang thai text."""
    cmd = [
        sys.executable, str(RUN_DAY8),
        "--scenario", scenario,
        "--execute", "--allow-gated",
    ]
    try:
        proc = subprocess.Popen(
            cmd, cwd=str(REPO_ROOT),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=env,
        )
    except Exception as e:
        return f"spawn_failed:{e}"

    try:
        proc.wait(timeout=max_seconds)
        return "completed"
    except subprocess.TimeoutExpired:
        # Ep dung neu kich ban chua tu ket thuc (quan trong voi DoS giu lau).
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        return "terminated_on_timeout"


def collect(args) -> int:
    timeline_path = Path(args.timeline_file)
    if not timeline_path.is_absolute():
        timeline_path = REPO_ROOT / timeline_path

    pool = args.scenarios or DEFAULT_POOL
    env = dict(os.environ)
    if args.opc_url:
        env["OPC_URL"] = args.opc_url

    print(f"[*] Thu thap OPC UA dataset (Day 8)")
    print(f"[*] run_day8.py : {RUN_DAY8}")
    print(f"[*] Timeline    : {timeline_path}")
    print(f"[*] Pool ({len(pool)}): {', '.join(pool)}")
    print(f"[*] warmup={args.warmup}s attack<={args.attack}s cooldown={args.cooldown}s")
    if args.duration:
        print(f"[*] Che do: chay theo thoi luong ~{args.duration}s")
    else:
        print(f"[*] Che do: {args.cycles} cycles")
    print(f"[*] LUU Y: bat Capture o cong mirror + de web_scada chay truoc khi bat dau.")
    print("-" * 60)

    file_exists = timeline_path.is_file()
    timeline_path.parent.mkdir(parents=True, exist_ok=True)

    start_wall = time.time()
    cycle = 0
    with open(timeline_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["start", "end", "label", "start_human", "end_human", "cycle", "status"])
            f.flush()

        while not _stop["flag"]:
            if args.duration:
                if time.time() - start_wall >= args.duration:
                    break
            elif cycle >= args.cycles:
                break
            cycle += 1
            scenario = random.choice(pool)
            print(f"\n[Cycle {cycle}] scenario = {scenario}")

            # 1. Warmup (benign baseline -- de web_scada tu giao tiep).
            print(f"  [>] warmup {args.warmup}s (baseline benign)...")
            if not _sleep_interruptible(args.warmup):
                break

            # 2. Attack.
            t_start = now_epoch()
            print(f"  [>] attack bat dau {human(t_start)}")
            status = run_one_scenario(scenario, args.attack, env)
            t_end = now_epoch()
            print(f"  [>] attack ket thuc {human(t_end)} ({status})")

            # 3. Ghi timeline (epoch giay -- tuong thich extract_opcua_features.py).
            writer.writerow([
                f"{t_start:.3f}", f"{t_end:.3f}", scenario,
                human(t_start), human(t_end), cycle, status,
            ])
            f.flush()

            # 4. Cooldown (bat canh TCP reconnect/retransmission cua web_scada).
            print(f"  [>] cooldown {args.cooldown}s (phuc hoi)...")
            if not _sleep_interruptible(args.cooldown):
                break

    elapsed = time.time() - start_wall
    print(f"\n[*] Xong: {cycle} cycle trong {elapsed:.0f}s. Timeline: {timeline_path}")
    print(f"[*] Buoc tiep: Stop Capture -> tai PCAP -> "
          f"python extract_opcua_features.py --pcap <file>.pcap --timeline {timeline_path} "
          f"--output opcua_features.csv --window 5 --plc-ip {args.plc_ip}")
    return 0


def _sleep_interruptible(seconds: float) -> bool:
    """Sleep nhung kiem tra Ctrl+C moi 0.5s. Tra ve False neu bi dung."""
    end = time.time() + seconds
    while time.time() < end:
        if _stop["flag"]:
            return False
        time.sleep(min(0.5, max(0.0, end - time.time())))
    return True


def main() -> int:
    signal.signal(signal.SIGINT, _handle_sigint)
    p = argparse.ArgumentParser(description="Wrapper tu dong thu thap dataset OPC UA (Day 8)")
    p.add_argument("--plc-ip", default="192.168.210.211", help="IP PLC (chi de in vao huong dan extract)")
    p.add_argument("--opc-url", default=None, help="OPC UA endpoint; mac dinh lay tu testbed.conf/OPC_URL")
    p.add_argument("--cycles", type=int, default=10, help="So vong lap (bo qua neu dung --duration)")
    p.add_argument("--duration", type=int, default=None, help="Chay theo thoi luong (giay) thay vi so cycle")
    p.add_argument("--warmup", type=int, default=40, help="Thoi gian baseline benign truoc tan cong (giay)")
    p.add_argument("--attack", type=int, default=20, help="Thoi gian toi da moi kich ban tan cong (giay)")
    p.add_argument("--cooldown", type=int, default=40, help="Thoi gian phuc hoi sau tan cong (giay)")
    p.add_argument("--timeline-file", default="test_results/day8/timeline_opcua_day8.csv", help="File CSV timeline")
    p.add_argument("--scenarios", nargs="*", default=None, help="Ghi de pool kich ban (mac dinh dung DEFAULT_POOL)")
    args = p.parse_args()
    return collect(args)


if __name__ == "__main__":
    raise SystemExit(main())
