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
  python tests/day8/collect_opcua.py --cycles 15 --warmup 40 --cooldown 40

  # Thu hoach lon theo thoi luong (may A -- tap TRAIN chinh)
  python tests/day8/collect_opcua.py --duration 10800 --warmup 60 --cooldown 45 \
      --host-id attacker_A --session-tag train

  # Tap OOD TEST doc lap (may B, phien/ngay khac, it cycle hon la du)
  python tests/day8/collect_opcua.py --cycles 50 --warmup 30 --cooldown 30 \
      --host-id attacker_B --session-tag oodtest

LUU Y AN TOAN THOI LUONG:
  --attack gio la 1 SAN toi thieu, khong phai gia tri co dinh cho moi cycle.
  Kich ban nhanh (browse, discovery) tu ket thuc som; 2 kich ban giu-phien
  (OPCUA_SLOWLORIS, OPCUA_BEHAVIORAL_PROFILING) can du thoi gian de khong bi
  asyncio.wait_for cat giua chung -> sinh episode "timeout"/0-goi giong dung
  loi ma bao cao TN2/TN3 da phat hien (17/30 episode khong co goi tan cong
  that vi cong cu ban cu cat qua som). Script TU TINH LAI muc an toan MOI
  CYCLE (xem _expected_duration_s()) sau khi ap dung tier ngau nhien -- xem
  muc DA DANG TAN SUAT ben duoi.

DA DANG TAN SUAT/CUONG DO (moi cho lan sua nay):
  Cac kich ban co tham so dieu chinh duoc (SESSION_BURST, SUBSCRIPTION_FLOOD,
  READ_SCRAPING, RECURSIVE_BROWSE, SLOWLORIS, BEHAVIORAL_PROFILING,
  PROTOCOL_FUZZ) gio duoc gan NGAU NHIEN 1 trong 3 tier (slow/medium/fast)
  MOI CYCLE thay vi luon dung 1 gia tri mac dinh co dinh nhu 224-cycle harvest
  cu -- xem TIER_ENV_OVERRIDES. Timeline CSV co them cot 'tier' de sau nay
  loc/phan tich rieng theo cuong do (vd: mo hinh co phat hien duoc SESSION_BURST
  tier "slow" (delay 2s/lan) kem nhu tier "fast" (delay 0.2s/lan) khong).
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import random
import signal
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TZ = timezone(timedelta(hours=7))

# Chay IN-PROCESS thay vi subprocess: tren Windows/venv, subprocess (sys.executable)
# co the khong tro dung python co asyncua -> ImportError tuc thi -> khong tan cong
# duoc (0.2s "completed" nhung 0 traffic toi PLC). Import thang run_day8 va goi
# execute_safe/execute_controlled_gated qua asyncio -> het loi moi truong.
sys.path.insert(0, str(Path(__file__).parent))
import run_day8 as d8  # noqa: E402

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

# Kich ban nao co "hold" noi tai (giu phien/subscription trong X giay) va bien
# moi truong dieu khien no -- doc dung ten bien + default + tran (cap) ma
# run_day8.py dang dung, de tinh dung thoi gian toi thieu can cho --attack.
# (scenario_id -> (env_var, default_str, cap_s, setup_margin_s))
SCENARIO_HOLD_ENV = {
    "OPCUA_SLOWLORIS": ("DAY8_SLOWLORIS_HOLD_S", "40", 120.0, 15.0),
    "OPCUA_BEHAVIORAL_PROFILING": ("DAY8_PROFILING_HOLD_S", "60", 300.0, 10.0),
    "OPCUA_SUBSCRIPTION_FLOOD": ("DAY8_SUBSCRIPTION_FLOOD_HOLD_S", "10", 30.0, 10.0),
}
# Kich ban khong co hold dai (browse/discovery/scraping/burst/fuzz/write) --
# uoc luong an toan cho truong hop xau nhat (vd read_scraping voi count lon).
FALLBACK_SCENARIO_DURATION_S = 20.0
# Bien so ma run_one_scenario() da cong them vao asyncio.wait_for() -- xem ben duoi.
WAIT_FOR_MARGIN_S = 15.0


def _expected_duration_s(scenario_id: str) -> float:
    """Uoc luong thoi gian kich ban co the chay THAT (doc cung bien moi truong
    ma run_day8.py doc, khong doan mo). Dung de tinh --attack toi thieu an toan."""
    cfg = SCENARIO_HOLD_ENV.get(scenario_id)
    if not cfg:
        return FALLBACK_SCENARIO_DURATION_S
    env_name, default, cap_s, margin_s = cfg
    try:
        requested = float(os.getenv(env_name, default))
    except ValueError:
        requested = float(default)
    return min(requested, cap_s) + margin_s


def _min_safe_attack_s(pool: list[str]) -> int:
    """--attack toi thieu de KHONG kich ban nao trong pool bi asyncio.wait_for
    cat giua chung (tranh dung loi episode 'timeout'/0-goi ma TN2/TN3 gap phai).
    Day la uoc luong THO ban dau (dung default env, chua tinh tier) -- muc an
    toan THAT su duoc tinh LAI MOI CYCLE trong collect() sau khi ap tier ngau
    nhien, xem _apply_random_tier()."""
    worst = max((_expected_duration_s(s) for s in pool), default=FALLBACK_SCENARIO_DURATION_S)
    return int(worst) + 1  # +1s lam tron an toan; WAIT_FOR_MARGIN_S da cong rieng trong run_one_scenario


# ---------------------------------------------------------------------------
# Da dang TAN SUAT/CUONG DO: moi cycle, kich ban co tham so dieu chinh duoc se
# duoc gan NGAU NHIEN 1 trong 3 muc (slow/medium/fast) truoc khi chay, thay vi
# luon dung 1 gia tri mac dinh co dinh nhu truoc (ly do 224-cycle harvest cu
# it da dang ve rate/cuong do). Gia tri dua tren dung bien moi truong + tran
# (cap) ma run_day8.py doc trong tung ham (khong vuot cap da khai o do).
# "slow" o day KHONG danh dong voi ten kich ban OPCUA_SLOWLORIS (van la 1
# kich ban rieng); day la muc do CHAM cua chinh moi kich ban co tham so.
TIER_ENV_OVERRIDES: dict[str, dict[str, dict[str, str]]] = {
    "OPCUA_SESSION_BURST": {
        "slow":   {"DAY8_SESSION_BURST_COUNT": "3",  "DAY8_SESSION_BURST_DELAY_S": "2.0"},
        "medium": {"DAY8_SESSION_BURST_COUNT": "5",  "DAY8_SESSION_BURST_DELAY_S": "0.5"},
        "fast":   {"DAY8_SESSION_BURST_COUNT": "10", "DAY8_SESSION_BURST_DELAY_S": "0.2"},
    },
    "OPCUA_SUBSCRIPTION_FLOOD": {
        "slow":   {"DAY8_SUBSCRIPTION_FLOOD_ITEMS": "20",  "DAY8_SUBSCRIPTION_FLOOD_INTERVAL_MS": "1000", "DAY8_SUBSCRIPTION_FLOOD_HOLD_S": "15"},
        "medium": {"DAY8_SUBSCRIPTION_FLOOD_ITEMS": "50",  "DAY8_SUBSCRIPTION_FLOOD_INTERVAL_MS": "200",  "DAY8_SUBSCRIPTION_FLOOD_HOLD_S": "10"},
        "fast":   {"DAY8_SUBSCRIPTION_FLOOD_ITEMS": "200", "DAY8_SUBSCRIPTION_FLOOD_INTERVAL_MS": "50",   "DAY8_SUBSCRIPTION_FLOOD_HOLD_S": "10"},
    },
    "OPCUA_READ_SCRAPING": {
        "slow":   {"DAY8_READ_SCRAPING_COUNT": "40",  "DAY8_READ_SCRAPING_INTERVAL_S": "1.0"},
        "medium": {"DAY8_READ_SCRAPING_COUNT": "100", "DAY8_READ_SCRAPING_INTERVAL_S": "0.05"},
        "fast":   {"DAY8_READ_SCRAPING_COUNT": "500", "DAY8_READ_SCRAPING_INTERVAL_S": "0.02"},
    },
    "OPCUA_RECURSIVE_BROWSE": {
        "slow":   {"DAY8_RECBROWSE_ITERS": "10", "DAY8_RECBROWSE_DEPTH": "2", "DAY8_RECBROWSE_INTERVAL_S": "2.0"},
        "medium": {"DAY8_RECBROWSE_ITERS": "20", "DAY8_RECBROWSE_DEPTH": "4", "DAY8_RECBROWSE_INTERVAL_S": "0.5"},
        "fast":   {"DAY8_RECBROWSE_ITERS": "60", "DAY8_RECBROWSE_DEPTH": "5", "DAY8_RECBROWSE_INTERVAL_S": "0.2"},
    },
    "OPCUA_SLOWLORIS": {
        "slow":   {"DAY8_SLOWLORIS_SESSIONS": "5",  "DAY8_SLOWLORIS_HOLD_S": "20", "DAY8_SLOWLORIS_KEEPALIVE_S": "25"},
        "medium": {"DAY8_SLOWLORIS_SESSIONS": "10", "DAY8_SLOWLORIS_HOLD_S": "40", "DAY8_SLOWLORIS_KEEPALIVE_S": "20"},
        "fast":   {"DAY8_SLOWLORIS_SESSIONS": "15", "DAY8_SLOWLORIS_HOLD_S": "60", "DAY8_SLOWLORIS_KEEPALIVE_S": "10"},
    },
    "OPCUA_BEHAVIORAL_PROFILING": {
        "slow":   {"DAY8_PROFILING_HOLD_S": "20"},
        "medium": {"DAY8_PROFILING_HOLD_S": "60"},
        "fast":   {"DAY8_PROFILING_HOLD_S": "90"},
    },
    "OPCUA_PROTOCOL_FUZZ": {
        "slow":   {"DAY8_FUZZ_COUNT": "2"},
        "medium": {"DAY8_FUZZ_COUNT": "3"},
        "fast":   {"DAY8_FUZZ_COUNT": "5"},
    },
}


def _apply_random_tier(scenario_id: str) -> str | None:
    """Neu scenario co tier dinh nghia, chon ngau nhien 1 muc va set bien moi
    truong tuong ung (os.environ) TRUOC khi dispatch -- ham thuc thi trong
    run_day8.py doc lai chinh cac bien nay tai thoi diem chay. Tra ve ten
    tier da chon, hoac None neu scenario khong co tham so dieu chinh duoc."""
    tiers = TIER_ENV_OVERRIDES.get(scenario_id)
    if not tiers:
        return None
    tier_name = random.choice(list(tiers.keys()))
    for env_name, value in tiers[tier_name].items():
        os.environ[env_name] = value
    return tier_name


_stop = {"flag": False}


def _handle_sigint(signum, frame):
    _stop["flag"] = True
    print("\n[!] Nhan Ctrl+C -- se dung sau chu ky hien tai, timeline da luu duoc giu nguyen.")


def now_epoch() -> float:
    return time.time()


def human(ts: float) -> str:
    return datetime.fromtimestamp(ts, TZ).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


async def _dispatch(scenario: str):
    """Goi dung executor cua run_day8 (safe truoc, roi gated)."""
    ev = await d8.execute_safe(scenario)
    if ev is None:
        ev = await d8.execute_controlled_gated(scenario)
    return ev


def run_one_scenario(scenario: str, max_seconds: int) -> str:
    """Chay 1 kich ban IN-PROCESS (asyncio). Tra ve trang thai + so evidence."""
    try:
        # +15s margin ngoai max_seconds de kich ban tu hoan tat (chung da co
        # timeout/hard-cap noi bo); wait_for chi la luoi an toan cuoi.
        ev = asyncio.run(asyncio.wait_for(_dispatch(scenario), timeout=max_seconds + 15))
        if ev is None:
            return "no_executor"
        return f"executed(evidence={len(ev)})"
    except asyncio.TimeoutError:
        return "timeout"
    except Exception as e:
        return f"error:{type(e).__name__}:{e}"


def collect(args) -> int:
    pool = args.scenarios or DEFAULT_POOL

    # --attack gio la 1 SAN toi thieu (co the de trong = 0/None), KHONG con la
    # gia tri co dinh ap dung cho moi cycle nua. Muc an toan THAT su duoc tinh
    # LAI moi cycle sau khi ap tier ngau nhien (xem vong lap ben duoi) --
    # tranh dung loi TN2/TN3 (episode "timeout"/0-goi vi cat qua som) o CA
    # tier "fast" (vd SLOWLORIS tier fast hold=60s), khong chi o muc default.
    # Con so nay chi la uoc luong THO de in ra cho operator biet truoc.
    rough_min_attack = _min_safe_attack_s(pool)
    print(f"[*] --attack la SAN toi thieu; muc an toan THAT tinh LAI moi cycle theo tier "
          f"(uoc luong tho ban dau cho pool nay: ~{rough_min_attack}s cho tier nang nhat).")

    session_tag = args.session_tag
    host_id = args.host_id
    timeline_file = args.timeline_file or f"test_results/day8/timeline_opcua_day8_{session_tag}_{host_id}.csv"
    timeline_path = Path(timeline_file)
    if not timeline_path.is_absolute():
        timeline_path = REPO_ROOT / timeline_path

    if args.opc_url:
        d8.OPC_URL = args.opc_url  # override endpoint cho cac executor in-process

    print(f"[*] Thu thap OPC UA dataset (Day 8)")
    print(f"[*] Che do      : IN-PROCESS (import run_day8, khong subprocess)")
    print(f"[*] host_id     : {host_id}")
    print(f"[*] session_tag : {session_tag}  (dung 'oodtest' cho tap held-out doc lap voi tap 'train')")
    print(f"[*] Timeline    : {timeline_path}")
    print(f"[*] Pool ({len(pool)}): {', '.join(pool)}")
    print(f"[*] warmup={args.warmup}s attack floor={args.attack or 0}s (tinh dong theo tier moi cycle) cooldown={args.cooldown}s")
    if args.duration:
        print(f"[*] Che do: chay theo thoi luong ~{args.duration}s")
    else:
        print(f"[*] Che do: {args.cycles} cycles")
    print(f"[*] LUU Y: bat Capture o cong mirror + de web_scada chay truoc khi bat dau.")
    print("-" * 60)

    # Metadata tai lap: ghi lai TOAN BO tham so lenh that da dung, khac phu luc
    # bao cao cu thieu lenh collect_opcua.py that (chi co mergecap/extract/eval).
    meta_path = timeline_path.with_name(timeline_path.stem + f"_meta_{time.strftime('%Y%m%d_%H%M%S')}.json")
    meta = {
        "host_id": host_id,
        "session_tag": session_tag,
        "pool": pool,
        "warmup_s": args.warmup,
        "attack_floor_s": args.attack,
        "rough_min_attack_s": rough_min_attack,
        "cooldown_s": args.cooldown,
        "cycles": args.cycles,
        "duration_s": args.duration,
        "opc_url": args.opc_url or getattr(d8, "OPC_URL", None),
        "plc_ip": args.plc_ip,
        "started_at": human(time.time()),
    }
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[*] Da ghi metadata tai lap: {meta_path}")

    file_exists = timeline_path.is_file()
    timeline_path.parent.mkdir(parents=True, exist_ok=True)

    start_wall = time.time()
    cycle = 0
    with open(timeline_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["start", "end", "label", "episode", "start_human", "end_human",
                              "cycle", "status", "host_id", "session_tag", "tier"])
            f.flush()

        while not _stop["flag"]:
            if args.duration:
                if time.time() - start_wall >= args.duration:
                    break
            elif cycle >= args.cycles:
                break
            cycle += 1
            scenario = random.choice(pool)

            # Da dang tan suat: gan ngau nhien 1 tier (slow/medium/fast) cho
            # kich ban nay NEU no co tham so dieu chinh duoc (xem
            # TIER_ENV_OVERRIDES) -- cung 1 lop tan cong se duoc thu voi nhieu
            # cuong do khac nhau qua cac cycle, khong chi 1 gia tri co dinh.
            tier = _apply_random_tier(scenario) or "fixed"
            # Tinh lai muc --attack CAN THIET cho ĐÚNG tier vua ap dung (doc
            # lai os.environ vua set o tren) -- args.attack (neu co) chi la
            # SAN toi thieu, khong bao gio lam giam muc an toan thuc te.
            required_s = _expected_duration_s(scenario)
            cycle_attack = int(max(args.attack or 0, required_s))
            print(f"\n[Cycle {cycle}] scenario = {scenario}  tier = {tier}  attack<={cycle_attack}s")

            # 1. Warmup (benign baseline -- de web_scada tu giao tiep).
            #    Ghi RIENG 1 dong BENIGN_NORMAL vao timeline cho khoang nay --
            #    truoc day khoang warmup/cooldown khong duoc ghi vao timeline
            #    o tat ca, nen extract_opcua_features.py roi vao nhanh
            #    "khong trung interval nao -> default --label" (thuong la
            #    "unknown" vi 04_day8_opcua.sh khong truyen --label), khien
            #    dataset Day 8 KHONG CO dong BENIGN nao (0/112 dong quan sat
            #    thuc te). Ghi tuong minh giong BENIGN_NORMAL cua Day 1-6
            #    (run_day_bangtruyen.sh) de is_benign_label() ("BENIGN",
            #    "BENIGN_NORMAL", "NORMAL", ...) nhan dung.
            print(f"  [>] warmup {args.warmup}s (baseline benign)...")
            t_warmup_start = now_epoch()
            if not _sleep_interruptible(args.warmup):
                break
            t_warmup_end = now_epoch()
            warmup_episode_id = f"day8_{session_tag}_{host_id}_c{cycle:03d}_BENIGN_warmup"
            writer.writerow([
                f"{t_warmup_start:.3f}", f"{t_warmup_end:.3f}", "BENIGN_NORMAL", warmup_episode_id,
                human(t_warmup_start), human(t_warmup_end), cycle, "benign_warmup", host_id, session_tag, "fixed",
            ])
            f.flush()

            # 2. Attack.
            t_start = now_epoch()
            print(f"  [>] attack bat dau {human(t_start)}")
            status = run_one_scenario(scenario, cycle_attack)
            t_end = now_epoch()
            print(f"  [>] attack ket thuc {human(t_end)} ({status})")

            # 3. Ghi timeline (epoch giay -- tuong thich extract_opcua_features.py).
            #    'episode' RIENG moi cycle, gan ca host_id+session_tag -> grouped
            #    CV / held-out theo dung quy uoc session_id|host_id|episode_id
            #    da dung cho Day 1-7 (train_ml.py DEFAULT_GROUP_COLUMNS). Cot
            #    'tier' rieng de sau nay loc/phan tich theo cuong do.
            episode_id = f"day8_{session_tag}_{host_id}_c{cycle:03d}_{scenario}_{tier}"
            writer.writerow([
                f"{t_start:.3f}", f"{t_end:.3f}", scenario, episode_id,
                human(t_start), human(t_end), cycle, status, host_id, session_tag, tier,
            ])
            f.flush()

            # 4. Cooldown (bat canh TCP reconnect/retransmission cua web_scada).
            #    Cung ghi BENIGN_NORMAL rieng, ly do nhu warmup o tren.
            print(f"  [>] cooldown {args.cooldown}s (phuc hoi)...")
            t_cooldown_start = now_epoch()
            if not _sleep_interruptible(args.cooldown):
                break
            t_cooldown_end = now_epoch()
            cooldown_episode_id = f"day8_{session_tag}_{host_id}_c{cycle:03d}_BENIGN_cooldown"
            writer.writerow([
                f"{t_cooldown_start:.3f}", f"{t_cooldown_end:.3f}", "BENIGN_NORMAL", cooldown_episode_id,
                human(t_cooldown_start), human(t_cooldown_end), cycle, "benign_cooldown", host_id, session_tag, "fixed",
            ])
            f.flush()

    elapsed = time.time() - start_wall
    print(f"\n[*] Xong: {cycle} cycle trong {elapsed:.0f}s. Timeline: {timeline_path}")
    print(f"[*] Buoc tiep: Stop Capture -> tai PCAP -> "
          f"python extract_opcua_features.py --pcap <file>.pcap --timeline {timeline_path} "
          f"--output opcua_features.csv --window 5 --plc-ip {args.plc_ip} \\\n"
          f"    --session-id day8_{session_tag}_{host_id}_{time.strftime('%Y%m%d')} --host-id {host_id}")
    print(f"[!] QUAN TRONG: LUON truyen --session-id/--host-id o buoc extract nhu tren -- "
          f"khac cot host_id/session_tag trong timeline CSV (chi de doi chieu), "
          f"day moi la gia tri THAT duoc ghi vao dataset cuoi cung de grouped-CV/held-out "
          f"phan biet duoc may A vs may B. Bo qua 2 co nay se ra 'unknown_session'/"
          f"'unknown_host' cho toan bo file (dung loi phu luc bao cao cu).")
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
    p.add_argument("--attack", type=int, default=None,
                    help="SAN toi thieu (giay) cho tran thoi gian moi kich ban -- KHONG con la "
                         "gia tri co dinh. Moi cycle tu tinh muc an toan THAT theo tier "
                         "(slow/medium/fast) vua duoc gan ngau nhien cho kich ban do, luon >= "
                         "gia tri nay, de SLOWLORIS/BEHAVIORAL_PROFILING/SUBSCRIPTION_FLOOD "
                         "khong bao gio bi asyncio.wait_for cat giua chung du roi vao tier nao.")
    p.add_argument("--cooldown", type=int, default=40, help="Thoi gian phuc hoi sau tan cong (giay)")
    p.add_argument("--timeline-file", default=None,
                    help="File CSV timeline. Mac dinh: "
                         "test_results/day8/timeline_opcua_day8_<session-tag>_<host-id>.csv")
    p.add_argument("--host-id", default="attacker_host",
                    help="ID may attacker dang chay script nay (vd attacker_A / attacker_B) -- "
                         "ghi vao timeline de grouped-CV/held-out theo host giong Day 1-7.")
    p.add_argument("--session-tag", default="train", choices=["train", "oodtest", "coordinated"],
                    help="'train' cho tap thu hoach chinh, 'oodtest' cho tap held-out doc lap "
                         "(chay session/ngay/may khac), 'coordinated' cho phien 2 may CHAY DONG THOI "
                         "voi --scenarios co dinh khac nhau moi may (vd A=SLOWLORIS, B=READ_SCRAPING) -- "
                         "moi loai tach file rieng, khong lan vao nhau.")
    p.add_argument("--scenarios", nargs="*", default=None, help="Ghi de pool kich ban (mac dinh dung DEFAULT_POOL)")
    args = p.parse_args()
    return collect(args)


if __name__ == "__main__":
    raise SystemExit(main())
