#!/usr/bin/env bash
set -euo pipefail

# ================================================================
# run_day_bangtruyen_ext2.sh
# Day 8: Integrity + Availability Advanced
#   Replay + EWS Rogue + EWS Firmware + DNS + KillChain
#
# Chạy:
#   bash run_day_bangtruyen_ext2.sh --day 8 --role attacker \
#       --session-id bt_ext_s2 --iface eth0
# ================================================================

[[ -f testbed.conf ]] && source ./testbed.conf

if [[ -z "${PY_CMD:-}" ]]; then
    command -v python3 &>/dev/null && PY_CMD="python3" || PY_CMD="python"
fi

export PYTHONPATH="${PYTHONPATH:-.}"

TARGET_IP="${TARGET_IP:-192.168.210.211}"
RACK="${RACK:-0}"
SLOT="${SLOT:-1}"
CAPTURE_IFACE="${CAPTURE_IFACE:-${IFACE:-}}"
CAPTURE_ENABLED="${CAPTURE_ENABLED:-1}"
SESSION_ID="${SESSION_ID:-}"
HOST_ID="${HOST_ID:-}"
PREFLIGHT_ENABLED="${PREFLIGHT_ENABLED:-1}"
DAY=8

HMI_IP="${HMI_IP:-}"
ATTACKER_IP="${ATTACKER_IP:-}"
ENABLE_DNS_SPOOF="${ENABLE_DNS_SPOOF:-1}"

CAPTURE_FILTER="${CAPTURE_FILTER:-}"
DAY8_DURATION_S="${DAY8_DURATION_S:-14400}"
WARMUP_S="${WARMUP_S:-300}"
BENIGN_GAP_S="${BENIGN_GAP_S:-300}"
COOLDOWN_S="${COOLDOWN_S:-600}"
COOLDOWN_L="${COOLDOWN_L:-1200}"
ATTACK_REPETITIONS="${ATTACK_REPETITIONS:-3}"
ATTACK_DURATION_S="${ATTACK_DURATION_S:-600}"
SHORT_ATTACK_DURATION_S="${SHORT_ATTACK_DURATION_S:-300}"

CAPTURE_DIR="${CAPTURE_DIR:-captures}"
LABEL_DIR="${LABEL_DIR:-labels}"
LOG_DIR="${LOG_DIR:-logs}"

usage() {
    cat <<'EOF'
Usage:
  bash run_day_bangtruyen_ext2.sh --day 8 --role attacker [options]

  --session-id ID      (auto nếu ko có)
  --target IP          (từ testbed.conf)
  --iface IFACE        (từ testbed.conf)
  --no-capture         Skip tshark
  --no-preflight       Skip Snap7 preflight
  --no-dns-spoof       Skip DNS spoof
  --preflight-only     Preflight and exit
  -h, --help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --day) DAY="$2"; shift 2 ;;
        --role) ROLE="$2"; shift 2 ;;
        --target) TARGET_IP="$2"; shift 2 ;;
        --rack) RACK="$2"; shift 2 ;;
        --slot) SLOT="$2"; shift 2 ;;
        --iface) CAPTURE_IFACE="$2"; shift 2 ;;
        --session-id) SESSION_ID="$2"; shift 2 ;;
        --host-id) HOST_ID="$2"; shift 2 ;;
        --no-capture) CAPTURE_ENABLED="0"; shift ;;
        --no-preflight) PREFLIGHT_ENABLED="0"; shift ;;
        --no-dns-spoof) ENABLE_DNS_SPOOF="0"; shift ;;
        --preflight-only) PREFLIGHT_ONLY="1"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[ERROR] $1" >&2; usage; exit 1 ;;
    esac
done

[[ -z "$SESSION_ID" ]] && SESSION_ID="day8_ext_s2"
[[ -z "$HOST_ID" ]] && HOST_ID="${ATTACKER_HOST_ID:-attacker_host}"
[[ -z "$CAPTURE_FILTER" ]] && CAPTURE_FILTER="host $TARGET_IP"
[[ -z "$ATTACKER_IP" ]] && ATTACKER_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || echo '192.168.1.100')"

if [[ -z "$HMI_IP" ]]; then
    SUBNET_PREFIX=$(echo "$TARGET_IP" | sed -E 's/\.[0-9]+$//')
    HMI_IP="${SUBNET_PREFIX}.31"
fi

mkdir -p "$CAPTURE_DIR/day${DAY}" "$LABEL_DIR" "$LOG_DIR"

declare -a PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT INT TERM

echo "================================================================"
echo "  DAY 8 — INTEGRITY + AVAILABILITY ADVANCED"
echo "  Target    : $TARGET_IP  (rack=$RACK slot=$SLOT)"
echo "  HMI       : $HMI_IP"
echo "  Session   : $SESSION_ID  | Host: $HOST_ID"
echo "  Interface : ${CAPTURE_IFACE:-auto}"
echo "================================================================"

# ── Helpers ────────────────────────────────────
now_ms() { "$PY_CMD" -c "import time; print(int(time.time() * 1000))"; }
label_file() { echo "$LABEL_DIR/day${DAY}_${SESSION_ID}_${HOST_ID}_timeline.csv"; }

label() {
    local s="$1" a="$2" ep="${3:-}" n="${4:-}" ts f
    ts="$(now_ms)"; f="$(label_file)"
    [[ ! -f "$f" ]] && echo "attacker_timestamp_ms,scenario_label,action,session_id,host_id,episode_id,day,note" > "$f"
    n="${n//,/;}"; ep="${ep//,/;}"
    printf '%s,%s,%s,%s,%s,%s,%s,%s\n' "$ts" "$s" "$a" "$SESSION_ID" "$HOST_ID" "$ep" "$DAY" "$n" >> "$f"
    echo "[$(date +%H:%M:%S)] label $s $a"
}

wait_s() { local sec="$1" m="${2:-wait}"; [[ "$sec" -le 0 ]] && return 0; echo "[wait] ${sec}s -- $m"; sleep "$sec"; }
rand_duration() { local b="${1:-$ATTACK_DURATION_S}"; "$PY_CMD" -c "import random,sys; b=max(1,int(float(sys.argv[1]))); lo=max(1,int(b*0.75)); hi=max(lo,int(b*1.25)); print(random.randint(lo, hi))" "$b"; }

# ── Capture ─────────────────────────────────────
start_capture() {
    local suf="$1" pcap="$CAPTURE_DIR/day${DAY}/${SESSION_ID}_${suf}.pcapng"
    [[ "$CAPTURE_ENABLED" != "1" ]] && { echo "[$suf] capture disabled"; return 0; }
    tshark -n -i "$CAPTURE_IFACE" -f "$CAPTURE_FILTER" -w "$pcap" -q \
        -o "tls.desegment_ssl_records:FALSE" -o "tls.desegment_ssl_application_data:FALSE" &
    PIDS+=("$!"); echo "[$suf] tshark -> $pcap"
}

# ── Preflight ────────────────────────────────────
preflight_plc() {
    "$PY_CMD" - <<PYEOF
import sys, snap7
try: from snap7.type import Areas
except ImportError: from snap7.types import Areas
c=snap7.client.Client()
try:
    c.connect("$TARGET_IP",int("$RACK"),int("$SLOT"))
    print(f"[preflight] state={c.get_cpu_state()}",flush=True)
    c.read_area(Areas.MK,0,0,1); print("[preflight] M OK",flush=True)
    c.disconnect(); sys.exit(0)
except Exception as e: print(f"[preflight] FAIL: {e}",flush=True); sys.exit(2)
PYEOF
}

# ── Restore ──────────────────────────────────────
restore_plc() {
    echo "[restore] Conveyor safe restore"
    "$PY_CMD" - <<PYEOF || true
import sys, time, snap7
try: from snap7.type import Areas
except ImportError: from snap7.types import Areas
from snap7.util import set_bool, set_dint
c=snap7.client.Client()
try:
    c.connect("$TARGET_IP",int("$RACK"),int("$SLOT"))
    m5=c.read_area(Areas.MK,0,5,1)
    for b in range(8): set_bool(m5,0,b,False)
    c.write_area(Areas.MK,0,5,m5)
    m6=c.read_area(Areas.MK,0,6,1)
    set_bool(m6,0,0,False);set_bool(m6,0,1,False);set_bool(m6,0,2,False)
    c.write_area(Areas.MK,0,6,m6)
    buf=bytearray(4); set_dint(buf,0,5000)
    c.write_area(Areas.MK,0,54,buf);c.write_area(Areas.MK,0,58,buf);c.write_area(Areas.MK,0,62,buf)
    set_dint(buf,0,0); c.write_area(Areas.MK,0,50,buf)
    m5=c.read_area(Areas.MK,0,5,1); set_bool(m5,0,0,True); set_bool(m5,0,1,False)
    c.write_area(Areas.MK,0,5,m5); time.sleep(0.3)
    m5=c.read_area(Areas.MK,0,5,1); set_bool(m5,0,0,False)
    c.write_area(Areas.MK,0,5,m5)
    c.disconnect(); print("[restore] OK",flush=True)
except Exception as e: print(f"[restore] {e}",flush=True)
PYEOF
    sleep 1
}

# ── Attack runners ───────────────────────────────
_run_attack() {
    local scenario="$1" module="$2" extra_args="${3:-}" dur ep
    dur="$(rand_duration "$SHORT_ATTACK_DURATION_S")"
    ep="${SESSION_ID}:day${DAY}:${scenario}"
    label "$scenario" "START" "$ep" "dur=${dur}s"
    "$PY_CMD" -u -m attacks_ext.${module} \
        --duration "$dur" --session-id "$SESSION_ID" --host-id "$HOST_ID" \
        --label-file "$(label_file)" --episode-id "$ep" --day "$DAY" \
        $extra_args 2>&1 || echo "[WARN] $scenario returned non-zero"
    label "$scenario" "END" "$ep" "dur=${dur}s"
}

run_ews_rogue_engineer() {
    _run_attack "EWS_ROGUE_ENGINEER" "ews_rogue_engineer" \
        "--target ${TARGET_IP} --rack ${RACK} --slot ${SLOT}"
    restore_plc
}
run_ews_firmware_tamper() {
    _run_attack "EWS_FIRMWARE_TAMPER" "ews_firmware_tamper" \
        "--target ${TARGET_IP} --rack ${RACK} --slot ${SLOT}"
    restore_plc
}
run_dns_spoof_ics() {
    [[ "$ENABLE_DNS_SPOOF" != "1" ]] && { echo "[skip] DNS_SPOOF_ICS"; return 0; }
    [[ "$EUID" -ne 0 ]] && { echo "[WARN] DNS_SPOOF need root"; label "DNS_SPOOF_ICS" "SKIP" "" "need_root"; return 0; }
    _run_attack "DNS_SPOOF_ICS" "dns_spoof_ics" \
        "--iface ${CAPTURE_IFACE:-eth0} --hmi-ip ${HMI_IP} --attacker-ip ${ATTACKER_IP}"
}
run_kill_chain() {
    local ep="${SESSION_ID}:day${DAY}:KILL_CHAIN"
    label "KILL_CHAIN" "START" "$ep" "5stage_apt"
    "$PY_CMD" -u -m attacks_ext.kill_chain \
        --duration 1800 --session-id "$SESSION_ID" --host-id "$HOST_ID" \
        --label-file "$(label_file)" --episode-id "$ep" --day "$DAY" \
        --target "$TARGET_IP" --rack "$RACK" --slot "$SLOT" \
        --opc-url "opc.tcp://127.0.0.1:4840" \
        2>&1 || echo "[WARN] KILL_CHAIN returned non-zero"
    label "KILL_CHAIN" "END" "$ep" "5stage_apt"
    restore_plc
}

# ── Controller ───────────────────────────────────
run_controller() {
    start_capture "controller"
    echo "[ctrl] Starting tag logger + HMI polling..."
    "$PY_CMD" log_tags_bangtruyen.py \
        --target "$TARGET_IP" --rack "$RACK" --slot "$SLOT" \
        --interval "${TAG_LOG_INTERVAL:-0.5}" \
        --output "$LOG_DIR/day${DAY}_${SESSION_ID}_${HOST_ID}_tags.csv" \
        --session-id "$SESSION_ID" --host-id "$HOST_ID" \
        --scenario-id "BENIGN_READER" \
        --episode-id "${SESSION_ID}:controller:tag_logger" --day "$DAY" &
    PIDS+=("$!")
    label "BENIGN_NORMAL" "START" "day8_controller_runtime" ""
    wait_s "$DAY8_DURATION_S" "controller_runtime"
    label "BENIGN_NORMAL" "END" "day8_controller_runtime" ""
}

# ── Main ─────────────────────────────────────────
[[ "$PREFLIGHT_ENABLED" == "1" ]] && { preflight_plc || { echo "[ERROR] Preflight failed" >&2; exit 2; }; }
[[ "${PREFLIGHT_ONLY:-0}" == "1" ]] && { echo "[preflight] done"; exit 0; }

case "${ROLE:-attacker}" in
    controller) run_controller; echo "DAY 8 CONTROLLER DONE"; exit 0 ;;
esac

start_capture "day8_ext_attacks"

echo ""
echo "  Day 8: EWS(×3) -> Replay(×3) -> LogicAware(×3) -> DNS(×2) -> KillChain(×2) -> Cooldown"
echo ""

# Phase 1: Warmup
label "BENIGN_NORMAL" "START" "day8_warmup" ""
wait_s "$WARMUP_S" "warmup"
label "BENIGN_NORMAL" "END" "day8_warmup" ""

# Phase 2: Integrity — EWS + Replay + Logic-Aware
echo "[Phase 2] Integrity — Rogue EWS + Firmware + Replay + Logic-Aware"
for i in $(seq 1 "$ATTACK_REPETITIONS"); do
    run_ews_rogue_engineer
    wait_s "$BENIGN_GAP_S" "gap_rogue_r${i}"

    run_ews_firmware_tamper
    wait_s "$BENIGN_GAP_S" "gap_fw_r${i}"

    _run_attack "S7_REPLAY" "s7_replay" \
        "--target ${TARGET_IP} --rack ${RACK} --slot ${SLOT}"
    wait_s "$BENIGN_GAP_S" "gap_replay_r${i}"

    _run_attack "LOGIC_AWARE" "logic_aware" \
        "--target ${TARGET_IP} --rack ${RACK} --slot ${SLOT}"
    wait_s "$COOLDOWN_S" "cooldown_round${i}"
done

# Phase 3: DNS Spoof
echo "[Phase 3] Network — DNS Spoof"
for i in 1 2; do
    run_dns_spoof_ics
    wait_s "$COOLDOWN_L" "cooldown_dns_${i}"
done

# Phase 4: Kill Chain
echo "[Phase 4] APT Simulation — Kill Chain ×2"
label "BENIGN_NORMAL" "START" "pre_killchain_gap" ""
wait_s 600 "buffer"
label "BENIGN_NORMAL" "END" "pre_killchain_gap" ""

run_kill_chain
wait_s "$COOLDOWN_L" "cooldown_kc1"
run_kill_chain

# Phase 5: Final
label "BENIGN_NORMAL" "START" "day8_cooldown_final" ""
wait_s "$COOLDOWN_S" "final"
label "BENIGN_NORMAL" "END" "day8_cooldown_final" ""

echo "================================================================"
echo "  DAY 8 COMPLETE"
echo "  Labels: $(label_file)"
echo "================================================================"
