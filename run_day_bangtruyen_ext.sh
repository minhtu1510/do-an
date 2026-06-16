#!/usr/bin/env bash
set -euo pipefail

# ================================================================
# run_day_bangtruyen_ext.sh
# Day 7: Extended Attack Scenarios (HMI / EWS / Network / KillChain)
#
# Cách chạy — đơn giản giống day 1-6:
#   bash run_day_bangtruyen_ext.sh --day 7 --role attacker \
#       --session-id bt_s1 --iface eth0
#
#   sudo bash run_day_bangtruyen_ext.sh --day 7 --role attacker \
#       --session-id bt_s1 --iface eth0
#
# Mọi config mặc định từ testbed.conf.
# Các trường mới (HMI, OPC) có thể thêm vào testbed.conf hoặc CLI.
# ================================================================

[[ -f testbed.conf ]] && source ./testbed.conf

if [[ -z "${PY_CMD:-}" ]]; then
    command -v python3 &>/dev/null && PY_CMD="python3" || PY_CMD="python"
fi

export PYTHONPATH="${PYTHONPATH:-.}"

# ── Config (từ testbed.conf hoặc default) ────────────────────────
TARGET_IP="${TARGET_IP:-192.168.1.10}"
RACK="${RACK:-0}"
SLOT="${SLOT:-1}"
CAPTURE_IFACE="${CAPTURE_IFACE:-${IFACE:-}}"
CAPTURE_ENABLED="${CAPTURE_ENABLED:-1}"
SESSION_ID="${SESSION_ID:-}"
HOST_ID="${HOST_ID:-}"
PREFLIGHT_ENABLED="${PREFLIGHT_ENABLED:-1}"
DAY=7

# ── Trường mới cho HMI / OPC / DNS (thêm vào testbed.conf nếu muốn)
HMI_IP="${HMI_IP:-}"
HMI_PORT="${HMI_PORT:-5000}"
OPC_SERVER_IP="${OPC_SERVER_IP:-${HMI_IP}}"
OPC_URL="${OPC_URL:-}"
OPC_USERNAME="${OPC_USERNAME:-admin}"
OPC_PASSWORD="${OPC_PASSWORD:-admin123}"
ATTACKER_IP="${ATTACKER_IP:-}"
ENABLE_DNS_SPOOF="${ENABLE_DNS_SPOOF:-1}"
ENABLE_OPC_ATTACKS="${ENABLE_OPC_ATTACKS:-1}"

# ── Timing (dùng chung với run_day_bangtruyen.sh) ────────────────
CAPTURE_FILTER="${CAPTURE_FILTER:-}"
WARMUP_S="${WARMUP_S:-300}"
BENIGN_GAP_S="${BENIGN_GAP_S:-300}"
COOLDOWN_S="${COOLDOWN_S:-600}"
COOLDOWN_L="${COOLDOWN_L:-1200}"
ATTACK_REPETITIONS="${ATTACK_REPETITIONS:-3}"
ATTACK_DURATION_S="${ATTACK_DURATION_S:-600}"
SHORT_ATTACK_DURATION_S="${SHORT_ATTACK_DURATION_S:-300}"

CAPTURE_DIR="${CAPTURE_DIR:-captures}"
LABEL_DIR="${LABEL_DIR:-labels}"

usage() {
    cat <<'EOF'
Usage:
  bash run_day_bangtruyen_ext.sh --day 7 --role attacker [options]

Options:
  --session-id ID      Session ID.           (auto nếu không có)
  --host-id ID         Host ID.              (auto nếu không có)
  --target IP          PLC IP.               (từ testbed.conf)
  --rack N             PLC rack.             (từ testbed.conf)
  --slot N             PLC slot.             (từ testbed.conf)
  --iface IFACE        TShark interface.     (từ testbed.conf)
  --hmi-ip IP          HMI IP.               (auto: subnet ~target)
  --opc-url URL        OPC-UA URL.           (auto: opc.tcp://<hmi>:4840)
  --attacker-ip IP     Attacker IP.          (auto: hostname -I)
  --no-capture         Run without tshark.
  --no-preflight       Skip Snap7 preflight.
  --no-dns-spoof       Skip DNS spoof.
  --no-opc             Skip OPC-UA attacks.
  --preflight-only     Preflight check and exit.
  -h, --help           Show help.

Examples:
  bash run_day_bangtruyen_ext.sh --day 7 --role attacker --session-id bt_s1 --iface eth0

  # Đặt HMI IP riêng
  bash run_day_bangtruyen_ext.sh --day 7 --role attacker --session-id bt_s1 --iface eth0 --hmi-ip 192.168.1.50

  # Skip DNS spoof (ko cần root) + skip OPC (chưa cài opcua)
  bash run_day_bangtruyen_ext.sh --day 7 --role attacker --session-id bt_s1 --iface eth0 --no-dns-spoof --no-opc
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
        --hmi-ip) HMI_IP="$2"; OPC_SERVER_IP="$2"; shift 2 ;;
        --opc-url) OPC_URL="$2"; shift 2 ;;
        --attacker-ip) ATTACKER_IP="$2"; shift 2 ;;
        --no-capture) CAPTURE_ENABLED="0"; shift ;;
        --no-preflight) PREFLIGHT_ENABLED="0"; shift ;;
        --no-dns-spoof) ENABLE_DNS_SPOOF="0"; shift ;;
        --no-opc) ENABLE_OPC_ATTACKS="0"; shift ;;
        --preflight-only) PREFLIGHT_ONLY="1"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[ERROR] Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

# ── Auto-generate missing values (giống run_day_bangtruyen.sh) ───
[[ -z "$SESSION_ID" ]] && SESSION_ID="day7_ext_s1"
[[ -z "$HOST_ID" ]] && HOST_ID="${ATTACKER_HOST_ID:-attacker_host}"
[[ -z "$CAPTURE_FILTER" ]] && CAPTURE_FILTER="host $TARGET_IP"
[[ -z "$ATTACKER_IP" ]] && ATTACKER_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || echo '192.168.1.100')"

# Tự suy HMI_IP từ subnet của TARGET_IP
if [[ -z "$HMI_IP" ]]; then
    SUBNET_PREFIX=$(echo "$TARGET_IP" | sed -E 's/\.[0-9]+$//')
    HMI_IP="${SUBNET_PREFIX}.20"
    OPC_SERVER_IP="$HMI_IP"
fi
[[ -z "$OPC_URL" ]] && OPC_URL="opc.tcp://${OPC_SERVER_IP}:4840"

mkdir -p "$CAPTURE_DIR/day${DAY}" "$LABEL_DIR"

declare -a PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do
        kill "$p" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

echo "================================================================"
echo "  DAY 7 — EXTENDED SCENARIOS"
echo "  Target     : $TARGET_IP  (rack=$RACK slot=$SLOT)"
echo "  HMI        : $HMI_IP  (OPC: $OPC_URL)"
echo "  Attacker   : $ATTACKER_IP"
echo "  Session    : $SESSION_ID  | Host: $HOST_ID"
echo "  Interface  : ${CAPTURE_IFACE:-auto}"
echo "  DNS Spoof  : $ENABLE_DNS_SPOOF  | OPC: $ENABLE_OPC_ATTACKS"
echo "================================================================"

# ── Helpers (cùng schema CSV với run_day_bangtruyen.sh) ──────────
now_ms() {
    "$PY_CMD" -c "import time; print(int(time.time() * 1000))"
}

label_file() {
    echo "$LABEL_DIR/day${DAY}_${SESSION_ID}_${HOST_ID}_timeline.csv"
}

label() {
    local scenario="$1" action="$2" episode_id="${3:-}" note="${4:-}"
    local ts f
    ts="$(now_ms)"
    f="$(label_file)"
    [[ ! -f "$f" ]] && echo "attacker_timestamp_ms,scenario_label,action,session_id,host_id,episode_id,day,note" > "$f"
    note="${note//,/;}"
    episode_id="${episode_id//,/;}"
    printf '%s,%s,%s,%s,%s,%s,%s,%s\n' "$ts" "$scenario" "$action" "$SESSION_ID" "$HOST_ID" "$episode_id" "$DAY" "$note" >> "$f"
    echo "[$(date +%H:%M:%S)] label $scenario $action"
}

wait_s() {
    local seconds="$1" message="${2:-wait}"
    [[ "$seconds" -le 0 ]] && return 0
    echo "[wait] ${seconds}s -- $message"
    sleep "$seconds"
}

rand_duration() {
    local base="${1:-$ATTACK_DURATION_S}"
    "$PY_CMD" -c "import random,sys; b=max(1,int(float(sys.argv[1]))); lo=max(1,int(b*0.75)); hi=max(lo,int(b*1.25)); print(random.randint(lo, hi))" "$base"
}

# ── Capture (dùng tshark giống run_day_bangtruyen.sh) ────────────
start_capture() {
    local suffix="$1"
    local pcap="$CAPTURE_DIR/day${DAY}/${SESSION_ID}_${suffix}.pcapng"
    if [[ "$CAPTURE_ENABLED" != "1" ]]; then
        echo "[$suffix] capture disabled"
        return 0
    fi
    tshark -n -i "$CAPTURE_IFACE" -f "$CAPTURE_FILTER" -w "$pcap" -q \
        -o "tls.desegment_ssl_records:FALSE" \
        -o "tls.desegment_ssl_application_data:FALSE" &
    PIDS+=("$!")
    echo "[$suffix] tshark -> $pcap"
}

# ── Preflight ────────────────────────────────────────────────────
preflight_plc() {
    "$PY_CMD" - <<PYEOF
import sys, snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
target = "$TARGET_IP"
rack = int("$RACK")
slot = int("$SLOT")
c = snap7.client.Client()
try:
    print(f"[preflight] connect {target} rack={rack} slot={slot}", flush=True)
    c.connect(target, rack, slot)
    state = "UNKNOWN"
    try: state = str(c.get_cpu_state())
    except Exception as exc: print(f"[preflight][WARN] CPU state: {exc}", flush=True)
    print(f"[preflight] CPU state: {state}", flush=True)
    m = c.read_area(Areas.MK, 0, 0, 1)
    print(f"[preflight] read M area OK ({len(m)} bytes)", flush=True)
    c.disconnect()
    sys.exit(0)
except Exception as exc:
    print(f"[preflight][ERROR] Snap7 check failed: {exc}", flush=True)
    try: c.disconnect()
    except: pass
    sys.exit(2)
PYEOF
}

# ── PLC Restore (conveyor safe) ─────────────────────────────────
restore_plc() {
    echo "[restore] Conveyor safe restore"
    "$PY_CMD" - <<PYEOF || true
import sys, time
import snap7
try: from snap7.type import Areas
except ImportError: from snap7.types import Areas
from snap7.util import set_bool, set_dint

target = "$TARGET_IP"
rack = int("$RACK")
slot = int("$SLOT")

c = snap7.client.Client()
try:
    c.connect(target, rack, slot)
    try:
        state = str(c.get_cpu_state())
        if "Stop" in state or state == "4":
            print("[restore][WARN] CPU STOP. Start manually.", flush=True)
    except: pass

    m5 = c.read_area(Areas.MK, 0, 5, 1)
    for bit in range(8): set_bool(m5, 0, bit, False)
    c.write_area(Areas.MK, 0, 5, m5)

    m6 = c.read_area(Areas.MK, 0, 6, 1)
    set_bool(m6, 0, 0, False); set_bool(m6, 0, 1, False); set_bool(m6, 0, 2, False)
    c.write_area(Areas.MK, 0, 6, m6)

    buf = bytearray(4)
    set_dint(buf, 0, 5000)
    c.write_area(Areas.MK, 0, 54, buf); c.write_area(Areas.MK, 0, 58, buf); c.write_area(Areas.MK, 0, 62, buf)
    set_dint(buf, 0, 0)
    c.write_area(Areas.MK, 0, 50, buf)

    m5 = c.read_area(Areas.MK, 0, 5, 1)
    set_bool(m5, 0, 0, True); set_bool(m5, 0, 1, False)
    c.write_area(Areas.MK, 0, 5, m5)
    time.sleep(0.3)
    m5 = c.read_area(Areas.MK, 0, 5, 1)
    set_bool(m5, 0, 0, False)
    c.write_area(Areas.MK, 0, 5, m5)
    print("[restore] START pulse sent", flush=True)

    c.disconnect()
    print("[restore] OK", flush=True)
except Exception as exc:
    print(f"[restore][WARN] failed: {exc}", flush=True)
    try: c.disconnect()
    except: pass
PYEOF
    sleep 1
}

# ── Attack runners ───────────────────────────────────────────────
_run_attack() {
    local scenario="$1" module="$2" extra_args="${3:-}"
    local dur ep note
    dur="$(rand_duration "$SHORT_ATTACK_DURATION_S")"
    ep="${SESSION_ID}:day${DAY}:${scenario}"

    label "$scenario" "START" "$ep" "dur=${dur}s"

    "$PY_CMD" -u -m attacks_ext.${module} \
        --duration "$dur" \
        --session-id "$SESSION_ID" \
        --host-id "$HOST_ID" \
        --label-file "$(label_file)" \
        --episode-id "$ep" \
        --day 7 \
        $extra_args \
    2>&1 || echo "[WARN] $scenario returned non-zero (continuing)"

    label "$scenario" "END" "$ep" "dur=${dur}s"
}

run_hmi_credential_brute() {
    _run_attack "HMI_CREDENTIAL_BRUTE" "hmi_credential_brute" \
        "--target-url 'http://${HMI_IP}:${HMI_PORT}'"
}

run_hmi_alarm_suppress() {
    [[ "$ENABLE_OPC_ATTACKS" == "1" ]] || { echo "[skip] HMI_ALARM_SUPPRESS (--no-opc)"; return 0; }
    _run_attack "HMI_ALARM_SUPPRESS" "hmi_alarm_suppress" \
        "--opc-url '$OPC_URL' --opc-username '$OPC_USERNAME' --opc-password '$OPC_PASSWORD'"
}

run_hmi_fake_display() {
    [[ "$ENABLE_OPC_ATTACKS" == "1" ]] || { echo "[skip] HMI_FAKE_DISPLAY (--no-opc)"; return 0; }
    _run_attack "HMI_FAKE_DISPLAY" "hmi_fake_display" \
        "--opc-url '$OPC_URL' --opc-username '$OPC_USERNAME' --opc-password '$OPC_PASSWORD'"
    restore_plc
}

run_ews_rogue_engineer() {
    _run_attack "EWS_ROGUE_ENGINEER" "ews_rogue_engineer" \
        "--target '$TARGET_IP' --rack '$RACK' --slot '$SLOT'"
    restore_plc
}

run_ews_firmware_tamper() {
    _run_attack "EWS_FIRMWARE_TAMPER" "ews_firmware_tamper" \
        "--target '$TARGET_IP' --rack '$RACK' --slot '$SLOT'"
    restore_plc
}

run_dns_spoof_ics() {
    if [[ "$ENABLE_DNS_SPOOF" != "1" ]]; then
        echo "[skip] DNS_SPOOF_ICS (--no-dns-spoof)"; return 0
    fi
    if [[ "$EUID" -ne 0 ]]; then
        echo "[WARN] DNS_SPOOF cần root. Bỏ qua."
        label "DNS_SPOOF_ICS" "SKIP" "" "need_root"
        return 0
    fi
    _run_attack "DNS_SPOOF_ICS" "dns_spoof_ics" \
        "--iface '${CAPTURE_IFACE:-eth0}' --hmi-ip '${HMI_IP}' --attacker-ip '${ATTACKER_IP}'"
}

run_kill_chain() {
    local ep="${SESSION_ID}:day${DAY}:KILL_CHAIN"
    label "KILL_CHAIN" "START" "$ep" "5stage_apt"

    local extra_args="--target '$TARGET_IP' --rack '$RACK' --slot '$SLOT' --opc-url '$OPC_URL'"
    [[ "$ENABLE_OPC_ATTACKS" == "1" ]] && extra_args="$extra_args --opc-username '$OPC_USERNAME' --opc-password '$OPC_PASSWORD'"

    "$PY_CMD" -u -m attacks_ext.kill_chain \
        --duration 1800 \
        --session-id "$SESSION_ID" \
        --host-id "$HOST_ID" \
        --label-file "$(label_file)" \
        --episode-id "$ep" \
        --day 7 \
        --target "$TARGET_IP" --rack "$RACK" --slot "$SLOT" \
        --opc-url "$OPC_URL" \
        --opc-username "$OPC_USERNAME" --opc-password "$OPC_PASSWORD" \
    2>&1 || echo "[WARN] KILL_CHAIN returned non-zero"

    label "KILL_CHAIN" "END" "$ep" "5stage_apt"
    restore_plc
}

# ── Main ─────────────────────────────────────────────────────────
if [[ "$PREFLIGHT_ENABLED" == "1" ]]; then
    if ! preflight_plc; then
        echo "[ERROR] Preflight failed. Check PLC, Snap7, PUT/GET." >&2
        exit 2
    fi
fi

if [[ "${PREFLIGHT_ONLY:-0}" == "1" ]]; then
    echo "[preflight] done"; exit 0
fi

start_capture "day7_ext_attacks"

echo ""
echo "  SCHEDULE: Warmup -> HMI(×3) -> EWS(×3) -> DNS(×2) -> KillChain(×2) -> Cooldown"
echo ""

# Phase 1: Warmup
label "BENIGN_NORMAL" "START" "day7_warmup" ""
wait_s "$WARMUP_S" "warmup_benign"
label "BENIGN_NORMAL" "END" "day7_warmup" ""

# Phase 2: HMI Attacks
echo "[Phase 2] HMI Attacks"
for i in $(seq 1 "$ATTACK_REPETITIONS"); do
    run_hmi_credential_brute
    wait_s "$BENIGN_GAP_S" "gap_hmi_brute_r${i}"

    run_hmi_alarm_suppress
    wait_s "$BENIGN_GAP_S" "gap_alarm_sup_r${i}"

    run_hmi_fake_display
    wait_s "$COOLDOWN_S" "cooldown_hmi_round${i}"
done

# Phase 3: EWS Attacks
echo "[Phase 3] EWS Attacks"
for i in $(seq 1 "$ATTACK_REPETITIONS"); do
    run_ews_rogue_engineer
    wait_s "$BENIGN_GAP_S" "gap_rogue_ews_r${i}"

    run_ews_firmware_tamper
    wait_s "$COOLDOWN_S" "cooldown_ews_round${i}"
done

# Phase 4: Network Attacks
echo "[Phase 4] Network Attacks"
for i in 1 2; do
    run_dns_spoof_ics
    wait_s "$COOLDOWN_L" "cooldown_dns_${i}"
done

# Phase 5: Full Kill Chain
echo "[Phase 5] Full Kill Chain"
label "BENIGN_NORMAL" "START" "pre_killchain_gap" ""
wait_s 600 "pre_killchain_buffer"
label "BENIGN_NORMAL" "END" "pre_killchain_gap" ""

run_kill_chain
wait_s "$COOLDOWN_L" "cooldown_after_killchain_1"
run_kill_chain

# Phase 6: Final
label "BENIGN_NORMAL" "START" "day7_cooldown_final" ""
wait_s "$COOLDOWN_S" "final_cooldown"
label "BENIGN_NORMAL" "END" "day7_cooldown_final" ""

echo "================================================================"
echo "  DAY 7 COMPLETE"
echo "  Labels: $(label_file)"
echo "================================================================"
