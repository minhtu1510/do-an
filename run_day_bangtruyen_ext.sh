#!/usr/bin/env bash
set -euo pipefail

# ================================================================
# run_day_bangtruyen_ext.sh
# Day 7: Advanced Attack Scenarios
#   SMB Enum + Eng Station Scan + Stealthy Write + Logic-Aware + Kill Chain
#   + Concealed Stop Attack (actuator+sensor concealment, Urbina CCS16-style)
#
# Chạy:
#   bash run_day_bangtruyen_ext.sh --day 7 --role attacker \
#       --session-id bt_ext_s1 --iface "\Device\NPF_{GUID}"
# ================================================================

[[ -f testbed.conf ]] && source ./testbed.conf

if [[ -z "${PY_CMD:-}" ]]; then
    command -v python3 &>/dev/null && PY_CMD="python3" || PY_CMD="python"
fi

export PYTHONPATH="${PYTHONPATH:-.}"
DAY=7

TARGET_IP="${TARGET_IP:-192.168.210.211}"
RACK="${RACK:-0}"
SLOT="${SLOT:-1}"
CAPTURE_IFACE="${CAPTURE_IFACE:-${IFACE:-}}"
CAPTURE_ENABLED="${CAPTURE_ENABLED:-1}"
SESSION_ID="${SESSION_ID:-}"
HOST_ID="${HOST_ID:-}"
PREFLIGHT_ENABLED="${PREFLIGHT_ENABLED:-1}"

HMI_IP="${HMI_IP:-}"

CAPTURE_FILTER="${CAPTURE_FILTER:-}"
DAY7_DURATION_S="${DAY7_DURATION_S:-14400}"
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
  bash run_day_bangtruyen_ext.sh --day 7 --role attacker [options]

  --session-id ID      Session ID.
  --target IP          PLC IP.         (từ testbed.conf)
  --rack N             PLC rack.       (từ testbed.conf)
  --slot N             PLC slot.       (từ testbed.conf)
  --iface IFACE        TShark interface.
  --hmi-ip IP          HMI IP.         (auto từ subnet target)
  --no-capture         Skip tshark.
  --no-preflight       Skip Snap7 preflight.
  --preflight-only     Preflight and exit.
  -h, --help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --day)           DAY="$2";          shift 2 ;;
        --role)          ROLE="$2";         shift 2 ;;
        --target)        TARGET_IP="$2";    shift 2 ;;
        --rack)          RACK="$2";         shift 2 ;;
        --slot)          SLOT="$2";         shift 2 ;;
        --iface)         CAPTURE_IFACE="$2";shift 2 ;;
        --session-id)    SESSION_ID="$2";   shift 2 ;;
        --host-id)       HOST_ID="$2";      shift 2 ;;
        --hmi-ip)        HMI_IP="$2";       shift 2 ;;
        --no-capture)    CAPTURE_ENABLED="0"; shift ;;
        --no-preflight)  PREFLIGHT_ENABLED="0"; shift ;;
        --preflight-only) PREFLIGHT_ONLY="1"; shift ;;
        -h|--help)       usage; exit 0 ;;
        *) echo "[ERROR] Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

[[ -z "$SESSION_ID" ]] && SESSION_ID="day7_ext_s1"
[[ -z "$HOST_ID" ]]    && HOST_ID="${ATTACKER_HOST_ID:-attacker_host}"

if [[ -z "$HMI_IP" ]]; then
    SUBNET_PREFIX=$(echo "$TARGET_IP" | sed -E 's/\.[0-9]+$//')
    HMI_IP="${SUBNET_PREFIX}.31"
fi

# Capture filter phai bao ca PLC (.211) LAN HMI (.31): SMB_RECON_ENUM,
# ENG_STATION_PORT_SCAN va nua lateral-movement cua KILL_CHAIN danh vao HMI,
# neu chi loc "host <PLC>" thi traffic tan cong toi HMI bi tshark drop sach
# -> pcap co label attack nhung 0 goi tuong ung. Set SAU khi HMI_IP da resolve.
# THEM 'ether proto 0x8892': PROFINET_DCP_ABUSE la layer-2 (khong co IP layer)
# -> loc theo "host ..." se drop sach frame DCP. Bat ca Profinet EtherType.
[[ -z "$CAPTURE_FILTER" ]] && CAPTURE_FILTER="host $TARGET_IP or host $HMI_IP or ether proto 0x8892"

mkdir -p "$CAPTURE_DIR/day${DAY}" "$LABEL_DIR" "$LOG_DIR"

declare -a PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT INT TERM

echo "================================================================"
echo "  DAY 7 — ADVANCED ATTACK SCENARIOS"
echo "  Target  : $TARGET_IP  (rack=$RACK slot=$SLOT)"
echo "  HMI     : $HMI_IP"
echo "  Session : $SESSION_ID  | Host: $HOST_ID"
echo "  Iface   : ${CAPTURE_IFACE:-auto}"
echo "================================================================"

# ── Helpers ─────────────────────────────────────────────────────
now_ms()     { "$PY_CMD" -c "import time; print(int(time.time()*1000))"; }
label_file() { echo "$LABEL_DIR/day${DAY}_${SESSION_ID}_${HOST_ID}_timeline.csv"; }

label() {
    local s="$1" a="$2" ep="${3:-}" n="${4:-}" ts f
    ts="$(now_ms)"; f="$(label_file)"
    [[ ! -f "$f" ]] && echo "attacker_timestamp_ms,scenario_label,action,session_id,host_id,episode_id,day,note" > "$f"
    n="${n//,/;}"; ep="${ep//,/;}"
    printf '%s,%s,%s,%s,%s,%s,%s,%s\n' "$ts" "$s" "$a" "$SESSION_ID" "$HOST_ID" "$ep" "$DAY" "$n" >> "$f"
    echo "[$(date +%H:%M:%S)] label $s $a"
}

wait_s() {
    local sec="$1" m="${2:-wait}"
    [[ "$sec" -le 0 ]] && return 0
    echo "[wait] ${sec}s -- $m"; sleep "$sec"
}

rand_duration() {
    local b="${1:-$ATTACK_DURATION_S}"
    "$PY_CMD" -c "import random,sys; b=max(1,int(float(sys.argv[1]))); lo=max(1,int(b*0.75)); hi=max(lo,int(b*1.25)); print(random.randint(lo,hi))" "$b"
}

# ── Capture ──────────────────────────────────────────────────────
start_capture() {
    local suf="$1" pcap="$CAPTURE_DIR/day${DAY}/${SESSION_ID}_${suf}.pcapng"
    [[ "$CAPTURE_ENABLED" != "1" ]] && { echo "[$suf] capture disabled"; return 0; }
    tshark -n -i "$CAPTURE_IFACE" -f "$CAPTURE_FILTER" -w "$pcap" -q \
        -o "tls.desegment_ssl_records:FALSE" \
        -o "tls.desegment_ssl_application_data:FALSE" &
    PIDS+=("$!"); echo "[$suf] tshark -> $pcap"
}

# ── Preflight ────────────────────────────────────────────────────
preflight_plc() {
    "$PY_CMD" - <<PYEOF
import sys, snap7
try: from snap7.type import Areas
except ImportError: from snap7.types import Areas
c = snap7.client.Client()
try:
    c.connect("$TARGET_IP", int("$RACK"), int("$SLOT"))
    print(f"[preflight] state={c.get_cpu_state()}", flush=True)
    c.read_area(Areas.MK, 0, 0, 1)
    print("[preflight] M area OK", flush=True)
    c.disconnect(); sys.exit(0)
except Exception as e:
    print(f"[preflight] FAIL: {e}", flush=True); sys.exit(2)
PYEOF
}

# ── Restore PLC ──────────────────────────────────────────────────
restore_plc() {
    echo "[restore] Conveyor safe restore"
    "$PY_CMD" - <<PYEOF || true
import sys, time, snap7
try: from snap7.type import Areas
except ImportError: from snap7.types import Areas
from snap7.util import set_bool, set_dint
c = snap7.client.Client()
try:
    c.connect("$TARGET_IP", int("$RACK"), int("$SLOT"))
    m5 = c.read_area(Areas.MK, 0, 5, 1)
    for b in range(8): set_bool(m5, 0, b, False)
    c.write_area(Areas.MK, 0, 5, m5)
    m6 = c.read_area(Areas.MK, 0, 6, 1)
    set_bool(m6,0,0,False); set_bool(m6,0,1,False); set_bool(m6,0,2,False)
    c.write_area(Areas.MK, 0, 6, m6)
    buf = bytearray(4)
    set_dint(buf,0,5000)
    c.write_area(Areas.MK,0,54,buf); c.write_area(Areas.MK,0,58,buf); c.write_area(Areas.MK,0,62,buf)
    set_dint(buf,0,0); c.write_area(Areas.MK,0,50,buf)
    m5 = c.read_area(Areas.MK,0,5,1)
    set_bool(m5,0,0,True); set_bool(m5,0,1,False)
    c.write_area(Areas.MK,0,5,m5); time.sleep(0.3)
    m5 = c.read_area(Areas.MK,0,5,1); set_bool(m5,0,0,False)
    c.write_area(Areas.MK,0,5,m5)
    c.disconnect(); print("[restore] OK", flush=True)
except Exception as e: print(f"[restore] {e}", flush=True)
PYEOF
    sleep 1
}

# ── Attack runners ───────────────────────────────────────────────
# LUU Y (sua loi trung nhan): MOI attack module tu ghi START/END cua no vao
# cung --label-file qua write_label() (config_ext.py). Truoc day shell CUNG ghi
# label START/END o day -> moi tan cong bi 2xSTART + 2xEND trung episode, tao
# interval chong lap khi dung timeline. Nay shell KHONG ghi nhan attack nua;
# module la nguon nhan duy nhat (timing sat hon + note giau hon: cong mo, ket
# qua probe...). Shell chi con ghi cac pha BENIGN (warmup/gap/cooldown).
_run_attack() {
    local scenario="$1" module="$2" extra_args="${3:-}" dur ep
    dur="$(rand_duration "$SHORT_ATTACK_DURATION_S")"
    ep="${SESSION_ID}:day${DAY}:${scenario}"
    echo "[$(date +%H:%M:%S)] >>> $scenario (dur=${dur}s, ep=$ep)"
    "$PY_CMD" -u -m attacks_ext.${module} \
        --duration "$dur" \
        --session-id "$SESSION_ID" --host-id "$HOST_ID" \
        --label-file "$(label_file)" \
        --episode-id "$ep" --day "$DAY" \
        $extra_args 2>&1 || echo "[WARN] $scenario returned non-zero"
}

run_kill_chain() {
    local ep="${SESSION_ID}:day${DAY}:KILL_CHAIN"
    echo "[$(date +%H:%M:%S)] >>> KILL_CHAIN (ep=$ep)"
    "$PY_CMD" -u -m attacks_ext.kill_chain \
        --session-id "$SESSION_ID" --host-id "$HOST_ID" \
        --label-file "$(label_file)" \
        --episode-id "$ep" --day "$DAY" \
        --target "$TARGET_IP" --rack "$RACK" --slot "$SLOT" \
        --hmi-target "$HMI_IP" \
        2>&1 || echo "[WARN] KILL_CHAIN returned non-zero"
}

# ── Controller ───────────────────────────────────────────────────
run_controller() {
    start_capture "controller"
    "$PY_CMD" log_tags_bangtruyen.py \
        --target "$TARGET_IP" --rack "$RACK" --slot "$SLOT" \
        --interval "${TAG_LOG_INTERVAL:-0.5}" \
        --output "$LOG_DIR/day${DAY}_${SESSION_ID}_${HOST_ID}_tags.csv" \
        --session-id "$SESSION_ID" --host-id "$HOST_ID" \
        --scenario-id "BENIGN_READER" \
        --episode-id "${SESSION_ID}:controller:tag_logger" \
        --day "$DAY" &
    PIDS+=("$!")
    echo "[ctrl] tag logger started"
    label "BENIGN_NORMAL" "START" "day7_controller_runtime" ""
    wait_s "$DAY7_DURATION_S" "controller_runtime"
    label "BENIGN_NORMAL" "END"   "day7_controller_runtime" ""
}

# ── Main ─────────────────────────────────────────────────────────
if [[ "$PREFLIGHT_ENABLED" == "1" ]]; then
    if ! preflight_plc; then
        echo "[ERROR] Preflight failed." >&2; exit 2
    fi
fi

[[ "${PREFLIGHT_ONLY:-0}" == "1" ]] && { echo "[preflight] done"; exit 0; }

case "${ROLE:-attacker}" in
    controller)
        run_controller
        echo "DAY 7 CONTROLLER DONE"
        exit 0
        ;;
esac

start_capture "day7_attacks"

echo ""
echo "  SCHEDULE: Warmup -> SMB(x3) -> ProgUpload(x2) -> DCP(x2) -> KillChain(x2) -> ConcealedStop(x2) -> Cooldown"
echo ""

# Phase 1: Warmup
label "BENIGN_NORMAL" "START" "day7_warmup" ""
wait_s "$WARMUP_S" "warmup_benign"
label "BENIGN_NORMAL" "END" "day7_warmup" ""

# Phase 2: SMB Recon
echo "[Phase 2] SMB Recon"
for i in $(seq 1 "$ATTACK_REPETITIONS"); do
    _run_attack "SMB_RECON_ENUM" "smb_enum" \
        "--target ${HMI_IP}"
    wait_s "$BENIGN_GAP_S" "gap_smb_${i}"
done
wait_s "$COOLDOWN_S" "cooldown_after_smb"

# Phase 2b (MOI): PROGRAM_UPLOAD_THEFT — hut logic OB/FB/FC/DB qua S7 (T0845).
# Chu ky rieng, khong trung read/write_area cua Day 1-6. Ghi nhan qua module.
echo "[Phase 2b] Program Upload Theft (T0845)"
for i in 1 2; do
    _run_attack "PROGRAM_UPLOAD_THEFT" "program_upload" \
        "--target ${TARGET_IP} --rack ${RACK} --slot ${SLOT}"
    wait_s "$BENIGN_GAP_S" "gap_progupload_${i}"
done
wait_s "$COOLDOWN_S" "cooldown_after_progupload"

# Phase 2c (MOI): PROFINET_DCP_ABUSE — tan cong layer-2 Profinet DCP (T0814/T0816).
# Mac dinh recon/identify-flood (an toan). Set-NameOfStation phai opt-in rieng:
# them "--enable-set-name --victim-mac <MAC> --new-name evil" vao extra_args.
# CAN root + dung --iface (cung segment Profinet). Neu CAPTURE_IFACE la ten kieu
# tshark (\Device\NPF_...) tren Windows, dat DCP_IFACE rieng cho scapy.
DCP_IFACE="${DCP_IFACE:-$CAPTURE_IFACE}"
if [[ -n "$DCP_IFACE" ]]; then
    echo "[Phase 2c] Profinet DCP Abuse (T0814/T0816) iface=$DCP_IFACE"
    for i in 1 2; do
        _run_attack "PROFINET_DCP_ABUSE" "profinet_dcp" \
            "--iface ${DCP_IFACE}"
        wait_s "$BENIGN_GAP_S" "gap_dcp_${i}"
    done
    wait_s "$COOLDOWN_S" "cooldown_after_dcp"
else
    echo "[Phase 2c] SKIP Profinet DCP — chua co --iface/DCP_IFACE (DCP can L2 raw socket)"
fi

# -- Da BO Phase 2b (ENG_STATION_PORT_SCAN standalone): chuc nang port-scan
#    may Engineering da nam san trong KILL_CHAIN lateral movement (import
#    PORTS + tcp_probe tu eng_station_scan), chay standalone la dư thua.
# -- Da BO Phase 3 (STEALTHY_WRITE): trung ten + trung ky thuat + trung vung
#    ghi voi STEALTHY_WRITE Day 3/4 (label collision), lai ghi MD100 khong
#    duoc tag logger ghi lai (process-view vo hinh). Module van giu trong repo.
# -- Da BO Phase 4 (LOGIC_AWARE): ghi S7 vao dung offset M5/CD54/CD58 giong
#    het RWRITE_BURST (Day3) + SETPOINT/SENSOR_SPOOF (Day4) o packet-level;
#    chi khac dieu kien/timing -> nguy co trung nhan cao, chat luong du lieu
#    khong tot. Module van giu trong repo.

# Phase 5: Kill Chain x2
echo "[Phase 5] Kill Chain (APT Simulation)"
label "BENIGN_NORMAL" "START" "pre_killchain_gap" ""
wait_s 600 "pre_killchain_buffer"
label "BENIGN_NORMAL" "END" "pre_killchain_gap" ""

run_kill_chain
wait_s "$COOLDOWN_L" "cooldown_kc1"
run_kill_chain

# Phase 5b: Concealed Stop Attack (S7 actuator STOP + OPC UA sensor
# concealment, Urbina et al. CCS16-style) x2
echo "[Phase 5b] Concealed Stop Attack (stealthy actuator+sensor concealment)"
for i in 1 2; do
    _run_attack "CONCEALED_STOP_ATTACK" "concealed_stop_attack" \
        "--target ${TARGET_IP} --rack ${RACK} --slot ${SLOT} --opc-url opc.tcp://${TARGET_IP}:4840"
    restore_plc
    wait_s "$COOLDOWN_S" "cooldown_concealed_${i}"
done

# Phase 6: Final cooldown
label "BENIGN_NORMAL" "START" "day7_cooldown_final" ""
wait_s "$COOLDOWN_S" "final_cooldown"
label "BENIGN_NORMAL" "END" "day7_cooldown_final" ""

echo "================================================================"
echo "  DAY 7 COMPLETE"
echo "  Labels : $(label_file)"
echo "  PCAP   : $CAPTURE_DIR/day${DAY}/"
echo "================================================================"
