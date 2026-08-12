#!/usr/bin/env bash
set -uo pipefail

# =============================================================================
# run_day6_extended.sh -- Bo sung cho Day 6 (OOD holdout).
#
# Day 6 GOC (run_day_bangtruyen.sh --day 6) chi lap lai 8 ky thuat cua
# Day 1-5 (SCAN_PORT/ENUM_TAGS/RWRITE_BURST/SETPOINT_ATTACK/SENSOR_SPOOF/
# STEALTHY_WRITE/S7_FLOOD/PROTOCOL_FUZZ) o toc do khac -- CHUA TUNG lap lai
# ky thuat cua Day 7 (SMB_RECON_ENUM, ENG_STATION_PORT_SCAN, LOGIC_AWARE,
# CONCEALED_STOP_ATTACK). Script nay THEM đung 4 ky thuat do vao, o toc do
# KHAC Day 7 goc (ATTACK_PROFILE=diverse_mix, xem attacks_ext/*.py), lam
# phan OOD test rieng cho chung -- dung y tuong voi Day 6 goc, chi mo rong
# pham vi ky thuat duoc kiem tra khai quat.
#
# Day 8 (OPC UA) da TU CO OOD qua co che tier ngau nhien trong chinh
# tests/day8/collect_opcua.py (moi cycle tu random 1 trong 3 muc tan suat,
# doc lap voi session-tag train/oodtest) -- KHONG can bo sung gi them o day.
#
# QUAN TRONG:
#   - KHONG thay the Day 6 goc -- chay SAU khi Day 6 goc da xong, la phan
#     BO SUNG. Nhan "day=6" giu nguyen (de gop chung vao Day 6 luc merge
#     dataset) nhung ten file/session co hau to "_day6ext" de KHONG ghi de
#     pcap/label cua Day 6 goc.
#   - CONCEALED_STOP_ATTACK va LOGIC_AWARE GHI THAT vao PLC (S7 STOP/START,
#     timer) -- CAN co controller/tag-logger chay dong thoi de co ground-
#     truth tag log, giong het Day 7. Dung lai controller CO SAN cua Day 7
#     (khong viet lai): xem lenh vi du duoi cung file nay.
#   - Khi gop vao pipeline (merge_dataset.py), kiem tra lai cach script do
#     nhom nhieu file cung "day=6" -- chua duoc xac minh trong lan sua nay.
#
# Cach dung (2 terminal, chay CUNG LUC):
#   Terminal 1 (attacker, script nay):
#     bash run_day6_extended.sh --session-id bt_redo_A --iface eth0
#   Terminal 2 (controller, dung lai Day 7 controller co san):
#     bash run_day_bangtruyen_ext.sh --day 7 --role controller \
#         --session-id bt_redo_A_day6ext --iface eth0
#     (dat DAY7_DURATION_S trong testbed.conf du dai de phu het thoi gian
#     script nay chay -- xem dong "DAY 6 MO RONG HOAN TAT" o cuoi log de
#     biet chay het bao lau lan truoc, hoac uoc luong: warmup 180s + 4 nhom
#     x REPS x (thoi luong ngau nhien 120-400s + gap) + cooldown 300s.)
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SCRIPT_DIR/testbed.conf" ]] && source "$SCRIPT_DIR/testbed.conf"

if [[ -z "${PY_CMD:-}" ]]; then
    command -v python3 &>/dev/null && PY_CMD="python3" || PY_CMD="python"
fi
export PYTHONPATH="${PYTHONPATH:-.}"

TARGET_IP="${TARGET_IP:-192.168.210.211}"
RACK="${RACK:-0}"
SLOT="${SLOT:-1}"
OPC_URL="${OPC_URL:-opc.tcp://${TARGET_IP}:4840}"
HMI_IP="${HMI_IP:-}"
SESSION_ID=""
HOST_ID="${ATTACKER_HOST_ID:-attacker_host}"
IFACE=""
NO_CAPTURE=0
DAY=6
REPS="${DAY6EXT_REPS:-2}"
GAP_S="${BENIGN_GAP_S:-300}"
CAPTURE_DIR="${CAPTURE_DIR:-captures}"
LABEL_DIR="${LABEL_DIR:-labels}"

usage() {
    cat <<'EOF'
Usage:
  bash run_day6_extended.sh --session-id ID --iface NIC [options]

Bat buoc:
  --session-id ID      Session goc dung cho Day 1-8 (vd bt_redo_A) -- script
                        tu them hau to "_day6ext", khong ghi de file cu.
  --iface NIC           TShark interface (bo qua neu --no-capture).

Tuy chon:
  --target IP / --rack N / --slot N / --opc-url URL
  --host-id ID          (default attacker_host)
  --hmi-ip IP           (default: suy tu subnet cua --target, .31)
  --reps N              So lan lap moi ky thuat (default 2 -- it hon Day 7
                        goc vi day chi la phan OOD bo sung, khong phai train)
  --no-capture
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --session-id) SESSION_ID="$2"; shift 2 ;;
        --host-id) HOST_ID="$2"; shift 2 ;;
        --target) TARGET_IP="$2"; shift 2 ;;
        --rack) RACK="$2"; shift 2 ;;
        --slot) SLOT="$2"; shift 2 ;;
        --opc-url) OPC_URL="$2"; shift 2 ;;
        --hmi-ip) HMI_IP="$2"; shift 2 ;;
        --iface) IFACE="$2"; shift 2 ;;
        --reps) REPS="$2"; shift 2 ;;
        --no-capture) NO_CAPTURE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[ERROR] Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

[[ -n "$SESSION_ID" ]] || { echo "[ERROR] --session-id bat buoc" >&2; usage; exit 1; }
[[ -n "$IFACE" || "$NO_CAPTURE" == "1" ]] || { echo "[ERROR] --iface bat buoc (hoac --no-capture)" >&2; exit 1; }

if [[ -z "$HMI_IP" ]]; then
    SUBNET_PREFIX=$(echo "$TARGET_IP" | sed -E 's/\.[0-9]+$//')
    HMI_IP="${SUBNET_PREFIX}.31"
fi

FULL_SESSION="${SESSION_ID}_day6ext"
mkdir -p "$CAPTURE_DIR/day${DAY}" "$LABEL_DIR"

declare -a PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

label_file() { echo "$LABEL_DIR/day${DAY}_${FULL_SESSION}_${HOST_ID}_timeline.csv"; }
now_ms() { "$PY_CMD" -c "import time; print(int(time.time()*1000))"; }
label() {
    local s="$1" a="$2" ep="${3:-}" n="${4:-}" ts f
    ts="$(now_ms)"; f="$(label_file)"
    [[ ! -f "$f" ]] && echo "attacker_timestamp_ms,scenario_label,action,session_id,host_id,episode_id,day,note" > "$f"
    n="${n//,/;}"; ep="${ep//,/;}"
    printf '%s,%s,%s,%s,%s,%s,%s,%s\n' "$ts" "$s" "$a" "$FULL_SESSION" "$HOST_ID" "$ep" "$DAY" "$n" >> "$f"
    echo "[$(date +%H:%M:%S)] label $s $a"
}
wait_s() { local sec="$1" m="${2:-wait}"; [[ "$sec" -le 0 ]] && return 0; echo "[wait] ${sec}s -- $m"; sleep "$sec"; }

if [[ "$NO_CAPTURE" != "1" ]]; then
    pcap="$CAPTURE_DIR/day${DAY}/${FULL_SESSION}.pcapng"
    tshark -n -i "$IFACE" -f "host $TARGET_IP" -w "$pcap" -q &
    PIDS+=("$!"); echo "[capture] tshark -> $pcap"
fi

export ATTACK_PROFILE=diverse_mix

echo "======================================================================"
echo "  DAY 6 MO RONG -- OOD test cho ky thuat Day 7"
echo "  (SMB_RECON_ENUM / ENG_STATION_PORT_SCAN / LOGIC_AWARE / CONCEALED_STOP_ATTACK)"
echo "  Session : $FULL_SESSION | reps=$REPS | profile=diverse_mix"
echo "  Nho chay CUNG LUC controller Day 7 (--role controller) o may khac!"
echo "======================================================================"

_run() {
    local scenario="$1" module="$2" extra="${3:-}" dur ep
    dur=$("$PY_CMD" -c "import random; print(random.randint(120,400))")
    ep="${FULL_SESSION}:day${DAY}ext:${scenario}"
    label "$scenario" "START" "$ep" "dur=${dur}s profile=diverse_mix"
    "$PY_CMD" -u -m attacks_ext.${module} \
        --duration "$dur" --session-id "$FULL_SESSION" --host-id "$HOST_ID" \
        --label-file "$(label_file)" --episode-id "$ep" --day "$DAY" \
        $extra 2>&1 || echo "[WARN] $scenario returned non-zero"
    label "$scenario" "END" "$ep" ""
}

label "BENIGN_NORMAL" "START" "day6ext_warmup" ""
wait_s 180 "warmup"
label "BENIGN_NORMAL" "END" "day6ext_warmup" ""

echo "[Phase 1] SMB_RECON_ENUM (OOD rate)"
for i in $(seq 1 "$REPS"); do
    _run "SMB_RECON_ENUM" "smb_enum" "--target ${HMI_IP}"
    wait_s "$GAP_S" "gap_smb_${i}"
done

echo "[Phase 2] ENG_STATION_PORT_SCAN (OOD rate)"
for i in $(seq 1 "$REPS"); do
    _run "ENG_STATION_PORT_SCAN" "eng_station_scan" "--target ${HMI_IP}"
    wait_s "$GAP_S" "gap_engscan_${i}"
done

echo "[Phase 3] LOGIC_AWARE (OOD rate, ghi that vao PLC -- can controller dang chay)"
for i in $(seq 1 "$REPS"); do
    _run "LOGIC_AWARE" "logic_aware" "--target ${TARGET_IP} --rack ${RACK} --slot ${SLOT}"
    wait_s "$GAP_S" "gap_logicaware_${i}"
done

echo "[Phase 4] CONCEALED_STOP_ATTACK (OOD rate, ghi that vao PLC + OPC UA -- can controller dang chay)"
for i in $(seq 1 "$REPS"); do
    _run "CONCEALED_STOP_ATTACK" "concealed_stop_attack" \
        "--target ${TARGET_IP} --rack ${RACK} --slot ${SLOT} --opc-url ${OPC_URL}"
    wait_s "$GAP_S" "gap_concealed_${i}"
done

label "BENIGN_NORMAL" "START" "day6ext_cooldown" ""
wait_s 300 "final_cooldown"
label "BENIGN_NORMAL" "END" "day6ext_cooldown" ""

echo "======================================================================"
echo "  DAY 6 MO RONG HOAN TAT"
echo "  Labels : $(label_file)"
echo "  PCAP   : $CAPTURE_DIR/day${DAY}/${FULL_SESSION}.pcapng"
echo "======================================================================"
