#!/usr/bin/env bash
set -uo pipefail

# =============================================================================
# run_all_bangtruyen_days.sh -- Chay TOAN BO Day 1-8 cua he bang tai (bangtruyen)
# tu 1 lenh duy nhat, cho 1 MAY ATTACKER (chay lai script nay lan 2 tren may
# con lai voi --host-id khac de co du lieu tu ca 2 may).
#
# Bao gom:
#   Day 1-6 (S7comm)          -> goi lai run_day_bangtruyen.sh --day N (khong sua)
#   Day 7   (kill-chain + SMB/ENG scan/stealthy-write/replay/logic-aware)
#                              -> goi lai run_day_bangtruyen_ext.sh --day 7 (khong sua)
#   Day 8   (OPC UA)          -> goi lai tests/day8/collect_opcua.py (khong sua)
#
# KHONG viet lai logic tan cong o day -- chi la lop dieu phoi goi dung 3 script
# da co (va da sua o Day 8) theo dung 1 --host-id/--session-id xuyen suot, de
# grouped-CV/held-out ve sau phan biet duoc nguon.
#
# QUAN TRONG:
#   - Day 1-8 o day la vai tro ATTACKER. Controller (--role controller) van
#     phai chay RIENG tren may controller trong SUOT thoi gian nay, giong quy
#     trinh cu -- script nay KHONG khoi dong controller thay ban.
#   - Chi chay TUAN TU tren 1 may tai 1 thoi diem. KHONG chay dong thoi ca may
#     A va B cung luc (Day 8 gan nhan theo moc thoi gian, chay chong nhau se
#     lam sai episode; Day 1-7 dung chung 1 PLC vat ly nen cung khong the
#     chay 2 chuong trinh PLC khac nhau cung luc).
#
# Cach dung:
#   # May A -- tap TRAIN day du (Day 1-8)
#   bash run_all_bangtruyen_days.sh --host-id attacker_A --session-id bt_full_A \
#       --iface eth0
#
#   # May B -- lap lai sau khi may A xong, de co host diversity
#   bash run_all_bangtruyen_days.sh --host-id attacker_B --session-id bt_full_B \
#       --iface eth0
#
#   # Chi chay rieng Day 7-8 (bo qua Day 1-6 da co du lieu cu roi)
#   bash run_all_bangtruyen_days.sh --host-id attacker_A --session-id bt_full_A \
#       --iface eth0 --days "7 8"
#
#   # Day 8 lam tap OOD TEST rieng (khong lan vao train)
#   bash run_all_bangtruyen_days.sh --host-id attacker_B --session-id bt_ood_B \
#       --iface eth0 --days "8" --day8-session-tag oodtest --day8-cycles 50
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SCRIPT_DIR/testbed.conf" ]] && source "$SCRIPT_DIR/testbed.conf"

if [[ -z "${PY_CMD:-}" ]]; then
    command -v python3 &>/dev/null && PY_CMD="python3" || PY_CMD="python"
fi

# ── Defaults ─────────────────────────────────────────────────────────────────
HOST_ID=""
SESSION_ID=""
TARGET_IP="${TARGET_IP:-192.168.210.211}"
RACK="${RACK:-0}"
SLOT="${SLOT:-1}"
IFACE=""
DAYS="1 2 3 4 5 6 7 8"
INTER_DAY_GAP="${INTER_DAY_GAP:-60}"
NO_CAPTURE=0
NO_PREFLIGHT_AFTER_FIRST=1   # preflight chi can o lan chay Day dau tien trong danh sach
EXTRA_ARGS_1_6=""
DAY8_DURATION=""
DAY8_CYCLES=""
DAY8_WARMUP="${DAY8_WARMUP:-60}"
DAY8_COOLDOWN="${DAY8_COOLDOWN:-45}"
DAY8_SESSION_TAG="train"
DAY8_BALANCED=0
DAY8_GROUP_DURATION="${DAY8_GROUP_DURATION:-3600}"

usage() {
    cat <<'EOF'
Usage:
  bash run_all_bangtruyen_days.sh --host-id ID --session-id ID --iface NIC [options]

Bat buoc:
  --host-id ID         attacker_A / attacker_B -- ID may dang chay script nay.
  --iface NIC           TShark capture interface (bo qua neu --no-capture).

Tuy chon:
  --session-id ID        Session ID goc, dung cho Day 1-7 (default: bt_full_<host-id>).
  --target IP             PLC IP (default 192.168.210.211)
  --rack N / --slot N
  --days "1 2 3..."       Danh sach day muon chay (default: "1 2 3 4 5 6 7 8")
  --gap N                 Giay nghi giua cac day (default 60)
  --no-capture            Bo qua TShark cho Day 1-7 (Day 8 tu quan ly capture rieng)
  --enable-cpu-control    Cho phep CPU_STOP o Day 1-6 (default tat, xem run_day_bangtruyen.sh)
  --day8-duration N       Gioi han Day 8 theo thoi luong (giay) thay vi so cycle
  --day8-cycles N         So cycle Day 8 (bo qua neu dung --day8-duration)
  --day8-warmup N         Warmup moi cycle Day 8 (default 60s)
  --day8-cooldown N       Cooldown moi cycle Day 8 (default 45s)
  --day8-session-tag T    'train' (default) hoac 'oodtest' cho Day 8
  --day8-balanced         Chay Day 8 theo 3 nhom kich ban rieng (thay vi 1 pool
                           11 kich ban random chung) de moi lop co so episode
                           deu nhau hon -- xem run_day_8_balanced() ben duoi.
                           Bo qua --day8-cycles/--scenarios khi dung co nay.
  --day8-group-duration N Thoi luong MOI nhom trong che do --day8-balanced
                           (default 3600s = 1h/nhom x 3 nhom = 3h tong)

Vi du xem dau file nay (comment tren cung).
EOF
}

EXTRA_1_6=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host-id) HOST_ID="$2"; shift 2 ;;
        --session-id) SESSION_ID="$2"; shift 2 ;;
        --target) TARGET_IP="$2"; shift 2 ;;
        --rack) RACK="$2"; shift 2 ;;
        --slot) SLOT="$2"; shift 2 ;;
        --iface) IFACE="$2"; shift 2 ;;
        --days) DAYS="$2"; shift 2 ;;
        --gap) INTER_DAY_GAP="$2"; shift 2 ;;
        --no-capture) NO_CAPTURE=1; EXTRA_1_6+=("--no-capture"); shift ;;
        --enable-cpu-control) EXTRA_1_6+=("--enable-cpu-control"); shift ;;
        --day8-duration) DAY8_DURATION="$2"; shift 2 ;;
        --day8-cycles) DAY8_CYCLES="$2"; shift 2 ;;
        --day8-warmup) DAY8_WARMUP="$2"; shift 2 ;;
        --day8-cooldown) DAY8_COOLDOWN="$2"; shift 2 ;;
        --day8-session-tag) DAY8_SESSION_TAG="$2"; shift 2 ;;
        --day8-balanced) DAY8_BALANCED=1; shift ;;
        --day8-group-duration) DAY8_GROUP_DURATION="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[ERROR] Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ -z "$HOST_ID" ]]; then
    echo "[ERROR] --host-id bat buoc (vd attacker_A / attacker_B)" >&2
    usage; exit 1
fi
[[ -z "$SESSION_ID" ]] && SESSION_ID="bt_full_${HOST_ID}"
[[ -z "$IFACE" && "$NO_CAPTURE" != "1" ]] && {
    echo "[ERROR] --iface bat buoc (hoac dung --no-capture)" >&2
    exit 1
}

DAY1_6_SCRIPT="$SCRIPT_DIR/run_day_bangtruyen.sh"
DAY7_SCRIPT="$SCRIPT_DIR/run_day_bangtruyen_ext.sh"
DAY8_SCRIPT="$SCRIPT_DIR/tests/day8/collect_opcua.py"
for f in "$DAY1_6_SCRIPT" "$DAY7_SCRIPT" "$DAY8_SCRIPT"; do
    [[ -f "$f" ]] || { echo "[ERROR] Khong tim thay $f" >&2; exit 1; }
done

START_TIME=$(date '+%Y-%m-%d %H:%M:%S')
echo ""
echo "======================================================================"
echo "  BANG TAI (bangtruyen) -- Thu toan bo Day 1-8, 1 may attacker"
echo "======================================================================"
echo "  Start      : $START_TIME"
echo "  host_id    : $HOST_ID"
echo "  session_id : $SESSION_ID  (dung cho Day 1-7; Day 8 tu sinh session rieng theo tag)"
echo "  Target     : $TARGET_IP rack=$RACK slot=$SLOT"
echo "  Days       : $DAYS"
echo "  Iface      : ${IFACE:-none (--no-capture)}"
echo "  Day8 tag   : $DAY8_SESSION_TAG"
echo "======================================================================"
echo ""
echo "[!] NHAC: dam bao vai tro CONTROLLER (--role controller) dang chay RIENG"
echo "    tren may controller truoc khi tiep tuc -- script nay chi phu trach"
echo "    phia ATTACKER."
echo ""

RESULTS_FILE="collection_results_bangtruyen_${SESSION_ID}.txt"
{
    echo "Bangtruyen full-day collection -- host_id=$HOST_ID session_id=$SESSION_ID"
    echo "Started: $START_TIME"
    echo "Days: $DAYS"
    echo "----------------------------------------"
} > "$RESULTS_FILE"

SUCCESS_DAYS=()
FAILED_DAYS=()
FIRST_1_6_DONE=0

run_day_1_6() {
    local day="$1"
    local cmd=(bash "$DAY1_6_SCRIPT" --day "$day" --role attacker
               --target "$TARGET_IP" --rack "$RACK" --slot "$SLOT"
               --session-id "$SESSION_ID" --host-id "$HOST_ID")
    [[ -n "$IFACE" ]] && cmd+=(--iface "$IFACE")
    cmd+=("${EXTRA_1_6[@]}")
    if [[ "$FIRST_1_6_DONE" == "1" ]]; then
        cmd+=(--no-preflight)
    fi
    echo ">>> Day $day (S7comm): ${cmd[*]}"
    if "${cmd[@]}"; then
        FIRST_1_6_DONE=1
        return 0
    fi
    return 1
}

run_day_7() {
    local cmd=(bash "$DAY7_SCRIPT" --day 7 --role attacker
               --target "$TARGET_IP" --rack "$RACK" --slot "$SLOT"
               --session-id "$SESSION_ID" --host-id "$HOST_ID")
    [[ -n "$IFACE" ]] && cmd+=(--iface "$IFACE")
    echo ">>> Day 7 (kill-chain + SMB/ENG scan + stealthy-write + replay + logic-aware): ${cmd[*]}"
    "${cmd[@]}"
}

run_day_8() {
    local cmd=("$PY_CMD" "$DAY8_SCRIPT" --host-id "$HOST_ID" --session-tag "$DAY8_SESSION_TAG"
               --plc-ip "$TARGET_IP" --warmup "$DAY8_WARMUP" --cooldown "$DAY8_COOLDOWN")
    if [[ -n "$DAY8_DURATION" ]]; then
        cmd+=(--duration "$DAY8_DURATION")
    elif [[ -n "$DAY8_CYCLES" ]]; then
        cmd+=(--cycles "$DAY8_CYCLES")
    fi
    echo ">>> Day 8 (OPC UA, tier ngau nhien slow/medium/fast): ${cmd[*]}"
    echo "    LUU Y: bat capture rieng o cong mirror cho Day 8 (khong dung TShark cua Day 1-7)."
    "${cmd[@]}"
}

# Day 8 chia 3 nhom kich ban (thay vi random.choice tren ca 11 kich ban moi
# cycle) de moi lop co so episode deu nhau hon trong cung 1 tong thoi luong --
# xem ly do trong lich su trao doi (pool 11 kich ban random + warmup/cooldown
# co dinh 60/45s moi cycle lam loang mat do mau/lop khi chay 1 pool lon).
# Nhom theo dac tinh: probe nhanh khong tier / tier ngan-trung / tier dai-hold.
DAY8_GROUP_1="OPCUA_ENDPOINT_DISCOVERY OPCUA_NODE_BROWSE OPCUA_WRITE_DENIED OPCUA_INVALID_WRITE OPCUA_PROTOCOL_FUZZ"
DAY8_GROUP_2="OPCUA_SESSION_BURST OPCUA_READ_SCRAPING OPCUA_RECURSIVE_BROWSE"
DAY8_GROUP_3="OPCUA_SLOWLORIS OPCUA_BEHAVIORAL_PROFILING OPCUA_SUBSCRIPTION_FLOOD"

run_day_8_balanced() {
    local gi=0 group ok_all=1
    for group in "$DAY8_GROUP_1" "$DAY8_GROUP_2" "$DAY8_GROUP_3"; do
        gi=$((gi + 1))
        local cmd=("$PY_CMD" "$DAY8_SCRIPT" --host-id "$HOST_ID" --session-tag "$DAY8_SESSION_TAG"
                   --plc-ip "$TARGET_IP" --warmup "$DAY8_WARMUP" --cooldown "$DAY8_COOLDOWN"
                   --duration "$DAY8_GROUP_DURATION" --scenarios $group)
        echo ">>> Day 8 nhom ${gi}/3 (${group}): ${cmd[*]}"
        if ! "${cmd[@]}"; then
            echo "[WARN] Day 8 nhom ${gi} that bai, tiep tuc nhom tiep theo"
            ok_all=0
        fi
    done
    echo "    LUU Y: bat capture rieng o cong mirror cho ca 3 nhom Day 8 (khong dung TShark cua Day 1-7)."
    [[ "$ok_all" == "1" ]]
}

for DAY in $DAYS; do
    echo ""
    echo "----------------------------------------------------------------------"
    echo " DAY $DAY  [$(date '+%H:%M:%S')]"
    echo "----------------------------------------------------------------------"
    DAY_START=$(date +%s)

    case "$DAY" in
        1|2|3|4|5|6) ok=0; run_day_1_6 "$DAY" && ok=1 ;;
        7)            ok=0; run_day_7 && ok=1 ;;
        8)            ok=0
                       if [[ "$DAY8_BALANCED" == "1" ]]; then
                           run_day_8_balanced && ok=1
                       else
                           run_day_8 && ok=1
                       fi
                       ;;
        *) echo "[WARN] Bo qua day khong hop le: $DAY"; continue ;;
    esac

    DAY_END=$(date +%s)
    ELAPSED=$(( DAY_END - DAY_START ))
    if [[ "$ok" == "1" ]]; then
        echo "OK Day $DAY xong trong ${ELAPSED}s"
        echo "Day $DAY: SUCCESS (${ELAPSED}s)" >> "$RESULTS_FILE"
        SUCCESS_DAYS+=("$DAY")
    else
        echo "LOI Day $DAY that bai sau ${ELAPSED}s"
        echo "Day $DAY: FAILED (${ELAPSED}s)" >> "$RESULTS_FILE"
        FAILED_DAYS+=("$DAY")
        echo "Tiep tuc cac day con lai? (Ctrl+C de dung, Enter de tiep tuc)"
        read -r -t 30 || true
    fi

    REMAINING="${DAYS#*$DAY}"
    REMAINING="${REMAINING# }"
    if [[ -n "$REMAINING" ]]; then
        echo "[gap] Nghi ${INTER_DAY_GAP}s truoc day tiep theo..."
        sleep "$INTER_DAY_GAP"
    fi
done

END_TIME=$(date '+%Y-%m-%d %H:%M:%S')
echo ""
echo "======================================================================"
echo "  HOAN TAT -- host_id=$HOST_ID session_id=$SESSION_ID"
echo "======================================================================"
echo "  Ket thuc : $END_TIME"
echo "  OK days  : ${SUCCESS_DAYS[*]:-none}"
echo "  Failed   : ${FAILED_DAYS[*]:-none}"
echo "======================================================================"
{
    echo "----------------------------------------"
    echo "Ended: $END_TIME"
    echo "Success: ${SUCCESS_DAYS[*]:-none}"
    echo "Failed:  ${FAILED_DAYS[*]:-none}"
} >> "$RESULTS_FILE"
echo "Tom tat: $RESULTS_FILE"

echo ""
echo "Buoc tiep theo:"
echo "  1. Lap lai TOAN BO lenh nay tren may attacker con lai voi --host-id khac"
echo "     (vd attacker_B) de co du lieu 2 host cho MOI ngay, khong chi Day 8."
echo "  2. Extract feature Day 1-7 nhu quy trinh cu (extract_s7_features.py)."
echo "  3. Extract feature Day 8 -- LUON truyen --session-id/--host-id dung:"
echo "     python extract_opcua_features.py --pcap <file>.pcap \\"
echo "       --timeline test_results/day8/timeline_opcua_day8_${DAY8_SESSION_TAG}_${HOST_ID}.csv \\"
echo "       --output opcua_${HOST_ID}_features.csv --window 5 --plc-ip $TARGET_IP \\"
echo "       --session-id day8_${DAY8_SESSION_TAG}_${HOST_ID} --host-id $HOST_ID"

[[ "${#FAILED_DAYS[@]}" -gt 0 ]] && exit 1 || exit 0
