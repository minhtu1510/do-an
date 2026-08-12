#!/usr/bin/env bash
set -uo pipefail

# =============================================================================
# run_full_2attacker.sh -- 1 LENH DUY NHAT tren MOI may ATTACKER, chay TOAN
# BO lich thu thap bangtruyen Day 1-8 voi 2 may.
#
# THIET KE (v2 -- host-consistent TRAIN/OOD, thay vi tag theo pha):
#   May A = host TRAIN xuyen suot ca 8 day (Day1-6, Day7, Day8 filler).
#   May B = host OOD/HELD-OUT xuyen suot ca 8 day -- MOI loai attack (ca 26
#   loai: 9 S7 Day1-6 + 6 Day7 gom CONCEALED_STOP_ATTACK moi + 11 OPC UA
#   Day8) deu co mat trong tap OOD, khong chi rieng OPC UA nhu ban truoc.
#   Day6 (da co san "day6_robust": lai toan bo Day2-5 o tan suat/thu tu khac)
#   tu no da la bien the OOD-flavor cho Day1-6; o day con tach het Day1-6 cua
#   B sang mot session_id/host_id RIENG (khong lan voi A) de grouped-CV/
#   held-out (session_id/host_id) phan biet ro rang train vs test.
#
#   Pha 2 (Day 8 coordinated) la truc thu 3, DOC LAP voi train/ood -- kiem
#   tra phat hien khi 2 tac nhan tan cong cung luc, khong dung de train/test
#   thong thuong.
#
# LY DO CHAY TUAN TU CHO DAY 1-7 (khong doi):
#   Day 1-7 (S7comm) dung CHUNG 1 PLC vat ly va CAN controller rieng cho tung
#   Day (tag logger + HMI simulation co the WRITE that vao PLC, xem
#   run_day_bangtruyen.sh::start_hmi). 2 may KHONG the vua chay Day 1-6 vua
#   chay Day 7 cung luc vi ca hai cung tac dong len 1 controller/PLC va se
#   lam sai ground-truth cua ca hai.
#   Day 8 (OPC UA) AN TOAN chay dong thoi voi Day 1-7 vi khong can controller
#   rieng va cac scenario trong DEFAULT_POOL hoac la read-only hoac la write
#   BI TU CHOI (khong thuc su doi state PLC) -- dung lam "filler" cho may
#   dang ranh trong luc may kia doc quyen S7.
#
#   Ve tan suat/tier: --day8-*-cycles duoi day KHONG co gang lap day 100%
#   thoi gian ranh -- co 25 to hop (scenario x tier) trong DEFAULT_POOL, chi
#   can ~15-20 mau/to hop la du thong ke, lap qua nhieu chi la trung lap tan
#   suat vo ich (dung nhu ban gop y "tan suat trung nhau thi bo bot"). Mac
#   dinh TRAIN (may A) ~500 cycle, OOD (may B) ~200 cycle -- OOD khong can
#   nhieu bang train.
#
#   Pha 1a (~22h) : A=Day1-6 TRAIN (S7, exclusive) || B=Day8 filler tag=oodtest
#   Pha 1b (~22h) : B=Day1-6 OOD   (S7, exclusive) || A=Day8 filler tag=train
#   Pha 1c (~4h)  : A=Day7   TRAIN (S7, exclusive) || B=Day8 filler tag=oodtest
#   Pha 1d (~4h)  : B=Day7   OOD   (S7, exclusive) || A=Day8 filler tag=train
#   Pha 2  (~25p) : A & B CUNG chay Day 8 --session-tag coordinated dong thoi
#
#   TONG ~52-53h/may, 1 lenh duy nhat, khong can go them gi giua chung.
#
# CONTROLLER (may thu 3, PLC/HMI that) PHAI chay RIENG, khop dung 4 pha S7
# bang run_full_2attacker_controller.sh (1 lenh duy nhat, tu noi tiep 4 pha).
#
# Cach dung:
#   May A: bash run_full_2attacker.sh --role A --peer-ip <IP_B> --iface eth0
#   May B: bash run_full_2attacker.sh --role B --peer-ip <IP_A> --iface eth0
#   May Controller (chay RIENG, cung luc voi khi May A bat dau Pha 1a):
#     bash run_full_2attacker_controller.sh --iface eth0
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SCRIPT_DIR/testbed.conf" ]] && source "$SCRIPT_DIR/testbed.conf"

if [[ -z "${PY_CMD:-}" ]]; then
    command -v python3 &>/dev/null && PY_CMD="python3" || PY_CMD="python"
fi

ORCH="$SCRIPT_DIR/run_all_bangtruyen_days.sh"
BARRIER="$SCRIPT_DIR/barrier_sync.py"
DAY8_DIRECT="$SCRIPT_DIR/tests/day8/collect_opcua.py"
for f in "$ORCH" "$BARRIER" "$DAY8_DIRECT"; do
    [[ -f "$f" ]] || { echo "[ERROR] Khong tim thay $f" >&2; exit 1; }
done

# ── Defaults ─────────────────────────────────────────────────────────────────
ROLE=""
PEER_IP=""
TARGET_IP="${TARGET_IP:-192.168.210.211}"
RACK="${RACK:-0}"
SLOT="${SLOT:-1}"
IFACE=""
NO_CAPTURE=0
BARRIER_PORT=57123

# Filler mac dinh: TRAIN (may A) nhieu hon OOD (may B), chia theo ty le thoi
# gian ranh cua tung pha (~22h vs ~4h) -- xem giai thich dau file.
DAY8_TRAIN_FILLER_1B=430   # A ranh trong Pha 1b (~22h)
DAY8_TRAIN_FILLER_1D=70    # A ranh trong Pha 1d (~4h)
DAY8_OOD_FILLER_1A=170     # B ranh trong Pha 1a (~22h)
DAY8_OOD_FILLER_1C=30      # B ranh trong Pha 1c (~4h)
DAY8_WARMUP=60
DAY8_COOLDOWN=45

ROUND2_CYCLES=10
ROUND2_SCENARIO_A="OPCUA_SLOWLORIS"
ROUND2_SCENARIO_B="OPCUA_READ_SCRAPING"

SKIP_PHASES=""   # vd "1a 1b" de bo qua cac pha da chay roi

usage() {
    cat <<'EOF'
Usage:
  bash run_full_2attacker.sh --role A|B --peer-ip IP --iface NIC [options]

Bat buoc:
  --role A|B          May A = host TRAIN, may B = host OOD/held-out (co dinh).
  --peer-ip IP         IP cua may attacker CON LAI (dung de dong bo barrier).
  --iface NIC          TShark capture interface (bo qua neu --no-capture).

Tuy chon:
  --target IP / --rack N / --slot N     PLC (default 192.168.210.211 / 0 / 1)
  --no-capture                          Bo qua TShark cho Day 1-7
  --barrier-port N                      Port TCP dong bo 2 may (default 57123)
  --day8-train-filler-1b N (default 430) / --day8-train-filler-1d N (default 70)
  --day8-ood-filler-1a N   (default 170) / --day8-ood-filler-1c N   (default 30)
  --day8-warmup N / --day8-cooldown N   (default 60 / 45)
  --round2-cycles N                     So cycle Day 8 coordinated (default 10)
  --round2-scenario-a ID / --round2-scenario-b ID
  --skip-phase "1a 1b"                  Bo qua (cac) pha da chay roi

Uoc luong thoi gian (mac dinh, xem chi tiet dau file):
  Pha 1a ~22h | Pha 1b ~22h | Pha 1c ~4h | Pha 1d ~4h | Pha 2 ~25p
  TONG ~52-53h moi may.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role) ROLE="$2"; shift 2 ;;
        --peer-ip) PEER_IP="$2"; shift 2 ;;
        --target) TARGET_IP="$2"; shift 2 ;;
        --rack) RACK="$2"; shift 2 ;;
        --slot) SLOT="$2"; shift 2 ;;
        --iface) IFACE="$2"; shift 2 ;;
        --no-capture) NO_CAPTURE=1; shift ;;
        --barrier-port) BARRIER_PORT="$2"; shift 2 ;;
        --day8-train-filler-1b) DAY8_TRAIN_FILLER_1B="$2"; shift 2 ;;
        --day8-train-filler-1d) DAY8_TRAIN_FILLER_1D="$2"; shift 2 ;;
        --day8-ood-filler-1a) DAY8_OOD_FILLER_1A="$2"; shift 2 ;;
        --day8-ood-filler-1c) DAY8_OOD_FILLER_1C="$2"; shift 2 ;;
        --day8-warmup) DAY8_WARMUP="$2"; shift 2 ;;
        --day8-cooldown) DAY8_COOLDOWN="$2"; shift 2 ;;
        --round2-cycles) ROUND2_CYCLES="$2"; shift 2 ;;
        --round2-scenario-a) ROUND2_SCENARIO_A="$2"; shift 2 ;;
        --round2-scenario-b) ROUND2_SCENARIO_B="$2"; shift 2 ;;
        --skip-phase) SKIP_PHASES="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[ERROR] Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

[[ "$ROLE" == "A" || "$ROLE" == "B" ]] || { echo "[ERROR] --role phai la A hoac B" >&2; usage; exit 1; }
[[ -n "$PEER_IP" ]] || { echo "[ERROR] --peer-ip bat buoc" >&2; usage; exit 1; }
[[ -n "$IFACE" || "$NO_CAPTURE" == "1" ]] || { echo "[ERROR] --iface bat buoc (hoac dung --no-capture)" >&2; exit 1; }

HOST_ID="attacker_${ROLE}"
[[ "$ROLE" == "A" ]] && DATA_ROLE="train" || DATA_ROLE="ood"
[[ "$ROLE" == "A" ]] && ROUND2_SCENARIO="$ROUND2_SCENARIO_A" || ROUND2_SCENARIO="$ROUND2_SCENARIO_B"

IFACE_ARGS=()
[[ -n "$IFACE" ]] && IFACE_ARGS+=(--iface "$IFACE")
[[ "$NO_CAPTURE" == "1" ]] && IFACE_ARGS+=(--no-capture)

skip_has() { [[ " $SKIP_PHASES " == *" $1 "* ]]; }

echo "======================================================================"
echo "  BANG TAI -- FULL 2-ATTACKER SCHEDULE Day1-8 (5 pha, xem comment dau file)"
echo "======================================================================"
echo "  May nay    : $ROLE  (host_id=$HOST_ID, data_role=$DATA_ROLE)"
echo "  Peer IP    : $PEER_IP  (chi dung dong bo barrier, khong tan cong)"
echo "  Barrier    : port $BARRIER_PORT, role A=server co dinh, role B=client co dinh"
echo "  Target PLC : $TARGET_IP rack=$RACK slot=$SLOT"
echo "  Round2 scn : $ROUND2_SCENARIO"
[[ -n "$SKIP_PHASES" ]] && echo "  Skip phase : $SKIP_PHASES"
echo "======================================================================"
echo ""
echo "[!] NHAC: chay dong thoi tren may CONTROLLER:"
echo "    bash run_full_2attacker_controller.sh --iface <NIC controller>"
echo ""

barrier() {
    local tag="$1"
    echo ""
    echo "[barrier] dong bo 2 may attacker truoc khi tiep tuc: $tag"
    if [[ "$ROLE" == "A" ]]; then
        "$PY_CMD" "$BARRIER" --role server --port "$BARRIER_PORT" --tag "$tag"
    else
        "$PY_CMD" "$BARRIER" --role client --peer-ip "$PEER_IP" --port "$BARRIER_PORT" --tag "$tag"
    fi
}

run_day1_6() {
    local session="$1"
    bash "$ORCH" --host-id "$HOST_ID" --session-id "$session" \
        --target "$TARGET_IP" --rack "$RACK" --slot "$SLOT" \
        --days "1 2 3 4 5 6" "${IFACE_ARGS[@]}"
}

run_day7() {
    local session="$1"
    bash "$ORCH" --host-id "$HOST_ID" --session-id "$session" \
        --target "$TARGET_IP" --rack "$RACK" --slot "$SLOT" \
        --days "7" "${IFACE_ARGS[@]}"
}

run_day8_filler() {
    local tag="$1" cycles="$2"
    [[ "$cycles" -le 0 ]] && { echo "[day8-filler] cycles=0, bo qua"; return 0; }
    echo "[day8-filler] host_id=$HOST_ID tag=$tag cycles=$cycles (tranh khong ngoi khong o barrier)"
    "$PY_CMD" "$DAY8_DIRECT" --host-id "$HOST_ID" --session-tag "$tag" \
        --cycles "$cycles" --plc-ip "$TARGET_IP" \
        --warmup "$DAY8_WARMUP" --cooldown "$DAY8_COOLDOWN"
}

# ── Pha 1a : A=Day1-6 TRAIN (exclusive) || B=Day8 filler(oodtest) ───────────
if skip_has 1a; then
    echo ""; echo ">>> PHA 1a: bo qua theo --skip-phase"
else
    echo ""; echo ">>> PHA 1a bat dau [$(date '+%Y-%m-%d %H:%M:%S')]"
    if [[ "$ROLE" == "A" ]]; then
        run_day1_6 "bt_train_A_day16"
    else
        run_day8_filler "oodtest" "$DAY8_OOD_FILLER_1A"
    fi
fi
barrier "phase1a_done"

# ── Pha 1b : B=Day1-6 OOD (exclusive) || A=Day8 filler(train) ───────────────
if skip_has 1b; then
    echo ""; echo ">>> PHA 1b: bo qua theo --skip-phase"
else
    echo ""; echo ">>> PHA 1b bat dau [$(date '+%Y-%m-%d %H:%M:%S')]"
    if [[ "$ROLE" == "B" ]]; then
        run_day1_6 "bt_ood_B_day16"
    else
        run_day8_filler "train" "$DAY8_TRAIN_FILLER_1B"
    fi
fi
barrier "phase1b_done"

# ── Pha 1c : A=Day7 TRAIN (exclusive) || B=Day8 filler(oodtest) ─────────────
if skip_has 1c; then
    echo ""; echo ">>> PHA 1c: bo qua theo --skip-phase"
else
    echo ""; echo ">>> PHA 1c bat dau [$(date '+%Y-%m-%d %H:%M:%S')]"
    if [[ "$ROLE" == "A" ]]; then
        run_day7 "bt_train_A_day7"
    else
        run_day8_filler "oodtest" "$DAY8_OOD_FILLER_1C"
    fi
fi
barrier "phase1c_done"

# ── Pha 1d : B=Day7 OOD (exclusive) || A=Day8 filler(train) ─────────────────
if skip_has 1d; then
    echo ""; echo ">>> PHA 1d: bo qua theo --skip-phase"
else
    echo ""; echo ">>> PHA 1d bat dau [$(date '+%Y-%m-%d %H:%M:%S')]"
    if [[ "$ROLE" == "B" ]]; then
        run_day7 "bt_ood_B_day7"
    else
        run_day8_filler "train" "$DAY8_TRAIN_FILLER_1D"
    fi
fi
barrier "phase1d_done"

# ── Pha 2 : ca 2 may cung chay Day 8 coordinated dong thoi ──────────────────
if skip_has 2; then
    echo ""; echo ">>> PHA 2: bo qua theo --skip-phase"
else
    echo ""
    echo ">>> PHA 2 bat dau NGAY SAU BARRIER [$(date '+%Y-%m-%d %H:%M:%S')] -- ca 2 may dong thoi"
    echo "    scenario=$ROUND2_SCENARIO cycles=$ROUND2_CYCLES session-tag=coordinated"
    "$PY_CMD" "$DAY8_DIRECT" \
        --host-id "$HOST_ID" --session-tag coordinated \
        --scenarios "$ROUND2_SCENARIO" --cycles "$ROUND2_CYCLES" \
        --plc-ip "$TARGET_IP" --warmup 20 --cooldown 20
fi

echo ""
echo "======================================================================"
echo "  HOAN TAT TOAN BO 5 PHA -- may $ROLE (host_id=$HOST_ID, data_role=$DATA_ROLE)"
echo "  [$(date '+%Y-%m-%d %H:%M:%S')]"
echo "======================================================================"
if [[ "$ROLE" == "A" ]]; then
    echo "  Sessions Day1-7 (TRAIN) : bt_train_A_day16, bt_train_A_day7"
    echo "  Day 8 (TRAIN)           : timeline_opcua_day8_train_attacker_A.csv"
else
    echo "  Sessions Day1-7 (OOD)   : bt_ood_B_day16, bt_ood_B_day7"
    echo "  Day 8 (OOD)             : timeline_opcua_day8_oodtest_attacker_B.csv"
fi
echo "  Day 8 (coordinated)     : timeline_opcua_day8_coordinated_${HOST_ID}.csv"
echo "======================================================================"
