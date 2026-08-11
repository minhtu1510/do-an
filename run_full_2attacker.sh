#!/usr/bin/env bash
set -uo pipefail

# =============================================================================
# run_full_2attacker.sh -- 1 LENH DUY NHAT tren MOI may ATTACKER, chay TOAN
# BO lich thu thap bangtruyen voi 2 may (host diversity + volume diversity +
# coordinated Day 8), tu dong dong bo 2 may qua barrier_sync.py.
#
# QUAN TRONG -- ly do thiet ke lai (khac ban truoc):
#   Day 1-7 (S7comm) dung CHUNG 1 PLC vat ly va CAN controller rieng cho tung
#   Day (tag logger + HMI simulation co the WRITE that vao PLC, xem
#   run_day_bangtruyen.sh::start_hmi). Vi vay Day 1-7 CHI duoc chay o 1 may
#   tai 1 thoi diem tren TOAN HE THONG (khong phai chi 1 may/1 thoi diem rieng
#   le) -- 2 may KHONG the vua chay Day 1-6 vua chay Day 7 cung luc, vi ca hai
#   cung tac dong len 1 controller/PLC va se lam sai ground-truth cua ca hai.
#
#   Day 8 (OPC UA) thi AN TOAN chay dong thoi voi Day 1-7, vi khong can
#   controller rieng (chi can OPC UA server tren PLC dang bat san) va cac
#   scenario trong DEFAULT_POOL hoac la read-only hoac la write BI TU CHOI
#   (khong thuc su doi state PLC).
#
# => Lich 5 PHA (thay vi 3 vong truoc), CHAY TUAN TU cho Day 1-7 nhung VAN
#    tan dung thoi gian ranh cua may khong-dang-la-attacker-S7-chinh de no
#    tranh thu thu them Day 8 (khong lang phi thoi gian cho o barrier):
#
#   Pha 1a (~22h) : A = Day 1-6 (S7)      || B = Day 8 filler (tag=train)
#   Pha 1b (~22h) : B = Day 1-6 (S7)      || A = Day 8 filler (tag=train)
#   Pha 1c (~4h)  : A = Day 7 (S7)        || B = Day 8 filler (tag=oodtest)
#   Pha 1d (~4h)  : B = Day 7 (S7)        || A = Day 8 filler (tag=oodtest)
#   Pha 2  (~25p) : A & B CUNG chay Day 8 --session-tag coordinated dong thoi
#
#   TONG ~52-53h/may, 1 lenh duy nhat, khong can go them gi giua chung.
#
# CONTROLLER (may thu 3, PLC/HMI that) PHAI chay RIENG, khop dung 4 pha S7
# (1a/1b/1c/1d) bang script doi ung run_full_2attacker_controller.sh (xem file
# do -- cung la 1 lenh duy nhat, tu dong noi tiep 4 pha, khong can Day 8).
#
# Cach dung (goi 1 LAN DUY NHAT tren moi may, khong can go them lenh nao nua):
#   May A:
#     bash run_full_2attacker.sh --role A --peer-ip 192.168.210.33 --iface eth0
#   May B:
#     bash run_full_2attacker.sh --role B --peer-ip 192.168.210.32 --iface eth0
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

DAY8_FILLER_LARGE_CYCLES=400   # dung trong Pha 1a/1b (~22h ranh), tag=train
DAY8_FILLER_SMALL_CYCLES=80    # dung trong Pha 1c/1d (~4h ranh), tag=oodtest
DAY8_WARMUP=60
DAY8_COOLDOWN=45

ROUND3_CYCLES=10
ROUND3_SCENARIO_A="OPCUA_SLOWLORIS"
ROUND3_SCENARIO_B="OPCUA_READ_SCRAPING"

SKIP_PHASES=""   # vd "1a 1b" de bo qua cac pha da chay roi

usage() {
    cat <<'EOF'
Usage:
  bash run_full_2attacker.sh --role A|B --peer-ip IP --iface NIC [options]

Bat buoc:
  --role A|B          May nay la A hay B (co dinh xuyen suot tat ca cac pha).
  --peer-ip IP         IP cua may attacker CON LAI (dung de dong bo barrier).
  --iface NIC          TShark capture interface (bo qua neu --no-capture).

Tuy chon:
  --target IP / --rack N / --slot N     PLC (default 192.168.210.211 / 0 / 1)
  --no-capture                          Bo qua TShark cho Day 1-7
  --barrier-port N                      Port TCP dong bo 2 may (default 57123)
  --day8-filler-large N                 Cycle Day8 filler o Pha 1a/1b (default 400)
  --day8-filler-small N                 Cycle Day8 filler o Pha 1c/1d (default 80)
  --day8-warmup N / --day8-cooldown N   (default 60 / 45)
  --round3-cycles N                     So cycle Day 8 coordinated (default 10)
  --round3-scenario-a ID / --round3-scenario-b ID
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
        --day8-filler-large) DAY8_FILLER_LARGE_CYCLES="$2"; shift 2 ;;
        --day8-filler-small) DAY8_FILLER_SMALL_CYCLES="$2"; shift 2 ;;
        --day8-warmup) DAY8_WARMUP="$2"; shift 2 ;;
        --day8-cooldown) DAY8_COOLDOWN="$2"; shift 2 ;;
        --round3-cycles) ROUND3_CYCLES="$2"; shift 2 ;;
        --round3-scenario-a) ROUND3_SCENARIO_A="$2"; shift 2 ;;
        --round3-scenario-b) ROUND3_SCENARIO_B="$2"; shift 2 ;;
        --skip-phase) SKIP_PHASES="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[ERROR] Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

[[ "$ROLE" == "A" || "$ROLE" == "B" ]] || { echo "[ERROR] --role phai la A hoac B" >&2; usage; exit 1; }
[[ -n "$PEER_IP" ]] || { echo "[ERROR] --peer-ip bat buoc" >&2; usage; exit 1; }
[[ -n "$IFACE" || "$NO_CAPTURE" == "1" ]] || { echo "[ERROR] --iface bat buoc (hoac dung --no-capture)" >&2; exit 1; }

HOST_ID="attacker_${ROLE}"
[[ "$ROLE" == "A" ]] && ROUND3_SCENARIO="$ROUND3_SCENARIO_A" || ROUND3_SCENARIO="$ROUND3_SCENARIO_B"

IFACE_ARGS=()
[[ -n "$IFACE" ]] && IFACE_ARGS+=(--iface "$IFACE")
[[ "$NO_CAPTURE" == "1" ]] && IFACE_ARGS+=(--no-capture)

skip_has() { [[ " $SKIP_PHASES " == *" $1 "* ]]; }

echo "======================================================================"
echo "  BANG TAI -- FULL 2-ATTACKER SCHEDULE (5 pha, xem comment dau file)"
echo "======================================================================"
echo "  May nay    : $ROLE  (host_id=$HOST_ID)"
echo "  Peer IP    : $PEER_IP  (chi dung dong bo barrier, khong tan cong)"
echo "  Barrier    : port $BARRIER_PORT, role A=server co dinh, role B=client co dinh"
echo "  Target PLC : $TARGET_IP rack=$RACK slot=$SLOT"
echo "  Round3 scn : $ROUND3_SCENARIO"
[[ -n "$SKIP_PHASES" ]] && echo "  Skip phase : $SKIP_PHASES"
echo "======================================================================"
echo ""
echo "[!] NHAC: chay dong thoi tren may CONTROLLER:"
echo "    bash run_full_2attacker_controller.sh --iface <NIC controller>"
echo "    (script do tu noi tiep dung Day 1-6/Day 7 khop 4 pha S7 ben duoi)"
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
    echo "[day8-filler] host_id=$HOST_ID tag=$tag cycles=$cycles (tranh khong ngoi khong o barrier)"
    "$PY_CMD" "$DAY8_DIRECT" --host-id "$HOST_ID" --session-tag "$tag" \
        --cycles "$cycles" --plc-ip "$TARGET_IP" \
        --warmup "$DAY8_WARMUP" --cooldown "$DAY8_COOLDOWN"
}

# ── Pha 1a : A=Day1-6 (exclusive) || B=Day8 filler(train) ───────────────────
if skip_has 1a; then
    echo ""; echo ">>> PHA 1a: bo qua theo --skip-phase"
else
    echo ""; echo ">>> PHA 1a bat dau [$(date '+%Y-%m-%d %H:%M:%S')]"
    if [[ "$ROLE" == "A" ]]; then
        run_day1_6 "bt_phase1a_A"
    else
        run_day8_filler "train" "$DAY8_FILLER_LARGE_CYCLES"
    fi
fi
barrier "phase1a_done"

# ── Pha 1b : B=Day1-6 (exclusive) || A=Day8 filler(train) ───────────────────
if skip_has 1b; then
    echo ""; echo ">>> PHA 1b: bo qua theo --skip-phase"
else
    echo ""; echo ">>> PHA 1b bat dau [$(date '+%Y-%m-%d %H:%M:%S')]"
    if [[ "$ROLE" == "B" ]]; then
        run_day1_6 "bt_phase1b_B"
    else
        run_day8_filler "train" "$DAY8_FILLER_LARGE_CYCLES"
    fi
fi
barrier "phase1b_done"

# ── Pha 1c : A=Day7 (exclusive) || B=Day8 filler(oodtest) ───────────────────
if skip_has 1c; then
    echo ""; echo ">>> PHA 1c: bo qua theo --skip-phase"
else
    echo ""; echo ">>> PHA 1c bat dau [$(date '+%Y-%m-%d %H:%M:%S')]"
    if [[ "$ROLE" == "A" ]]; then
        run_day7 "bt_phase1c_A"
    else
        run_day8_filler "oodtest" "$DAY8_FILLER_SMALL_CYCLES"
    fi
fi
barrier "phase1c_done"

# ── Pha 1d : B=Day7 (exclusive) || A=Day8 filler(oodtest) ───────────────────
if skip_has 1d; then
    echo ""; echo ">>> PHA 1d: bo qua theo --skip-phase"
else
    echo ""; echo ">>> PHA 1d bat dau [$(date '+%Y-%m-%d %H:%M:%S')]"
    if [[ "$ROLE" == "B" ]]; then
        run_day7 "bt_phase1d_B"
    else
        run_day8_filler "oodtest" "$DAY8_FILLER_SMALL_CYCLES"
    fi
fi
barrier "phase1d_done"

# ── Pha 2 : ca 2 may cung chay Day 8 coordinated dong thoi ──────────────────
if skip_has 2; then
    echo ""; echo ">>> PHA 2: bo qua theo --skip-phase"
else
    echo ""
    echo ">>> PHA 2 bat dau NGAY SAU BARRIER [$(date '+%Y-%m-%d %H:%M:%S')] -- ca 2 may dong thoi"
    echo "    scenario=$ROUND3_SCENARIO cycles=$ROUND3_CYCLES session-tag=coordinated"
    "$PY_CMD" "$DAY8_DIRECT" \
        --host-id "$HOST_ID" --session-tag coordinated \
        --scenarios "$ROUND3_SCENARIO" --cycles "$ROUND3_CYCLES" \
        --plc-ip "$TARGET_IP" --warmup 20 --cooldown 20
fi

echo ""
echo "======================================================================"
echo "  HOAN TAT TOAN BO 5 PHA -- may $ROLE (host_id=$HOST_ID) [$(date '+%Y-%m-%d %H:%M:%S')]"
echo "======================================================================"
echo "  Sessions Day1-7: bt_phase1a_A, bt_phase1b_B, bt_phase1c_A, bt_phase1d_B"
echo "  Day 8 timeline : test_results/day8/timeline_opcua_day8_{train,oodtest,coordinated}_${HOST_ID}.csv"
echo "======================================================================"
