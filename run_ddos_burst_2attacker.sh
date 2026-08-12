#!/usr/bin/env bash
set -uo pipefail

# =============================================================================
# run_ddos_burst_2attacker.sh -- CHI dung 2 may attacker cho dung phan CAN 2
# nguon that: nhom DoS/flood (S7_FLOOD, PROTOCOL_FUZZ, va 5 scenario OPC UA
# T0814). Day con lai (1-4, 6, 7, Day8 non-DoS) chay 1 may tuan tu binh
# thuong bang run_all_bangtruyen_days.sh (khong doi gi, khong can script nay).
#
# TAI SAO CHI 2 SCENARIO NAY DUOC PHEP DUNG 2 MAY:
#   - S7_FLOOD / PROTOCOL_FUZZ (Day 5, sau khi bo SYN_FLOOD vi trung co che voi
#     S7_FLOOD): chi la vong lap connect/disconnect hoac gui frame di dang,
#     KHONG ghi vao M-area cua PLC -- khong co race condition khi 2 may cung
#     lam luc. DoS/DDoS thuc su chi dung nghia khi tan cong tu NHIEU nguon,
#     nen day la truong hop DUY NHAT trong nhom S7 nen dung 2 may.
#   - 5 scenario OPC UA T0814 (SESSION_BURST, SUBSCRIPTION_FLOOD,
#     PROTOCOL_FUZZ, SLOWLORIS, RECURSIVE_BROWSE): da xac nhan read/connection-
#     level, khong ghi state -- an toan dong thoi (giong Pha 2 truoc day, gio
#     mo rong tu 2 len ca 5 scenario DoS).
#   Cac attack con lai (RWRITE_BURST, SETPOINT_ATTACK, SENSOR_SPOOF,
#   STEALTHY_WRITE, CPU_STOP, LOGIC_AWARE, CONCEALED_STOP_ATTACK...) GHI THAT
#   vao PLC -- khong bao gio duoc chay tu 2 may cung luc (xem giai thich rieng
#   ve race condition M5.0/M5.1).
#
# DA CAT BOT 2 CAP ATTACK TRUNG LAP CO CHE (truoc khi viet script nay):
#   - SYN_FLOOD bo khoi Day 5/6 (run_day_bangtruyen.sh) -- gan nhu trung S7_FLOOD,
#     ca hai deu la vong lap connect/disconnect toi port 102, S7_FLOOD dai dien.
#   - STEALTHY_WRITE bo khoi Day 7 (run_day_bangtruyen_ext.sh) -- trung y tuong
#     voi STEALTHY_WRITE cua Day 4, giu ban Day 4 lam dai dien.
#
# Cach dung:
#   May A: bash run_ddos_burst_2attacker.sh --role A --peer-ip <IP_B> --iface eth0
#   May B: bash run_ddos_burst_2attacker.sh --role B --peer-ip <IP_A> --iface eth0
#   May Controller (chi can 1 lenh, dung luc voi Buoc 1 ben duoi):
#     bash run_day_bangtruyen.sh --day 5 --role controller --session-id ddos_burst --iface eth0
#     (Buoc 2, OPC UA, khong can controller.)
#
# Buoc 1 (~1-2h): ca 2 may chay Day 5 (S7_FLOOD + PROTOCOL_FUZZ) DONG THOI.
# Buoc 2 (~10-15p): ca 2 may chay 5 scenario OPC UA DoS DONG THOI.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SCRIPT_DIR/testbed.conf" ]] && source "$SCRIPT_DIR/testbed.conf"

if [[ -z "${PY_CMD:-}" ]]; then
    command -v python3 &>/dev/null && PY_CMD="python3" || PY_CMD="python"
fi

DAY1_6_SCRIPT="$SCRIPT_DIR/run_day_bangtruyen.sh"
BARRIER="$SCRIPT_DIR/barrier_sync.py"
DAY8_DIRECT="$SCRIPT_DIR/tests/day8/collect_opcua.py"
for f in "$DAY1_6_SCRIPT" "$BARRIER" "$DAY8_DIRECT"; do
    [[ -f "$f" ]] || { echo "[ERROR] Khong tim thay $f" >&2; exit 1; }
done

ROLE=""
PEER_IP=""
TARGET_IP="${TARGET_IP:-192.168.210.211}"
RACK="${RACK:-0}"
SLOT="${SLOT:-1}"
IFACE=""
NO_CAPTURE=0
BARRIER_PORT=57124
SESSION_ID="ddos_burst"
OPCUA_CYCLES=15
OPCUA_WARMUP=20
OPCUA_COOLDOWN=20
OPCUA_DOS_SCENARIOS="OPCUA_SESSION_BURST OPCUA_SUBSCRIPTION_FLOOD OPCUA_PROTOCOL_FUZZ OPCUA_SLOWLORIS OPCUA_RECURSIVE_BROWSE"

usage() {
    cat <<'EOF'
Usage:
  bash run_ddos_burst_2attacker.sh --role A|B --peer-ip IP --iface NIC [options]

Bat buoc:
  --role A|B          Co dinh cho moi may (chi dung phan biet barrier server/client).
  --peer-ip IP         IP may attacker con lai.
  --iface NIC          TShark interface (bo qua neu --no-capture).

Tuy chon:
  --target IP / --rack N / --slot N
  --no-capture
  --barrier-port N        (default 57124)
  --session-id ID          (default ddos_burst, dung cho Day 5)
  --opcua-cycles N         (default 15)
  --opcua-warmup N / --opcua-cooldown N  (default 20 / 20)

Nhac: chay 1 lenh tren may Controller cung luc voi Buoc 1:
  bash run_day_bangtruyen.sh --day 5 --role controller --session-id ddos_burst --iface <NIC>
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
        --session-id) SESSION_ID="$2"; shift 2 ;;
        --opcua-cycles) OPCUA_CYCLES="$2"; shift 2 ;;
        --opcua-warmup) OPCUA_WARMUP="$2"; shift 2 ;;
        --opcua-cooldown) OPCUA_COOLDOWN="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[ERROR] Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

[[ "$ROLE" == "A" || "$ROLE" == "B" ]] || { echo "[ERROR] --role phai la A hoac B" >&2; usage; exit 1; }
[[ -n "$PEER_IP" ]] || { echo "[ERROR] --peer-ip bat buoc" >&2; usage; exit 1; }
[[ -n "$IFACE" || "$NO_CAPTURE" == "1" ]] || { echo "[ERROR] --iface bat buoc (hoac --no-capture)" >&2; exit 1; }

HOST_ID="attacker_${ROLE}"
IFACE_ARGS=()
[[ -n "$IFACE" ]] && IFACE_ARGS+=(--iface "$IFACE")
[[ "$NO_CAPTURE" == "1" ]] && IFACE_ARGS+=(--no-capture)

barrier() {
    local tag="$1"
    echo ""; echo "[barrier] dong bo 2 may: $tag"
    if [[ "$ROLE" == "A" ]]; then
        "$PY_CMD" "$BARRIER" --role server --port "$BARRIER_PORT" --tag "$tag"
    else
        "$PY_CMD" "$BARRIER" --role client --peer-ip "$PEER_IP" --port "$BARRIER_PORT" --tag "$tag"
    fi
}

echo "======================================================================"
echo "  DDOS BURST -- 2 may attacker DONG THOI, chi Day 5 + 5 scenario OPC UA DoS"
echo "======================================================================"
echo "  May nay : $ROLE (host_id=$HOST_ID)"
echo "  Peer IP : $PEER_IP"
echo "  Target  : $TARGET_IP rack=$RACK slot=$SLOT"
echo "======================================================================"
echo ""
echo "[!] NHAC: chay tren may Controller CUNG LUC voi Buoc 1:"
echo "    bash run_day_bangtruyen.sh --day 5 --role controller --session-id $SESSION_ID --iface <NIC controller>"
echo ""

barrier "burst_start"

echo ""
echo ">>> BUOC 1: Day 5 (S7_FLOOD + PROTOCOL_FUZZ) dong thoi tren ca 2 may [$(date '+%H:%M:%S')]"
bash "$DAY1_6_SCRIPT" --day 5 --role attacker \
    --target "$TARGET_IP" --rack "$RACK" --slot "$SLOT" \
    --session-id "$SESSION_ID" --host-id "$HOST_ID" \
    "${IFACE_ARGS[@]}"

barrier "day5_done"

echo ""
echo ">>> BUOC 2: 5 scenario OPC UA DoS dong thoi tren ca 2 may [$(date '+%H:%M:%S')]"
"$PY_CMD" "$DAY8_DIRECT" --host-id "$HOST_ID" --session-tag coordinated \
    --scenarios $OPCUA_DOS_SCENARIOS \
    --cycles "$OPCUA_CYCLES" --plc-ip "$TARGET_IP" \
    --warmup "$OPCUA_WARMUP" --cooldown "$OPCUA_COOLDOWN"

echo ""
echo "======================================================================"
echo "  DDOS BURST XONG -- may $ROLE (host_id=$HOST_ID) [$(date '+%H:%M:%S')]"
echo "======================================================================"
