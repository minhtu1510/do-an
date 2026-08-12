#!/usr/bin/env bash
set -uo pipefail

# =============================================================================
# run_full_2attacker_controller.sh -- 1 LENH DUY NHAT tren may CONTROLLER,
# noi tiep dung 4 pha S7 (1a/1b/1c/1d) khop voi run_full_2attacker.sh chay
# tren 2 may attacker A/B. Day 8 (Pha 2, OPC UA) KHONG can lenh controller.
#
# Khong dung barrier voi attacker (controller chi co san run_day_bangtruyen.sh
# / run_day_bangtruyen_ext.sh, khong ho tro socket dong bo). Thay vao do dua
# vao viec CA HAI BEN dung chung hang so thoi luong tu testbed.conf (vd
# DAY1_DURATION_S..DAY6_DURATION_S, DAY7_DURATION_S) nen tu nhien ket thuc
# gan nhau; moi Day/pha da co san warmup/cooldown vai tram giay lam dem, du
# de hap thu do lech vai phut do attacker co them --gap giua cac day/preflight
# ma controller khong co.
#
# BAT DAU script nay CUNG LUC voi khi May A bat dau Pha 1a ben attacker.
#
# Cach dung:
#   bash run_full_2attacker_controller.sh --iface eth0
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SCRIPT_DIR/testbed.conf" ]] && source "$SCRIPT_DIR/testbed.conf"

CTRL_ORCH="$SCRIPT_DIR/run_all_bangtruyen_days_controller.sh"
[[ -f "$CTRL_ORCH" ]] || { echo "[ERROR] Khong tim thay $CTRL_ORCH" >&2; exit 1; }

TARGET_IP="${TARGET_IP:-192.168.210.211}"
RACK="${RACK:-0}"
SLOT="${SLOT:-1}"
IFACE=""
NO_CAPTURE=0
HOST_ID="${HOST_ID:-controller_host}"

usage() {
    cat <<'EOF'
Usage:
  bash run_full_2attacker_controller.sh --iface NIC [options]

Bat buoc:
  --iface NIC   TShark interface tren may controller (bo qua neu --no-capture)

Tuy chon:
  --target IP / --rack N / --slot N
  --host-id ID       (default controller_host)
  --no-capture
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET_IP="$2"; shift 2 ;;
        --rack) RACK="$2"; shift 2 ;;
        --slot) SLOT="$2"; shift 2 ;;
        --iface) IFACE="$2"; shift 2 ;;
        --host-id) HOST_ID="$2"; shift 2 ;;
        --no-capture) NO_CAPTURE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[ERROR] Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

[[ -n "$IFACE" || "$NO_CAPTURE" == "1" ]] || { echo "[ERROR] --iface bat buoc (hoac --no-capture)" >&2; exit 1; }

IFACE_ARGS=()
[[ -n "$IFACE" ]] && IFACE_ARGS+=(--iface "$IFACE")
[[ "$NO_CAPTURE" == "1" ]] && IFACE_ARGS+=(--no-capture)

run_ctrl_days() {
    local session="$1" days="$2"
    bash "$CTRL_ORCH" --session-id "$session" --host-id "$HOST_ID" \
        --target "$TARGET_IP" --rack "$RACK" --slot "$SLOT" \
        --days "$days" "${IFACE_ARGS[@]}"
}

echo "======================================================================"
echo "  BANG TAI -- CONTROLLER, noi tiep 4 pha S7 (khop run_full_2attacker.sh)"
echo "======================================================================"

echo ""; echo ">>> PHA 1a (khop May A / Day1-6 TRAIN) controller bat dau [$(date '+%H:%M:%S')]"
run_ctrl_days "bt_train_A_day16" "1 2 3 4 5 6"

echo ""; echo ">>> PHA 1b (khop May B / Day1-6 OOD) controller bat dau [$(date '+%H:%M:%S')]"
run_ctrl_days "bt_ood_B_day16" "1 2 3 4 5 6"

echo ""; echo ">>> PHA 1c (khop May A / Day7 TRAIN) controller bat dau [$(date '+%H:%M:%S')]"
run_ctrl_days "bt_train_A_day7" "7"

echo ""; echo ">>> PHA 1d (khop May B / Day7 OOD) controller bat dau [$(date '+%H:%M:%S')]"
run_ctrl_days "bt_ood_B_day7" "7"

echo ""
echo "======================================================================"
echo "  CONTROLLER HOAN TAT CA 4 PHA [$(date '+%H:%M:%S')]"
echo "  Pha 2 (Day 8 coordinated) KHONG can controller -- chi can OPC UA"
echo "  server tren PLC dang bat, 2 may attacker se tu chay."
echo "======================================================================"
