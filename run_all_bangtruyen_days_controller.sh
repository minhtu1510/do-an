#!/usr/bin/env bash
set -uo pipefail

# =============================================================================
# run_all_bangtruyen_days_controller.sh -- ban doi CONTROLLER cua
# run_all_bangtruyen_days.sh. Goi lai dung 2 script co san (khong sua logic):
#   Day 1-6 -> run_day_bangtruyen.sh     --day N --role controller
#   Day 7   -> run_day_bangtruyen_ext.sh --day 7 --role controller
# Day 8 (OPC UA) KHONG can lenh controller rieng -- collect_opcua.py chi can
# OPC UA server tren PLC dang bat va accessible, khong co "--role controller".
#
# Chay tren MAY CONTROLLER, --session-id/--host-id PHAI khop voi lenh attacker
# dang chay tren may attacker tuong ung (cung mot phien) de log/tag ghep dung.
#
# Cach dung:
#   bash run_all_bangtruyen_days_controller.sh --session-id bt_A_16 \
#       --host-id controller_host --iface eth0 --days "1 2 3 4 5 6"
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SCRIPT_DIR/testbed.conf" ]] && source "$SCRIPT_DIR/testbed.conf"

SESSION_ID=""
HOST_ID="${HOST_ID:-controller_host}"
TARGET_IP="${TARGET_IP:-192.168.210.211}"
RACK="${RACK:-0}"
SLOT="${SLOT:-1}"
IFACE=""
DAYS="1 2 3 4 5 6 7"
NO_CAPTURE=0

usage() {
    cat <<'EOF'
Usage:
  bash run_all_bangtruyen_days_controller.sh --session-id ID --iface NIC [options]

Bat buoc:
  --session-id ID   PHAI trung voi --session-id ben attacker dang chay cung luc.
  --iface NIC        TShark interface (bo qua neu --no-capture).

Tuy chon:
  --host-id ID            (default controller_host)
  --target IP / --rack N / --slot N
  --days "1 2 3..."        (default "1 2 3 4 5 6 7")
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
        --iface) IFACE="$2"; shift 2 ;;
        --days) DAYS="$2"; shift 2 ;;
        --no-capture) NO_CAPTURE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[ERROR] Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

[[ -n "$SESSION_ID" ]] || { echo "[ERROR] --session-id bat buoc (phai khop voi attacker)" >&2; usage; exit 1; }
[[ -n "$IFACE" || "$NO_CAPTURE" == "1" ]] || { echo "[ERROR] --iface bat buoc (hoac --no-capture)" >&2; exit 1; }

DAY1_6_SCRIPT="$SCRIPT_DIR/run_day_bangtruyen.sh"
DAY7_SCRIPT="$SCRIPT_DIR/run_day_bangtruyen_ext.sh"

echo "======================================================================"
echo "  BANG TAI -- CONTROLLER, session=$SESSION_ID host=$HOST_ID days=$DAYS"
echo "======================================================================"

for DAY in $DAYS; do
    echo ""
    echo ">>> DAY $DAY controller [$(date '+%H:%M:%S')]"
    case "$DAY" in
        1|2|3|4|5|6)
            cmd=(bash "$DAY1_6_SCRIPT" --day "$DAY" --role controller
                 --target "$TARGET_IP" --rack "$RACK" --slot "$SLOT"
                 --session-id "$SESSION_ID" --host-id "$HOST_ID")
            [[ -n "$IFACE" ]] && cmd+=(--iface "$IFACE")
            "${cmd[@]}"
            ;;
        7)
            cmd=(bash "$DAY7_SCRIPT" --day 7 --role controller
                 --target "$TARGET_IP" --rack "$RACK" --slot "$SLOT"
                 --session-id "$SESSION_ID" --host-id "$HOST_ID")
            [[ -n "$IFACE" ]] && cmd+=(--iface "$IFACE")
            "${cmd[@]}"
            ;;
        *)
            echo "[WARN] Day $DAY khong co vai tro controller rieng (vd Day 8) -- bo qua."
            ;;
    esac
done

echo ""
echo "======================================================================"
echo "  CONTROLLER XONG session=$SESSION_ID [$(date '+%H:%M:%S')]"
echo "======================================================================"
