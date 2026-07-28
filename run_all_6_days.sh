#!/usr/bin/env bash
# =============================================================================
# run_all_6_days.sh — Chạy tự động 6 ngày liên tiếp (1 lệnh duy nhất)
# =============================================================================
#
# Cách dùng:
#   bash run_all_6_days.sh --iface 3
#   bash run_all_6_days.sh --iface 3 --target 192.168.1.10 --session bt_s2
#   bash run_all_6_days.sh --iface 3 --days 2 3 4     # chỉ chạy ngày chọn
#   bash run_all_6_days.sh --iface 3 --profile extended_300k
#
# Nên chạy vào ban đêm (toàn bộ mất ~16-20 giờ profile standard).
# Log toàn bộ ra file để xem lại:
#   bash run_all_6_days.sh --iface 3 2>&1 | tee collection_run.log
# =============================================================================
set -uo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
TARGET_IP="${TARGET_IP:-192.168.1.10}"
RACK="${RACK:-0}"
SLOT="${SLOT:-1}"
IFACE=""
SESSION_ID="${SESSION_ID:-bt_s1}"
PROFILE="standard"
DAYS="1 2 3 4 5 6"
INTER_DAY_GAP="${INTER_DAY_GAP:-60}"   # giây nghỉ giữa các ngày

[[ -f testbed.conf ]] && source ./testbed.conf

# ── Parse args ────────────────────────────────────────────────────────────────
usage() {
    cat <<'EOF'
Usage:
  bash run_all_6_days.sh --iface <NIC> [options]

Required:
  --iface NIC        TShark capture interface (run: tshark -D)

Options:
  --target IP        PLC IP (default: 192.168.1.10)
  --rack N           PLC rack (default: 0)
  --slot N           PLC slot (default: 1)
  --session ID       Session ID cho dataset (default: bt_s1)
  --days "1 2 3..."  Danh sách ngày muốn chạy (default: 1 2 3 4 5 6)
  --profile P        standard | extended_300k
  --gap N            Giây nghỉ giữa các ngày (default: 60)
  --no-capture       Skip TShark (capture từ thiết bị ngoài)
  --no-preflight     Skip preflight check

Examples:
  # Chạy đủ 6 ngày qua đêm:
  bash run_all_6_days.sh --iface 3 --session bt_s1

  # Chỉ chạy ngày 2 và 3 (đã có ngày 1):
  bash run_all_6_days.sh --iface 3 --days "2 3"

  # Dataset lớn (~300k windows):
  bash run_all_6_days.sh --iface 3 --profile extended_300k
EOF
}

EXTRA_ARGS=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --iface)      IFACE="$2";        shift 2 ;;
        --target)     TARGET_IP="$2";    shift 2 ;;
        --rack)       RACK="$2";         shift 2 ;;
        --slot)       SLOT="$2";         shift 2 ;;
        --session)    SESSION_ID="$2";   shift 2 ;;
        --profile)    PROFILE="$2";      shift 2 ;;
        --days)       DAYS="$2";         shift 2 ;;
        --gap)        INTER_DAY_GAP="$2"; shift 2 ;;
        --no-capture) EXTRA_ARGS="$EXTRA_ARGS --no-capture"; shift ;;
        --no-preflight) EXTRA_ARGS="$EXTRA_ARGS --no-preflight"; shift ;;
        -h|--help)    usage; exit 0 ;;
        *) echo "[ERROR] Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

[[ -z "$IFACE" && "$EXTRA_ARGS" != *"--no-capture"* ]] && {
    echo "[ERROR] --iface required (run: tshark -D to list interfaces)" >&2
    exit 1
}

# ── Summary ───────────────────────────────────────────────────────────────────
START_TIME=$(date '+%Y-%m-%d %H:%M:%S')
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║       ICS DATASET COLLECTION — run_all_6_days.sh            ║"
echo "╠══════════════════════════════════════════════════════════════╣"
printf "║  Start   : %-49s ║\n" "$START_TIME"
printf "║  Target  : %-49s ║\n" "$TARGET_IP rack=$RACK slot=$SLOT"
printf "║  Session : %-49s ║\n" "$SESSION_ID"
printf "║  Days    : %-49s ║\n" "$DAYS"
printf "║  Profile : %-49s ║\n" "$PROFILE"
printf "║  Iface   : %-49s ║\n" "${IFACE:-none (--no-capture)}"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMBINED_SCRIPT="$SCRIPT_DIR/run_combined_day.sh"

if [[ ! -f "$COMBINED_SCRIPT" ]]; then
    echo "[ERROR] run_combined_day.sh not found at $COMBINED_SCRIPT" >&2
    exit 1
fi

# ── Status tracking ───────────────────────────────────────────────────────────
RESULTS_FILE="collection_results_${SESSION_ID}.txt"
{
    echo "Collection Results — Session: $SESSION_ID"
    echo "Started: $START_TIME"
    echo "Days: $DAYS | Profile: $PROFILE"
    echo "────────────────────────────────────────"
} > "$RESULTS_FILE"

SUCCESS_DAYS=()
FAILED_DAYS=()

# ── Run each day ──────────────────────────────────────────────────────────────
for DAY in $DAYS; do
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " STARTING DAY $DAY  [$(date '+%H:%M:%S')]"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    DAY_START=$(date +%s)

    # Build command
    CMD=(bash "$COMBINED_SCRIPT"
        --day "$DAY"
        --target "$TARGET_IP"
        --rack "$RACK"
        --slot "$SLOT"
        --session "$SESSION_ID"
        --profile "$PROFILE"
    )
    [[ -n "$IFACE" ]]                   && CMD+=(--iface "$IFACE")
    [[ "$EXTRA_ARGS" == *no-capture* ]] && CMD+=(--no-capture)
    [[ "$EXTRA_ARGS" == *no-preflight* ]] && CMD+=(--no-preflight)
    # Preflight chỉ cần ngày đầu tiên
    [[ "${DAY}" != "${DAYS%% *}" ]]     && CMD+=(--no-preflight)

    if "${CMD[@]}"; then
        DAY_END=$(date +%s)
        ELAPSED=$(( DAY_END - DAY_START ))
        echo ""
        echo "✓ Day $DAY DONE in ${ELAPSED}s [$(date '+%H:%M:%S')]"
        echo "Day $DAY: SUCCESS (${ELAPSED}s)" >> "$RESULTS_FILE"
        SUCCESS_DAYS+=("$DAY")
    else
        EXIT_CODE=$?
        echo ""
        echo "✗ Day $DAY FAILED (exit $EXIT_CODE) [$(date '+%H:%M:%S')]"
        echo "Day $DAY: FAILED (exit $EXIT_CODE)" >> "$RESULTS_FILE"
        FAILED_DAYS+=("$DAY")
        echo ""
        echo "Continue with remaining days? (Ctrl+C to abort, Enter to continue)"
        read -r -t 30 || true
    fi

    # Nghỉ giữa các ngày
    REMAINING_DAYS="${DAYS#*$DAY}"
    REMAINING_DAYS="${REMAINING_DAYS# }"
    if [[ -n "$REMAINING_DAYS" ]]; then
        echo "[gap] ${INTER_DAY_GAP}s inter-day pause before Day ${REMAINING_DAYS%% *}..."
        sleep "$INTER_DAY_GAP"
    fi
done

# ── Final summary ─────────────────────────────────────────────────────────────
END_TIME=$(date '+%Y-%m-%d %H:%M:%S')
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                  COLLECTION COMPLETE                        ║"
echo "╠══════════════════════════════════════════════════════════════╣"
printf "║  Ended   : %-49s ║\n" "$END_TIME"
printf "║  Session : %-49s ║\n" "$SESSION_ID"
printf "║  OK days : %-49s ║\n" "${SUCCESS_DAYS[*]:-none}"
printf "║  Failed  : %-49s ║\n" "${FAILED_DAYS[*]:-none}"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Output files:                                               ║"
printf "║    PCAP  : captures/${SESSION_ID}_day*.pcapng%-15s ║\n" ""
printf "║    Tags  : logs/${SESSION_ID}_day*_tags.csv%-18s ║\n" ""
printf "║    Labels: labels/${SESSION_ID}_day*_timeline.csv%-12s ║\n" ""
printf "║    Events: labels/${SESSION_ID}_day*_attack_events.csv%-6s ║\n" ""
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

{
    echo "────────────────────────────────────────"
    echo "Ended: $END_TIME"
    echo "Success: ${SUCCESS_DAYS[*]:-none}"
    echo "Failed:  ${FAILED_DAYS[*]:-none}"
} >> "$RESULTS_FILE"

echo "Summary saved to: $RESULTS_FILE"

# Gợi ý bước tiếp theo
echo ""
echo "Bước tiếp theo:"
echo "  1. Trích xuất features:"
echo "     python SemanticAware-S7comm-Dataset/scripts/feature_extract.py \\"
echo "       --pcap captures/${SESSION_ID}_day1.pcapng --output processed/day1_features.csv"
echo "  2. Merge dataset:"
echo "     python SemanticAware-S7comm-Dataset/scripts/merge_dataset.py \\"
echo "       --features-dir processed/ --tags-dir logs/ --labels-dir labels/ \\"
echo "       --output-dir SemanticAware-S7comm-Dataset/processed/"
echo "  3. Train ML:"
echo "     python SemanticAware-S7comm-Dataset/scripts/train_ml.py \\"
echo "       --network-data SemanticAware-S7comm-Dataset/processed/network.csv \\"
echo "       --fusion-data SemanticAware-S7comm-Dataset/processed/fusion.csv \\"
echo "       --output-dir ml_results/new_run --feature-profile hybrid \\"
echo "       --binary-threshold-mode fbeta_oof --validation-session-id day6"

[[ "${#FAILED_DAYS[@]}" -gt 0 ]] && exit 1 || exit 0
