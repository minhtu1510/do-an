#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# run_full_5_days.sh
# Legacy 5-day traffic-light collection wrapper.
#
# Prefer run_day_bangtruyen.sh for the conveyor publication dataset. Use this
# wrapper only for the older traffic-light flow after confirming the checklist.
#
# Pre-run checklist:
#   1. Set TARGET_IP/RACK/SLOT and CAPTURE_IFACE in testbed.conf.
#   2. Confirm PLC is powered, reachable, in a lab-safe state, and PUT/GET is enabled.
#   3. Run: tshark -D
#   4. Run: bash run_full_5_days.sh --preflight-only
#   5. Confirm Git Bash resolves python/python3 to the environment with python-snap7.
# ==============================================================================

[[ -f testbed.conf ]] && source ./testbed.conf

if [[ -z "${PY_CMD:-}" ]]; then
    command -v python3 &>/dev/null && PY_CMD="python3" || PY_CMD="python"
fi

TARGET_IP="${TARGET_IP:-192.168.1.10}"
RACK="${RACK:-0}"
SLOT="${SLOT:-1}"
CAPTURE_IFACE="${CAPTURE_IFACE:-${IFACE:-}}"
CAPTURE_ENABLED="${CAPTURE_ENABLED:-1}"
ENABLE_CPU_CONTROL_ATTACK="${ENABLE_CPU_CONTROL_ATTACK:-0}"
SESSION_PREFIX="${SESSION_PREFIX:-full5}"
HOST_ID="${ATTACKER_HOST_ID:-attacker_host}"
TAG_INTERVAL="${TAG_LOG_INTERVAL:-0.5}"

usage() {
    cat <<'EOF'
Usage:
  bash run_full_5_days.sh [options]

Options:
  --target IP             PLC IP address.
  --rack N                PLC rack, default 0.
  --slot N                PLC slot, default 1.
  --iface IFACE           Capture interface from `tshark -D` / `dumpcap -D`.
  --session-prefix ID     Prefix for generated session ids.
  --host-id ID            Host metadata for collect_dataset.py.
  --enable-cpu-control    Include day-5 cpu_control phase. Default disabled.
  --preflight-only        Run PLC/capture checks and exit.
  -h, --help              Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET_IP="$2"; shift 2 ;;
        --rack) RACK="$2"; shift 2 ;;
        --slot) SLOT="$2"; shift 2 ;;
        --iface) CAPTURE_IFACE="$2"; shift 2 ;;
        --session-prefix) SESSION_PREFIX="$2"; shift 2 ;;
        --host-id) HOST_ID="$2"; shift 2 ;;
        --enable-cpu-control) ENABLE_CPU_CONTROL_ATTACK="1"; shift ;;
        --preflight-only) PREFLIGHT_ONLY="1"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[ERROR] Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

declare -a PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do
        kill "$p" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

print_capture_interfaces() {
    if command -v tshark &>/dev/null; then
        echo "[capture] Available TShark interfaces:"
        tshark -D || true
    elif command -v dumpcap &>/dev/null; then
        echo "[capture] Available Dumpcap interfaces:"
        dumpcap -D || true
    else
        echo "[capture] Neither tshark nor dumpcap is in PATH. Install Wireshark/Npcap and reopen Git Bash."
    fi
}

validate_capture_config() {
    [[ "$CAPTURE_ENABLED" == "1" ]] || return 0
    local tool=""
    if command -v tshark &>/dev/null; then
        tool="tshark"
    elif command -v dumpcap &>/dev/null; then
        tool="dumpcap"
    else
        echo "[ERROR] CAPTURE_ENABLED=1 but neither tshark nor dumpcap was found." >&2
        print_capture_interfaces >&2
        exit 2
    fi

    if [[ -z "$CAPTURE_IFACE" ]]; then
        echo "[ERROR] CAPTURE_ENABLED=1 but CAPTURE_IFACE/--iface is empty." >&2
        echo "[ERROR] Run 'tshark -D' and set CAPTURE_IFACE in testbed.conf or pass --iface." >&2
        print_capture_interfaces >&2
        exit 2
    fi

    local ifaces
    ifaces="$($tool -D 2>/dev/null || true)"
    if [[ "$CAPTURE_IFACE" =~ ^[0-9]+$ ]]; then
        if ! grep -Eq "^[[:space:]]*${CAPTURE_IFACE}\." <<<"$ifaces"; then
            echo "[ERROR] Capture interface index '$CAPTURE_IFACE' was not found." >&2
            print_capture_interfaces >&2
            exit 2
        fi
    elif ! grep -Fq -- "$CAPTURE_IFACE" <<<"$ifaces"; then
        echo "[ERROR] Capture interface '$CAPTURE_IFACE' was not found." >&2
        print_capture_interfaces >&2
        exit 2
    fi
}

preflight_plc() {
    "$PY_CMD" - <<PYEOF
import sys
import snap7
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
    try:
        print(f"[preflight] CPU state: {c.get_cpu_state()}", flush=True)
    except Exception as exc:
        print(f"[preflight][WARN] cannot read CPU state: {exc}", flush=True)
    m = c.read_area(Areas.MK, 0, 0, 82)
    print(f"[preflight] read M area OK ({len(m)} bytes)", flush=True)
    c.disconnect()
    sys.exit(0)
except Exception as exc:
    print(f"[preflight][ERROR] Snap7 check failed: {exc}", flush=True)
    try:
        c.disconnect()
    except Exception:
        pass
    sys.exit(2)
PYEOF
}

validate_capture_config
preflight_plc

if [[ "${PREFLIGHT_ONLY:-0}" == "1" ]]; then
    echo "[preflight] done"
    exit 0
fi

run_day() {
    local day_num="$1"
    local phases="$2"
    local process_log="day${day_num}_process.csv"
    local dataset_dir="dataset_day${day_num}"
    local session_id="${SESSION_PREFIX}_day${day_num}"
    local net_csv=""
    local final_csv="final_dataset_day${day_num}.csv"

    echo "=========================================================="
    echo " START DAY $day_num"
    echo " Target=$TARGET_IP rack=$RACK slot=$SLOT iface=$CAPTURE_IFACE"
    echo " Phases=$phases session=$session_id host=$HOST_ID"
    echo "=========================================================="

    echo "[*] Start process logger -> $process_log"
    "$PY_CMD" log_tags.py \
        --target "$TARGET_IP" \
        --rack "$RACK" \
        --slot "$SLOT" \
        --interval "$TAG_INTERVAL" \
        --output "$process_log" &
    PIDS+=("$!")
    local process_pid="$!"

    sleep 2

    echo "[*] Start network collector -> $dataset_dir"
    local collector_args=(
        collect_dataset.py
        --target "$TARGET_IP"
        --rack "$RACK"
        --slot "$SLOT"
        --iface "$CAPTURE_IFACE"
        --phase "$phases"
        --output "$dataset_dir"
        --session-id "$session_id"
        --host-id "$HOST_ID"
    )
    if [[ "$ENABLE_CPU_CONTROL_ATTACK" == "1" ]]; then
        collector_args+=(--enable-cpu-control)
    fi
    "$PY_CMD" "${collector_args[@]}"

    echo "[*] Stop process logger"
    kill -SIGINT "$process_pid" 2>/dev/null || true
    wait "$process_pid" 2>/dev/null || true

    net_csv=$(ls -t "${dataset_dir}"/labeled_dataset_*.csv 2>/dev/null | head -n 1 || true)
    if [[ -n "$net_csv" && -f "$net_csv" ]]; then
        echo "[*] Merge network/process datasets -> $final_csv"
        "$PY_CMD" preprocess_pipeline.py --net "$net_csv" --phys "$process_log" --out "$final_csv"
        echo "[+] Day $day_num complete: $final_csv"
    else
        echo "[!] Network CSV not found in $dataset_dir. Check capture interface/backend and collector logs." >&2
    fi
    echo ""
}

day5_phases="normal,replay"
if [[ "$ENABLE_CPU_CONTROL_ATTACK" == "1" ]]; then
    day5_phases="${day5_phases},cpu_control"
else
    echo "[info] Day 5 cpu_control disabled by default. Use --enable-cpu-control only if PLC permits it."
fi

run_day 1 "normal"
run_day 2 "normal,scan,enum_tags"
run_day 3 "normal,rwrite,spoof_constant"
run_day 4 "normal,flood,fuzz"
run_day 5 "$day5_phases"

echo "=========================================================="
echo " FULL 5-DAY LEGACY COLLECTION COMPLETE"
echo " final_dataset_day1.csv -> final_dataset_day5.csv are ready if all days succeeded."
echo "=========================================================="
