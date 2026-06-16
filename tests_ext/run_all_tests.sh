#!/usr/bin/env bash
# ================================================================
# tests_ext/run_all_tests.sh
# Chạy toàn bộ test theo thứ tự, dừng nếu FAIL.
#
# Usage:
#   bash tests_ext/run_all_tests.sh 192.168.1.10 192.168.1.20 eth0
#
#   # Với custom ports
#   TARGET=192.168.1.10 HMI=192.168.1.20 IFACE=eth0 bash tests_ext/run_all_tests.sh
# ================================================================
set -euo pipefail

TARGET="${1:-${TARGET:-192.168.1.10}}"
HMI="${2:-${HMI:-192.168.1.20}}"
IFACE="${3:-${IFACE:-eth0}}"

PY_CMD="${PY_CMD:-python3}"

PASS=0
FAIL=0
TOTAL=0

run_test() {
    local name="$1" cmd="$2"
    TOTAL=$((TOTAL + 1))
    echo ""
    echo "========================================"
    echo "  TEST #${TOTAL}: ${name}"
    echo "========================================"
    if eval "$cmd"; then
        PASS=$((PASS + 1))
        echo "  >> PASS"
    else
        FAIL=$((FAIL + 1))
        echo "  >> FAIL"
    fi
}

echo "================================================================"
echo "  ICS ATTACK TEST SUITE"
echo "  PLC: $TARGET  |  HMI: $HMI  |  IFACE: $IFACE"
echo "================================================================"

# ── Bước 1: Kiểm tra kết nối ────────────────────────────────────
run_test "Ping PLC"                     "ping -c 2 -W 1 $TARGET"
run_test "TCP port 102 (S7)"            "timeout 3 bash -c '</dev/tcp/$TARGET/102' 2>/dev/null && true"
run_test "Ping HMI"                     "ping -c 2 -W 1 $HMI"
run_test "TCP port 4840 (OPC-UA)"       "timeout 3 bash -c '</dev/tcp/$HMI/4840' 2>/dev/null && true"

# ── Bước 2: Python connectivity ─────────────────────────────────
run_test "Snap7 connect PLC" \
    "sudo -E $PY_CMD -c 'import snap7; c=snap7.client.Client(); c.connect(\"$TARGET\",0,1); print(\"State:\", c.get_cpu_state()); c.disconnect()'"

# ── Bước 3: Attack module tests ─────────────────────────────────
run_test "EWS Rogue Engineer" \
    "$PY_CMD tests_ext/test_ews_rogue_engineer.py --target $TARGET"

run_test "EWS Firmware Tamper" \
    "$PY_CMD tests_ext/test_ews_firmware_tamper.py --target $TARGET"

run_test "HMI Credential Brute" \
    "$PY_CMD tests_ext/test_hmi_credential_brute.py --target-url http://${HMI}:5000"

run_test "HMI Alarm Suppress (OPC-UA)" \
    "$PY_CMD tests_ext/test_hmi_alarm_suppress.py --opc-url opc.tcp://${HMI}:4840"

run_test "HMI Fake Display (OPC-UA)" \
    "$PY_CMD tests_ext/test_hmi_fake_display.py --opc-url opc.tcp://${HMI}:4840"

# ── Bước 4: DNS spoof (cần root) ────────────────────────────────
run_test "DNS Spoof (scapy)" \
    "sudo -E $PY_CMD tests_ext/test_dns_spoof_ics.py --iface $IFACE --attacker-ip $(hostname -I | awk '{print $1}')"

echo ""
echo "================================================================"
echo "  TEST SUITE COMPLETE"
echo "  Passed: $PASS / $TOTAL"
echo "  Failed: $FAIL / $TOTAL"
echo "================================================================"

if [[ "$FAIL" -gt 0 ]]; then
    echo "  [!] Có test FAIL — kiểm tra lại trước khi chạy Day 7"
    exit 1
else
    echo "  [OK] Tất cả test PASS — sẵn sàng chạy Day 7:"
    echo "       bash run_day_bangtruyen_ext.sh --day 7 --role attacker --session-id bt_s1 --iface $IFACE"
    exit 0
fi
