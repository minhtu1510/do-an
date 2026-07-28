#!/usr/bin/env bash
# =============================================================================
# run_pipeline.sh — Xử lý dữ liệu sau khi thu thập xong 6 ngày PCAP
# =============================================================================
# Chạy sau run_all_6_days.sh khi đã có đủ:
#   captures/bt_s1_day{1-6}.pcapng
#   logs/bt_s1_day{1-6}_tags.csv
#   labels/bt_s1_day{1-6}_timeline.csv
#   labels/bt_s1_day{1-6}_attack_events.csv
#
# Pipeline: PCAP → features → merge → train ML
#
# Usage:
#   bash run_pipeline.sh
#   bash run_pipeline.sh --session bt_s2 --plc-ip 192.168.1.10
# =============================================================================
set -uo pipefail

# ── Cấu hình — sửa nếu cần ──────────────────────────────────────────────────
SESSION="${SESSION:-bt_s1}"
HOST_ID="${HOST_ID:-combined_host}"
PLC_IP="${PLC_IP:-192.168.1.10}"
WINDOW="${WINDOW:-2.0}"

CAPTURE_DIR="${CAPTURE_DIR:-captures}"
LOG_DIR="${LOG_DIR:-logs}"
LABEL_DIR="${LABEL_DIR:-labels}"
PROCESSED_DIR="${PROCESSED_DIR:-SemanticAware-S7comm-Dataset/processed}"
ML_OUTPUT="${ML_OUTPUT:-ml_results/main_run}"

SCRIPTS_DIR="SemanticAware-S7comm-Dataset/scripts"

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --session)    SESSION="$2";    shift 2 ;;
        --plc-ip)     PLC_IP="$2";     shift 2 ;;
        --host-id)    HOST_ID="$2";    shift 2 ;;
        --window)     WINDOW="$2";     shift 2 ;;
        *) echo "[ERROR] Unknown: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "${PY_CMD:-}" ]]; then
    command -v python3 &>/dev/null && PY_CMD="python3" || PY_CMD="python"
fi

mkdir -p "$PROCESSED_DIR" "$ML_OUTPUT"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║        ICS IDS Pipeline — Post-Collection           ║"
echo "╠══════════════════════════════════════════════════════╣"
printf "║  Session : %-41s ║\n" "$SESSION"
printf "║  PLC IP  : %-41s ║\n" "$PLC_IP"
printf "║  Window  : %-41s ║\n" "${WINDOW}s"
printf "║  Output  : %-41s ║\n" "$PROCESSED_DIR"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# =============================================================================
# BƯỚC 1 — TRÍCH XUẤT ĐẶC TRƯNG TỪ PCAP (1 lần / ngày)
# =============================================================================
# QUAN TRỌNG:
#   --session-id  = "day1" / "day2" ... / "day6"
#       → Phải khác nhau mỗi ngày để GroupKFold phân tách đúng
#       → train_ml.py dùng --validation-session-id day6 để giữ Day 6 làm holdout
#
#   --host-id     = "combined_host"
#       → Phải nhất quán qua tất cả ngày
#
#   Cả hai đều bị DROP khỏi ML features (trong SAFE_DROP_EXACT)
#   Chỉ dùng để tạo group key: session_id|host_id|episode_id cho GroupKFold

echo "=== BƯỚC 1: Feature Extraction (6 ngày) ==="
echo ""

EXTRACT_OK=1
for DAY in 1 2 3 4 5 6; do
    PCAP="${CAPTURE_DIR}/${SESSION}_day${DAY}.pcapng"
    TIMELINE="${LABEL_DIR}/${SESSION}_day${DAY}_timeline.csv"
    TAGLOG="${LOG_DIR}/${SESSION}_day${DAY}_tags.csv"
    OUT="${PROCESSED_DIR}/day${DAY}_features.csv"

    if [[ ! -f "$PCAP" ]]; then
        echo "[SKIP] Day $DAY: PCAP không tìm thấy ($PCAP)"
        EXTRACT_OK=0
        continue
    fi

    echo "[Day $DAY] Extracting: $PCAP → $OUT"

    EXTRA_ARGS=()
    [[ -f "$TIMELINE" ]] && EXTRA_ARGS+=(--timeline "$TIMELINE") || echo "  [WARN] Không có timeline, dùng label=unknown"
    [[ -f "$TAGLOG"   ]] && EXTRA_ARGS+=(--tag-log  "$TAGLOG")   || echo "  [WARN] Không có tag log"

    "$PY_CMD" "$SCRIPTS_DIR/feature_extract.py" \
        --pcap       "$PCAP" \
        --output     "$OUT" \
        --plc-ip     "$PLC_IP" \
        --window     "$WINDOW" \
        --session-id "day${DAY}" \
        --host-id    "$HOST_ID" \
        --role       mirror \
        "${EXTRA_ARGS[@]}" \
    && echo "  [OK] Day $DAY: $(wc -l < "$OUT") dòng" \
    || { echo "  [FAIL] Day $DAY extract failed"; EXTRACT_OK=0; }

    echo ""
done

if [[ "$EXTRACT_OK" == "0" ]]; then
    echo "[WARN] Một số ngày bị lỗi extract. Tiếp tục với các ngày có dữ liệu..."
fi

# =============================================================================
# BƯỚC 2 — MERGE DATASET (network + process + fusion)
# =============================================================================
# merge_dataset.py:
#   - Gán nhãn authoritative từ timeline (START/END events), không từ extractor
#   - Override episode_id với format: session:day:scenario:note:rep
#   - Gán BENIGN episode_id: session:BENIGN:<10min_chunk>
#   - proc_data_valid: gán TRƯỚC ffill, per-day groupby (không cross-day)
#   - Loại transition windows ±10s quanh biên attack (--drop-transition-seconds)

echo "=== BƯỚC 2: Merge Dataset ==="
echo ""

# Kiểm tra có features CSV nào không
N_FEATURES=$(ls "$PROCESSED_DIR"/day*_features.csv 2>/dev/null | wc -l)
if [[ "$N_FEATURES" == "0" ]]; then
    echo "[ERROR] Không tìm thấy features CSV trong $PROCESSED_DIR" >&2
    exit 1
fi
echo "[INFO] Tìm thấy $N_FEATURES features files"

"$PY_CMD" "$SCRIPTS_DIR/merge_dataset.py" \
    --features-dir       "$PROCESSED_DIR" \
    --tags-dir           "$LOG_DIR" \
    --labels-dir         "$LABEL_DIR" \
    --output-dir         "$PROCESSED_DIR" \
    --drop-transition-seconds 10 \
&& echo "[OK] Merge hoàn thành" \
|| { echo "[FAIL] Merge thất bại"; exit 1; }

echo ""

# Kiểm tra output
for VIEW in network process fusion; do
    F="$PROCESSED_DIR/${VIEW}.csv"
    if [[ -f "$F" ]]; then
        ROWS=$(( $(wc -l < "$F") - 1 ))
        echo "  [CHECK] $VIEW.csv: $ROWS rows"
    else
        echo "  [MISS] $VIEW.csv không tìm thấy"
    fi
done
echo ""

# =============================================================================
# BƯỚC 3 — KIỂM TRA LEAKAGE & GROUP SPLIT
# =============================================================================
echo "=== BƯỚC 3: Group Split Audit (kiểm tra leakage) ==="
echo ""

if [[ -f "run_group_split_audit.py" ]]; then
    "$PY_CMD" run_group_split_audit.py \
    && echo "[OK] Audit passed — zero train/test group overlap" \
    || echo "[WARN] Audit có vấn đề — xem ml_results/group_split_audit/"
else
    echo "[SKIP] run_group_split_audit.py không tìm thấy"
fi
echo ""

# =============================================================================
# BƯỚC 4 — HUẤN LUYỆN & ĐÁNH GIÁ ML
# =============================================================================
# train_ml.py defaults (đã cập nhật):
#   --binary-threshold-mode fbeta_oof   ← không bias in-sample
#   --binary-threshold-beta 2.0         ← ưu tiên recall (giảm false negative)
#   --validation-session-id day6        ← Day 6 làm OOD holdout
#   --default-window-seconds 2.0        ← tính FPR/hour đúng với 2s window
#
# Leakage controls trong train_ml.py (ALWAYS_DROP + SAFE_DROP_EXACT):
#   - src_ip, dst_ip, src_mac, dst_mac   ← endpoint identity
#   - session_id, host_id, episode_id    ← group metadata
#   - window_start_ms, window_end_ms     ← timestamps
#   - proc_data_valid                    ← collection artifact
#   - scan_detected_rule, ...            ← hand-crafted rule flags
#   - *_score columns                    ← derived rule outputs
#
# GroupKFold: 5 folds × 5 seeds (42-46)
#   Group key: session_id|host_id|episode_id
#   Mỗi attack episode là 1 group → không bị split giữa train/test
#   Mỗi 10-phút benign là 1 group → không bị split giữa train/test

echo "=== BƯỚC 4: Train & Evaluate ML ==="
echo ""

NET_CSV="$PROCESSED_DIR/network.csv"
PROC_CSV="$PROCESSED_DIR/process.csv"
FUSION_CSV="$PROCESSED_DIR/fusion.csv"

# Kiểm tra file đầu vào
MISSING=0
for F in "$NET_CSV" "$PROC_CSV" "$FUSION_CSV"; do
    [[ -f "$F" ]] || { echo "[ERROR] Thiếu $F"; MISSING=1; }
done
[[ "$MISSING" == "1" ]] && exit 1

"$PY_CMD" "$SCRIPTS_DIR/train_ml.py" \
    --network-data  "$NET_CSV" \
    --process-data  "$PROC_CSV" \
    --fusion-data   "$FUSION_CSV" \
    --output-dir    "$ML_OUTPUT" \
    --feature-profile hybrid \
    --tasks binary \
&& echo "[OK] Training hoàn thành → $ML_OUTPUT" \
|| { echo "[FAIL] Training thất bại"; exit 1; }

echo ""

# =============================================================================
# KẾT QUẢ
# =============================================================================
echo "╔══════════════════════════════════════════════════════╗"
echo "║                 PIPELINE HOÀN THÀNH                ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║ Files đầu ra:                                       ║"
printf "║  network.csv  : %-37s ║\n" "$PROCESSED_DIR/network.csv"
printf "║  process.csv  : %-37s ║\n" "$PROCESSED_DIR/process.csv"
printf "║  fusion.csv   : %-37s ║\n" "$PROCESSED_DIR/fusion.csv"
printf "║  ML results   : %-37s ║\n" "$ML_OUTPUT"
echo "╠══════════════════════════════════════════════════════╣"
echo "║ Kết quả kỳ vọng (network-only, Day6 OOD, CatBoost) ║"
echo "║  Macro-F1 ≈ 0.659 ± 0.006                          ║"
echo "║  MCC       ≈ 0.477 ± 0.007                          ║"
echo "║  FPR/hour  ≈ 1.64  ± 0.70                           ║"
echo "╚══════════════════════════════════════════════════════╝"

# In summary nếu có
SUMMARY="$ML_OUTPUT/summary_mean_std.csv"
if [[ -f "$SUMMARY" ]]; then
    echo ""
    echo "=== Kết Quả Thực Tế ==="
    "$PY_CMD" - <<PYEOF
import pandas as pd, sys
try:
    df = pd.read_csv("$SUMMARY")
    # Lọc binary + Day 6 holdout + network_only
    mask = (df.get("task","") == "binary") if "task" in df.columns else pd.Series([True]*len(df))
    print(df[mask].to_string(max_rows=30))
except Exception as e:
    print(f"Không đọc được summary: {e}")
PYEOF
fi
