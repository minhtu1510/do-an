#!/usr/bin/env python3
"""
eval_dataset_quality.py
Đánh giá nhanh chất lượng feature CSV do extract_opcua_features.py (hoặc
extract_s7_features.py) sinh ra -- trước khi đem đi train.

Kiểm tra:
  - Tổng số cửa sổ (windows), phân bố nhãn (class distribution).
  - Tỉ lệ benign vs attack.
  - Cột toàn NaN / hằng số (feature vô dụng -> nên bỏ).
  - Cột có NaN (và %).
  - Cảnh báo nhãn quá ít mẫu (mất cân bằng).
  - Cảnh báo cột nghi leakage (port/ip/mac/id...) còn sót.

Chạy:
  python eval_dataset_quality.py --input opcua_features.csv
  python eval_dataset_quality.py --input opcua_features.csv --label-col label
"""

from __future__ import annotations

import argparse
import sys

import pandas as pd


LEAKAGE_HINT_SUBSTR = ("src_ip", "dst_ip", "src_mac", "dst_mac", "src_port",
                       "dst_port", "ip.", "mac", "session_id", "host_id",
                       "top_", "capture_", "decode_level")

BENIGN_TOKENS = {"BENIGN", "NORMAL", "BENIGN_NORMAL", "", "0"}


def is_benign(label: str) -> bool:
    s = str(label).strip().upper()
    return s in BENIGN_TOKENS or s.startswith("BENIGN")


def main() -> int:
    ap = argparse.ArgumentParser(description="Đánh giá chất lượng feature CSV")
    ap.add_argument("--input", required=True, help="File feature CSV")
    ap.add_argument("--label-col", default="label", help="Tên cột nhãn (mặc định 'label')")
    ap.add_argument("--min-per-class", type=int, default=30,
                    help="Ngưỡng cảnh báo số mẫu tối thiểu mỗi lớp")
    args = ap.parse_args()

    try:
        df = pd.read_csv(args.input, low_memory=False)
    except Exception as e:
        print(f"[ERROR] Không đọc được {args.input}: {e}", file=sys.stderr)
        return 1

    n = len(df)
    print("=" * 60)
    print(f"  ĐÁNH GIÁ CHẤT LƯỢNG: {args.input}")
    print("=" * 60)
    print(f"Tổng số windows : {n}")
    print(f"Tổng số cột     : {len(df.columns)}")

    if n == 0:
        print("[FAIL] File rỗng — kiểm tra lại extract (pcap/timeline có khớp thời gian không).")
        return 1

    # ── Phân bố nhãn ────────────────────────────────────────────────────────
    if args.label_col not in df.columns:
        print(f"[FAIL] Không có cột nhãn '{args.label_col}'. Các cột: {list(df.columns)[:10]}...")
        return 1

    labels = df[args.label_col].fillna("BENIGN").astype(str)
    counts = labels.value_counts()
    benign = sum(c for lbl, c in counts.items() if is_benign(lbl))
    attack = n - benign

    print("\n-- Phân bố nhãn --")
    for lbl, c in counts.items():
        tag = "(benign)" if is_benign(lbl) else "(attack)"
        print(f"  {lbl:<32} {c:>7}  ({c/n*100:5.1f}%) {tag}")
    print(f"\n  BENIGN tổng: {benign} ({benign/n*100:.1f}%)  |  ATTACK tổng: {attack} ({attack/n*100:.1f}%)")

    # ── Cảnh báo mất cân bằng ────────────────────────────────────────────────
    attack_labels = {lbl: c for lbl, c in counts.items() if not is_benign(lbl)}
    thin = {lbl: c for lbl, c in attack_labels.items() if c < args.min_per_class}
    if thin:
        print(f"\n[CẢNH BÁO] {len(thin)} lớp attack có < {args.min_per_class} mẫu (khó train):")
        for lbl, c in thin.items():
            print(f"    {lbl}: {c}  -> chạy thêm cycle cho kịch bản này")
    if attack == 0:
        print("\n[FAIL] Không có mẫu attack nào — timeline không khớp pcap? Kiểm tra epoch/timezone.")

    # ── Cột toàn NaN / hằng số / có NaN ──────────────────────────────────────
    numeric = df.select_dtypes(include="number")
    all_nan = [c for c in df.columns if df[c].isna().all()]
    const_cols = [c for c in numeric.columns if numeric[c].nunique(dropna=True) <= 1]
    nan_cols = {c: df[c].isna().mean() for c in df.columns if 0 < df[c].isna().mean() < 1}

    print("\n-- Chất lượng cột --")
    print(f"  Cột toàn NaN     : {len(all_nan)}" + (f" -> {all_nan}" if all_nan else ""))
    print(f"  Cột hằng số      : {len(const_cols)} (feature vô dụng, model bỏ qua)")
    if nan_cols:
        worst = sorted(nan_cols.items(), key=lambda x: -x[1])[:8]
        print(f"  Cột có NaN 1 phần: {len(nan_cols)} — nặng nhất:")
        for c, r in worst:
            print(f"      {c}: {r*100:.1f}% NaN")
    else:
        print("  Cột có NaN 1 phần: 0 (tốt)")

    # ── Nghi leakage ─────────────────────────────────────────────────────────
    leak = [c for c in df.columns if any(s in c.lower() for s in LEAKAGE_HINT_SUBSTR)
            and c != args.label_col]
    if leak:
        print(f"\n[CẢNH BÁO leakage] {len(leak)} cột nghi lộ danh tính/port -> "
              f"LOẠI trước khi train (train_ml.py đã có SAFE_DROP nhưng nên rà):")
        for c in leak:
            print(f"    {c}")

    # ── Kết luận ─────────────────────────────────────────────────────────────
    print("\n-- Kết luận --")
    problems = []
    if attack == 0:
        problems.append("không có mẫu attack")
    if len(all_nan) > 0:
        problems.append(f"{len(all_nan)} cột toàn NaN")
    if thin:
        problems.append(f"{len(thin)} lớp attack quá ít mẫu")
    if benign == 0:
        problems.append("không có mẫu benign (thiếu baseline/web_scada)")
    if problems:
        print("  [CẦN XỬ LÝ] " + "; ".join(problems))
        return 2
    print("  [OK] Dataset dùng được: có cả benign lẫn attack, không cột toàn NaN, các lớp đủ mẫu.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
