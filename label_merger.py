#!/usr/bin/env python3
"""
label_merger.py – Gán nhãn ground-truth vào Flow CSV
======================================================
Đọc file Flow CSV (từ CICFlowMeter hoặc Scapy extractor) và file
Label Timeline CSV (từ label_webhook_server.py), sau đó gán nhãn
cho từng flow dựa vào thời gian bắt đầu của flow.

Sử dụng:
    # Gán nhãn cho một ngày
    python label_merger.py \
        --flows /data/features/day2_flows.csv \
        --timeline /data/labels/day2_timeline.csv \
        --output /data/labeled/day2_labeled.csv \
        --flow-ts-col Timestamp \
        --flow-ts-format "%d/%m/%Y %H:%M:%S"

    # Hợp nhất và gán nhãn cho tất cả 5 ngày
    python label_merger.py --merge-all --days-dir /data --output /data/labeled/final_dataset.csv
"""

import pandas as pd
import numpy as np
import argparse
import os
import sys
from datetime import datetime
from typing import List, Optional


# ═══════════════════════════════════════════════
#  LABEL WINDOWS BUILDER
# ═══════════════════════════════════════════════

def build_attack_windows(timeline_csv: str) -> List[dict]:
    """
    Đọc file timeline và tạo danh sách các khoảng thời gian tấn công.
    
    Returns:
        List[dict]: mỗi dict có keys: label, start_ms, end_ms
    """
    events = pd.read_csv(timeline_csv)
    events = events.sort_values('attacker_timestamp_ms')

    active = {}
    windows = []

    for _, row in events.iterrows():
        label = row['label']
        action = row['action']
        # Ưu tiên dùng attacker timestamp, fallback sang server timestamp
        ts = row['attacker_timestamp_ms']
        if pd.isna(ts):
            ts = row.get('server_timestamp_ms', 0)

        if action == 'START':
            active[label] = ts
        elif action == 'END' and label in active:
            windows.append({
                'label': label,
                'start_ms': active.pop(label),
                'end_ms': ts
            })

    # Đóng bất kỳ window nào chưa có END (bất thường nhưng xử lý an toàn)
    for label, start_ts in active.items():
        print(f"[WARN] Nhãn {label} không có END event – mở đến cuối timeline")
        if events['attacker_timestamp_ms'].max():
            windows.append({
                'label': label,
                'start_ms': start_ts,
                'end_ms': events['attacker_timestamp_ms'].max()
            })

    print(f"[Timeline] Đã xây dựng {len(windows)} attack windows:")
    for w in windows:
        dur = (w['end_ms'] - w['start_ms']) / 1000
        print(f"  {w['label']:15s} | {w['start_ms']} → {w['end_ms']} ({dur:.1f}s)")

    return windows


def get_label_for_ts(ts_ms: float, windows: List[dict]) -> str:
    """Trả về nhãn phù hợp với timestamp (ms). Mặc định: NORMAL."""
    for w in windows:
        if w['start_ms'] <= ts_ms <= w['end_ms']:
            return w['label']
    return 'NORMAL'


# ═══════════════════════════════════════════════
#  FLOW TIMESTAMP PARSING
# ═══════════════════════════════════════════════

COMMON_TS_FORMATS = [
    "%d/%m/%Y %H:%M:%S",       # CICFlowMeter default
    "%Y-%m-%d %H:%M:%S",       # ISO-like
    "%Y-%m-%dT%H:%M:%S",       # ISO 8601
    "%d/%m/%Y %H:%M:%S.%f",    # CICFlowMeter with microseconds
    "%m/%d/%Y %I:%M:%S %p",    # US format
]


def parse_flow_timestamp(ts_str: str, fmt: Optional[str] = None) -> float:
    """
    Parse timestamp string thành milliseconds từ epoch.
    Thử tự động detect format nếu fmt=None.
    """
    if fmt:
        try:
            return datetime.strptime(ts_str.strip(), fmt).timestamp() * 1000
        except Exception:
            pass

    for f in COMMON_TS_FORMATS:
        try:
            return datetime.strptime(ts_str.strip(), f).timestamp() * 1000
        except Exception:
            continue

    try:
        return float(ts_str) * 1000   # unix timestamp in seconds
    except Exception:
        return 0.0


# ═══════════════════════════════════════════════
#  MAIN MERGE FUNCTION
# ═══════════════════════════════════════════════

def merge_labels(
    flows_csv: str,
    timeline_csv: str,
    output_csv: str,
    flow_ts_col: str = 'Timestamp',
    flow_ts_format: Optional[str] = None,
    drop_unlabeled: bool = False
) -> pd.DataFrame:
    """
    Gán nhãn cho flows dựa trên label timeline.
    
    Args:
        flows_csv        : File CSV chứa flow features (CICFlowMeter output)
        timeline_csv     : File CSV chứa label events (webhook server output)
        output_csv       : Đường dẫn file CSV kết quả
        flow_ts_col      : Tên cột timestamp trong flows_csv
        flow_ts_format   : Format của timestamp (None = tự detect)
        drop_unlabeled   : Nếu True, bỏ các flow không khớp nhãn nào
    
    Returns:
        DataFrame đã được gán nhãn
    """
    print(f"\n[Merger] Đang đọc flows: {flows_csv}")
    flows = pd.read_csv(flows_csv, low_memory=False)
    print(f"  → {len(flows)} flows, {len(flows.columns)} columns")

    # Tìm cột timestamp
    if flow_ts_col not in flows.columns:
        # Thử tìm cột có chứa "time" / "timestamp"
        candidates = [c for c in flows.columns if 'time' in c.lower() or 'stamp' in c.lower()]
        if candidates:
            flow_ts_col = candidates[0]
            print(f"  [auto-detect] Dùng cột timestamp: '{flow_ts_col}'")
        else:
            print(f"  [ERROR] Không tìm thấy cột timestamp! Cột hiện có: {list(flows.columns)[:10]}")
            sys.exit(1)

    # Parse timestamps
    print(f"[Merger] Đang parse timestamps (cột: {flow_ts_col})...")
    flows['_ts_ms'] = flows[flow_ts_col].astype(str).apply(
        lambda x: parse_flow_timestamp(x, flow_ts_format)
    )

    # Build attack windows từ timeline
    print(f"\n[Merger] Đang đọc label timeline: {timeline_csv}")
    windows = build_attack_windows(timeline_csv)

    # Gán nhãn
    print(f"\n[Merger] Đang gán nhãn cho {len(flows)} flows...")
    flows['Label'] = flows['_ts_ms'].apply(lambda ts: get_label_for_ts(ts, windows))
    flows['is_attack'] = (flows['Label'] != 'NORMAL').astype(int)

    # Dọn dẹp
    flows = flows.drop(columns=['_ts_ms'])

    if drop_unlabeled:
        before = len(flows)
        flows = flows[flows['Label'] != 'UNLABELED']
        print(f"  Drop unlabeled: {before - len(flows)} rows removed")

    # Lưu output
    os.makedirs(os.path.dirname(os.path.abspath(output_csv)), exist_ok=True)
    flows.to_csv(output_csv, index=False)

    print(f"\n✓ Đã gán nhãn → {output_csv}")
    print(f"  Tổng: {len(flows)} flows")
    print(f"\n  Phân phối nhãn:")
    for lbl, cnt in flows['Label'].value_counts().items():
        pct = cnt / len(flows) * 100
        bar = '█' * int(pct / 2)
        print(f"  {lbl:20s} {cnt:6d} ({pct:5.1f}%) {bar}")

    return flows


# ═══════════════════════════════════════════════
#  MERGE ALL 5 DAYS
# ═══════════════════════════════════════════════

def merge_all_days(
    days_dir: str,
    output_csv: str,
    flow_ts_format: Optional[str] = None
) -> pd.DataFrame:
    """
    Hợp nhất dataset của 5 ngày.
    Giả định cấu trúc:
        days_dir/features/day1_flows.csv
        days_dir/labels/day1_timeline.csv
        ...
    """
    all_dfs = []

    for day in range(1, 6):
        flows_path = os.path.join(days_dir, 'features', f'day{day}_flows.csv')
        timeline_path = os.path.join(days_dir, 'labels', f'day{day}_timeline.csv')
        out_path = os.path.join(days_dir, 'labeled', f'day{day}_labeled.csv')

        if not os.path.exists(flows_path):
            print(f"[SKIP] Ngày {day}: Không tìm thấy {flows_path}")
            continue
        if not os.path.exists(timeline_path):
            print(f"[SKIP] Ngày {day}: Không tìm thấy {timeline_path}")
            continue

        print(f"\n{'='*60}")
        print(f"  XỬ LÝ NGÀY {day}")
        print(f"{'='*60}")

        df = merge_labels(
            flows_csv=flows_path,
            timeline_csv=timeline_path,
            output_csv=out_path,
            flow_ts_format=flow_ts_format
        )
        df['day'] = day
        all_dfs.append(df)

    if not all_dfs:
        print("[ERROR] Không có ngày nào có đủ dữ liệu!")
        sys.exit(1)

    print(f"\n{'='*60}")
    print("  HỢP NHẤT TẤT CẢ NGÀY")
    print(f"{'='*60}")

    merged = pd.concat(all_dfs, ignore_index=True)

    # Xáo trộn ngẫu nhiên (quan trọng để tránh bias theo thời gian)
    merged = merged.sample(frac=1, random_state=42).reset_index(drop=True)

    os.makedirs(os.path.dirname(os.path.abspath(output_csv)), exist_ok=True)
    merged.to_csv(output_csv, index=False)

    print(f"\n✓ Dataset cuối cùng: {output_csv}")
    print(f"  Tổng: {len(merged)} flows × {len(merged.columns)} features")
    print(f"\n  Phân phối nhãn tổng hợp:")
    for lbl, cnt in merged['Label'].value_counts().items():
        pct = cnt / len(merged) * 100
        bar = '█' * int(pct / 2)
        print(f"  {lbl:20s} {cnt:6d} ({pct:5.1f}%) {bar}")

    print(f"\n  Phân phối theo ngày:")
    print(merged.groupby(['day', 'Label']).size().unstack(fill_value=0).to_string())

    return merged


# ═══════════════════════════════════════════════
#  VERIFY DATASET QUALITY
# ═══════════════════════════════════════════════

def verify_dataset(labeled_csv: str):
    """Kiểm tra chất lượng dataset sau khi gán nhãn."""
    print(f"\n{'='*60}")
    print("  KIỂM TRA CHẤT LƯỢNG DATASET")
    print(f"{'='*60}\n")

    df = pd.read_csv(labeled_csv)

    # 1. Thống kê cơ bản
    dist = df['Label'].value_counts()
    print(f"[1] Tổng số mẫu   : {len(df):,}")
    print(f"[2] Số features    : {len(df.columns)}")
    print(f"[3] Phân phối nhãn :\n{dist}\n")

    # 2. Kiểm tra null
    null_count = df.isnull().sum().sum()
    print(f"[4] Null values : {null_count}", "✓" if null_count == 0 else "⚠️ Cần xử lý!")

    # 3. Kiểm tra mất cân bằng
    if len(dist) >= 2:
        ratio = dist.max() / dist.min()
        status = "✓" if ratio <= 10 else "⚠️ Mất cân bằng!"
        print(f"[5] Tỷ lệ max/min  : {ratio:.1f}x {status}")

    # 4. Kiểm tra đặc trưng theo nhãn (dựa trên features của CICFlowMeter)
    feature_checks = {
        'SCAN': ('Flow Packets/s', 'cao', lambda x: x > 50),
        'FLOOD': ('Flow Packets/s', '> 200', lambda x: x > 200),
        'RWRITE': ('Bwd Packet Length Mean', 'nhỏ', lambda x: x < 200),
        'NORMAL': ('Flow IAT Mean', 'lớn hơn attack', lambda x: x > 100),
    }

    print("\n[6] Kiểm tra đặc trưng:")
    for label, (feat, desc, check) in feature_checks.items():
        if label in df['Label'].values and feat in df.columns:
            vals = df[df['Label'] == label][feat].dropna()
            pct = (vals.apply(check)).mean() * 100
            status = "✓" if pct > 60 else "⚠️"
            print(f"  {label:15s} | {feat:30s} | {desc:15s} | {pct:.0f}% đúng {status}")

    print(f"\n{'='*60}")
    print("  KIỂM TRA HOÀN TẤT")
    print(f"{'='*60}\n")


# ═══════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Gán nhãn ground-truth vào Flow CSV từ Label Timeline',
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command')

    # Sub-command: merge (một ngày)
    p_merge = subparsers.add_parser('merge', help='Gán nhãn cho một file flows CSV')
    p_merge.add_argument('--flows', required=True, help='File flows CSV (CICFlowMeter output)')
    p_merge.add_argument('--timeline', required=True, help='File timeline CSV (webhook server output)')
    p_merge.add_argument('--output', required=True, help='File CSV output đã gán nhãn')
    p_merge.add_argument('--flow-ts-col', default='Timestamp', help='Tên cột timestamp trong flows CSV')
    p_merge.add_argument('--flow-ts-format', default=None,
                         help='Format timestamp (mặc định: tự detect)\nVí dụ: "%%d/%%m/%%Y %%H:%%M:%%S"')
    p_merge.add_argument('--verify', action='store_true', help='Kiểm tra dataset sau khi merge')

    # Sub-command: merge-all (5 ngày)
    p_all = subparsers.add_parser('merge-all', help='Hợp nhất và gán nhãn cho tất cả 5 ngày')
    p_all.add_argument('--days-dir', required=True,
                       help='Thư mục gốc chứa features/ và labels/ subdirs')
    p_all.add_argument('--output', required=True, help='File CSV output cuối cùng')
    p_all.add_argument('--flow-ts-format', default=None)
    p_all.add_argument('--verify', action='store_true')

    # Sub-command: verify
    p_verify = subparsers.add_parser('verify', help='Kiểm tra chất lượng dataset đã gán nhãn')
    p_verify.add_argument('--dataset', required=True, help='File CSV đã gán nhãn để kiểm tra')

    args = parser.parse_args()

    if args.command == 'merge':
        df = merge_labels(
            flows_csv=args.flows,
            timeline_csv=args.timeline,
            output_csv=args.output,
            flow_ts_col=args.flow_ts_col,
            flow_ts_format=args.flow_ts_format
        )
        if args.verify:
            verify_dataset(args.output)

    elif args.command == 'merge-all':
        df = merge_all_days(
            days_dir=args.days_dir,
            output_csv=args.output,
            flow_ts_format=args.flow_ts_format
        )
        if args.verify:
            verify_dataset(args.output)

    elif args.command == 'verify':
        verify_dataset(args.dataset)

    else:
        parser.print_help()
        print("\nVí dụ sử dụng:")
        print("  python label_merger.py merge \\")
        print("      --flows /data/features/day2_flows.csv \\")
        print("      --timeline /data/labels/day2_timeline.csv \\")
        print("      --output /data/labeled/day2_labeled.csv --verify")
        print()
        print("  python label_merger.py merge-all \\")
        print("      --days-dir /data --output /data/labeled/final_dataset.csv --verify")
