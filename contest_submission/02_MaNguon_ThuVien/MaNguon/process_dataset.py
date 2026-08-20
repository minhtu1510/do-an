#!/usr/bin/env python3
"""
process_dataset.py – Pipeline xử lý PCAP → Feature Extraction → Train IDS
============================================================================
Bước 1: Lọc PCAP theo nhãn từ file timeline.csv
  - File PCAP tấn công: Chỉ giữ gói tin trong khoảng thời gian tấn công
    VÀ có IP nguồn/đích khớp với TARGET_IP (PLC)
  - File PCAP bình thường: Giữ toàn bộ, gán nhãn BENIGN
Bước 2: Trích xuất đặc trưng CICFlow (thống kê TCP) + S7 (giao thức ICS)
  - Tổng hợp theo cửa sổ thời gian (Window Size, mặc định 120s)
Bước 3: Train và đánh giá mô hình MLP và Random Forest

Usage:
  # Chạy đầy đủ pipeline
  python process_dataset.py --plc-ip 192.168.1.10 --window 120 \\
      --attack-pcap day2.pcap --timeline timeline.csv \\
      --benign-pcap day1.pcap --output results/

  # Chỉ extract features (bỏ qua train)
  python process_dataset.py --plc-ip 192.168.1.10 --window 120 \\
      --attack-pcap day2.pcap --timeline timeline.csv \\
      --benign-pcap day1.pcap --output results/ --no-train

  # Chạy nhiều file attack và nhiều file benign
  python process_dataset.py --plc-ip 192.168.1.10 --window 60 \\
      --attack-pcap day2.pcap day3.pcap day4.pcap \\
      --timeline timeline_day2.csv timeline_day3.csv timeline_day4.csv \\
      --benign-pcap day1.pcap --output results/

Requirements:
  pip install scapy pandas scikit-learn
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
import time
import statistics
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ══════════════════════════════════════════════════════════════
#  CẤU HÌNH MẶC ĐỊNH (có thể ghi đè qua tham số dòng lệnh)
# ══════════════════════════════════════════════════════════════

DEFAULT_WINDOW_SECONDS = 120.0   # Thời gian cửa sổ trích xuất đặc trưng
DEFAULT_PLC_PORT       = 102     # Cổng S7 comm
DEFAULT_MIN_PKTS       = 3       # Cửa sổ có ít hơn số này sẽ bị bỏ qua


# ══════════════════════════════════════════════════════════════
#  CÁC ĐẶC TRƯNG S7 (ánh xạ function code → tên)
# ══════════════════════════════════════════════════════════════

def _parse_s7_pdu_type(raw: bytes) -> str:
    """Giải mã loại PDU trong giao thức S7comm từ raw bytes."""
    if len(raw) < 10 or raw[0] != 0x03:
        return "OTHER"
    cotp_len  = raw[4] + 1
    s7_start  = 4 + cotp_len
    if len(raw) < s7_start + 2 or raw[s7_start] != 0x32:
        return "OTHER"
    rosctr = raw[s7_start + 1]
    func   = raw[s7_start + 10] if len(raw) > s7_start + 10 else 0
    mapping = {
        (0x01, 0x04): "S7_READ",
        (0x01, 0x05): "S7_WRITE",
        (0x01, 0x29): "S7_STOP",
        (0x01, 0x28): "S7_START",
        (0x01, 0xF0): "S7_NEGOTIATE",
        (0x03, 0x04): "S7_READ_RESP",
        (0x03, 0x05): "S7_WRITE_RESP",
        (0x07, 0x05): "S7_USERDATA",    # Authentication, SZL reads..
    }
    return mapping.get((rosctr, func), f"S7_0x{rosctr:02x}_0x{func:02x}")


# ══════════════════════════════════════════════════════════════
#  BƯỚC 1 – ĐỌC TIMELINE CSV
# ══════════════════════════════════════════════════════════════

def load_timeline(timeline_csv: str) -> List[Dict]:
    """
    Đọc file timeline.csv do label_webhook_server.py tạo ra.
    Trả về list các khoảng thời gian tấn công với nhãn tương ứng.

    Cấu trúc CSV: timestamp, label, action, day, note
    - action = START: bắt đầu khoảng tấn công
    - action = END:   kết thúc khoảng tấn công
    """
    events: List[Dict] = []
    try:
        with open(timeline_csv, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                events.append({
                    "timestamp_ms": int(row.get("timestamp", 0)),
                    "label":        row.get("label", "").strip().upper(),
                    "action":       row.get("action", "").strip().upper(),
                    "note":         row.get("note", "").strip(),
                })
    except Exception as e:
        print(f"[!] Không đọc được timeline: {e}")
        return []

    # Ghép cặp START–END thành các khoảng [t_start, t_end, label]
    windows = []
    pending: Dict[str, float] = {}

    for ev in sorted(events, key=lambda x: x["timestamp_ms"]):
        lbl = ev["label"]
        ts  = ev["timestamp_ms"] / 1000.0   # chuyển sang giây
        if ev["action"] == "START":
            pending[lbl] = ts
        elif ev["action"] == "END" and lbl in pending:
            windows.append({
                "t_start": pending.pop(lbl),
                "t_end":   ts,
                "label":   lbl,
            })

    print(f"[✓] Timeline: {len(windows)} khoảng tấn công được đọc từ '{timeline_csv}'")
    for w in windows:
        dur = w["t_end"] - w["t_start"]
        print(f"    {w['label']:20s}  {datetime.fromtimestamp(w['t_start']).strftime('%H:%M:%S')} "
              f"→ {datetime.fromtimestamp(w['t_end']).strftime('%H:%M:%S')}  ({dur:.0f}s)")
    return windows


def label_for_time(t: float, attack_windows: List[Dict]) -> Optional[str]:
    """Trả về nhãn tấn công tại thời điểm t, hoặc None nếu không trong khoảng tấn công."""
    for w in attack_windows:
        if w["t_start"] <= t <= w["t_end"]:
            return w["label"]
    return None


# ══════════════════════════════════════════════════════════════
#  BƯỚC 2 – LỌC GÓI TIN TỪ PCAP
# ══════════════════════════════════════════════════════════════

def filter_attack_pcap(
    pcap_file: str,
    attack_windows: List[Dict],
    plc_ip: str,
    plc_port: int = DEFAULT_PLC_PORT,
) -> List[Tuple]:
    """
    Lọc PCAP file tấn công:
    - Chỉ giữ gói tin trong khoảng thời gian tấn công (attack_windows)
    - VÀ có IP nguồn hoặc đích là plc_ip
    Trả về list (packet, label).
    """
    try:
        from scapy.all import rdpcap, IP, TCP, Raw
    except ImportError:
        print("[!] scapy chưa cài. Chạy: pip install scapy")
        sys.exit(1)

    print(f"\n[→] Lọc PCAP tấn công: {pcap_file}")
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[!] Không đọc được PCAP: {e}")
        return []

    total = len(packets)
    kept  = []
    skipped_time = skipped_ip = 0

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        t      = float(pkt.time)
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # Kiểm tra IP
        if plc_ip not in (src_ip, dst_ip):
            skipped_ip += 1
            continue

        # Kiểm tra thời gian tấn công
        label = label_for_time(t, attack_windows)
        if label is None:
            skipped_time += 1
            continue

        kept.append((pkt, label))

    print(f"    Tổng gói tin: {total}")
    print(f"    Giữ lại     : {len(kept)} (trong khoảng tấn công + khớp IP PLC)")
    print(f"    Bỏ (IP sai) : {skipped_ip}")
    print(f"    Bỏ (ngoài TG): {skipped_time}")
    return kept


def load_benign_pcap(
    pcap_file: str,
    plc_ip: str,
    plc_port: int = DEFAULT_PLC_PORT,
) -> List[Tuple]:
    """
    Đọc PCAP file bình thường:
    - Lọc chỉ lấy gói tin có IP PLC (tùy chọn)
    - Gán nhãn BENIGN cho tất cả
    """
    try:
        from scapy.all import rdpcap, IP, TCP
    except ImportError:
        print("[!] scapy chưa cài. Chạy: pip install scapy")
        sys.exit(1)

    print(f"\n[→] Đọc PCAP bình thường: {pcap_file}")
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[!] Không đọc được PCAP: {e}")
        return []

    kept = []
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        # Lấy tất cả gói tin liên quan PLC (optional - bỏ dòng sau nếu muốn lấy hết)
        if plc_ip not in (pkt[IP].src, pkt[IP].dst):
            continue
        kept.append((pkt, "BENIGN"))

    print(f"    Tổng: {len(packets)} → Giữ: {len(kept)} gói tin PLC (BENIGN)")
    return kept


# ══════════════════════════════════════════════════════════════
#  BƯỚC 3 – TRÍCH XUẤT ĐẶC TRƯNG (CICFlow + S7)
# ══════════════════════════════════════════════════════════════

FEATURE_COLUMNS = [
    # ── Định danh cửa sổ ──────────────────────
    "window_start", "window_end", "label",
    # ── Đặc trưng tổng hợp (CICFlow-style) ────
    "pkt_count", "byte_count",
    "avg_pkt_size", "std_pkt_size", "max_pkt_size", "min_pkt_size",
    "flow_duration_ms",
    "avg_iat_ms", "std_iat_ms", "max_iat_ms", "min_iat_ms",
    "bytes_per_second", "pkts_per_second",
    # ── TCP flags ─────────────────────────────
    "tcp_syn_count", "tcp_ack_count", "tcp_rst_count",
    "tcp_fin_count", "tcp_psh_count",
    "syn_rate",
    # ── Đặc trưng S7 giao thức ────────────────
    "s7_pkt_count",
    "s7_read_count", "s7_write_count",
    "s7_stop_count", "s7_start_count",
    "s7_negotiate_count",
    "s7_userdata_count",
    "s7_read_resp_count", "s7_write_resp_count",
    "s7_other_count",
    # ── Tỉ lệ dẫn xuất ────────────────────────
    "write_read_ratio",      # RWRITE/SPOOF sẽ phát sáng ở đây
    "s7_ratio",              # Tỉ lệ gói S7 so với tổng gói
    "stop_ratio",            # CPU_STOP sẽ phát sáng
    "error_ratio",           # FUZZ sẽ phát sáng
]


def _process_window(pkts_labels: List[Tuple], ws: float, we: float) -> Optional[Dict]:
    """Gom nhóm các gói tin trong 1 cửa sổ và tính toán đặc trưng."""
    if not pkts_labels:
        return None

    try:
        from scapy.all import IP, TCP, Raw
    except ImportError:
        return None

    pkts   = [p for p, _ in pkts_labels]
    labels = [l for _, l in pkts_labels]

    # Nhãn chiếm đa số trong cửa sổ
    dominant_label = max(set(labels), key=labels.count)

    sizes  = [len(p) for p in pkts]
    times  = [float(p.time) for p in pkts]
    n      = len(pkts)

    # IAT
    iats = [times[i+1] - times[i] for i in range(len(times)-1)] if n > 1 else [0.0]
    duration_ms = (times[-1] - times[0]) * 1000 if n > 1 else 0.0
    elapsed_s   = max((times[-1] - times[0]), 0.001)

    # TCP flags
    syn = ack = rst = fin = psh = 0
    for p in pkts:
        if p.haslayer(TCP):
            flags = int(p[TCP].flags)
            syn += bool(flags & 0x02)
            ack += bool(flags & 0x10)
            rst += bool(flags & 0x04)
            fin += bool(flags & 0x01)
            psh += bool(flags & 0x08)

    # S7 PDU type counts
    s7_total = s7_read = s7_write = s7_stop = s7_start_ = 0
    s7_neg   = s7_ud   = s7_rresp = s7_wresp = s7_other = 0
    for p in pkts:
        if not (p.haslayer(TCP) and p.haslayer(Raw)):
            continue
        if DEFAULT_PLC_PORT not in (p[TCP].dport, p[TCP].sport):
            continue
        ptype = _parse_s7_pdu_type(bytes(p[Raw].load))
        s7_total += 1
        if ptype == "S7_READ":          s7_read   += 1
        elif ptype == "S7_WRITE":       s7_write  += 1
        elif ptype == "S7_STOP":        s7_stop   += 1
        elif ptype == "S7_START":       s7_start_ += 1
        elif ptype == "S7_NEGOTIATE":   s7_neg    += 1
        elif ptype == "S7_USERDATA":    s7_ud     += 1
        elif ptype == "S7_READ_RESP":   s7_rresp  += 1
        elif ptype == "S7_WRITE_RESP":  s7_wresp  += 1
        else:                           s7_other  += 1

    byte_total = sum(sizes)
    std_size = round(statistics.stdev(sizes), 4) if n > 1 else 0.0
    std_iat  = round(statistics.stdev([i*1000 for i in iats]), 4) if len(iats) > 1 else 0.0

    return {
        "window_start":      round(ws, 3),
        "window_end":        round(we, 3),
        "label":             dominant_label,
        # CICFlow
        "pkt_count":         n,
        "byte_count":        byte_total,
        "avg_pkt_size":      round(byte_total / n, 2),
        "std_pkt_size":      std_size,
        "max_pkt_size":      max(sizes),
        "min_pkt_size":      min(sizes),
        "flow_duration_ms":  round(duration_ms, 2),
        "avg_iat_ms":        round(sum(iats) / len(iats) * 1000, 2),
        "std_iat_ms":        std_iat,
        "max_iat_ms":        round(max(iats) * 1000, 2),
        "min_iat_ms":        round(min(iats) * 1000, 2),
        "bytes_per_second":  round(byte_total / elapsed_s, 2),
        "pkts_per_second":   round(n / elapsed_s, 2),
        # TCP flags
        "tcp_syn_count":     syn,
        "tcp_ack_count":     ack,
        "tcp_rst_count":     rst,
        "tcp_fin_count":     fin,
        "tcp_psh_count":     psh,
        "syn_rate":          round(syn / elapsed_s, 4),
        # S7
        "s7_pkt_count":      s7_total,
        "s7_read_count":     s7_read,
        "s7_write_count":    s7_write,
        "s7_stop_count":     s7_stop,
        "s7_start_count":    s7_start_,
        "s7_negotiate_count": s7_neg,
        "s7_userdata_count": s7_ud,
        "s7_read_resp_count": s7_rresp,
        "s7_write_resp_count": s7_wresp,
        "s7_other_count":    s7_other,
        # Tỉ lệ
        "write_read_ratio":  round(s7_write / max(s7_read, 1), 4),
        "s7_ratio":          round(s7_total / max(n, 1), 4),
        "stop_ratio":        round(s7_stop / max(s7_total, 1), 4),
        "error_ratio":       round(s7_other / max(s7_total, 1), 4),
    }


def extract_features(
    labeled_packets: List[Tuple],
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
    min_pkts: int = DEFAULT_MIN_PKTS,
) -> List[Dict]:
    """
    Trích xuất đặc trưng từ danh sách (packet, label) theo cửa sổ thời gian.
    """
    if not labeled_packets:
        return []

    # Sắp xếp theo thời gian
    labeled_packets.sort(key=lambda x: float(x[0].time))

    rows = []
    t_start = float(labeled_packets[0][0].time)
    t_end   = t_start + window_seconds
    window  = []

    for pkt, lbl in labeled_packets:
        pt = float(pkt.time)
        if pt > t_end:
            row = _process_window(window, t_start, t_end)
            if row and len(window) >= min_pkts:
                rows.append(row)
            t_start = t_end
            t_end   = t_start + window_seconds
            window  = []
        window.append((pkt, lbl))

    # Cửa sổ cuối cùng
    if window and len(window) >= min_pkts:
        row = _process_window(window, t_start, t_end)
        if row:
            rows.append(row)

    return rows


def save_csv(rows: List[Dict], output_path: str) -> None:
    """Ghi danh sách đặc trưng ra file CSV."""
    if not rows:
        print(f"[!] Không có dữ liệu để ghi: {output_path}")
        return
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FEATURE_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"[✓] Đã lưu {len(rows)} dòng → {output_path}")


# ══════════════════════════════════════════════════════════════
#  BƯỚC 4 – TRAIN MLP & RANDOM FOREST
# ══════════════════════════════════════════════════════════════

# Feature gây bias (Data Leakage) – bị loại bỏ trước khi train
# - window_start / window_end: Mang thông tin thời gian tuyệt đối.
#   AI sẽ "học" theo cái khung giờ chạy tấn công thay vì học hành vi mạng.
# - flow_duration_ms: Phụ thuộc 100% vào window_size đã chọn,
#   không ổn định khi deploy với window khác.
BIAS_FEATURES = [
    "window_start",
    "window_end",
    "flow_duration_ms",
]


def preprocess_features(
    df,
    feature_cols: List[str],
    corr_threshold: float = 0.99,    # Nâng ngưỡng lên để giữ nhiều feature hơn
    variance_threshold: float = 1e-6,
):
    """
    Tiền xử lý dữ liệu trước khi train:
      1. Loại bỏ BIAS features (data leakage)
      2. Xử lý NaN và Inf
      3. Loại bỏ feature có variance ≈ 0 (hằng số)
      4. Loại bỏ feature tương quan rất cao (Pearson > corr_threshold)
    Trả về (X_df sau xử lý, danh sách feature còn lại)
    """
    import numpy as np
    import pandas as pd
    from sklearn.feature_selection import VarianceThreshold

    print(f"\n{'─'*60}")
    print("  TIỀN XỬ LÝ DỮ LIỆU (Preprocessing)")
    print(f"{'─'*60}")
    print(f"  Số feature đầu vào   : {len(feature_cols)}")

    X = df[feature_cols].copy()

    # ── 1. Loại bỏ feature gây Bias / Data Leakage ────────────
    bias_to_drop = [c for c in BIAS_FEATURES if c in X.columns]
    if bias_to_drop:
        print(f"\n  Loại bỏ feature gây BIAS / Leakage ({len(bias_to_drop)}):")
        for c in bias_to_drop:
            reasons = {
                "window_start":   "Thời gian tuyệt đối → AI học theo giờ chạy, không học hành vi",
                "window_end":     "Thời gian tuyệt đối → AI học theo giờ chạy, không học hành vi",
                "flow_duration_ms": "Phụ thuộc window_size → không ổn định khi deploy",
            }
            print(f"    ✗ {c:<25} ({reasons.get(c, 'Bias')})")
        X.drop(columns=bias_to_drop, inplace=True)
    else:
        print(f"  Không có feature bias trong danh sách cần loại.")

    print(f"  Feature sau bước 1   : {len(X.columns)}")

    # ── 2. Xử lý NaN và Inf ───────────────────────────────────
    nan_cnt = X.isna().sum().sum()
    inf_cnt = np.isinf(X.select_dtypes(include='number').values).sum()
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)
    print(f"  NaN/Inf              : {nan_cnt + inf_cnt} giá trị → thay bằng 0")

    # ── 3. Loại bỏ feature Variance ≈ 0 (hằng số) ────────────
    cols_before = list(X.columns)
    selector = VarianceThreshold(threshold=variance_threshold)
    selector.fit(X)
    low_var_cols = [c for c, keep in zip(cols_before, selector.get_support()) if not keep]
    if low_var_cols:
        print(f"\n  Loại bỏ feature variance thấp (= hằng số) ({len(low_var_cols)}):")
        for c in low_var_cols:
            print(f"    ✗ {c}")
        X.drop(columns=low_var_cols, inplace=True)
    else:
        print(f"  Không có feature hằng số.")
    print(f"  Feature sau bước 3   : {len(X.columns)}")

    # ── 4. Loại bỏ feature tương quan rất cao (> 0.99) ────────
    corr_matrix = X.corr().abs()
    to_drop = []
    seen = set()
    for col in corr_matrix.columns:
        for row in corr_matrix.index:
            if row == col or row in seen:
                continue
            if corr_matrix.loc[row, col] > corr_threshold and col not in to_drop:
                to_drop.append(col)
        seen.add(col)

    if to_drop:
        print(f"\n  Loại bỏ feature tương quan > {corr_threshold} ({len(to_drop)}):")
        for c in to_drop:
            vals = corr_matrix[c].drop(c).sort_values(ascending=False)
            partner = vals.index[0]
            print(f"    ✗ {c:<30} ↔ '{partner}' (r={vals.iloc[0]:.3f})")
        X.drop(columns=to_drop, inplace=True, errors='ignore')
    else:
        print(f"  Không có feature tương quan quá cao.")

    final_features = list(X.columns)
    print(f"\n  ✓ Feature sau tiền xử lý: {len(final_features)}")
    print(f"  ✓ Đã loại bỏ tổng cộng : {len(feature_cols) - len(final_features)} feature")
    print(f"\n  Danh sách feature sử dụng để train:")
    for i, c in enumerate(final_features):
        print(f"    {i+1:>2}. {c}")

    return X, final_features


def train_and_evaluate(csv_file: str, output_dir: str) -> None:
    """
    Load dataset CSV, tiền xử lý, train MLP và RF, in báo cáo đầy đủ.
    Cả RF và MLP đều được scale bằng StandardScaler.
    """
    try:
        import pandas as pd
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.neural_network import MLPClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import LabelEncoder, StandardScaler
        from sklearn.metrics import (classification_report, confusion_matrix,
                                     accuracy_score, f1_score)
    except ImportError as e:
        print(f"[!] Thiếu thư viện: {e}")
        print("    Chạy: pip install scikit-learn pandas numpy")
        return

    print(f"\n{'═'*60}")
    print("  HUẤN LUYỆN MÔ HÌNH IDS")
    print(f"{'═'*60}")

    # ── Đọc CSV ──────────────────────────────────────────────
    df = pd.read_csv(csv_file)
    print(f"\n[✓] Dataset gốc: {len(df)} dòng, {len(df.columns)} cột")

    # Thống kê phân phối nhãn ban đầu
    print(f"\n  Phân phối nhãn (gốc):")
    label_counts = df["label"].value_counts()
    total = len(df)
    for lbl, cnt in label_counts.items():
        pct = cnt / total * 100
        bar = "█" * int(pct / 2)
        print(f"    {lbl:<25} {cnt:>6} mẫu  ({pct:5.1f}%)  {bar}")

    # Kiểm tra mất cân bằng
    max_cnt = label_counts.max()
    min_cnt = label_counts.min()
    imbalance_ratio = max_cnt / max(min_cnt, 1)
    if imbalance_ratio > 10:
        print(f"\n  ⚠️  DỮ LIỆU MẤT CÂN BẰNG NẶNG (ratio = {imbalance_ratio:.1f}x)")
        print(f"     Sẽ dùng class_weight='balanced' để bù đắp.")
    else:
        print(f"\n  ✓  Dữ liệu tương đối cân bằng (ratio = {imbalance_ratio:.1f}x)")

    # ── Chuẩn bị feature đầu vào (loại bias feature) ─────────
    feature_cols = [c for c in FEATURE_COLUMNS
                    if c not in ("window_start", "window_end", "label")]

    # Loại bias features trước split (không ảnh hưởng vì chỉ dựa
    # vào định nghĩa cố định của BIAS_FEATURES, không học từ data)
    raw_X = df[[c for c in feature_cols if c not in BIAS_FEATURES]].copy()
    raw_X.replace([np.inf, -np.inf], np.nan, inplace=True)
    raw_X.fillna(0, inplace=True)
    candidate_features = list(raw_X.columns)

    print(f"\n  Feature sau khi loại bias: {len(candidate_features)}")
    print(f"  (Bias loại: {[c for c in BIAS_FEATURES if c in feature_cols]})")

    # Encode nhãn
    y_raw = df["label"].values
    le = LabelEncoder()
    y  = le.fit_transform(y_raw)
    print(f"\n  Các nhãn ({len(le.classes_)}): {list(le.classes_)}")

    # ─────────────────────────────────────────────────────────────
    # ✅ SPLIT TRƯỚC – chống Data Leakage
    # Tất cả các bước fit (VarianceThreshold, Correlation, Scaler)
    # chỉ được thực hiện trên tập TRAIN sau khi đã split.
    # ─────────────────────────────────────────────────────────────
    X_raw = raw_X.values
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X_raw, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\n  Train : {len(X_train_raw)} mẫu  |  Test : {len(X_test_raw)} mẫu")
    print(f"  (Split TRƯỚC preprocessing – không data leakage)")

    import pandas as _pd
    X_train_df = _pd.DataFrame(X_train_raw, columns=candidate_features)
    X_test_df  = _pd.DataFrame(X_test_raw,  columns=candidate_features)

    # ── Bước A: VarianceThreshold – fit trên TRAIN ────────────
    from sklearn.feature_selection import VarianceThreshold
    var_sel = VarianceThreshold(threshold=1e-6)
    var_sel.fit(X_train_df)
    keep_mask   = var_sel.get_support()
    low_var_cols = [c for c, k in zip(candidate_features, keep_mask) if not k]
    if low_var_cols:
        print(f"\n  Loại bỏ feature hằng số ({len(low_var_cols)}): {low_var_cols}")
    X_train_df = X_train_df.loc[:, keep_mask]
    X_test_df  = X_test_df.loc[:, keep_mask]
    after_var_features = list(X_train_df.columns)

    # ── Bước B: Correlation – tính trên TRAIN only ────────────
    corr_threshold = 0.99
    corr_matrix = X_train_df.corr().abs()
    to_drop_corr = []
    seen = set()
    for col in corr_matrix.columns:
        for row in corr_matrix.index:
            if row == col or row in seen:
                continue
            if corr_matrix.loc[row, col] > corr_threshold and col not in to_drop_corr:
                to_drop_corr.append(col)
        seen.add(col)

    if to_drop_corr:
        print(f"\n  Loại bỏ feature tương quan > {corr_threshold} ({len(to_drop_corr)}):")
        for c in to_drop_corr:
            vals = corr_matrix[c].drop(c).sort_values(ascending=False)
            print(f"    ✗ {c:<30} ↔ '{vals.index[0]}' (r={vals.iloc[0]:.3f})")
        X_train_df.drop(columns=to_drop_corr, inplace=True, errors='ignore')
        X_test_df.drop(columns=to_drop_corr,  inplace=True, errors='ignore')

    final_features = list(X_train_df.columns)
    print(f"\n  ✓ Feature dùng để train: {len(final_features)}")
    for i, c in enumerate(final_features):
        print(f"    {i+1:>2}. {c}")

    X_train_arr = X_train_df.values
    X_test_arr  = X_test_df.values

    # ── Bước C: StandardScaler – fit trên TRAIN only ──────────
    print(f"\n  Áp dụng StandardScaler (fit trên TRAIN only)...")
    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train_arr)  # fit + transform train
    X_test_sc  = scaler.transform(X_test_arr)        # chỉ transform test
    print(f"  ✓ Mean ~ 0, Std ~ 1 – Test set chỉ được transform, KHÔNG fit")


    # ── Cấu hình models ───────────────────────────────────────
    models = {
        "Random Forest": {
            "model": RandomForestClassifier(
                n_estimators=200,
                max_depth=None,
                min_samples_split=2,
                class_weight="balanced",
                n_jobs=-1,
                random_state=42,
            ),
            "X_train": X_train_sc,   # Dùng dữ liệu đã scale
            "X_test":  X_test_sc,
        },
        "MLP": {
            "model": MLPClassifier(
                hidden_layer_sizes=(256, 128, 64),
                activation="relu",
                solver="adam",
                max_iter=300,
                early_stopping=True,
                validation_fraction=0.1,
                random_state=42,
            ),
            "X_train": X_train_sc,
            "X_test":  X_test_sc,
        },
    }

    results = {}
    for name, cfg in models.items():
        print(f"\n{'─'*60}")
        print(f"  Mô hình: {name}")
        print(f"{'─'*60}")
        t0 = time.time()
        clf = cfg["model"]
        clf.fit(cfg["X_train"], y_train)
        y_pred = clf.predict(cfg["X_test"])
        elapsed = time.time() - t0

        acc = accuracy_score(y_test, y_pred)
        f1  = f1_score(y_test, y_pred, average="weighted", zero_division=0)
        print(f"  Thời gian train : {elapsed:.1f}s")
        print(f"  Accuracy        : {acc*100:.2f}%")
        print(f"  F1 (weighted)   : {f1*100:.2f}%")

        print(f"\n  Classification Report:")
        print(classification_report(
            y_test, y_pred,
            target_names=le.classes_,
            zero_division=0
        ))

        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        print(f"  Confusion Matrix (hàng = thực, cột = dự đoán):")
        header = f"{'':>22}" + "".join(f"{c[:8]:>10}" for c in le.classes_)
        print(f"  {header}")
        for i, row in enumerate(cm):
            row_str = f"  {le.classes_[i]:>22}" + "".join(f"{v:>10}" for v in row)
            print(row_str)

        # Feature Importance (chỉ cho RF)
        if hasattr(clf, "feature_importances_"):
            fi = sorted(zip(final_features, clf.feature_importances_),
                        key=lambda x: -x[1])[:10]
            print(f"\n  Top 10 đặc trưng quan trọng (RF):")
            for feat, imp in fi:
                bar = "█" * int(imp * 60)
                print(f"    {feat:<32} {imp:.4f}  {bar}")

        results[name] = {"acc": acc, "f1": f1}

        # Lưu model
        model_path = os.path.join(output_dir, f"model_{name.lower().replace(' ', '_')}.pkl")
        try:
            import pickle
            with open(model_path, "wb") as f:
                pickle.dump({"model": clf, "scaler": scaler if name == "MLP" else None,
                             "label_encoder": le, "features": final_features}, f)
            print(f"\n  [✓] Model lưu tại: {model_path}")
        except Exception as e:
            print(f"  [!] Không lưu được model: {e}")

    # ── Tóm tắt kết quả ───────────────────────────────────────
    print(f"\n{'═'*60}")
    print("  TÓM TẮT KẾT QUẢ CUỐI CÙNG")
    print(f"{'═'*60}")
    print(f"  Dataset    : {len(df)} mẫu → sau tiền xử lý: {len(X)} mẫu")
    print(f"  Features   : {len(feature_cols)} → sau tiền xử lý: {len(final_features)}")
    print(f"  {'Mô hình':<25} {'Accuracy':>10} {'F1 (weighted)':>15}")
    print(f"  {'─'*52}")
    for name, r in results.items():
        print(f"  {name:<25} {r['acc']*100:>9.2f}%  {r['f1']*100:>14.2f}%")
    print(f"{'═'*60}")



# ══════════════════════════════════════════════════════════════
#  MAIN PIPELINE
# ══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Pipeline: PCAP → Features (CICFlow+S7) → MLP/RF IDS",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # ── Tham số bắt buộc ──────────────────────────────────────
    parser.add_argument("--plc-ip", required=True,
                        help="IP của PLC (dùng làm bộ lọc gói tin)")

    # ── File đầu vào ──────────────────────────────────────────
    parser.add_argument("--attack-pcap", nargs="+", default=[],
                        metavar="FILE.pcap",
                        help="Một hoặc nhiều file PCAP chứa kịch bản tấn công")
    parser.add_argument("--timeline", nargs="+", default=[],
                        metavar="FILE.csv",
                        help="File timeline.csv tương ứng với từng attack-pcap\n"
                             "(số lượng phải bằng số attack-pcap)")
    parser.add_argument("--benign-pcap", nargs="+", default=[],
                        metavar="FILE.pcap",
                        help="Một hoặc nhiều file PCAP bình thường (gán nhãn BENIGN)")

    # ── Có thể chỉ dùng CSV đã extract sẵn ───────────────────
    parser.add_argument("--features-csv", default="",
                        help="Bỏ qua bước extract, dùng thẳng file CSV này để train")

    # ── Tham số cấu hình ──────────────────────────────────────
    parser.add_argument("--window", type=float, default=DEFAULT_WINDOW_SECONDS,
                        help=f"Thời gian cửa sổ trích xuất đặc trưng (giây) "
                             f"[mặc định: {DEFAULT_WINDOW_SECONDS}]")
    parser.add_argument("--plc-port", type=int, default=DEFAULT_PLC_PORT,
                        help=f"Cổng S7 comm [mặc định: {DEFAULT_PLC_PORT}]")
    parser.add_argument("--min-pkts", type=int, default=DEFAULT_MIN_PKTS,
                        help=f"Số gói tin tối thiểu để giữ một cửa sổ [mặc định: {DEFAULT_MIN_PKTS}]")
    parser.add_argument("--output", default="results",
                        help="Thư mục lưu kết quả [mặc định: results/]")

    # ── Flags ─────────────────────────────────────────────────
    parser.add_argument("--no-train", action="store_true",
                        help="Chỉ extract features, không train model")
    parser.add_argument("--no-extract", action="store_true",
                        help="Bỏ qua extract, chỉ train từ features-csv đã có")

    args = parser.parse_args()

    # Validation
    if not args.features_csv and not args.no_extract:
        if not args.attack_pcap and not args.benign_pcap:
            parser.error("Cần ít nhất --attack-pcap hoặc --benign-pcap (hoặc --features-csv)")
        if args.attack_pcap and len(args.attack_pcap) != len(args.timeline):
            parser.error("Số lượng --attack-pcap và --timeline phải bằng nhau")

    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    global DEFAULT_PLC_PORT
    DEFAULT_PLC_PORT = args.plc_port

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║          ICS DATASET PIPELINE – PCAP → TRAIN IDS            ║
╠══════════════════════════════════════════════════════════════╣
║  PLC IP       : {args.plc_ip:<44}║
║  PLC Port     : {args.plc_port:<44}║
║  Window Size  : {args.window:<44}║
║  Min Pkts/Win : {args.min_pkts:<44}║
║  Output Dir   : {args.output:<44}║
╚══════════════════════════════════════════════════════════════╝
""")

    # ── BƯỚC 1 & 2: Extract Features ──────────────────────────
    final_csv = os.path.join(args.output, f"features_{ts}.csv")

    if args.features_csv:
        final_csv = args.features_csv
        print(f"[→] Dùng features-csv có sẵn: {final_csv}")
    elif not args.no_extract:
        all_rows: List[Dict] = []

        # Xử lý các file ATTACK
        for pcap_f, timeline_f in zip(args.attack_pcap, args.timeline):
            if not os.path.exists(pcap_f):
                print(f"[!] Không tìm thấy file: {pcap_f}")
                continue
            if not os.path.exists(timeline_f):
                print(f"[!] Không tìm thấy timeline: {timeline_f}")
                continue

            windows = load_timeline(timeline_f)
            labeled = filter_attack_pcap(pcap_f, windows, args.plc_ip, args.plc_port)
            rows    = extract_features(labeled, args.window, args.min_pkts)
            print(f"[✓] Extract xong {pcap_f}: {len(rows)} cửa sổ đặc trưng")
            all_rows.extend(rows)

        # Xử lý các file BENIGN
        for pcap_f in args.benign_pcap:
            if not os.path.exists(pcap_f):
                print(f"[!] Không tìm thấy file: {pcap_f}")
                continue
            labeled = load_benign_pcap(pcap_f, args.plc_ip, args.plc_port)
            rows    = extract_features(labeled, args.window, args.min_pkts)
            print(f"[✓] Extract xong {pcap_f}: {len(rows)} cửa sổ (BENIGN)")
            all_rows.extend(rows)

        # Lưu CSV
        save_csv(all_rows, final_csv)

        # Thống kê
        if all_rows:
            from collections import Counter
            cnt = Counter(r["label"] for r in all_rows)
            print(f"\n  Tổng cộng: {len(all_rows)} cửa sổ")
            for lbl, c in cnt.most_common():
                print(f"    {lbl:<25} {c:>6} mẫu")

    # ── BƯỚC 3: Train ─────────────────────────────────────────
    if not args.no_train:
        if os.path.exists(final_csv):
            train_and_evaluate(final_csv, args.output)
        else:
            print(f"[!] Không tìm thấy file features: {final_csv}")
            print("    Chạy lại không có --no-extract để tạo features trước.")
    else:
        print("\n[→] Bỏ qua bước train (--no-train được đặt)")

    print(f"\n[✓] Xong! Kết quả tại: {args.output}/")


if __name__ == "__main__":
    main()
