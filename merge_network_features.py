#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
merge_network_features.py
============================================================
Hợp nhất dữ liệu mạng đa tầng (Multi-Layer ICS Network Fusion):
- Ghép Layer 3/4 Bidirectional Flow + S7comm DPI (extract_s7_features.py)
- Với Layer 2 Broadcast Profinet DCP features (extract_dcp_features.py)

Phương pháp ghép:
- Left Join theo [window_start_ms, capture_role]
- Mọi luồng mạng đơn lẻ sẽ được làm giàu thêm ngữ cảnh quét thiết bị Layer 2.
"""

from __future__ import annotations

import argparse
import os
import sys


def merge_features(s7_csv: str, dcp_csv: str, output_csv: str) -> None:
    try:
        import pandas as pd
    except ImportError:
        print("[ERROR] Script này yêu cầu thư viện pandas. Hãy cài đặt: pip install pandas")
        sys.exit(1)

    if not os.path.exists(s7_csv):
        print(f"[ERROR] File S7 features không tồn tại: {s7_csv}")
        sys.exit(1)

    if not os.path.exists(dcp_csv):
        print(f"[ERROR] File DCP features không tồn tại: {dcp_csv}")
        sys.exit(1)

    print(f"[1/4] Đang đọc file S7comm/Flow features: {s7_csv}")
    df_s7 = pd.read_csv(s7_csv)
    print(f"      -> Tìm thấy {len(df_s7)} dòng dữ liệu Flow.")

    print(f"[2/4] Đang đọc file DCP Layer 2 features: {dcp_csv}")
    df_dcp = pd.read_csv(dcp_csv)
    print(f"      -> Tìm thấy {len(df_dcp)} dòng dữ liệu DCP.")

    # Loại bỏ các cột thời gian kết thúc trùng lặp của DCP để tránh hậu tố _x, _y khi ghép
    df_dcp = df_dcp.drop(columns=["window_end_ms"], errors="ignore")

    # Đảm bảo mốc thời gian là kiểu số nguyên
    df_s7["window_start_ms"] = df_s7["window_start_ms"].astype(int)
    df_dcp["window_start_ms"] = df_dcp["window_start_ms"].astype(int)

    # Thực hiện phép ghép Left Join
    print("[3/4] Đang thực hiện ghép dữ liệu đa tầng (Layer 2 + Layer 3/4)...")
    df_merged = pd.merge(
        df_s7,
        df_dcp,
        on=["window_start_ms", "capture_role"],
        how="left"
    )

    # Điền giá trị 0 cho các cột đặc trưng DCP ở các cửa sổ không có traffic DCP
    dcp_cols = [col for col in df_dcp.columns if col not in ["window_start_ms", "capture_role"]]
    df_merged[dcp_cols] = df_merged[dcp_cols].fillna(0)

    # Lưu file kết quả
    print(f"[4/4] Đang ghi file kết quả ghép: {output_csv}")
    os.makedirs(os.path.dirname(os.path.abspath(output_csv)) or ".", exist_ok=True)
    df_merged.to_csv(output_csv, index=False)

    print(f"[OK] Hoàn tất ghép đặc trưng mạng!")
    print(f"     Tổng số mẫu (Flows): {len(df_merged)}")
    print(f"     Tổng số đặc trưng: {len(df_merged.columns)}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Hợp nhất đặc trưng luồng mạng S7comm và Layer 2 Profinet DCP."
    )
    parser.add_argument(
        "--s7",
        required=True,
        help="Đường dẫn file CSV sinh ra từ extract_s7_features.py",
    )
    parser.add_argument(
        "--dcp",
        required=True,
        help="Đường dẫn file CSV sinh ra từ extract_dcp_features.py",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Đường dẫn file CSV đầu ra đã ghép",
    )

    args = parser.parse_args()
    merge_features(args.s7, args.dcp, args.out)


if __name__ == "__main__":
    main()
