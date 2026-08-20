import pandas as pd
import numpy as np

def preprocess_twosource_dataset(net_csv, process_csv, output_path):
    print("[*] Tích hợp 2 nguồn dữ liệu (Chuẩn DataSense): Network/DPI + Process/Sensor")

    # 1. Tải dữ liệu
    df_net = pd.read_csv(net_csv, parse_dates=['timestamp'])
    df_phys = pd.read_csv(process_csv, parse_dates=['timestamp'])
    
    # 2. Đồng bộ hóa (Time-Series Alignment) theo 1 giây
    df_net.set_index('timestamp', inplace=True)
    df_phys.set_index('timestamp', inplace=True)

    net_resampled = df_net.resample('1S').sum().fillna(0)
    # Lấy trạng thái vật lý cuối cùng của giây đó và điền tiếp nếu không đổi
    phys_resampled = df_phys.resample('1S').last().ffill().fillna(0)

    # Ghép 2 DataFrame lại với nhau dựa trên mốc thời gian
    df_merged = pd.concat([net_resampled, phys_resampled], axis=1).fillna(0)

    # 3. TRÍCH XUẤT ĐẶC TRƯNG DẪN XUẤT (Derived Features)
    print("[*] Đang tính toán Đặc trưng dẫn xuất từ Payload và Trạng thái vật lý...")
    
    # Motor có thay đổi trạng thái hay không
    df_merged['motor_prev'] = df_merged['motor_status'].shift(1).fillna(0)
    df_merged['motor_changed'] = (df_merged['motor_status'] != df_merged['motor_prev']).astype(int)

    # Logic: Động cơ tự nhiên bật (0->1) mà không có vật phẩm ở Sensor 1 (Dấu hiệu của Spoof/Stealthy Write)
    df_merged['abnormal_start'] = np.where(
        (df_merged['motor_prev'] == 0) & 
        (df_merged['motor_status'] == 1) & 
        (df_merged['sensor_s1'] == 0), 1, 0)

    # Logic: Setpoint vượt ngưỡng an toàn (Setpoint out of range)
    MIN_SAFE = 20
    MAX_SAFE = 80
    if 'setpoint_speed' in df_merged.columns:
        df_merged['setpoint_out_of_range'] = np.where(
            (df_merged['setpoint_speed'] < MIN_SAFE) | 
            (df_merged['setpoint_speed'] > MAX_SAFE), 1, 0)

    # Lưu lại
    df_merged.to_csv(output_path)
    print(f"[+] Hoàn tất! Output shape: {df_merged.shape}")
    print(f"[+] Đã lưu vào: {output_path}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="DataSense Pipeline: Merge Network and Process Logs")
    parser.add_argument("--net", required=True, help="Đường dẫn file CSV mạng (sinh ra từ collect_dataset.py)")
    parser.add_argument("--phys", required=True, help="Đường dẫn file CSV vật lý (sinh ra từ log_tags.py)")
    parser.add_argument("--out", required=True, help="Đường dẫn file CSV đầu ra (final_dataset)")
    
    args = parser.parse_args()
    
    # Chạy hàm tích hợp
    preprocess_twosource_dataset(args.net, args.phys, args.out)
