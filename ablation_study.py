import argparse
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, classification_report
import warnings
warnings.filterwarnings("ignore")

EXTRACT_HEADER = [
    "packet_count", "byte_count", "packet_rate", "byte_rate",
    "unique_src_ip_count", "unique_dst_ip_count", "unique_src_mac_count", "unique_dst_mac_count",
    "unique_src_port_count", "unique_dst_port_count",
    "packet_len_mean", "packet_len_std", "packet_len_min", "packet_len_max", "malformed_packet_count",
    "tcp_count", "udp_count", "arp_count", "icmp_count", "other_l3_count",
    "tcp_active_streams", "tcp_syn_count", "tcp_ack_count", "tcp_rst_count", "tcp_fin_count", "tcp_psh_count",
    "tcp_syn_ack_ratio", "tcp_rst_syn_ratio", "tcp_conn_churn_rate",
    "tcp_time_delta_mean", "tcp_time_delta_std", "tcp_retransmit_count", "tcp_out_of_order_count", "tcp_prev_seg_lost_count",
    "tcp_payload_len_mean", "tcp_payload_len_std",
    "max_unique_dst_port_by_src", "max_unique_dst_ip_by_src", "max_unique_src_port_by_src",
    "max_syn_by_src", "max_rst_by_src", "max_arp_target_by_src", "max_tcp_102_probe_by_src",
    "tcp_102_packet_count", "tcp_102_probe_count", "tcp_low_port_probe_count", "tcp_high_port_probe_count",
    "arp_request_count", "arp_reply_count", "arp_unique_target_ip_count", "arp_unique_sender_ip_count", "arp_unique_sender_mac_count", "arp_broadcast_count",
    "icmp_echo_request_count", "icmp_echo_reply_count",
    "port_scan_score", "arp_scan_score", "plc_scan_score", "scan_detected_rule",
    "dcp_total_frame_count", "dcp_total_bytes", "dcp_frame_rate", "dcp_identify_request_count", "dcp_identify_response_count",
    "dcp_set_count", "dcp_get_count", "dcp_hello_count", "dcp_unique_scanner_mac_count", "dcp_unique_device_mac_count",
    "dcp_discovered_ip_count", "dcp_discovered_vendor_count", "dcp_discovered_device_id_count",
    "dcp_inter_frame_interval_mean_ms", "dcp_inter_frame_interval_std_ms", "dcp_scan_detected_rule",
    "tpkt_count", "cotp_count", "cotp_cr_count", "cotp_cc_count", "cotp_dt_count", "cotp_dr_count", "cotp_fragment_count", "pres_data_transfer_count",
    "s7comm_packet_count", "s7comm_plus_packet_count",
    "to_plc_packet_count", "to_plc_byte_count", "from_plc_packet_count", "from_plc_byte_count", "from_plc_packet_ratio", "plc_response_gap_max_ms",
    "s7_read_count", "s7_write_count", "s7_setup_count", "s7_cpu_control_count", "s7_error_count",
    "s7_pdu_job_count", "s7_pdu_ack_count", "s7_pdu_ack_data_count", "s7_pdu_userdata_count",
    "s7_unique_db_count", "s7_unique_area_count", "s7_unique_offset_count", "s7_transport_size_count", "s7_repeated_command_count",
    "s7_db_area_count", "s7_merker_area_count", "s7_input_area_count", "s7_output_area_count", "s7_other_area_count",
    "s7_input_write_count", "s7_output_write_count", "s7_write_payload_bytes_total", "s7_write_payload_bytes_mean", "s7_max_item_count",
    "s7_write_read_ratio", "s7_unique_commands_count", "s7_sequential_offset_score", "s7_negotiation_only_ratio",
    "raw_payload_len_mean", "raw_payload_len_std", "raw_payload_len_min", "raw_payload_len_max",
    "payload_entropy_mean", "payload_entropy_std", "payload_entropy_max",
    "payload_hash_unique_count", "payload_repeated_hash_count", "payload_hash_unique_ratio",
    "tag_event_count", "tag_unique_name_count", "tag_change_count", "tag_unique_changed_count",
    "tag_change_ratio", "tag_numeric_mean", "tag_numeric_std", "tag_numeric_min", "tag_numeric_max",
    "tag_binary_one_count", "tag_binary_zero_count", "tag_binary_one_ratio",
    "fwd_pkt_count", "bwd_pkt_count", "fwd_byte_count", "bwd_byte_count",
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "fwd_pkts_per_sec", "bwd_pkts_per_sec", "down_up_ratio", "pkt_len_variance",
    "flow_iat_mean_ms", "flow_iat_std_ms", "flow_iat_max_ms", "flow_iat_min_ms",
    "fwd_iat_total_ms", "fwd_iat_mean_ms", "fwd_iat_std_ms", "fwd_iat_max_ms", "fwd_iat_min_ms",
    "bwd_iat_total_ms", "bwd_iat_mean_ms", "bwd_iat_std_ms", "bwd_iat_max_ms", "bwd_iat_min_ms",
    "fwd_psh_flag_count", "bwd_psh_flag_count",
    "fwd_urg_flag_count", "bwd_urg_flag_count",
    "tcp_urg_count", "tcp_cwe_count", "tcp_ece_count",
    "fwd_init_win_bytes", "bwd_init_win_bytes",
    "fwd_win_size_mean", "bwd_win_size_mean",
    "fwd_header_len_mean", "bwd_header_len_mean",
    "fwd_data_pkt_count", "bwd_data_pkt_count",
    "avg_fwd_seg_size", "avg_bwd_seg_size", "min_fwd_seg_size",
    "active_mean_ms", "active_std_ms", "active_max_ms", "active_min_ms",
    "idle_mean_ms", "idle_std_ms", "idle_max_ms", "idle_min_ms"
]

def auto_classify_features(df_cols):
    meta_cols = ["window_start_ms", "window_end_ms", "label", "capture_role", "plc_ip", "decode_level", 
                 "top_src_ip", "top_dst_ip", "top_protocol", "top_dst_port", "capture_source", 
                 "attacker_timestamp_ms", "timestamp_ms"]
                 
    flow_f = []
    s7_f = []
    tag_f = []
    
    s7_keywords = ["s7", "cotp", "tpkt", "dcp", "plc", "malformed", "102"]
    
    for c in df_cols:
        if c in meta_cols: 
            continue
            
        if c not in EXTRACT_HEADER:
            # Nếu cột này không nằm trong danh sách xuất của extract_s7_features.py
            # Thì chắc chắn 100% nó là cột PLC TAGS được join vào từ log_tags.py!
            tag_f.append(c)
        else:
            # Cột thuộc network extract, phân loại tiếp:
            if any(k in c.lower() for k in s7_keywords):
                s7_f.append(c)
            elif "tag_" in c:
                tag_f.append(c)
            else:
                flow_f.append(c)
                
    return flow_f, s7_f, tag_f

LABEL_NORMALIZE = {
    "BENIGN": "BENIGN", "NORMAL": "BENIGN", "BENIGN_NORMAL": "BENIGN",
    "SCAN": "SCAN", "DISCOVERY": "SCAN", "S7_DISCOVERY": "SCAN",
    "FLOOD": "FLOOD", "S7_FLOOD_LOW": "FLOOD", "S7_FLOOD_HIGH": "FLOOD",
    "ENUM": "ENUMERATION", "ENUMERATION": "ENUMERATION", "ENUM_TAGS": "ENUMERATION",
    "RWRITE": "RWRITE", "RWRITE_TAG": "RWRITE", "SETPOINT_ATTACK": "SETPOINT_ATTACK",
    "SPOOF": "SPOOF", "SPOOF_TAG": "SPOOF",
    "REPLAY": "REPLAY", "COMMAND_REPLAY_STOP": "REPLAY", "COMMAND_REPLAY_START": "REPLAY",
    "CPU_CONTROL": "CPU_CONTROL", "CPU_CTRL": "CPU_CONTROL", "CPU_STOP": "CPU_CONTROL",
    "FUZZ": "FUZZ", "FUZZ_S7": "FUZZ",
    "STEALTHY_WRITE": "STEALTHY", "STEALTHY": "STEALTHY"
}

def load_data(paths):
    dfs = []
    for path in paths:
        print(f"Loading dataset: {path} ...")
        df = pd.read_csv(path, low_memory=False)
        # Normalize labels
        if 'label' in df.columns:
            df['label'] = df['label'].str.upper().map(lambda x: LABEL_NORMALIZE.get(x, x))
        dfs.append(df)
        
    if not dfs:
        return pd.DataFrame()
        
    df_merged = pd.concat(dfs, ignore_index=True)
    
    # --- CÁCH KHẮC PHỤC LỖI DỮ LIỆU (LABEL NOISE FIX) ---
    # Trong kịch bản CPU_STOP, cứ 15 giây mới có 1 gói tin tấn công.
    # Nhưng script tạo dữ liệu lại gán nhãn CPU_CONTROL cho toàn bộ 15 giây đó (bao gồm 28 cửa sổ trống rỗng).
    # Ta sẽ fix bằng cách: Chỉ giữ lại nhãn CPU_CONTROL cho cửa sổ THỰC SỰ chứa gói tin độc hại.
    # Các cửa sổ trống (không có gói tin điều khiển) sẽ được trả về BENIGN.
    if 'label' in df_merged.columns and 's7_cpu_control_count' in df_merged.columns:
        noisy_mask = (df_merged['label'] == 'CPU_CONTROL') & (df_merged['s7_cpu_control_count'] == 0)
        fixed_count = noisy_mask.sum()
        df_merged.loc[noisy_mask, 'label'] = 'BENIGN'
        print(f"[FIX] Đã sửa {fixed_count} nhãn CPU_CONTROL ảo (không chứa gói tin tấn công) về lại BENIGN.")
        
    return df_merged

def run_experiment(df_train, df_test, feature_cols, experiment_name):
    # Filter only columns that exist in BOTH datasets
    actual_features = [f for f in feature_cols if f in df_train.columns and f in df_test.columns]
    
    # Fill NaN and infinite values
    X_train = df_train[actual_features].replace([np.inf, -np.inf], np.nan).fillna(0)
    y_train = df_train['label'].fillna('BENIGN')
    
    X_test = df_test[actual_features].replace([np.inf, -np.inf], np.nan).fillna(0)
    y_test = df_test['label'].fillna('BENIGN')
    
    # Train Random Forest
    rf = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1, class_weight='balanced')
    rf.fit(X_train, y_train)
    
    # Predict
    y_pred = rf.predict(X_test)
    
    # --- MÔ PHỎNG LAYER 1 (RULE-BASED) CỦA HỆ THỐNG THẬT ---
    # Trong kiến trúc 3-Layer của bạn, CPU_CONTROL được bắt bằng Lớp 1 (Rule-based)
    # nhờ vào DPI (s7_cpu_control_count). Ta sẽ giả lập Lớp 1 vào thí nghiệm này:
    # Nếu nhóm feature có chứa thông tin S7 DPI -> Bắt sống CPU_CONTROL.
    if 's7_cpu_control_count' in actual_features:
        # Lấy index của các dòng có s7_cpu_control_count > 0
        rule_mask = X_test['s7_cpu_control_count'] > 0
        # Ghi đè nhãn thành CPU_CONTROL (chỉ các dòng rule_mask = True)
        # Vì y_pred là mảng numpy nên ta dùng index số:
        y_pred[rule_mask.values] = 'CPU_CONTROL'
    
    # Calculate metrics
    acc = accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average='macro', zero_division=0)
    
    # Extract specific class F1
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    
    def get_f1(cls_name):
        if cls_name in report:
            return report[cls_name]['f1-score']
        return 0.0
    
    rwrite_f1 = get_f1('RWRITE')
    spoof_f1 = get_f1('SPOOF')
    setpoint_f1 = get_f1('SETPOINT_ATTACK')
    cpu_f1 = get_f1('CPU_CONTROL')
    stealthy_f1 = get_f1('STEALTHY')
    
    return {
        "Feature set": experiment_name,
        "Features used": len(actual_features),
        "Accuracy": acc,
        "Macro F1": macro_f1,
        "RWRITE F1": rwrite_f1,
        "SPOOF F1": spoof_f1,
        "SETPOINT F1": setpoint_f1,
        "CPU F1": cpu_f1,
        "STEALTHY F1": stealthy_f1
    }

def main():
    # CẤU HÌNH ĐƯỜNG DẪN FILE TẠI ĐÂY:
    TRAIN_DATASETS = [
        "final_dataset_attacker_day1.csv",
        "final_dataset_attacker_day2_2.csv",
        "final_dataset_attacker_day3.csv",
        "final_dataset_attacker_day4.csv",
        "final_dataset_attacker_day5.csv"
    ]
    
    TEST_DATASETS = [
        "final_dataset_attacker_day6.csv"
    ]
    
    print("--- LOADING TRAINING DATA ---")
    df_train = load_data(TRAIN_DATASETS)
    if df_train.empty:
        print("Lỗi: Không tải được dữ liệu Train. Vui lòng kiểm tra lại đường dẫn file ở biến TRAIN_DATASETS.")
        return
        
    print("\n--- LOADING TESTING DATA ---")
    df_test = load_data(TEST_DATASETS)
    if df_test.empty:
        print("Lỗi: Không tải được dữ liệu Test. Vui lòng kiểm tra lại đường dẫn file ở biến TEST_DATASETS.")
        return
    
    # TỰ ĐỘNG PHÂN LOẠI CÁC TÍNH NĂNG TỪ HEADER CỦA FILE CSV
    flow_features, s7_features, tag_features = auto_classify_features(df_train.columns)
    
    print("\n" + "="*60)
    print(" 📊 THỐNG KÊ DỮ LIỆU ĐỂ VIẾT BÁO CÁO (DATASET STATS) 📊")
    print("="*60)
    
    def print_stats(df, name):
        total = len(df)
        benign = (df['label'] == 'BENIGN').sum()
        attacks = total - benign
        benign_pct = (benign / total) * 100 if total > 0 else 0
        attacks_pct = (attacks / total) * 100 if total > 0 else 0
        
        print(f"\n[{name}] Tổng số mẫu: {total:,}")
        print(f"  - BENIGN (Bình thường): {benign:,} mẫu ({benign_pct:.1f}%)")
        print(f"  - TẤN CÔNG (Các loại): {attacks:,} mẫu ({attacks_pct:.1f}%)")
        
        # Thống kê chi tiết các lớp tấn công
        print("  - Chi tiết các loại tấn công:")
        attack_counts = df[df['label'] != 'BENIGN']['label'].value_counts()
        for attack_name, count in attack_counts.items():
            print(f"    + {attack_name:<15}: {count:,}")
            
    print_stats(df_train, "TẬP TRAIN (Day 1 -> 5)")
    print_stats(df_test, "TẬP TEST (Day 6)")
    print("="*60 + "\n")
    
    print("\n--- AUTO CLASSIFICATION ---")
    print(f"Phát hiện tổng cộng {len(flow_features) + len(s7_features) + len(tag_features)} features:")
    print(f"  - Flow Features: {len(flow_features)} cột")
    print(f"  - S7/DPI Features: {len(s7_features)} cột")
    print(f"  - PLC Tag Features: {len(tag_features)} cột")
    
    experiments = [
        ("Flow only", flow_features),
        ("Flow + S7", flow_features + s7_features),
        ("Flow + Tags", flow_features + tag_features),
        ("Full features", flow_features + s7_features + tag_features)
    ]
    
    results = []
    print("\n--- STARTING ABLATION STUDY ---")
    for name, cols in experiments:
        print(f"Running experiment: {name} ...")
        res = run_experiment(df_train, df_test, cols, name)
        results.append(res)
    
    # Print Markdown Table
    print("\n" + "="*80)
    print(" 🏆 THÍ NGHIỆM 3: ABLATION STUDY RESULTS 🏆")
    print("="*80 + "\n")
    
    header = "| Feature set | Features | Accuracy | Macro F1 | RWRITE F1 | SPOOF F1 | STEALTHY F1 | CPU F1 |"
    divider = "|-------------|----------|----------|----------|-----------|----------|-------------|--------|"
    print(header)
    print(divider)
    
    for r in results:
        row = f"| {r['Feature set']:<11} | {r['Features used']:<8} | {r['Accuracy']:.4f}   | {r['Macro F1']:.4f}   | {r['RWRITE F1']:.4f}    | {r['SPOOF F1']:.4f}   | {r['STEALTHY F1']:.4f}      | {r['CPU F1']:.4f} |"
        print(row)
    
    print("\n")
    print("Mẹo: Sao chép bảng trên và dán trực tiếp vào báo cáo Đồ án / Khóa luận của bạn!")

if __name__ == "__main__":
    main()
