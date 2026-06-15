import time
import os

# ==========================================
# ĐƯỜNG DẪN BẠN ĐIỀN ĐỂ LƯU FILE GÁN NHÃN DỮ LIỆU (GROUND TRUTH TIMELINE)
# ==========================================
LABEL_TXT_PATH = r"e:\Đồ án\code\iiot\dataset_labels_timeline.txt"

def log_event(label_type, action_detail):
    """
    Hàm này ghi thẳng thông tin Nhãn (Label) và Thời gian thực thi (Timestamp)
    vào file TXT mà bạn điền ở trên, dùng để map (đối chiếu) với file PCAP sau này.
    
    :param label_type: Nhãn (Ví dụ: BENIGN, ATTACK_DOS, ATTACK_LOGIC)
    :param action_detail: Chi tiết hành động (VD: HMI_READ, NMAP_SCAN)
    """
    time_str = time.strftime('%Y-%m-%d %H:%M:%S')
    time_epoch = f"{time.time():.6f}"
    
    log_line = f"{time_str},{time_epoch},{label_type},{action_detail}\n"
    
    try:
        # Mở file chế độ append ('a') để ghi nối tiếp các ngày
        with open(LABEL_TXT_PATH, 'a', encoding='utf-8') as f:
            f.write(log_line)
    except Exception as e:
        print(f"Lỗi khi ghi lịch sử vào text file: {e}")
