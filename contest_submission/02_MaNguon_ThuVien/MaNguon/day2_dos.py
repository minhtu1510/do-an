import time
import random
import threading
import subprocess
import logging
import os
import re
import sys

# Nhúng module ghi log timeline (ground truth)
from label_logger import log_event

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# ==========================================
# CẤU HÌNH IP
# ==========================================
def load_testbed_value(name, default=""):
    try:
        with open("testbed.conf", "r", encoding="utf-8") as f:
            for line in f:
                match = re.match(rf"^\s*{re.escape(name)}\s*=\s*[\"']?([^\"'#]*)", line)
                if match:
                    return match.group(1).strip()
    except OSError:
        pass
    return default


PLC_IP = os.getenv("TARGET_IP") or load_testbed_value("TARGET_IP", "192.168.1.10")
TOOL_DIR = r"e:\Đồ án\code\iiot\s7pwn"  # Thư mục chứa công cụ của bạn

# ==========================================
# MODULE 1: DUY TRÌ LƯU LƯỢNG NỀN (BENIGN) TỪ NGÀY 1
# ==========================================
def simulate_benign_traffic_background():
    """Chạy ngầm traffic sạch để tạo bối cảnh thực tế cho dataset"""
    logging.info("[Benign] Khởi động lưu lượng nền (Background Traffic).")
    while True:
        try:
            # Ghi chú: Có thể không cần ghi log BENIGN dày đặc trong ngày tấn công,
            # hoặc chỉ log thưa ra để tập trung vào nhãn ATTACK
            time.sleep(random.uniform(5.0, 10.0))
        except Exception:
            pass

# ==========================================
# MODULE 2: LÊN LỊCH TẤN CÔNG THEO KHUNG GIỜ
# ==========================================
def run_scan_attack():
    logging.warning(f"!!! KÍCH HOẠT: Quét hệ thống PLC {PLC_IP} !!!")
    
    # 1. Ghi nhãn lúc bắt đầu tính toán thời gian
    log_event("ATTACK_SCAN", f"START_SCAN_NMAP_S7_TO_{PLC_IP}")
    
    # 2. CHẠY CÔNG CỤ CỦA BẠN (Đã comment sẵn để bạn có thể mở ra)
    try:
        # Ví dụ gọi scan.py của bạn qua mảng subprocess để chạy thật:
        # scan_path = f"{TOOL_DIR}\\scan.py" # Thay thế bằng đường dẫn nếu dùng lệnh khác
        # subprocess.run(["python", scan_path, "--target", PLC_IP], timeout=60)
        
        # Mô phỏng thời gian chạy của công cụ quét...
        time.sleep(15) 
    except Exception as e:
        logging.error(f"Lỗi chạy tool Scan: {e}")
        
    # 3. Ghi nhãn kết thúc
    log_event("ATTACK_SCAN", f"END_SCAN_TO_{PLC_IP}")
    logging.info("Hoàn tất rà quét.")

def run_dos_flood_attack():
    logging.warning(f"!!! KÍCH HOẠT: TẤN CÔNG TỪ CHỐI DỊCH VỤ S7Comm {PLC_IP} !!!")
    
    # 1. Ghi nhãn thời điểm bắt đầu
    log_event("ATTACK_DOS", f"START_S7_FLOOD_{PLC_IP}")
    
    try:
        # 2. GỌI CÔNG CỤ TỪ CHỐI DỊCH VỤ CỦA BẠN
        # Lệnh gọi mẫu file flood.py:
        # flood_path = f"{TOOL_DIR}\\flood.py"
        # subprocess.run(["python", flood_path, "--target", PLC_IP, "--threads", "200"], timeout=120)
        
        # Mô phỏng thời gian càn quét làm ngập lụt PLC (ví dụ 45 giây)
        time.sleep(45)
    except Exception as e:
        logging.error(f"Lỗi chạy tool DoS: {e}")
        
    # 3. Ghi nhãn kết thúc (rất quan trọng cho việc train model Machine Learning)
    log_event("ATTACK_DOS", f"END_S7_FLOOD_{PLC_IP}")
    logging.info("Mạng đã bình phục sau DoS.")

def attack_scheduler():
    """Bộ định tuyến khung giờ tấn công"""
    # Trong môi trường lab, thay vì chờ "vào một khung giờ", 
    # ta có thể sắp xếp timeline tuần tự như sau để có ngay dữ liệu:
    
    # Chờ 30s đầu cho mạng ổn định với lượng lưu lượng nền (baseline)
    logging.info("Đang chờ thu thập mạng làm baseline (30s)...")
    time.sleep(30)
    
    # Khung giờ 1: Gây ra vụ rà quét
    run_scan_attack()
    
    # Chờ hệ thống yên tĩnh trở lại sau đợt quét (30s)
    logging.info("Hệ thống nghỉ ngơi (30s)...")
    time.sleep(30)
    
    # Khung giờ 2: Thực thi tấn công DoS đánh sập kết nối SCADA
    run_dos_flood_attack()
    
    # Kết thúc thử nghiệm ngày 2
    logging.info("Hoàn thành các bài Test Ngày 2.")
    log_event("SYSTEM", "END_DAY2_TESTING")

if __name__ == '__main__':
    logging.info("=== BẮT ĐẦU KỊCH BẢN NGÀY 2: DOS VÀ SCAN ===")
    logging.warning("day2_dos.py là script mô phỏng cũ; dùng run_day_bangtruyen.sh cho bộ dữ liệu chính.")
    log_event("SYSTEM", "START_DAY2_SCENARIOS")
    
    # 1. Bật duy trì lưu lượng chạy nền
    t_benign = threading.Thread(target=simulate_benign_traffic_background, daemon=True)
    t_benign.start()
    
    # 2. Khởi chạy luồng lên lịch Tấn công
    t_schedule = threading.Thread(target=attack_scheduler)
    t_schedule.start()
    
    # Chờ luồng lập lịch chạy xong
    t_schedule.join()
    logging.info("Thoát chương trình Ngày 2.")
