import time
import random
import threading
import socket
import urllib.request
import logging

# Nhúng module ghi log timeline (dùng để gán nhãn Pcap)
from label_logger import log_event

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# CẤU HÌNH IP
PLC_IP = "192.168.0.100"      
IT_SERVER_IP = "192.168.0.10" 

def simulate_hmi_plc_scada():
    logging.info("Bắt đầu luồng giao tiếp SCADA/HMI (Đọc/Ghi lệnh hợp lệ).")
    while True:
        try:
            logging.info(f"[HMI -> PLC] Đang đọc trạng thái thanh ghi...")
            # ===== GHI TIMELINE XÁC NHẬN SỰ KIỆN BENIGN =====
            log_event("BENIGN", f"HMI_READ_PLC_STATUS_{PLC_IP}")
            
            time.sleep(random.uniform(0.5, 2.0))
            
            if random.random() < 0.2:
                logging.info(f"[HMI -> PLC] Đang gửi lệnh ĐIỀU KHIỂN...")
                # ===== GHI TIMELINE SỰ KIỆN ĐIỀU KHIỂN HỢP LỆ =====
                log_event("BENIGN", f"HMI_WRITE_PLC_COMMAND_{PLC_IP}")
            
            time.sleep(random.uniform(2.0, 5.0))
        except Exception as e:
            time.sleep(5)

def generate_http_background_traffic():
    while True:
        try:
            url = f"http://{IT_SERVER_IP}/"
            # ===== GHI TIMELINE NHIỄU HTTP =====
            log_event("BACKGROUND_TRAFFIC", f"HTTP_GET_TO_{IT_SERVER_IP}")
            
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=3) as response:
                pass
        except Exception:
            pass
        time.sleep(random.uniform(5, 15))

def generate_tcp_background_traffic(port, protocol_name):
    while True:
        try:
            # ===== GHI TIMELINE NHIỄU TCP =====
            log_event("BACKGROUND_TRAFFIC", f"TCP_CONNECT_{protocol_name}_TO_PORT_{port}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((IT_SERVER_IP, port))
                s.sendall(b"Ping\n")
        except Exception:
            pass
        time.sleep(random.uniform(10, 30))

if __name__ == '__main__':
    logging.info("=== BẮT ĐẦU THU THẬP NGÀY 1 ===")
    
    # Ghi nhận thời điểm bắt đầu
    log_event("SYSTEM", "START_DAY1_BENIGN_TRAFFIC")
    
    threads = []
    threads.append(threading.Thread(target=simulate_hmi_plc_scada, daemon=True))
    threads.append(threading.Thread(target=generate_http_background_traffic, daemon=True))
    threads.append(threading.Thread(target=generate_tcp_background_traffic, args=(22, "SSH"), daemon=True))
    threads.append(threading.Thread(target=generate_tcp_background_traffic, args=(21, "FTP"), daemon=True))
    
    for t in threads:
        t.start()
        
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_event("SYSTEM", "STOP_DAY1_BENIGN_TRAFFIC")
        logging.info("Đã dừng kịch bản Ngày 1.")
