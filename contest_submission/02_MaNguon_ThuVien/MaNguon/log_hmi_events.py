import csv
import argparse
from datetime import datetime

def log_companion(output_file):
    print(f"[*] TIA Portal / WinCC Companion Logger (Trợ thủ ghi mốc thời gian)")
    print(f"[*] File xuất ra: {output_file}")
    print("--------------------------------------------------")
    print("HƯỚNG DẪN: Đặt cửa sổ này cạnh màn hình TIA Portal.")
    print("Ngay khi em click chuột trên TIA Portal, hãy bấm phím ở đây để AI lấy đúng Timestamp!")
    print(" [1] Vừa nhấn nút START")
    print(" [2] Vừa nhấn nút STOP")
    print(" [3] Vừa đổi SETPOINT")
    print(" [4] Vừa Upload/Download Project (Bảo trì)")
    print(" [q] Thoát chương trình")
    print("--------------------------------------------------")
    
    with open(output_file, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp', 'device', 'user', 'action', 'tag', 'value', 'result'])
        
        try:
            while True:
                choice = input("\n[?] Hành động em vừa làm trên TIA (1/2/3/4/q): ").strip().lower()
                
                if choice == 'q':
                    print("[!] Đã dừng ghi log.")
                    break
                    
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                user = "engineer_01"
                action = ""
                tag = ""
                value = 1
                device = "WinCC_HMI"
                
                if choice == '1':
                    action = "START_BUTTON"
                    tag = "motor_start"
                elif choice == '2':
                    action = "STOP_BUTTON"
                    tag = "motor_stop"
                elif choice == '3':
                    action = "CHANGE_SETPOINT"
                    tag = "setpoint_speed"
                    value = "changed"
                elif choice == '4':
                    action = "TIA_DOWNLOAD_PROJECT"
                    tag = "maintenance_mode"
                    device = "ENGINEERING_WS"
                else:
                    print("     [Lỗi] Phím không hợp lệ!")
                    continue
                
                # Ghi ngay lập tức vào CSV
                writer.writerow([now, device, user, action, tag, value, "SUCCESS"])
                f.flush()
                print(f"✅ [{now}] Đã chốt mốc thời gian cho hành động: {action}")
                
        except KeyboardInterrupt:
            print("\n[!] Đã dừng ghi log.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # Tên file default đổi thành operator_event_log.csv cho khớp với yêu cầu của giáo viên
    parser.add_argument("--output", default="operator_event_log.csv")
    args = parser.parse_args()
    log_companion(args.output)
