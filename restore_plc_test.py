#!/usr/bin/env python3
import argparse
import time
import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import set_bool, set_dint

def main():
    parser = argparse.ArgumentParser(description="Tool kiểm tra và khôi phục trạng thái PLC S7-1200")
    parser.add_argument("--target", default="192.168.1.10", help="Địa chỉ IP của PLC (Mặc định: 192.168.1.10)")
    parser.add_argument("--rack", type=int, default=0, help="Rack (Mặc định: 0)")
    parser.add_argument("--slot", type=int, default=1, help="Slot (Mặc định: 1)")
    args = parser.parse_args()

    print("=" * 60)
    print(f"Bắt đầu kết nối và khôi phục PLC: {args.target} (rack={args.rack}, slot={args.slot})")
    print("=" * 60)

    c = snap7.client.Client()
    try:
        c.connect(args.target, args.rack, args.slot)
        print("[+] Kết nối thành công tới PLC!")
    except Exception as e:
        print(f"[!] LỖI KẾT NỐI: Không thể kết nối tới PLC tại {args.target}. Lỗi: {e}")
        print("[!] Vui lòng kiểm tra IP, dây mạng hoặc cấu hình GET/PUT trên PLC.")
        return

    # Bước 1: Kiểm tra và khởi động lại CPU nếu đang ở trạng thái STOP
    try:
        state = c.get_cpu_state()
        print(f"[*] Trạng thái CPU hiện tại: {state}")
        
        if "Stop" in str(state) or state == 4:
            print("[*] Phát hiện CPU đang ở trạng thái STOP. Tiến hành khởi động...")
            try:
                c.plc_hot_start()
                print("[+] Đã gửi lệnh PLC Hot Start (Khởi động nóng).")
            except Exception as e_hot:
                print(f"[!] Hot Start không thành công ({e_hot}). Đang thử Cold Start (Khởi động lạnh)...")
                try:
                    c.plc_cold_start()
                    print("[+] Đã gửi lệnh PLC Cold Start thành công.")
                except Exception as e_cold:
                    print(f"[!] LỖI: Cả Hot/Cold Start đều thất bại: {e_cold}")
                    print("[!] Vui lòng bật RUN thủ công qua TIA Portal nếu thiết bị chặn lệnh.")
            
            # Chờ 3 giây để CPU chuyển trạng thái
            time.sleep(3)
            new_state = c.get_cpu_state()
            print(f"[+] Trạng thái CPU sau khi khởi động: {new_state}")
        else:
            print("[+] CPU đã ở trạng thái RUN/OK.")
    except Exception as e_state:
        print(f"[!] Không thể kiểm tra hoặc khởi động lại trạng thái CPU: {e_state}")

    # Bước 2: Reset Q Output (Pha đầu ra vật lý)
    try:
        print("[*] Đang reset vùng nhớ đầu ra Q (PA Area)...")
        c.write_area(Areas.PA, 0, 0, bytearray([0]))
        print("[+] Reset Q Output thành công.")
    except Exception as e_q:
        print(f"[!] LỖI reset Q Output: {e_q} (Có thể PLC vẫn đang bị STOP)")

    # Bước 3: Đọc và Reset vùng nhớ M, đồng thời tạo xung kích hoạt START (M2.1)
    try:
        print("[*] Đang khôi phục vùng nhớ M (Merker) và tạo xung kích hoạt START...")
        m = c.read_area(Areas.MK, 0, 0, 82)
        
        # Ghi các thông số khôi phục
        set_bool(m, 2, 1, 1)    # START = 1 (Tạo xung bắt đầu chạy chu trình đèn)
        set_bool(m, 2, 2, 0)    # STOP  = 0
        set_bool(m, 28, 0, 0)   # s1 = 0
        set_bool(m, 28, 1, 0)   # s4 = 0
        set_bool(m, 28, 2, 0)   # s2 = 0
        set_bool(m, 28, 3, 0)   # s3 = 0
        
        # Reset các bộ timer setpoint về giá trị an toàn mặc định
        set_dint(m,  3, 30000)  # TimeR1 = 30s
        set_dint(m,  8, 30000)  # TimeR2 = 30s
        set_dint(m, 12,  3000)  # TimeY1 = 3s
        set_dint(m, 16,  3000)  # TimeY2 = 3s
        set_dint(m, 20, 25000)  # TimeG1 = 25s
        set_dint(m, 24, 25000)  # TimeG2 = 25s
        
        c.write_area(Areas.MK, 0, 0, m)
        print("[+] Đã set START = 1 và thiết lập lại toàn bộ setpoint timer.")

        # Chờ 1 giây để PLC nhận bit START trong vòng quét logic
        time.sleep(1.0)
        
        # Reset START về 0 (nhả nút Start)
        m = c.read_area(Areas.MK, 0, 0, 82)
        set_bool(m, 2, 1, 0)    # START = 0
        c.write_area(Areas.MK, 0, 0, m)
        print("[+] Đã trả START = 0. Chu trình xung bắt đầu đã hoàn tất!")
        print("[+] Đèn giao thông trên PLC sẽ bắt đầu hoạt động bình thường!")

    except Exception as e_m:
        print(f"[!] LỖI ghi vùng nhớ M: {e_m}")

    finally:
        try:
            c.disconnect()
            print("[+] Đã đóng kết nối PLC an toàn.")
        except:
            pass

    print("=" * 60)
    print("HOÀN THÀNH QUÁ TRÌNH KHÔI PHỤC PLC!")
    print("=" * 60)

if __name__ == "__main__":
    main()
