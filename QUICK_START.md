# S7Pwn - Hướng dẫn nhanh

## Cài đặt

```bash
# Clone repository
git clone <repo-url>
cd S7.Pwn

# Cài đặt dependencies
pip install -r requirements.txt

# Cài đặt S7Pwn
pip install -e .
```

## Sử dụng CLI

### 1. Khởi động
```bash
s7pwn
```

### 2. Quét mạng
```bash
s7pwn> scan
Found 5 device(s); PLCs (Siemens 1500/1200/300/400): 2.
Type 'list' to show PLC list, 'select <n>' to set current target.
```

### 3. Xem danh sách PLC
```bash
s7pwn> list
PLC devices (Siemens S7-1500/1200/300/400):
  [0] IP=192.168.1.100 MAC=00:11:22:33:44:55 vendor=Siemens model=S7-1200 rack=0 slot=1
  [1] IP=192.168.1.101 MAC=00:11:22:33:44:56 vendor=Siemens model=S7-1500 rack=0 slot=1
```

### 4. Chọn target
```bash
s7pwn> select 0
Current target set to 192.168.1.100 (rack=0, slot=1)
```

### 5. Probe target
```bash
s7pwn> probe_target
Probing target: 192.168.1.100 (rack 0, slot 1)

Target Information:
ModuleTypeName: CPU 1214C DC/DC/DC
SerialNumber: S V-xxxxxxx
ASName: MyPLC
Copyright: Original Siemens Equipment
ModuleName: PLC_1
CPUState: S7CpuStatusRun
```

### 6. Đọc bộ nhớ
```bash
s7pwn> read M0:BYTE M1:BYTE M2:WORD
Reading from target 192.168.1.100
M0 (BYTE): 42
M1 (BYTE): 100
M2 (WORD): 1234
```

### 7. Ghi bộ nhớ
```bash
s7pwn> write M0=50:BYTE M2=5000:WORD
Writing to target 192.168.1.100
Successfully wrote M0 (BYTE): 50
Successfully wrote M2 (WORD): 5000
```

### 8. Xuất báo cáo
```bash
# Xuất kết quả scan
s7pwn> export scan json
Scan results exported to: reports/scan_20250131_143022.json

# Xuất danh sách PLC ra CSV
s7pwn> export plcs csv
PLC data exported to: reports/plcs_20250131_143045.csv

# Xuất báo cáo HTML
s7pwn> export scan html
Scan results exported to: reports/scan_20250131_143102.html
```

## Sử dụng Web GUI

### 1. Khởi động Web GUI
```bash
s7pwn> webgui
S7Pwn Web GUI v1.0.0
Server starting at http://127.0.0.1:5000
Press Ctrl+C to stop
```

Trình duyệt sẽ tự động mở tại `http://127.0.0.1:5000`

### 2. Hoặc khởi động với cấu hình tùy chỉnh
```bash
# Bind tất cả interfaces, port 8080
s7pwn> webgui 0.0.0.0 8080
```

### 3. Sử dụng giao diện web

**Bước 1: Quét mạng**
- Điều chỉnh Timeout và Retries nếu cần
- Click "Scan Network"
- Đợi kết quả hiển thị

**Bước 2: Chọn target**
- Xem danh sách PLC trong panel "Discovered PLCs"
- Click "Select" ở PLC muốn chọn
- Hoặc nhập thủ công IP/Rack/Slot và click "Set Target"

**Bước 3: Probe target**
- Click "Probe Target"
- Xem thông tin chi tiết PLC

**Bước 4: Thao tác bộ nhớ**
- Chọn Area (M, I, Q, DB)
- Nhập Start Address và Size
- Click "Read Memory" để đọc
- Click "Write Memory" để ghi (nhập dữ liệu khi được hỏi)

**Bước 5: Xuất báo cáo**
- Từ mỗi panel, click nút Export
- Chọn định dạng: JSON, CSV, hoặc HTML
- File sẽ được lưu trong thư mục `reports/`

## Các lệnh hữu ích

### Xem trợ giúp
```bash
s7pwn> help
```

### Hiển thị target hiện tại
```bash
s7pwn> show_target
```

### Thiết lập target thủ công
```bash
s7pwn> set_target 192.168.1.100 0 1
```

### Giám sát bộ nhớ (real-time)
```bash
s7pwn> monitor --byte
```

### Ghi lặp lại
```bash
s7pwn> rwrite M0=100:BYTE
```

### Flood attack (DoS test)
```bash
s7pwn> flood 100 10
```

## Cấu trúc thư mục

```
S7.Pwn/
├── s7pwn/
│   ├── cli.py              # CLI main
│   ├── web_gui.py          # Web GUI
│   ├── report_exporter.py  # Export module
│   ├── commands/           # CLI commands
│   │   ├── scan.py
│   │   ├── read.py
│   │   ├── write.py
│   │   ├── export.py       # NEW
│   │   └── ...
│   ├── templates/          # HTML templates
│   │   └── index.html
│   └── static/             # Static files
├── reports/                # Exported reports
├── requirements.txt        # Dependencies
├── FEATURES.md            # Chi tiết tính năng
└── QUICK_START.md         # File này
```

## Lưu ý quan trọng

1. **Chỉ sử dụng trên mạng được phép kiểm thử**
2. **Web GUI không có authentication** - chỉ dùng trong mạng nội bộ
3. **Flood attack có thể gây mất kết nối PLC** - cẩn thận khi sử dụng
4. **Backup cấu hình PLC** trước khi ghi bộ nhớ
5. **Báo cáo có thể chứa thông tin nhạy cảm** - bảo mật file export

## Troubleshooting

### Không quét được PLC
- Kiểm tra kết nối mạng
- Đảm bảo trong cùng subnet với PLC
- Tắt firewall tạm thời
- Tăng timeout: sửa trong code hoặc dùng Web GUI

### Không kết nối được PLC
- Kiểm tra IP/Rack/Slot đúng
- PLC có bật Profinet/S7 communication
- Không có password protection
- PLC không trong trạng thái STOP

### Web GUI không mở
- Kiểm tra Flask đã cài: `pip install flask`
- Port 5000 đã bị chiếm: dùng port khác
- Mở thủ công: http://127.0.0.1:5000

### Export lỗi
- Tạo thư mục: `mkdir reports`
- Kiểm tra quyền ghi file
- Đảm bảo có dữ liệu để export (chạy scan trước)

## Hỗ trợ

- Xem file `FEATURES.md` để biết chi tiết tính năng
- Xem file `README.md` để hiểu cấu trúc hoạt động
- Gõ `help` trong CLI để xem tất cả lệnh
