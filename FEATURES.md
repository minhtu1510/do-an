# Tính năng mới của S7Pwn

## 1. Network Topology Scanner 🗺️ (MỚI!)

### Tổng quan

Tính năng quét và hiển thị topology mạng theo thời gian thực với giao diện đồ họa trực quan.

### Tính năng chính

**Quét mạng toàn diện:**
- ARP scan - Phát hiện devices trong LAN
- ICMP ping sweep - Tìm devices không respond ARP
- Port scanning - Nhận dạng services và device types
- Auto-detect gateway và local network

**Hiển thị Topology Graph:**
- Visualization real-time bằng vis.js
- Phân biệt device types bằng màu và hình dạng
- Interactive graph: click để xem chi tiết
- Auto-layout với physics simulation

**Phân tích thiết bị:**
- Device Type: PLC, Switch, Computer, Gateway, etc.
- OS Detection (từ TTL fingerprinting)
- Open Ports và Services
- Vendor identification (từ MAC address)
- Response time measurement

**Chế độ quét:**
- **Quick Scan**: Nhanh, chỉ scan ports ICS/SCADA
- **Full Scan**: Chi tiết, scan tất cả ports phổ biến
- **Continuous Scan**: Tự động quét lại mỗi 30s, cập nhật real-time

**Export Topology:**
- JSON: Dữ liệu đầy đủ
- CSV: Danh sách thiết bị
- HTML: Báo cáo đẹp mắt

### Sử dụng

**Từ Web GUI:**
1. Click "🗺️ Network Topology" trên dashboard
2. Click "Start Scan"
3. Xem topology graph hiển thị real-time
4. Click vào node để xem chi tiết device

**API Endpoints:**
- `POST /api/topology/scan` - Bắt đầu quét
- `GET /api/topology/data` - Lấy topology data
- `POST /api/topology/continuous` - Quét liên tục
- `POST /api/topology/export` - Xuất báo cáo

### Chi tiết

Xem [TOPOLOGY_GUIDE.md](TOPOLOGY_GUIDE.md) để biết hướng dẫn chi tiết.

---

## 2. Giao diện Web (Web GUI)

### Khởi động Web GUI

Từ CLI, sử dụng lệnh:
```bash
s7pwn> webgui
```

Hoặc chỉ định host và port:
```bash
s7pwn> webgui 0.0.0.0 8080
```

Giao diện web sẽ tự động mở trong trình duyệt tại `http://127.0.0.1:5000`

### Tính năng của Web GUI

**Dashboard chính:**
- Hiển thị trạng thái hệ thống realtime
- Số lượng thiết bị và PLC đã quét
- Target hiện tại đang được chọn

**Quét mạng (Network Scan):**
- Quét Profinet devices trong mạng
- Cấu hình timeout và retries
- Hiển thị danh sách thiết bị và PLC tìm được
- Xuất kết quả ra JSON/CSV/HTML

**Quản lý Target:**
- Thiết lập target thủ công (IP, Rack, Slot)
- Chọn target từ danh sách PLC đã quét
- Hiển thị thông tin target hiện tại
- Probe target để lấy thông tin chi tiết

**Danh sách PLC:**
- Hiển thị tất cả PLC Siemens đã tìm thấy
- Thông tin: IP, Model, Rack/Slot
- Click để chọn làm target

**Thao tác bộ nhớ (Memory Operations):**
- Đọc vùng nhớ: M (Merker), I (Input), Q (Output), DB (Data Block)
- Ghi vùng nhớ với dữ liệu tùy chỉnh
- Chỉ định địa chỉ bắt đầu và kích thước
- Hiển thị dữ liệu đọc được

**Lịch sử thao tác (Operation Log):**
- Ghi lại tất cả các thao tác (scan, probe, read, write)
- Hiển thị timestamp, loại thao tác, kết quả
- Xuất log ra file
- Xóa log

## 2. Xuất báo cáo (Report Export)

### Sử dụng từ CLI

Cú pháp:
```bash
export <type> <format>
```

**Các loại dữ liệu (type):**
- `scan` - Kết quả quét mạng đầy đủ
- `devices` - Tất cả thiết bị tìm được
- `plcs` - Chỉ các PLC Siemens

**Các định dạng (format):**
- `json` - JSON format
- `csv` - CSV format (dạng bảng)
- `html` - HTML report đẹp mắt

**Ví dụ:**
```bash
# Xuất kết quả scan ra JSON
s7pwn> export scan json

# Xuất danh sách PLC ra CSV
s7pwn> export plcs csv

# Xuất tất cả devices ra HTML
s7pwn> export devices html
```

### Sử dụng từ Web GUI

Từ mỗi panel, click vào nút:
- **Export JSON** - Xuất ra file JSON
- **Export CSV** - Xuất ra file CSV
- **Export HTML** - Xuất ra file HTML với định dạng đẹp

### Vị trí file xuất

Tất cả file được lưu trong thư mục `reports/` với tên file có timestamp:
```
reports/
├── scan_20250131_143022.json
├── plcs_20250131_143045.csv
├── scan_20250131_143102.html
└── operations_20250131_143130.json
```

## 3. Cấu trúc báo cáo

### Báo cáo Scan (JSON)
```json
{
  "report_type": "Network Scan",
  "timestamp": "2025-01-31T14:30:22",
  "summary": {
    "total_devices": 10,
    "total_plcs": 3
  },
  "all_devices": [...],
  "plc_devices": [...]
}
```

### Báo cáo HTML
- Header với tiêu đề và timestamp
- Bảng dữ liệu được format đẹp
- Responsive design
- Màu sắc phân biệt rõ ràng

### Báo cáo CSV
- Header row với tên cột
- Dữ liệu dạng bảng
- Dễ dàng import vào Excel

## 4. API Endpoints (Web GUI)

### Status & Info
- `GET /api/status` - Trạng thái hệ thống
- `GET /api/devices` - Danh sách devices
- `GET /api/operations` - Lịch sử thao tác

### Operations
- `POST /api/scan` - Quét mạng
- `GET/POST /api/target` - Get/Set target
- `POST /api/probe` - Probe target
- `POST /api/read` - Đọc bộ nhớ
- `POST /api/write` - Ghi bộ nhớ

### Export
- `POST /api/export` - Xuất báo cáo
- `GET /api/export/download/<filename>` - Tải file

## 5. Yêu cầu cài đặt

Cập nhật dependencies:
```bash
pip install -r requirements.txt
```

Dependencies mới:
- `flask>=2.3.0` - Web framework

## 6. Ví dụ sử dụng

### Workflow CLI với Export
```bash
# 1. Quét mạng
s7pwn> scan

# 2. Xem danh sách PLC
s7pwn> list

# 3. Chọn target
s7pwn> select 0

# 4. Probe target
s7pwn> probe_target

# 5. Xuất kết quả
s7pwn> export scan html
s7pwn> export plcs csv
```

### Workflow Web GUI
1. Khởi động: `s7pwn> webgui`
2. Mở trình duyệt: `http://127.0.0.1:5000`
3. Click "Scan Network"
4. Chọn PLC từ danh sách
5. Click "Probe Target"
6. Thực hiện Read/Write memory
7. Click "Export HTML" để xuất báo cáo

## 7. Lưu ý bảo mật

- Web GUI chỉ bind localhost (127.0.0.1) mặc định
- Để cho phép truy cập từ xa: `webgui 0.0.0.0 5000`
- Không có authentication - chỉ dùng trong mạng tin cậy
- Các báo cáo có thể chứa thông tin nhạy cảm

## 8. Troubleshooting

### Web GUI không khởi động
```bash
# Kiểm tra Flask đã cài
pip install flask

# Kiểm tra port đã bị chiếm
netstat -ano | findstr :5000

# Sử dụng port khác
s7pwn> webgui 127.0.0.1 8080
```

### Export lỗi
```bash
# Kiểm tra thư mục reports
mkdir reports

# Kiểm tra quyền ghi file
```

### Không thấy devices sau scan
- Đảm bảo trong cùng mạng với PLC
- Kiểm tra firewall
- Tăng timeout: scan timeout lên 5-10s
