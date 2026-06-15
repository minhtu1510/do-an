# ICSScout v2.0 - Hướng Dẫn Cài Đặt Trên Windows

## 📋 Yêu Cầu Hệ Thống

- **Windows 10/11** (64-bit khuyến nghị)
- **Python 3.8+** (64-bit)
- **Quyền Administrator** (bắt buộc cho packet capture)

---

## 🚀 Cài Đặt Nhanh (5 Bước)

### **Bước 1: Cài Đặt Python**

1. Tải Python từ: https://www.python.org/downloads/
2. **QUAN TRỌNG:** Tick vào "Add Python to PATH" khi cài đặt
3. Chọn "Install Now"
4. Kiểm tra cài đặt:
```cmd
python --version
```

---

### **Bước 2: Cài Đặt Npcap (Bắt Buộc!)**

**Npcap là thư viện bắt gói tin trên Windows - không có Npcap sẽ không bắt được gói tin!**

1. **Tải Npcap:** https://npcap.com/#download
2. **Chạy installer với quyền Administrator**
3. **Cài đặt với các tùy chọn sau:**
   - ✅ **"Install Npcap in WinPcap API-compatible Mode"** (QUAN TRỌNG!)
   - ✅ "Support raw 802.11 traffic"
   - ✅ "Install Npcap Loopback Adapter"

4. **Khởi động lại máy tính** sau khi cài Npcap

---

### **Bước 3: Cài Đặt Dependencies**

Mở **Command Prompt** hoặc **PowerShell** với quyền **Administrator**:

**Cách 1: Chạy CMD/PowerShell as Administrator:**
- Nhấn `Win + X`
- Chọn "Windows Terminal (Admin)" hoặc "Command Prompt (Admin)"

**Cách 2: Từ Start Menu:**
- Tìm "cmd" hoặc "PowerShell"
- Nhấn chuột phải → "Run as administrator"

**Sau đó chạy:**
```cmd
cd path\to\S7.Pwn
pip install -r requirements.txt
```

**Lưu ý:** Nếu gặp lỗi với `python-snap7`, thử cài riêng:
```cmd
pip install python-snap7 --no-cache-dir
```

---

### **Bước 4: Khởi Động Web Application**

**Trong Command Prompt/PowerShell với quyền Administrator:**

```cmd
python start_webapp.py
```

**Hoặc chỉ định host/port:**
```cmd
python start_webapp.py --host 127.0.0.1 --port 5000
```

**Bạn sẽ thấy:**
```
============================================================
ICSScout Web Application v2.0.0
============================================================
Server: http://127.0.0.1:5000
Press Ctrl+C to stop
============================================================
```

---

### **Bước 5: Mở Trình Duyệt**

Truy cập: **http://127.0.0.1:5000** hoặc **http://localhost:5000**

---

## 🔍 Chọn Network Interface Đúng

Trên Windows, các network interface có tên khác Linux:

**Các interface thường gặp:**
- `\Device\NPF_{GUID}` - Ethernet adapter
- `Ethernet` - Ethernet card
- `Wi-Fi` - Wireless adapter
- `Npcap Loopback Adapter` - Loopback

**Cách tìm tên interface:**

1. **Mở PowerShell as Administrator:**
```powershell
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status
```

2. **Hoặc dùng Python:**
```python
from scapy.all import get_if_list
print(get_if_list())
```

3. **Trong Web GUI:**
   - Chọn "Auto-detect" để ICSScout tự động chọn
   - Hoặc nhập tên interface thủ công nếu biết

---

## ⚙️ Cấu Hình Network Interface Cho OT Assessment

### **Khi Đánh Giá Hệ Thống OT (Nhà Máy Thủy Điện):**

**Option 1: Kết Nối Trực Tiếp**
- Cắm laptop vào switch của mạng OT
- Chọn interface Ethernet tương ứng
- Đặt IP tĩnh trong dải mạng OT (ví dụ: 192.168.1.100)

**Option 2: Port Mirroring (SPAN)**
- Yêu cầu network admin cấu hình port mirroring
- Tất cả traffic từ mạng OT được mirror sang port của bạn
- Không cần IP, chỉ cần capture mode

**Option 3: TAP Device**
- Sử dụng network TAP vật lý
- Kết nối vào đường truyền giữa SCADA và PLC
- Chế độ passive hoàn toàn, không thể bị phát hiện

---

## 🎯 Workflow Đánh Giá OT Trên Windows

### **Chuẩn Bị:**

1. **Khởi động Web App với Admin:**
```cmd
python start_webapp.py
```

2. **Mở trình duyệt:** http://localhost:5000

3. **Vào trang "Packet Analyzer"**

### **Bắt Đầu Capture:**

1. **Chọn Interface:**
   - Auto-detect (khuyến nghị)
   - Hoặc chọn Ethernet card kết nối với mạng OT

2. **Cấu hình:**
   - Duration: 600 seconds (10 phút)
   - Protocols: ✅ S7, ✅ Modbus TCP, ✅ OPC UA

3. **Click "Start Capture"**
   - Đợi 10-30 phút để thu thập đủ traffic
   - Quan sát real-time statistics

4. **Phân Tích:**
   - Click vào các gói tin S7/Modbus
   - Xem địa chỉ PLC (Source IP)
   - Xem memory operations (DB numbers, addresses)
   - Xác định loại thiết bị (S7-300, S7-1200, S7-1500, etc.)

5. **Export:**
   - Click "Export PCAP"
   - Mở bằng Wireshark trên Windows để phân tích sâu hơn

6. **Quét Lỗ Hổng:**
   - Vào trang "Vulnerabilities"
   - Chọn các PLC đã phát hiện
   - Click "Start Scan"
   - Xem CVE và recommendations

---

## 🛠️ Troubleshooting Windows

### **1. "No module named 'scapy'"**

**Nguyên nhân:** Scapy chưa được cài đặt

**Giải pháp:**
```cmd
pip install scapy
```

---

### **2. "Permission denied" hoặc "Access is denied"**

**Nguyên nhân:** Chưa chạy với quyền Administrator

**Giải pháp:**
1. Đóng Command Prompt hiện tại
2. Mở lại **Command Prompt as Administrator**
3. Chạy lại `python start_webapp.py`

---

### **3. "No such device exists" khi capture**

**Nguyên nhân:**
- Npcap chưa được cài đặt
- Hoặc Npcap không ở chế độ WinPcap compatible

**Giải pháp:**
1. **Gỡ cài Npcap** (Control Panel → Uninstall)
2. **Cài lại Npcap** với option: "Install in WinPcap API-compatible Mode"
3. **Khởi động lại máy**

---

### **4. "ImportError: DLL load failed"**

**Nguyên nhân:**
- Thiếu Visual C++ Redistributable
- Hoặc Python 32-bit trên Windows 64-bit

**Giải pháp:**
1. **Cài Visual C++ Redistributable:**
   - Tải từ: https://aka.ms/vs/17/release/vc_redist.x64.exe
   - Chạy installer

2. **Kiểm tra Python:**
```cmd
python -c "import platform; print(platform.architecture())"
```
Phải hiện `('64bit', 'WindowsPE')` nếu dùng Windows 64-bit

---

### **5. "Port 5000 already in use"**

**Nguyên nhân:** Port 5000 đã được dùng bởi ứng dụng khác

**Giải pháp:**
```cmd
python start_webapp.py --port 8080
```

Sau đó truy cập: http://localhost:8080

---

### **6. Không bắt được gói tin S7/Modbus**

**Nguyên nhân:**
- Interface không đúng
- Không có traffic S7/Modbus trên mạng
- Firewall chặn

**Giải pháp:**
1. **Kiểm tra interface:**
   - Chọn đúng Ethernet adapter kết nối với mạng OT
   - Không dùng Wi-Fi cho OT assessment

2. **Tắt Firewall tạm thời:**
   - Windows Defender Firewall → Turn off (Private network)
   - **LƯU Ý:** Chỉ tắt khi đánh giá, sau đó bật lại!

3. **Kiểm tra có traffic:**
   - Mở Wireshark trên Windows
   - Capture trên cùng interface
   - Lọc: `tcp.port == 102 or tcp.port == 502`
   - Nếu không thấy gì → không có traffic S7/Modbus

---

### **7. Web GUI không load được (blank page)**

**Nguyên nhân:**
- Browser cache
- JavaScript bị block

**Giải pháp:**
1. Hard refresh: `Ctrl + F5`
2. Xóa cache browser
3. Thử browser khác (Chrome, Firefox, Edge)
4. Kiểm tra browser console (F12) xem có lỗi JavaScript

---

## 🔥 Windows Firewall Configuration

**Nếu muốn truy cập Web GUI từ máy khác trong mạng:**

### **Bước 1: Tạo Firewall Rule**

**PowerShell as Administrator:**
```powershell
New-NetFirewallRule -DisplayName "ICSScout Web GUI" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow
```

### **Bước 2: Khởi động với host 0.0.0.0**
```cmd
python start_webapp.py --host 0.0.0.0 --port 5000
```

### **Bước 3: Truy cập từ máy khác**
```
http://<IP_của_máy_Windows>:5000
```

**Ví dụ:** Nếu IP máy Windows là `192.168.1.50`:
```
http://192.168.1.50:5000
```

---

## 📦 Các Công Cụ Hỗ Trợ Trên Windows

### **Wireshark**
- Tải: https://www.wireshark.org/download.html
- Dùng để phân tích PCAP files đã export
- Có dissector tốt cho S7, Modbus

### **Python-Snap7**
- Đã được cài qua `requirements.txt`
- Cho phép kết nối trực tiếp với PLC S7

### **Nmap for Windows**
- Tải: https://nmap.org/download.html
- Dùng để scan network trước khi chạy ICSScout

---

## ⚡ Tối Ưu Performance Trên Windows

### **1. Tắt Windows Defender Realtime Scanning (Tạm Thời)**

**Trong quá trình capture packets:**
1. Windows Security → Virus & threat protection
2. Manage settings
3. Tắt "Real-time protection" (tạm thời)
4. **Nhớ bật lại sau khi xong!**

### **2. Sử dụng SSD**

Lưu PCAP files vào SSD để ghi nhanh hơn

### **3. Đóng Các Ứng Dụng Không Cần Thiết**

Tắt Chrome, Office, etc. để tập trung tài nguyên cho packet capture

### **4. Power Plan**

Control Panel → Power Options → High Performance

---

## 🎯 Checklist Trước Khi Đi Đánh Giá Nhà Máy

### **Phần Mềm:**
- ✅ Python 3.8+ (64-bit) đã cài
- ✅ Npcap đã cài (WinPcap compatible mode)
- ✅ ICSScout dependencies đã cài (`pip install -r requirements.txt`)
- ✅ Wireshark đã cài (để phân tích offline)
- ✅ Đã test Web GUI chạy được: `python start_webapp.py`

### **Phần Cứng:**
- ✅ Laptop có Ethernet port (hoặc USB-to-Ethernet adapter)
- ✅ Dây mạng Ethernet (dự phòng 2-3 sợi)
- ✅ Adapter USB-C to Ethernet (nếu laptop mới)
- ✅ Pin laptop đầy hoặc có nguồn điện

### **Kiến Thức:**
- ✅ Đọc WEB_GUI_GUIDE.md
- ✅ Đọc QUICKSTART.md
- ✅ Test capture packets trên mạng lab trước
- ✅ Biết cách export PCAP
- ✅ Biết cách phân tích S7/Modbus packets

### **Giấy Tờ:**
- ✅ Giấy phép pentesting (Authorization Letter)
- ✅ Scope of Work đã được approve
- ✅ Contact của plant operator/engineer
- ✅ Emergency contact (nếu có sự cố)

---

## 📚 Tài Liệu Bổ Sung

- **WEB_GUI_GUIDE.md** - Hướng dẫn chi tiết Web GUI
- **QUICKSTART.md** - Quick start guide (chung)
- **IMPLEMENTATION_STATUS.md** - Tình trạng features
- **examples/** - Ví dụ sử dụng Python API

---

## 🚨 Lưu Ý Bảo Mật

### **QUAN TRỌNG:**

1. **Web GUI không có authentication!**
   - Chỉ chạy trên laptop của bạn
   - Không expose ra Internet
   - Không để `--host 0.0.0.0` khi ở mạng không tin cậy

2. **Packet Capture cần quyền Admin:**
   - Luôn chạy Command Prompt as Administrator
   - Không chạy Web GUI với quyền thường sẽ không capture được

3. **Passive Reconnaissance:**
   - Chế độ mặc định là READ-ONLY
   - Không ghi vào PLC khi chưa có phép
   - Chỉ bắt gói tin, không gửi commands

4. **Backup:**
   - Export PCAP ngay sau khi capture xong
   - Lưu vào nhiều nơi (laptop + USB drive)
   - Mã hóa nếu có thông tin nhạy cảm

---

## 💡 Tips Cho Windows Users

### **1. Dùng Windows Terminal**
Windows Terminal hiện đại hơn CMD:
- Cài từ Microsoft Store
- Hỗ trợ tabs, colors
- Copy/paste dễ hơn

### **2. Virtual Environment (Khuyến Nghị)**
```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### **3. Path Issues**
Nếu `python` không được nhận diện:
```cmd
py -3 start_webapp.py
```

### **4. Windows Subsystem for Linux (WSL)**
Nếu muốn trải nghiệm Linux trên Windows:
- Cài WSL2
- Chạy ICSScout trong Ubuntu on WSL
- **LƯU Ý:** Packet capture trong WSL phức tạp hơn, không khuyến nghị

---

## ✅ Sẵn Sàng!

Sau khi hoàn thành các bước trên, bạn đã sẵn sàng sử dụng ICSScout trên Windows!

**Khởi động:**
```cmd
python start_webapp.py
```

**Truy cập:**
```
http://localhost:5000
```

**Bắt đầu đánh giá bảo mật hệ thống OT!** 🚀

---

## 🤝 Hỗ Trợ

Nếu gặp vấn đề:
1. Kiểm tra phần Troubleshooting ở trên
2. Xem WEB_GUI_GUIDE.md
3. Kiểm tra Python version: `python --version` (phải >= 3.8)
4. Kiểm tra Npcap: Control Panel → Programs → Npcap

---

**Chúc bạn đánh giá thành công! Hãy luôn nhớ an toàn và có giấy phép hợp lệ trước khi pentest!** 🎯
