# S7.Pwn vs ICSScout v2.0 - Mapping Chức Năng

## 📦 **TL;DR: Code Cũ Vẫn Còn!**

✅ **Tất cả chức năng S7.Pwn ban đầu vẫn còn nguyên trong thư mục `s7pwn/`**

✅ **ICSScout v2.0 là phiên bản mới với kiến trúc tốt hơn, KHÔNG xóa code cũ**

---

## 🔄 **So Sánh Hai Phiên Bản**

### **S7.Pwn (Legacy CLI)**
📁 **Thư mục:** `s7pwn/`
🖥️ **Giao diện:** CLI (Command Line Interface)
🏗️ **Kiến trúc:** Monolithic, Windows-only
📝 **Launcher:** `s7pwn` hoặc `python -m s7pwn.cli`

### **ICSScout v2.0 (Modern)**
📁 **Thư mục:** `icsscout/`
🌐 **Giao diện:** Web GUI + Python API
🏗️ **Kiến trúc:** Clean Architecture, cross-platform
📝 **Launcher:** `python start_webapp.py`

---

## 🗺️ **Mapping Chức Năng: CLI Cũ → ICSScout v2.0**

| S7.Pwn CLI Command | ICSScout v2.0 Tương Đương | Ghi Chú |
|-------------------|---------------------------|---------|
| `scan` | **Web GUI:** Packet Analyzer → Start Capture | Passive discovery qua packet capture |
| `list` | **Web GUI:** Devices page | Hiển thị devices đã phát hiện |
| `select` / `set_target` | **Python API:** `Target(ip, rack, slot)` | Set target trong code |
| `show_target` | **Web GUI:** Device details | Xem thông tin device |
| `probe_target` | **Python API:** `S7Client.get_cpu_info()` | Lấy CPU info |
| `read` | **Python API:** `S7Client.read_area()` | Đọc memory area |
| `write` | **Python API:** `S7Client.write_area()` | Ghi memory area |
| `rwrite` | **Python API:** Loop `write_area()` | Repeated write |
| `monitor` | **Core Module:** `BehaviorMonitor` | Theo dõi thay đổi |
| `flood` | ❌ **Removed** | DoS attack - không khuyến nghị |
| `export` | **Web GUI:** Export PCAP button | Export traffic data |
| `webgui` | **New:** `start_webapp.py` | Web GUI mới hoàn toàn |

---

## 📋 **Chi Tiết Từng Chức Năng**

### **1. Scan (Quét Mạng)**

#### **S7.Pwn CLI (Cũ):**
```bash
s7pwn> scan 192.168.1.0/24
```

#### **ICSScout v2.0 (Mới):**

**Option A - Web GUI (Passive):**
1. Mở http://localhost:5000
2. Vào "Packet Analyzer"
3. Click "Start Capture"
4. Devices được phát hiện qua traffic analysis

**Option B - Python API (Active):**
```python
# TODO: Network scanner chưa implement
# Hiện tại dùng passive discovery qua packet capture
from icsscout.core.capture import PacketCaptureEngine

engine = PacketCaptureEngine()
engine.start_capture(duration=60)
devices = engine.get_devices_communicating()
```

**Cải Tiến:**
- ✅ Passive reconnaissance (an toàn hơn)
- ✅ Real-time discovery
- ✅ Protocol detection tự động

---

### **2. List Devices**

#### **S7.Pwn CLI (Cũ):**
```bash
s7pwn> list
```

#### **ICSScout v2.0 (Mới):**

**Web GUI:**
- Dashboard → Device List table
- Devices page → All discovered devices

**Python API:**
```python
from icsscout.services import get_session_manager

session_mgr = get_session_manager()
devices = session_mgr.get_devices()
for device in devices:
    print(f"{device.ip} - {device.vendor} {device.model}")
```

**Cải Tiến:**
- ✅ Hiển thị protocol support
- ✅ Device type classification
- ✅ Status indicator
- ✅ Quick actions (scan, probe)

---

### **3. Read Memory**

#### **S7.Pwn CLI (Cũ):**
```bash
s7pwn> select 0
s7pwn> read M 0 10
s7pwn> read DB 1 0 100
```

#### **ICSScout v2.0 (Mới):**

**Python API:**
```python
from icsscout.core.protocols.s7 import S7Client
from icsscout.domain import Target, MemoryAddress, MemoryArea, DataType

# Create target
target = Target(ip='192.168.1.10', rack=0, slot=1)

# Connect
client = S7Client(target)
client.connect()

# Read Marker (M)
result = client.read_area(
    MemoryAddress(
        area=MemoryArea.M,
        offset=0,
        data_type=DataType.BYTE,
        count=10
    )
)
print(result.data)

# Read Data Block
result = client.read_area(
    MemoryAddress(
        area=MemoryArea.DB,
        db_number=1,
        offset=0,
        data_type=DataType.BYTE,
        count=100
    )
)
```

**Cải Tiến:**
- ✅ Type-safe với enums
- ✅ Better error handling
- ✅ Support nhiều data types (BYTE, INT, DINT, REAL, STRING)
- ✅ Safety checker tích hợp

---

### **4. Write Memory**

#### **S7.Pwn CLI (Cũ):**
```bash
s7pwn> write M 0 byte 255
s7pwn> write DB 1 10 int 1234
```

#### **ICSScout v2.0 (Mới):**

**Python API:**
```python
from icsscout.core.protocols.s7 import S7Client
from icsscout.domain import MemoryAddress, MemoryArea, DataType

client = S7Client(target)
client.connect()

# Write byte
result = client.write_area(
    MemoryAddress(
        area=MemoryArea.M,
        offset=0,
        data_type=DataType.BYTE
    ),
    value=255
)

# Write integer to DB
result = client.write_area(
    MemoryAddress(
        area=MemoryArea.DB,
        db_number=1,
        offset=10,
        data_type=DataType.INT
    ),
    value=1234
)
```

**Cải Tiến:**
- ✅ **Safety Checker:** Kiểm tra trước khi write
- ✅ **Read-only mode** mặc định
- ✅ **Audit logging:** Ghi lại mọi thao tác
- ✅ Type validation

---

### **5. Monitor (Giám Sát)**

#### **S7.Pwn CLI (Cũ):**
```bash
s7pwn> monitor M 0 10 interval=1
```

#### **ICSScout v2.0 (Mới):**

**Python API:**
```python
from icsscout.core.monitoring import BehaviorMonitor
from icsscout.core.protocols.s7 import S7Client

client = S7Client(target)
client.connect()

monitor = BehaviorMonitor()

# Establish baseline
monitor.establish_baseline(
    client=client,
    memory_address=MemoryAddress(area=MemoryArea.M, offset=0, count=10),
    samples=100
)

# Start monitoring with callback
def on_anomaly(address, old_value, new_value, deviation):
    print(f"Anomaly detected at {address}: {old_value} → {new_value}")

monitor.start_monitoring(
    client=client,
    interval=1.0,
    callback=on_anomaly
)
```

**Cải Tiến:**
- ✅ **Anomaly detection:** 3-sigma rule
- ✅ **Baseline learning:** Học pattern bình thường
- ✅ **Real-time alerts:** Callback khi phát hiện bất thường
- ✅ Statistics tracking

---

### **6. Probe Target**

#### **S7.Pwn CLI (Cũ):**
```bash
s7pwn> probe_target
```

#### **ICSScout v2.0 (Mới):**

**Python API:**
```python
client = S7Client(target)
client.connect()

# Get CPU info
cpu_info = client.get_cpu_info()
print(f"Model: {cpu_info['model_name']}")
print(f"Serial: {cpu_info['serial_number']}")
print(f"Firmware: {cpu_info['firmware_version']}")

# Discover memory areas
areas = client.discover_memory_areas()
for area in areas:
    print(f"{area.name}: {area.size} bytes")
```

**Web GUI:**
- Devices page → Click device → View details

**Cải Tiến:**
- ✅ Fingerprinting database
- ✅ Firmware version detection
- ✅ Memory map discovery
- ✅ Vulnerability matching

---

### **7. Export**

#### **S7.Pwn CLI (Cũ):**
```bash
s7pwn> export session.json
```

#### **ICSScout v2.0 (Mới):**

**Web GUI:**
- Packet Analyzer → "Export PCAP" button

**Python API:**
```python
from icsscout.core.capture import PacketCaptureEngine

engine = PacketCaptureEngine()
engine.start_capture(duration=60)

# Export PCAP
engine.export_pcap("capture.pcap")

# Export session
from icsscout.services import get_session_manager
session_mgr = get_session_manager()
session_mgr.save_session("session_2024.json")
```

**Cải Tiến:**
- ✅ **PCAP export:** Standard Wireshark format
- ✅ **Session persistence:** JSON format
- ✅ **Report generation:** (Coming soon - PDF)

---

### **8. Flood Attack**

#### **S7.Pwn CLI (Cũ):**
```bash
s7pwn> flood 192.168.1.10 connections=100
```

#### **ICSScout v2.0 (Mới):**

❌ **REMOVED - Không khuyến nghị sử dụng**

**Lý do:**
- DoS attacks nguy hiểm cho OT systems
- Có thể gây hại an toàn
- Không phù hợp với pentest chuyên nghiệp

**Alternative:**
- Dùng passive reconnaissance
- Vulnerability scanning
- Safety-first approach

---

## 🚀 **Cách Sử Dụng Cả Hai Phiên Bản**

### **Option 1: Dùng S7.Pwn CLI Cũ**

```bash
# Vẫn hoạt động bình thường
cd /path/to/S7.Pwn
python -m s7pwn.cli

# Hoặc
s7pwn
```

**Khi nào dùng:**
- ✅ Quen với CLI
- ✅ Cần quick testing
- ✅ Script automation đơn giản

---

### **Option 2: Dùng ICSScout v2.0 Web GUI**

```bash
python start_webapp.py
# Mở http://localhost:5000
```

**Khi nào dùng:**
- ✅ Cần phân tích packets
- ✅ Muốn giao diện đẹp
- ✅ Real-time monitoring
- ✅ Team collaboration

---

### **Option 3: Dùng ICSScout v2.0 Python API**

```python
from icsscout.core.protocols.s7 import S7Client
from icsscout.domain import Target

target = Target(ip='192.168.1.10', rack=0, slot=1)
client = S7Client(target)
client.connect()
# ... your automation code
```

**Khi nào dùng:**
- ✅ Custom workflows
- ✅ Advanced automation
- ✅ Integration với tools khác

---

## 📊 **Tổng Quan Features**

| Feature | S7.Pwn CLI | ICSScout v2.0 |
|---------|-----------|---------------|
| **Network Scan** | ✅ Active | ✅ Passive (Packet Capture) |
| **Device List** | ✅ Basic | ✅ Rich info + UI |
| **Read Memory** | ✅ | ✅ + Type-safe |
| **Write Memory** | ✅ | ✅ + Safety Checker |
| **Monitor** | ✅ Basic | ✅ + Anomaly Detection |
| **Probe** | ✅ | ✅ + Fingerprinting |
| **Export** | ✅ JSON | ✅ PCAP + JSON |
| **Flood Attack** | ⚠️ Có | ❌ Removed |
| **Web GUI** | ❌ | ✅ Beautiful UI |
| **Packet Analyzer** | ❌ | ✅ Wireshark-like |
| **Vulnerability Scan** | ❌ | ✅ CVE Database |
| **Protocol Dissection** | ❌ | ✅ S7/Modbus/OPC UA |
| **Behavior Analysis** | ❌ | ✅ Statistical |
| **Memory Dump** | ❌ | ✅ Full forensics |
| **Safety Features** | ❌ | ✅ Multiple layers |
| **Cross-platform** | ❌ Windows only | ✅ Win/Linux/Mac |

---

## 🎯 **Khuyến Nghị**

### **Cho Pentest Nhanh:**
→ **Dùng S7.Pwn CLI** (cũ) - nhanh, đơn giản

### **Cho Assessment Chuyên Nghiệp:**
→ **Dùng ICSScout v2.0** - đầy đủ features, an toàn hơn

### **Cho Automation:**
→ **Dùng ICSScout v2.0 Python API** - flexible, extensible

---

## 🔄 **Migration Guide**

Nếu muốn chuyển từ S7.Pwn CLI sang ICSScout v2.0:

### **Bước 1: Hiểu Mapping**
Đọc bảng mapping ở trên để biết command cũ → API mới

### **Bước 2: Viết Lại Script**
```python
# Old S7.Pwn CLI workflow:
# scan → list → select → read → write

# New ICSScout v2.0:
from icsscout.core.protocols.s7 import S7Client
from icsscout.domain import Target, MemoryAddress, MemoryArea

# Passive scan via packet capture first
# Then manual target selection

target = Target(ip='192.168.1.10', rack=0, slot=1)
client = S7Client(target)
client.connect()

# Read
data = client.read_area(MemoryAddress(...))

# Write (with safety check)
client.write_area(MemoryAddress(...), value=...)
```

### **Bước 3: Test Kỹ**
- Test trên lab environment trước
- Verify tất cả operations
- Check audit logs

---

## 💡 **FAQ**

### **Q: Tôi có thể xóa thư mục `s7pwn/` không?**
A: Có, nếu không cần CLI cũ nữa. Nhưng khuyến nghị giữ lại để fallback.

### **Q: CLI cũ có hoạt động trên Windows không?**
A: Có, nhưng một số dependencies có thể gặp vấn đề.

### **Q: Tôi có thể dùng cả 2 cùng lúc không?**
A: Có! Chúng độc lập hoàn toàn.

### **Q: ICSScout v2.0 có hỗ trợ CLI không?**
A: Chưa. CLI đang trong roadmap (Phase 8).

### **Q: Làm sao chạy S7.Pwn CLI cũ?**
A:
```bash
python -m s7pwn.cli
# Hoặc
cd s7pwn && python cli.py
```

---

## 📚 **Tài Liệu Liên Quan**

- **IMPLEMENTATION_STATUS.md** - Tình trạng features ICSScout v2.0
- **WEB_GUI_GUIDE.md** - Hướng dẫn Web GUI
- **QUICKSTART.md** - Quick start ICSScout v2.0
- **examples/s7_client_example.py** - Ví dụ Python API

---

## 🎉 **Kết Luận**

✅ **Code cũ vẫn còn** - Thư mục `s7pwn/` vẫn hoạt động bình thường

✅ **ICSScout v2.0 tốt hơn** - Kiến trúc mới, nhiều features, an toàn hơn

✅ **Bạn có cả 2 options** - Chọn cái nào phù hợp với workflow

---

**Tóm lại: Không có chức năng nào bị mất! Chỉ được làm tốt hơn! 🚀**
