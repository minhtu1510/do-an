# ICSScout v2.0

**Industrial Control Systems Security Assessment Platform**

Công cụ đánh giá bảo mật chuyên nghiệp cho hệ thống OT/ICS với giao diện Web đẹp mắt và trực quan.

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-Educational-orange)

---

## 🌟 Tính Năng Chính

### ✨ **Web GUI Đẹp Mắt**
- 🎨 Dark theme với glass morphism
- 📊 Real-time dashboard với biểu đồ
- 🔄 WebSocket cho cập nhật trực tiếp
- 📱 Responsive design (desktop, tablet, mobile)

### 🔍 **Packet Analyzer (Wireshark-like)**
- 📦 3-pane layout giống Wireshark
- 🔬 Protocol dissection chi tiết (S7, Modbus TCP, OPC UA)
- 🔢 Hex/ASCII viewer
- 💾 Export PCAP files

### 🛡️ **Vulnerability Scanner**
- 🔴 CVE database tích hợp
- 🔐 Kiểm tra default credentials
- 🔓 Phát hiện unencrypted protocols
- 📋 Recommendations chi tiết

### 🎯 **Protocol Support**
- **Siemens S7** (S7-300, S7-400, S7-1200, S7-1500)
- **Modbus TCP** (Coils, Registers)
- **OPC UA** (Protocol detection)
- Dễ dàng mở rộng cho protocols khác

### 🔒 **Safety Features**
- ✅ Read-only mode mặc định
- ✅ Safety checker trước mọi thao tác
- ✅ Audit trail logging
- ✅ Session management

---

## 🚀 Quick Start

### **Windows Users** (Khuyến Nghị! ⭐)

**Đọc:** [WINDOWS_SETUP.md](WINDOWS_SETUP.md) - Hướng dẫn chi tiết cho Windows

**Cài đặt nhanh:**

1. **Cài Npcap** (bắt buộc): https://npcap.com/#download
   - ✅ Tick "Install in WinPcap API-compatible Mode"
   - Khởi động lại máy

2. **Cài dependencies:**
   - Cách 1: Double-click `install_windows.bat` (Run as Administrator)
   - Cách 2: Hoặc chạy thủ công:
     ```cmd
     pip install -r requirements.txt
     ```

3. **Khởi động Web App:**
   - Double-click `start_webapp.bat` (Run as Administrator)
   - Hoặc: `python start_webapp.py`

4. **Mở trình duyệt:** http://localhost:5000

---

### **Linux/macOS Users**

**Đọc:** [QUICKSTART.md](QUICKSTART.md)

**Cài đặt:**
```bash
# Install dependencies
pip install -r requirements.txt

# Start web app (needs sudo for packet capture)
sudo python3 start_webapp.py

# Open browser
http://localhost:5000
```

---

## 📖 Tài Liệu

| File | Mô Tả | Dành Cho |
|------|-------|----------|
| [WINDOWS_SETUP.md](WINDOWS_SETUP.md) | Hướng dẫn cài đặt Windows chi tiết | ⭐ Windows users |
| [QUICKSTART.md](QUICKSTART.md) | Quick start guide (3 phút) | Tất cả |
| [WEB_GUI_GUIDE.md](WEB_GUI_GUIDE.md) | Hướng dẫn sử dụng Web GUI đầy đủ | Người dùng mới |
| [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) | Tình trạng features & kiến trúc | Developers |

---

## 🎯 Use Cases

### **1. Passive OT Reconnaissance** ✅ Khuyến Nghị
- Bắt gói tin mạng OT
- Phân tích protocols (S7, Modbus)
- Phát hiện devices
- Không gây ảnh hưởng đến hệ thống

**Thích hợp cho:**
- Đánh giá nhà máy sản xuất
- Audit hệ thống điện/nước
- Red team exercises
- Security research

### **2. Vulnerability Assessment**
- Quét CVE trên PLCs
- Kiểm tra default passwords
- Phát hiện unencrypted communications
- Recommendations cụ thể

### **3. Memory Forensics**
- Dump PLC memory
- Phân tích logic ladder
- Extract configurations
- Incident response

---

## 🖼️ Screenshots

### **Dashboard**
- Quick statistics (devices, packets, vulnerabilities)
- Protocol distribution chart
- Device list với quick actions

### **Packet Analyzer** (Main Feature!)
```
┌────────────────────────────────────────────────────────┐
│  Packet List (Top Pane)                                │
│  Time | Source | Dest | Protocol | Length | Info       │
├────────────────────────────────────────────────────────┤
│  Packet Details (Middle Pane)                          │
│  ▼ TPKT                                                │
│  ▼ COTP                                                │
│  ▼ S7 Header                                           │
│  ▼ S7 Parameter (Read Var, DB1.DBX0.0)                 │
├────────────────────────────────────────────────────────┤
│  Hex Dump (Bottom Pane)                                │
│  0000  03 00 00 1f 02 f0 80 ...  |.......2........|   │
└────────────────────────────────────────────────────────┘
```

### **Protocol Dissection Example:**
- **S7**: TPKT → COTP → S7 Header → Parameters (function, area, address) → Data
- **Modbus**: MBAP Header → PDU (function code, registers)
- **OPC UA**: Message type, security headers

---

## ⚙️ System Requirements

### **Minimum:**
- **OS:** Windows 10/11 (64-bit), Linux, macOS
- **Python:** 3.8 or later (64-bit recommended)
- **RAM:** 4 GB
- **Disk:** 500 MB free space

### **Recommended:**
- **RAM:** 8 GB+ (for large packet captures)
- **SSD** (faster PCAP writing)
- **Ethernet adapter** (for OT network connection)

### **Windows-Specific:**
- **Npcap** (required for packet capture)
- **Visual C++ Redistributable** (for some dependencies)
- **Administrator privileges** (for network operations)

---

## 🛠️ Dependencies

### **Core:**
- `scapy` - Packet capture and analysis
- `python-snap7` - Siemens S7 protocol
- `pymodbus` - Modbus TCP protocol

### **Web GUI:**
- `flask` - Web framework
- `flask-socketio` - Real-time WebSocket
- `flask-cors` - CORS support

### **Windows-Only:**
- `pywin32` - Windows API
- `wmi` - WMI access

**Full list:** See [requirements.txt](requirements.txt)

---

## 🔐 Security & Legal

### ⚠️ **DISCLAIMER**

**ICSScout chỉ được sử dụng cho:**
- ✅ Pentesting có giấy phép hợp lệ
- ✅ Security audit với sự cho phép
- ✅ Research và education
- ✅ CTF competitions
- ✅ Red team exercises được ủy quyền

**KHÔNG được dùng cho:**
- ❌ Truy cập trái phép vào hệ thống
- ❌ Gây hại hệ thống critical infrastructure
- ❌ Hoạt động bất hợp pháp
- ❌ Gây nguy hiểm an toàn con người

### 🔒 **Safety by Design:**

- **Read-only mode** mặc định
- **Safety checker** kiểm tra trước mọi thao tác nguy hiểm
- **Audit trail** ghi lại tất cả actions
- **Session management** theo dõi workflow

### 📋 **Before Assessment:**

1. ✅ Có giấy phép pentesting hợp lệ
2. ✅ Scope of work đã được approve
3. ✅ Liên hệ với plant operator/engineer
4. ✅ Backup và rollback plan sẵn sàng
5. ✅ Emergency contacts được chuẩn bị

---

## 📊 Project Status

**Version:** 2.0.0
**Completion:** ~90%

### ✅ **Working Features:**
- ✅ Packet capture & analysis (S7, Modbus, OPC UA)
- ✅ Protocol dissectors
- ✅ Web GUI with real-time updates
- ✅ Dashboard & statistics
- ✅ Vulnerability scanner
- ✅ Device manager
- ✅ Memory dumper
- ✅ Safety checker
- ✅ Session management
- ✅ PCAP export

### 🔄 **Coming Soon:**
- [ ] CLI interface
- [ ] Active network scanner
- [ ] OPC UA client
- [ ] PDF report generator

---

## 🎓 Examples

### **Passive Reconnaissance:**
```python
from icsscout.core.capture import PacketCaptureEngine
from icsscout.core.capture import TrafficAnalyzer

# Start capture
engine = PacketCaptureEngine()
engine.start_capture(duration=300, protocols=['S7', 'Modbus TCP'])

# Analyze
analyzer = TrafficAnalyzer()
analyzer.analyze_capture(engine.packets)
report = analyzer.generate_report()
print(report)
```

**See:** [examples/passive_recon_example.py](examples/passive_recon_example.py)

---

## 🏗️ Architecture

**Clean Architecture** với 4 layers:

```
┌─────────────────────────────────────┐
│  Interfaces (Web GUI, CLI)          │
├─────────────────────────────────────┤
│  Services (Session, Business Logic) │
├─────────────────────────────────────┤
│  Core (Protocols, Capture, Security)│
├─────────────────────────────────────┤
│  Domain (Models, Value Objects)     │
└─────────────────────────────────────┘
```

- **Domain:** Device, Protocol, Vulnerability models
- **Core:** Protocol clients, packet capture, scanners
- **Services:** Session management, workflow orchestration
- **Interfaces:** Web GUI, CLI (coming soon)

---

## 🤝 Contributing

ICSScout là công cụ educational/research. Contributions welcome!

**Areas for improvement:**
- Additional protocol support (DNP3, IEC 104, etc.)
- More CVE entries in database
- UI/UX enhancements
- Documentation translations
- Bug fixes

---

## 📞 Support

**Documentation:**
- Windows: [WINDOWS_SETUP.md](WINDOWS_SETUP.md)
- Quick Start: [QUICKSTART.md](QUICKSTART.md)
- Web GUI Guide: [WEB_GUI_GUIDE.md](WEB_GUI_GUIDE.md)

**Common Issues:**
- See "Troubleshooting" sections in respective docs
- Check [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for known limitations

---

## 📜 License

Educational/Research use only. See disclaimer above.

---

## 🙏 Acknowledgments

**Built with:**
- Python-Snap7 for S7 protocol
- Scapy for packet manipulation
- Flask for Web framework
- Chart.js for visualizations
- Tailwind CSS for beautiful UI

**Inspired by:**
- Wireshark (packet analyzer UX)
- Metasploit (pentest workflow)
- Nmap (network discovery)

---

## 📈 Version History

### **v2.0.0** (Current)
- ✨ Complete Web GUI with real-time packet analyzer
- ✨ Protocol dissectors (S7, Modbus, OPC UA)
- ✨ Vulnerability scanner with CVE database
- ✨ Beautiful dark theme UI
- ✨ Dashboard with charts
- ✨ Windows support with batch files

### **v1.x** (Legacy S7.Pwn)
- Basic S7 protocol support
- Windows-only
- CLI only
- Limited features

---

## 🎯 Roadmap

**Short-term:**
- [ ] Interactive CLI
- [ ] Network scanner
- [ ] More protocols

**Long-term:**
- [ ] Machine learning for anomaly detection
- [ ] Protocol fuzzing capabilities
- [ ] Cloud integration
- [ ] Multi-user support

---

## 🌟 Star History

If you find ICSScout useful, please give it a star! ⭐

---

**ICSScout v2.0** - Built with ❤️ for OT Security Professionals

Made for: Pentesting hydro plants, factories, power grids, and critical infrastructure (with proper authorization!)

**Bắt đầu ngay:**
- Windows: `install_windows.bat` → `start_webapp.bat`
- Linux: `sudo python3 start_webapp.py`

**Enjoy secure OT assessments!** 🚀🔒
