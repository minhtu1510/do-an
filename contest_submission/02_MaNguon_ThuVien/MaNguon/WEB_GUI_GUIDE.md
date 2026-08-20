# ICSScout Web GUI - User Guide

**ICSScout v2.0** - Industrial Control Systems Security Assessment Platform

---

## 🚀 Quick Start

### Installation

1. **Install Dependencies:**
```bash
pip install -r requirements.txt
```

Required packages:
- `flask>=2.3.0` - Web framework
- `flask-socketio>=5.3.0` - Real-time WebSocket communication
- `flask-cors>=4.0.0` - CORS support
- `scapy` - Packet capture
- `python-snap7` - S7 protocol support
- `pymodbus>=3.0.0` - Modbus protocol support

### Launch Web Application

```bash
python3 start_webapp.py
```

**Optional Arguments:**
```bash
python3 start_webapp.py --host 0.0.0.0 --port 5000 --debug
```

- `--host`: Host to bind to (default: 0.0.0.0)
- `--port`: Port to bind to (default: 5000)
- `--debug`: Enable debug mode

**Access the application:**
Open your browser and navigate to: http://localhost:5000

---

## 📊 Dashboard

The main dashboard provides an overview of your OT security assessment:

### **Features:**
- **Quick Statistics:**
  - Devices Found
  - PLCs Detected
  - Packets Captured
  - Vulnerabilities Discovered

- **Protocol Distribution Chart:**
  - Visual breakdown of captured protocols (S7, Modbus TCP, OPC UA)
  - Pie chart with color-coded segments

- **Device List:**
  - All discovered devices with IP, vendor, model, type
  - Quick scan button for each device

- **Recent Activity Log:**
  - Real-time updates of system activities

**Navigation:**
- Click "Start Packet Capture" to begin passive reconnaissance
- Click "Scan Vulnerabilities" to analyze discovered devices

---

## 🔍 Packet Analyzer

The **Packet Analyzer** is the core feature - a Wireshark-like interface for analyzing OT/ICS protocol traffic.

### **Layout (3-Pane Design):**

#### **1. Control Panel (Top)**
Configure your packet capture:

**Capture Interface:**
- Auto-detect: Automatically select the best network interface
- Manual selection: eth0, eth1, wlan0, etc.

**Duration:**
- Set capture duration (10 - 3600 seconds)
- Default: 300 seconds (5 minutes)

**Protocol Filters:**
- ✅ S7 (Siemens S7 protocol)
- ✅ Modbus TCP
- ✅ OPC UA
- Select protocols to capture

**Capture Controls:**
- **Start Capture**: Begin real-time packet capture
- **Stop**: Manually stop capture before duration ends

**Live Statistics:**
- Total packets captured
- Total bytes captured
- Capture duration
- Packet rate (packets/second)

#### **2. Packet List Pane**
View all captured packets in a table format:

| Column | Description |
|--------|-------------|
| # | Packet number |
| Time | Timestamp with milliseconds |
| Source | Source IP:Port |
| Destination | Destination IP:Port |
| Protocol | Protocol badge (S7, Modbus, OPC UA) |
| Length | Packet size in bytes |
| Info | Brief description of packet function |

**Actions:**
- **Click on any packet** to view detailed dissection
- **Export PCAP**: Download captured packets as .pcap file
- **Clear**: Remove all packets from view

#### **3. Packet Details Pane**
Protocol-specific dissection with expandable layers:

**S7 Protocol:**
- **TPKT Layer**: Version, Reserved, Length
- **COTP Layer**: PDU Type, TPDU Number
- **S7 Header**: Protocol ID, Message Type, PDU Reference, Parameter/Data Length
- **S7 Parameter**: Function code (Read Var, Write Var, PLC Control), Item details
- **S7 Data**: Memory area (I, Q, M, DB), Address, Data values

**Modbus TCP:**
- **MBAP Header**: Transaction ID, Protocol ID, Length, Unit ID
- **Modbus PDU**: Function code (Read Coils, Write Registers, etc.), Address, Quantity, Data

**OPC UA:**
- **OPC UA Header**: Message Type (Hello, Open Secure Channel, etc.), Chunk Type, Message Size
- **Message Details**: Protocol version, buffer sizes, security settings

#### **4. Hex/ASCII Viewer Pane**
Raw packet data in hex dump format:

```
0000  03 00 00 1f 02 f0 80 32 01 00 00 04 00 00 08 00  |.......2........|
0010  00 f0 00 00 01 00 01 01 e0                       |.........|
```

- **Offset**: Byte offset in hex
- **Hex Bytes**: 16 bytes per row
- **ASCII**: Printable characters (or '.' for non-printable)

---

## 🐛 Vulnerability Scanner

Scan discovered devices for security vulnerabilities.

### **Features:**

**1. Device Selection:**
- Multi-select dropdown
- "All Devices" option for comprehensive scan
- Populated from discovered devices

**2. Vulnerability Detection:**
Checks for:
- ✅ **CVE Database**: Known vulnerabilities (Siemens, Modbus, OPC UA)
- ✅ **Default Credentials**: Common factory default passwords
- ✅ **Unencrypted Communication**: Protocol encryption status
- ✅ **Exposed Services**: Open ports and services
- ✅ **Firmware Age**: Outdated firmware versions

**3. Results Display:**

For each device:
- **IP Address** and Device Model
- **Severity Badges:**
  - 🔴 Critical
  - 🟠 High
  - 🟡 Medium
  - 🟢 Low

**Vulnerability Cards:**
- **Title**: Vulnerability name
- **Description**: Detailed explanation
- **CVE ID**: If applicable (e.g., CVE-2019-13945)
- **Severity**: Color-coded badge
- **Recommendation**: ✨ Remediation steps

---

## 🖥️ Device Manager

Manage and interact with discovered OT devices.

### **Features:**

**Device Grid:**
- Card-based layout for each device
- **Device Info:**
  - IP Address
  - Vendor & Model (e.g., "Siemens S7-1500")
  - Status indicator (green = online)

**Protocol Badges:**
- Color-coded protocol support (S7, Modbus, OPC UA, etc.)

**Actions:**
- **View**: See detailed device information
- **Scan**: Run vulnerability scan for specific device

**Refresh:**
- Click "Refresh" to rescan network for new devices

---

## 🎨 User Interface Design

### **Dark Theme:**
Beautiful, professional dark theme optimized for security operations:

- **Primary Colors:**
  - Background: Dark navy (`#0f172a`)
  - Cards: Semi-transparent slate with glass morphism
  - Accent: Purple-indigo gradient (`#667eea` → `#764ba2`)

- **Protocol Colors:**
  - S7: Blue (`#3b82f6`)
  - Modbus TCP: Green (`#10b981`)
  - OPC UA: Orange (`#f59e0b`)
  - Other: Gray (`#6b7280`)

- **Status Colors:**
  - Success/Online: Green
  - Warning: Yellow
  - Error/Critical: Red
  - Info: Blue

### **Responsive Design:**
- Works on desktop, tablet, and mobile
- Grid layout adapts to screen size
- Scrollable tables and panels

---

## 🔄 Real-Time Features

### **WebSocket Connection:**

The application uses **Socket.IO** for real-time communication:

**Real-time Updates:**
- ✅ Packet capture statistics
- ✅ New packets streaming to packet list
- ✅ Capture completion notifications
- ✅ Connection status indicator

**Connection Indicator:**
- 🟢 Green pulse = Connected
- Toast notification on connect/disconnect

**Live Statistics:**
- Packet count updates every packet
- Dashboard refreshes every 30 seconds
- Capture stats update every second

---

## 📁 Exported Files

### **PCAP Export:**

Export captured packets for analysis in Wireshark or other tools:

1. Click **"Export PCAP"** in Packet Analyzer
2. File downloads as: `capture_YYYYMMDD_HHMMSS.pcap`
3. Location: Browser's download folder

**Use Cases:**
- Offline analysis with Wireshark
- Share with team members
- Archive for compliance
- Deep protocol analysis

---

## 🔐 Security Considerations

### **Important Notes:**

1. **Authentication:**
   - ⚠️ Web GUI has NO authentication in current version
   - Do NOT expose to untrusted networks
   - Run on isolated assessment network only

2. **Permissions:**
   - Packet capture requires root/admin privileges
   - Run with `sudo` on Linux: `sudo python3 start_webapp.py`

3. **Safety:**
   - All operations are **READ-ONLY** by default
   - Safety checker prevents dangerous write operations
   - Audit trail logs all security-relevant actions

4. **Network Impact:**
   - Passive packet capture has minimal impact
   - Active vulnerability scanning may be detected by IDS/IPS
   - Coordinate with plant operators before assessment

---

## 🛠️ Troubleshooting

### **Common Issues:**

**1. Web App Won't Start**
```
Error: Address already in use
```
**Solution:** Port 5000 is in use. Change port:
```bash
python3 start_webapp.py --port 8080
```

**2. No Packets Captured**
```
Permission denied: You need root access
```
**Solution:** Run with sudo:
```bash
sudo python3 start_webapp.py
```

**3. WebSocket Connection Failed**
```
Failed to connect to WebSocket
```
**Solution:**
- Check browser console for errors
- Ensure Socket.IO CDN is accessible
- Check firewall settings

**4. Protocol Dissection Fails**
```
Error: Packet too short
```
**Solution:**
- Packet may be fragmented or malformed
- Check BPF filter configuration
- Verify protocol port mapping

**5. Empty Device List**
```
No devices discovered yet
```
**Solution:**
- Start packet capture first (passive discovery)
- Ensure network interface is correct
- Check network connectivity

---

## 🎯 Use Cases

### **1. Passive OT Reconnaissance (Hydro Plant Example)**

**Scenario:** Assess hydro plant OT security without disrupting operations

**Workflow:**
1. **Launch Web GUI:**
   ```bash
   sudo python3 start_webapp.py
   ```

2. **Navigate to Packet Analyzer**

3. **Configure Capture:**
   - Interface: Auto-detect
   - Duration: 600 seconds (10 minutes)
   - Protocols: S7, Modbus TCP, OPC UA ✅

4. **Start Capture**
   - Monitor real-time statistics
   - Watch packet list populate
   - Observe communication patterns

5. **Analyze Traffic:**
   - Click on S7 packets to see PLC operations
   - Identify memory addresses being read/written
   - Map device communication relationships

6. **Export Results:**
   - Download PCAP for offline analysis
   - Review traffic patterns with team

7. **Run Vulnerability Scan:**
   - Navigate to Vulnerability Scanner
   - Select discovered devices
   - Review security findings

8. **Generate Report:**
   - Document findings
   - Provide recommendations

### **2. Active PLC Assessment**

**Scenario:** Security audit of specific Siemens S7-1500 PLC

**Workflow:**
1. **Device Discovery:**
   - Use Packet Analyzer to capture traffic
   - Identify PLC IP address

2. **Vulnerability Scanning:**
   - Navigate to Vulnerability Scanner
   - Select target PLC
   - Review CVE matches (firmware version)

3. **Memory Forensics:**
   - Use Python API for memory dump (see examples/)
   - Analyze extracted data

4. **Safety Validation:**
   - Check device is not in critical state
   - Verify read-only operations
   - Document all actions in audit log

---

## 📚 Additional Resources

- **IMPLEMENTATION_STATUS.md**: Feature completion status
- **examples/passive_recon_example.py**: Python API usage examples
- **icsscout/data/cve/**: CVE database (JSON format)

---

## 🤝 Support

For issues, questions, or feature requests:
- Check troubleshooting section above
- Review examples in `examples/` directory
- Consult API documentation in code comments

---

## 📝 License & Disclaimer

**DISCLAIMER:** ICSScout is intended for authorized security assessments only. Always obtain proper authorization before testing OT/ICS systems. Unauthorized access to industrial control systems is illegal and dangerous.

**Use Responsibly:**
- ✅ Authorized penetration tests
- ✅ Security audits with permission
- ✅ Red team exercises
- ✅ Educational research
- ✅ CTF competitions

- ❌ Unauthorized access
- ❌ Disrupting critical infrastructure
- ❌ Causing safety incidents
- ❌ Malicious activities

---

**ICSScout v2.0** - Built with ❤️ for OT Security Professionals
