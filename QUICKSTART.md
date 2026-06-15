# ICSScout v2.0 - Quick Start Guide

## 🚀 Getting Started in 3 Minutes

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Launch Web Application
```bash
sudo python3 start_webapp.py
```

**Why sudo?** Packet capture requires root/administrator privileges to access network interfaces.

### Step 3: Open Browser
Navigate to: **http://localhost:5000**

---

## 🎯 Quick Workflow: Passive OT Reconnaissance

### For Your Hydro Plant Assessment:

1. **Open Packet Analyzer**
   - Click "Packet Analyzer" in navigation
   - Or go to: http://localhost:5000/packet-analyzer

2. **Configure Capture**
   - Interface: Auto-detect
   - Duration: 300 seconds (5 minutes minimum recommended)
   - Protocols: ✅ S7, ✅ Modbus TCP, ✅ OPC UA

3. **Start Capture**
   - Click "Start Capture" button
   - Watch real-time statistics update
   - Packets appear in list as they're captured

4. **Analyze Packets**
   - Click any packet in the list
   - View protocol-specific dissection
   - See hex dump at bottom
   - Identify:
     - PLC IP addresses
     - Memory operations (reads/writes)
     - Device communication patterns
     - Protocol types in use

5. **Export Results**
   - Click "Export PCAP" to download capture file
   - Open in Wireshark for deeper analysis if needed

6. **Scan for Vulnerabilities**
   - Navigate to "Vulnerabilities" page
   - Select discovered devices
   - Click "Start Vulnerability Scan"
   - Review security findings with recommendations

---

## 📊 What You'll See

### Dashboard
- Device count (discovered from traffic)
- Protocol distribution chart
- Real-time packet statistics
- Device list with quick actions

### Packet Analyzer (The Main Feature!)
**3-Pane Wireshark-like Layout:**

**Top Pane - Packet List:**
- Time | Source | Destination | Protocol | Length | Info
- Click any row to inspect

**Middle Pane - Packet Details:**
- Dissected protocol layers (expandable)
- S7: TPKT → COTP → S7 Header → Parameters → Data
- Modbus: MBAP Header → PDU → Function details
- OPC UA: Message headers and security info

**Bottom Pane - Hex Viewer:**
- Raw packet bytes in hex
- ASCII representation on the right
- 16 bytes per row (like Wireshark)

---

## 🎨 Interface Features

✨ **Beautiful Dark Theme**
- Professional security tool aesthetic
- Purple-indigo gradient accents
- Glass morphism effects
- Smooth animations

🔄 **Real-Time Updates**
- WebSocket connection for live data
- Statistics update every second during capture
- Packets stream in real-time
- Green pulse indicator shows connection status

📱 **Responsive Design**
- Works on desktop, tablet, mobile
- Adaptive grid layouts
- Scrollable tables and panels

---

## 🔍 Protocol Dissection Examples

### Siemens S7 Packet
```
▼ TPKT
  Version: 3
  Length: 31

▼ COTP
  PDU Type: 0xF0
  TPDU Number: 0

▼ S7 Header
  Protocol ID: 0x32
  Message Type: Job Request
  Function: Read Var

▼ S7 Parameter
  Item Count: 1
  ▼ Item 1:
    Area: Data Block (DB)
    DB Number: 1
    Address: 0
    Length: 10
```

### Modbus TCP Packet
```
▼ MBAP Header
  Transaction ID: 1
  Protocol ID: 0
  Unit ID: 1

▼ Modbus PDU
  Function Code: 3 - Read Holding Registers
  Starting Address: 1000
  Quantity: 10
```

---

## 📝 Tips for OT Pentesting

### Passive Reconnaissance (Safe):
✅ Capture traffic for 10-30 minutes
✅ Identify all devices and protocols
✅ Map communication patterns
✅ Extract memory addresses from traffic
✅ Check for unencrypted protocols
✅ Scan for known CVEs

### Active Testing (Requires Authorization):
⚠️ Only with explicit permission
⚠️ Test in maintenance window
⚠️ Use read-only operations first
⚠️ Monitor for anomalies
⚠️ Have rollback plan

### Critical Safety:
🛑 Never write to PLCs without authorization
🛑 Never stop/start PLCs in production
🛑 Don't disrupt critical processes
🛑 Always coordinate with plant operators

---

## 📚 Documentation

- **WEB_GUI_GUIDE.md** - Comprehensive user guide (detailed)
- **IMPLEMENTATION_STATUS.md** - Feature status and architecture
- **examples/passive_recon_example.py** - Python API usage

---

## 🐛 Troubleshooting

**"Permission denied" when starting capture**
```bash
# Solution: Run with sudo
sudo python3 start_webapp.py
```

**"Port 5000 already in use"**
```bash
# Solution: Use different port
python3 start_webapp.py --port 8080
```

**No packets captured**
- Check network interface is correct
- Ensure traffic is flowing on network
- Verify BPF filter configuration
- Check firewall settings

**WebSocket disconnected**
- Refresh browser page
- Check browser console for errors
- Ensure server is still running

---

## 🎯 Project Status

**Current Version:** 2.0.0
**Completion:** ~90%

### ✅ What Works:
- ✅ Passive packet capture and analysis
- ✅ S7 and Modbus TCP protocol support
- ✅ Protocol dissection (S7, Modbus, OPC UA)
- ✅ Vulnerability scanning
- ✅ Memory forensics
- ✅ Real-time web interface
- ✅ PCAP export
- ✅ Safety mechanisms

### 🔄 Coming Soon:
- [ ] CLI interface
- [ ] Active network scanner
- [ ] OPC UA client implementation
- [ ] Professional PDF reports

---

## 🤝 Need Help?

1. Read **WEB_GUI_GUIDE.md** for detailed instructions
2. Check **examples/** directory for Python API usage
3. Review **IMPLEMENTATION_STATUS.md** for feature details

---

**Ready to secure your OT environment? Start capturing!** 🎉

```bash
sudo python3 start_webapp.py
```

**Then open:** http://localhost:5000
