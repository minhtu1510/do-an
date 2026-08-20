# Network Topology & Scanning - Status Report

## 📊 **TL;DR:**

| Feature | S7.Pwn (Old) | ICSScout v2.0 (New) | Status |
|---------|-------------|---------------------|--------|
| **Network Scanner** | ✅ Có (459 lines) | ❌ Chưa có | ⏳ Cần implement |
| **Topology Mapping** | ✅ Có | ❌ Chưa có | ⏳ Cần implement |
| **Real-time Visualization** | ❌ Không | ❌ Chưa có | 💡 Cơ hội làm mới |
| **Passive Discovery** | ❌ Không | ✅ Có (via PacketCapture) | ✅ Done |

---

## 🔍 **Chi Tiết:**

### **S7.Pwn (Code Cũ) - CÓ Network Topology**

**File:** `s7pwn/network_topology.py` (459 dòng)

**Features:**

#### **1. NetworkDevice Class**
```python
class NetworkDevice:
    - ip, mac, hostname
    - vendor, device_type
    - open_ports, services
    - connected_to (topology connections)
    - os_guess, ttl
    - response_time
```

#### **2. NetworkScanner Class**

**Scanning Methods:**
- ✅ **ARP Scan:** Discover devices in subnet
- ✅ **Ping Sweep:** ICMP echo requests
- ✅ **Port Scan:** Detect open ports
- ✅ **Service Detection:** Identify services (HTTP, S7, Modbus, etc.)
- ✅ **Vendor Identification:** MAC address lookup
- ✅ **Device Type Detection:** Based on open ports
- ✅ **Continuous Scanning:** Background monitoring

**Example Usage (Old Code):**
```python
from s7pwn.network_topology import get_scanner

scanner = get_scanner()

# Quick scan
topology = scanner.full_scan(network="192.168.1.0/24", quick=True)

# Get topology data for visualization
data = topology.get_topology_data()
# Returns: {'nodes': [...], 'edges': [...]}
```

#### **3. NetworkTopology Class**
```python
class NetworkTopology:
    devices: Dict[str, NetworkDevice]
    connections: List[Tuple[str, str]]  # (ip1, ip2) pairs
    gateway_ip

    def get_topology_data() -> Dict:
        # Returns nodes + edges for graph visualization
```

**Limitations:**
- ❌ Không có Web GUI visualization
- ❌ Active scanning only (có thể bị phát hiện)
- ❌ Không real-time updates

---

### **ICSScout v2.0 (Code Mới) - CHƯA CÓ Full Topology**

**Có:**
- ✅ **TrafficAnalyzer:** Communication mapping (passive)
- ✅ **PacketCaptureEngine:** Passive device discovery
- ✅ **Communication class:** Track device communications

**Chưa có:**
- ❌ Active network scanner
- ❌ Topology graph visualization
- ❌ Real-time topology updates
- ❌ Port scanning
- ❌ Service detection

**What Exists Now:**
```python
# TrafficAnalyzer can map communications
from icsscout.core.capture import TrafficAnalyzer, PacketCaptureEngine

engine = PacketCaptureEngine()
engine.start_capture(duration=60)

analyzer = TrafficAnalyzer()
stats = analyzer.analyze_capture(engine.packets)

# stats.communications contains:
# - src_ip → dst_ip
# - protocol
# - packet count
# - bytes transferred
```

**But:**
- No graph visualization
- No active scanning
- No port detection
- No topology map

---

## 💡 **Đề Xuất: Implement Network Topology cho ICSScout v2.0**

### **Option 1: Port Code Cũ** (Nhanh - 2-3 giờ)

**Pros:**
- ✅ Code đã có, chỉ cần port
- ✅ Tested và hoạt động
- ✅ Full features (ARP, ping, port scan)

**Cons:**
- ❌ Không có Web GUI
- ❌ Active scanning (có thể bị phát hiện)
- ❌ Không modern architecture

**Tasks:**
1. Copy `network_topology.py` → `icsscout/core/scanner/network_scanner.py`
2. Refactor để fit Clean Architecture
3. Update imports và dependencies
4. Add to ICSScout API

---

### **Option 2: Viết Mới với Modern Architecture** (Tốt - 4-6 giờ)

**Features:**

#### **1. Hybrid Discovery (Passive + Active)**
```python
# Passive discovery via packet capture
passive_devices = traffic_analyzer.get_discovered_devices()

# Active scanning (optional, với confirmation)
scanner.active_scan(subnet="192.168.1.0/24",
                   methods=['arp', 'ping'],  # Not port scan by default
                   stealth=True)
```

#### **2. Real-time Topology Visualization**

**Web GUI Page:** `/network-topology`

**Features:**
- 🌐 **Interactive network graph** (D3.js hoặc vis.js)
- 🔄 **Real-time updates** (WebSocket)
- 🎨 **Color-coded nodes:**
  - 🔴 PLC (port 102, 502)
  - 🟠 HMI (port 80, 443, 8080)
  - 🟢 SCADA Server
  - 🔵 Engineering Workstation
  - ⚪ Unknown
- 📊 **Edge thickness:** Communication volume
- 🔍 **Click node:** Show device details
- 📈 **Timeline slider:** View topology over time

**Example Visualization:**
```
        [SCADA Server]
       /      |      \
      /       |       \
  [PLC-1]  [PLC-2]  [HMI-1]
     |        |        |
  [Sensor] [Valve] [Display]
```

#### **3. Smart Device Classification**

Based on:
- ✅ Open ports (102=S7, 502=Modbus, 80=HTTP)
- ✅ Traffic patterns (who talks to who)
- ✅ Protocol usage
- ✅ Hostname/vendor
- ✅ Behavioral analysis

```python
def classify_device(device):
    if has_port(102) or has_port(502):
        return "PLC"
    elif has_port(80) and talks_to_many_plcs:
        return "HMI" or "SCADA"
    elif has_port(20000):  # DNP3
        return "RTU"
    ...
```

#### **4. Topology Metrics**

- **Network Depth:** Longest path from SCADA to field device
- **Critical Nodes:** Devices with most connections
- **Isolated Devices:** Devices with no/few connections
- **Suspicious Communications:** Unexpected connections

---

### **Option 3: Best of Both Worlds** ⭐ (Khuyến Nghị - 6-8 giờ)

**Combine:**
1. **Passive Discovery** (default, an toàn)
   - Via PacketCaptureEngine
   - TrafficAnalyzer communication mapping
   - No network noise

2. **Optional Active Scanning** (with user confirmation)
   - Port từ code cũ
   - ARP scan, ping sweep
   - Port scanning (optional)

3. **Modern Web Visualization**
   - D3.js force-directed graph
   - Real-time WebSocket updates
   - Interactive controls

---

## 🎯 **Implementation Plan**

### **Phase 1: Backend - Network Scanner** (2-3 hours)

**File:** `icsscout/core/scanner/network_scanner.py`

```python
class NetworkScanner:
    """Active + Passive network scanner"""

    def passive_discover(self, packets: List[CapturedPacket]) -> NetworkTopology:
        """Discover devices from packet capture (safe)"""

    def arp_scan(self, subnet: str) -> List[Device]:
        """ARP-based discovery"""

    def detect_services(self, device: Device) -> List[str]:
        """Detect services via banner grabbing"""
```

**File:** `icsscout/core/scanner/topology_builder.py`

```python
class TopologyBuilder:
    """Build network topology from discoveries"""

    def build_from_traffic(self, communications: List[Communication]) -> Topology:
        """Build topology from passive traffic analysis"""

    def add_active_scans(self, scan_results: List[Device]) -> None:
        """Merge active scan results"""

    def get_graph_data(self) -> Dict:
        """Export for D3.js visualization"""
        return {
            'nodes': [
                {'id': '192.168.1.10', 'type': 'PLC', 'label': 'S7-1500'},
                {'id': '192.168.1.20', 'type': 'HMI', 'label': 'WinCC'}
            ],
            'links': [
                {'source': '192.168.1.20', 'target': '192.168.1.10',
                 'value': 1234, 'protocol': 'S7'}
            ]
        }
```

---

### **Phase 2: Web GUI - Topology Page** (3-4 hours)

**File:** `icsscout/interfaces/web/templates/network_topology.html`

**Features:**

```html
<div class="topology-container">
  <!-- Control Panel -->
  <div class="controls">
    <button onclick="startPassiveScan()">
      🔍 Passive Discovery (Safe)
    </button>
    <button onclick="startActiveScan()">
      ⚡ Active Scan (Requires Confirmation)
    </button>
    <button onclick="exportTopology()">
      💾 Export Topology
    </button>
  </div>

  <!-- Network Graph -->
  <div id="network-graph" style="height: 600px;">
    <!-- D3.js force-directed graph here -->
  </div>

  <!-- Device Info Panel -->
  <div id="device-info">
    <h3>Device Details</h3>
    <div id="device-details">
      <!-- Click on node to show details -->
    </div>
  </div>

  <!-- Timeline -->
  <div id="timeline-slider">
    <input type="range" min="0" max="100"
           onchange="updateTopologyTime(this.value)">
  </div>
</div>
```

**JavaScript (D3.js):**
```javascript
// Load D3.js
const svg = d3.select("#network-graph")
  .append("svg")
  .attr("width", width)
  .attr("height", height);

// Force simulation
const simulation = d3.forceSimulation(nodes)
  .force("link", d3.forceLink(links).id(d => d.id))
  .force("charge", d3.forceManyBody().strength(-300))
  .force("center", d3.forceCenter(width / 2, height / 2));

// Real-time updates via WebSocket
socket.on('topology_update', function(data) {
  updateGraph(data.nodes, data.links);
});
```

---

### **Phase 3: API Endpoints** (1 hour)

```python
# app.py

@app.route('/network-topology')
def network_topology_page():
    """Network topology visualization page"""
    return render_template('network_topology.html')

@app.route('/api/topology/passive', methods=['POST'])
def api_passive_discover():
    """Start passive discovery from packet capture"""
    # Use existing packet capture data

@app.route('/api/topology/active', methods=['POST'])
def api_active_scan():
    """Start active network scan (with confirmation)"""
    # ARP scan + ping sweep

@app.route('/api/topology/data')
def api_topology_data():
    """Get current topology graph data"""
    # Returns nodes + links in D3.js format

@socketio.on('subscribe_topology')
def handle_topology_subscribe():
    """Subscribe to real-time topology updates"""
```

---

## 🎨 **Visualization Examples**

### **Node Types:**

```
🔴 PLC          - Siemens S7, Modbus RTU
🟠 HMI          - WinCC, FactoryTalk
🟢 SCADA        - Central server
🔵 Engineering  - TIA Portal workstation
🟣 Database     - Historian
⚪ Unknown      - Unclassified device
```

### **Edge Properties:**

- **Thickness:** Packet count / bytes transferred
- **Color:** Protocol (blue=S7, green=Modbus, orange=OPC UA)
- **Animation:** Real-time traffic flow
- **Labels:** Protocol name + packet count

### **Layout Algorithms:**

- **Force-directed:** Default, organic layout
- **Hierarchical:** SCADA → HMI → PLC → Sensors
- **Circular:** Ring layout
- **Grid:** Structured grid

---

## ⏱️ **Estimated Timeline:**

| Task | Time | Priority |
|------|------|----------|
| Backend: NetworkScanner | 2-3 hrs | HIGH |
| Backend: TopologyBuilder | 1-2 hrs | HIGH |
| Web GUI: Topology page HTML/CSS | 1 hr | MEDIUM |
| Web GUI: D3.js visualization | 2-3 hrs | HIGH |
| API Endpoints | 1 hr | HIGH |
| WebSocket real-time updates | 1 hr | MEDIUM |
| Testing & Polish | 1-2 hrs | MEDIUM |
| **TOTAL** | **9-13 hrs** | - |

---

## 🚀 **Quick Start (Minimum Viable Product - 4 hours)**

**Just want basic topology ASAP?**

### **MVP Features:**
1. ✅ Passive discovery from packet capture
2. ✅ Simple graph visualization (vis.js - easier than D3.js)
3. ✅ Device list with connections
4. ✅ No active scanning (use existing traffic)

**Files to Create:**
- `icsscout/core/scanner/topology_builder.py` (150 lines)
- `icsscout/interfaces/web/templates/network_topology.html` (200 lines)
- Add API endpoints in `app.py` (50 lines)

**Total:** ~400 lines, 4 hours work

---

## 💬 **Câu Hỏi Cho Bạn:**

1. **Bạn muốn option nào?**
   - A. Port code cũ (nhanh, có active scan)
   - B. Viết mới với visualization đẹp (lâu hơn, modern)
   - C. MVP đơn giản (4 hours, passive only)

2. **Passive hay Active scanning?**
   - Passive = An toàn, không bị phát hiện, nhưng chậm
   - Active = Nhanh, đầy đủ, nhưng có thể trigger IDS

3. **Visualization library nào?**
   - D3.js = Powerful, flexible, learning curve cao
   - vis.js = Dễ dùng, đẹp, ít options hơn
   - Cytoscape.js = Chuyên cho network graphs

4. **Real-time updates có cần không?**
   - Có = Cool, nhưng phức tạp hơn
   - Không = Đơn giản, chỉ refresh khi cần

---

## 📋 **Current Status:**

```
Network Topology Feature: ❌ NOT IMPLEMENTED in ICSScout v2.0

Legacy Code Available: ✅ s7pwn/network_topology.py (459 lines)

Next Steps:
[ ] User decides which option to implement
[ ] Create topology_builder.py
[ ] Create network_topology.html with visualization
[ ] Add API endpoints
[ ] Test with real network traffic
```

---

**Bạn muốn tôi implement feature này không? Chọn option nào? 🚀**
