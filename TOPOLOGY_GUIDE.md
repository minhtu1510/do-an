# Network Topology Scanner - Hướng dẫn chi tiết

## Tổng quan

Tính năng **Network Topology Scanner** cho phép bạn:
- 🔍 Quét toàn bộ mạng, không chỉ PLC
- 🗺️ Hiển thị topology mạng dưới dạng đồ họa
- 📊 Phân tích thiết bị (device type, OS, ports, services)
- ⚡ Cập nhật real-time
- 📤 Xuất topology ra file

---

## Khởi động

### Từ Web GUI

1. Mở S7Pwn Web GUI
2. Click vào **"🗺️ Network Topology"** trên header
3. Hoặc truy cập trực tiếp: `http://127.0.0.1:5000/topology`

---

## Các chế độ quét

### 1. **Single Scan** (Quét một lần)

**Cách sử dụng:**
1. Nhập network range (hoặc để trống để auto-detect)
2. Chọn "Quick Scan" nếu muốn quét nhanh
3. Click **"Start Scan"**

**Thời gian:**
- Quick scan: 30-60 giây
- Full scan: 2-5 phút (tùy kích thước mạng)

**Kết quả:**
- Danh sách tất cả devices
- Network topology graph
- Thông tin chi tiết từng device

### 2. **Continuous Scan** (Quét liên tục)

**Cách sử dụng:**
1. Click **"Start Continuous"**
2. Scanner sẽ tự động quét lại mỗi 30 giây
3. Topology được cập nhật real-time

**Use cases:**
- Giám sát devices lên/xuống mạng
- Phát hiện thiết bị mới
- Tracking network changes

**Dừng:**
- Click **"Stop Continuous"** hoặc **"Stop"**

---

## Hiểu topology graph

### Các loại node (thiết bị)

| Biểu tượng | Màu sắc | Loại thiết bị |
|-----------|---------|---------------|
| ⭐ Ngôi sao | Đỏ (#FF6B6B) | **Gateway/Router** |
| ⬜ Vuông | Xanh ngọc (#4ECDC4) | **PLC / ICS Device** |
| ◆ Kim cương | Xanh nhạt (#95E1D3) | **Switch / Network Device** |
| ● Tròn | Xanh lá (#A8E6CF) | **Computer / Server** |
| ● Tròn | Xám (#CCCCCC) | **Unknown Device** |

### Màu node
- **Màu đậm**: Device đang online
- **Màu xám**: Device offline
- **Kích thước**: Tỷ lệ với số open ports

### Cạnh (connections)
- **Nét liền**: Kết nối trực tiếp
- **Nét đứt**: Kết nối qua gateway (giả định)
- **Độ dày**: Mức độ kết nối

---

## Phân tích thiết bị

### Click vào node để xem chi tiết:

**Thông tin cơ bản:**
- IP Address
- MAC Address (nếu có)
- Hostname
- Vendor (nhận dạng từ MAC)

**Thông tin kỹ thuật:**
- Device Type
- OS Guess (từ TTL)
- Response Time (ping)
- Online Status

**Network info:**
- Open Ports
- Detected Services
- TTL value

### Device Type Detection

Scanner tự động nhận dạng thiết bị dựa trên:

**PLC / ICS Device:**
- Port 102 (S7comm) → Siemens PLC
- Port 502 (Modbus) → Modbus device
- Port 20000 (DNP3) → DNP3 device

**Computer/Server:**
- Port 445 (SMB) + 3389 (RDP) → Windows PC
- Port 22 (SSH) + 80 (HTTP) → Linux server

**Switch/Network Device:**
- Nhiều open ports (>10)
- Thường có nhiều connections

**Gateway:**
- Được phát hiện từ routing table
- Tự động đánh dấu là center node

---

## Công nghệ quét

### 1. **ARP Scan**
```
Gửi ARP requests broadcast
→ Nhận MAC + IP của devices
→ Nhanh nhất, chính xác nhất trong LAN
```

**Ưu điểm:**
- Không cần root/admin (trên Windows)
- Phát hiện cả thiết bị "stealth"
- Lấy được MAC address

### 2. **ICMP Ping Sweep**
```
Gửi ICMP Echo Request tới toàn subnet
→ Phát hiện devices không respond ARP
→ Measure response time
→ Guess OS từ TTL
```

**TTL fingerprinting:**
- TTL ≤ 64 → Linux/Unix
- TTL ≤ 128 → Windows
- TTL > 128 → Network devices

### 3. **Port Scanning**
```
TCP SYN scan các ports phổ biến
→ Phát hiện services
→ Nhận dạng device type
```

**Common ports scanned:**
- 21 (FTP), 22 (SSH), 23 (Telnet)
- 80 (HTTP), 443 (HTTPS)
- 102 (S7comm) - **Siemens PLC**
- 445 (SMB), 502 (Modbus)
- 3389 (RDP), 8080 (HTTP-Alt)
- 20000 (DNP3)

---

## Export Topology

### Các format

**1. JSON Export**
```json
{
  "report_type": "Network Topology",
  "scan_time": "2025-01-31T15:30:00",
  "stats": {
    "total_devices": 15,
    "online_devices": 12,
    "gateway": "192.168.1.1"
  },
  "devices": [
    {
      "ip": "192.168.1.100",
      "mac": "00:1D:9C:C8:BD:F0",
      "hostname": "PLC_Line1",
      "device_type": "PLC",
      "open_ports": [80, 102],
      "services": {"102": "S7comm"},
      "vendor": "Siemens"
    }
  ]
}
```

**2. HTML Export**
- Báo cáo đẹp mắt
- Bảng thiết bị
- Thống kê
- Có thể in hoặc chia sẻ

**3. CSV Export**
- Import vào Excel
- Phân tích dữ liệu
- Tạo báo cáo

---

## Use Cases thực tế

### 1. **Network Audit**
```
Mục đích: Kiểm tra toàn bộ thiết bị trong mạng
Cách làm:
1. Full scan toàn mạng
2. Export to CSV
3. So sánh với inventory
4. Phát hiện unauthorized devices
```

### 2. **PLC Discovery**
```
Mục đích: Tìm tất cả PLC trong hệ thống
Cách làm:
1. Quick scan network
2. Filter nodes màu xanh ngọc (PLC)
3. Click từng PLC để xem details
4. Export danh sách PLC
```

### 3. **Security Assessment**
```
Mục đích: Phát hiện open ports nguy hiểm
Cách làm:
1. Full scan (không quick)
2. Xem device details
3. Check open ports: 23 (Telnet), 21 (FTP)
4. Report unauthorized services
```

### 4. **Network Monitoring**
```
Mục đích: Giám sát realtime
Cách làm:
1. Start Continuous scan
2. Để chạy trong background
3. Topology tự động update
4. Phát hiện devices offline
```

### 5. **Documentation**
```
Mục đích: Tạo tài liệu mạng
Cách làm:
1. Scan toàn mạng
2. Screenshot topology graph
3. Export HTML report
4. Include vào documentation
```

---

## Performance Tips

### Scan nhanh hơn

**1. Sử dụng Quick Scan:**
- Chỉ scan ports ICS/SCADA
- Bỏ qua deep inspection
- Nhanh gấp 3-5 lần

**2. Chỉ định network cụ thể:**
```
Network: 192.168.1.0/24
→ Không auto-detect
→ Scan chính xác subnet cần thiết
```

**3. Giảm timeout (trong code):**
```python
scanner.arp_scan(network, timeout=1)  # Giảm từ 2s → 1s
```

### Scan kỹ hơn

**1. Bỏ Quick Scan:**
- Full port scan
- Chi tiết hơn
- Chậm hơn

**2. Tăng retries:**
```python
scanner.full_scan(network, quick=False)
```

---

## Troubleshooting

### Không phát hiện được devices

**Nguyên nhân & Giải pháp:**

1. **Firewall blocking:**
   - Tắt firewall tạm thời
   - Hoặc add exception cho Python

2. **Không có admin privileges:**
   ```bash
   # Windows: Run as Administrator
   # Linux: sudo python start_webgui.py
   ```

3. **Sai subnet:**
   - Check IP range
   - Nhập network thủ công

4. **Devices có firewall:**
   - Một số thiết bị block ICMP
   - Vẫn có thể detect qua ARP

### Topology graph trống

**Kiểm tra:**
1. Đã scan chưa?
2. Console có lỗi?
3. Refresh trang
4. Check network connectivity

### Continuous scan không update

**Khắc phục:**
1. Stop và start lại
2. Clear browser cache
3. Check browser console (F12)

### Nhận dạng device type sai

**Lý do:**
- Dựa vào open ports → không 100% chính xác
- Có thể custom trong code

**Cải thiện:**
```python
# Trong network_topology.py
def _identify_device_type(self, ports):
    # Thêm logic của bạn
    if 102 in ports and 80 in ports:
        return "Siemens PLC with HMI"
```

---

## API Endpoints

Có thể sử dụng programmatically:

### Start scan
```bash
curl -X POST http://localhost:5000/api/topology/scan \
  -H "Content-Type: application/json" \
  -d '{"network": "192.168.1.0/24", "quick": false}'
```

### Get topology data
```bash
curl http://localhost:5000/api/topology/data
```

### Start continuous
```bash
curl -X POST http://localhost:5000/api/topology/continuous \
  -H "Content-Type: application/json" \
  -d '{"action": "start", "interval": 30}'
```

### Export
```bash
curl -X POST http://localhost:5000/api/topology/export \
  -H "Content-Type: application/json" \
  -d '{"format": "json"}'
```

---

## Security Considerations

⚠️ **Quan trọng:**

1. **Chỉ scan mạng được phép:**
   - Có authorization
   - Mạng nội bộ
   - Hoặc lab/test environment

2. **Port scanning có thể trigger IDS:**
   - Notify security team trước
   - Hoặc whitelist IP của bạn

3. **Network load:**
   - ARP scan: minimal impact
   - Full scan: có thể gây chậm mạng nhỏ
   - Tránh scan trong giờ cao điểm

4. **Thông tin nhạy cảm:**
   - Topology reveals network structure
   - Bảo mật file export
   - Không chia sẻ public

---

## Mở rộng

### Tùy chỉnh ports scan

Edit `s7pwn/network_topology.py`:

```python
def port_scan(self, device, ports=None):
    if ports is None:
        # Add your custom ports here
        ports = [21, 22, 23, 25, 80, 102, 443, 445, 502, 1883, 5000]
```

### Thêm vendor detection

```python
def _identify_vendor(self, mac):
    vendors = {
        "00001D": "Siemens",
        "001122": "Your Custom Vendor",
        # Add more...
    }
```

### Custom device types

```python
def _identify_device_type(self, ports):
    if 1883 in ports:  # MQTT
        return "IoT Device"
    if 5000 in ports:
        return "UPnP Device"
    # Your logic...
```

---

## So sánh với công cụ khác

| Feature | S7Pwn Topology | Nmap | Angry IP | Wireshark |
|---------|---------------|------|----------|-----------|
| **GUI Visualization** | ✅ Real-time graph | ❌ | ❌ | ❌ |
| **Web Interface** | ✅ | ❌ | ❌ | ❌ |
| **PLC Detection** | ✅ Optimized | ⚠️ Manual | ❌ | ⚠️ Passive |
| **Continuous Scan** | ✅ | ❌ | ⚠️ Limited | ✅ |
| **Export** | ✅ JSON/CSV/HTML | ✅ XML | ✅ CSV | ✅ PCAP |
| **Speed** | ⚡ Fast | ⚡ Fast | ⚡⚡ Very Fast | 🐌 Slow |
| **Easy to use** | ✅ | ⚠️ CLI | ✅ | ❌ Complex |

---

## FAQ

**Q: Scan có ảnh hưởng tới PLC không?**
A: Không. Chỉ scan ports, không ghi dữ liệu.

**Q: Tại sao không thấy một số devices?**
A: Có thể do firewall, hoặc device không respond ICMP/ARP.

**Q: Quick scan khác gì Full scan?**
A: Quick chỉ scan ports ICS/SCADA, Full scan tất cả ports phổ biến.

**Q: Có thể scan subnet lớn hơn /24?**
A: Có, nhưng sẽ chậm. Ví dụ /16 = 65k IPs.

**Q: Topology được lưu lại không?**
A: Chỉ trong memory. Export để lưu vĩnh viễn.

**Q: Có thể integrate với SIEM không?**
A: Có, export JSON và parse bằng tools khác.

---

## Kết luận

Network Topology Scanner là công cụ mạnh mẽ để:
- Hiểu rõ cấu trúc mạng
- Phát hiện thiết bị
- Monitoring real-time
- Security assessment

**Best practices:**
1. Luôn có authorization
2. Document findings
3. Regular scans để detect changes
4. Export và backup topology data

Happy scanning! 🔍🗺️
