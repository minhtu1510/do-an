# OT Protocol Scanning

## Tổng quan (Overview)

S7.Pwn hiện đã hỗ trợ **multi-protocol scanning** cho các mạng OT (Operational Technology). Ngoài việc sử dụng Profinet DCP, công cụ có thể quét các thiết bị OT bằng nhiều giao thức công nghiệp khác nhau.

S7.Pwn now supports **multi-protocol scanning** for OT (Operational Technology) networks. Beyond Profinet DCP, the tool can scan OT devices using various industrial protocols.

## Các giao thức được hỗ trợ (Supported Protocols)

### 1. Profinet DCP (Layer 2)
- **Port**: N/A (Layer 2 protocol)
- **EtherType**: 0x8892
- **Vendors**: Siemens, Beckhoff, Wago, Phoenix Contact, Hirschmann, etc.
- **Requirements**: Admin/root privileges
- **Use case**: Phát hiện thiết bị Profinet trong mạng local / Discover Profinet devices on local network

### 2. Modbus TCP (Layer 4)
- **Port**: 502
- **Vendors**: Schneider Electric, ABB, Honeywell, và nhiều hãng khác / and many others
- **Function**: Read Device Identification (Function Code 0x2B/0x0E)
- **Use case**: Quét PLC, RTU, và thiết bị công nghiệp hỗ trợ Modbus / Scan PLCs, RTUs, and Modbus-enabled industrial devices

### 3. EtherNet/IP (Layer 4)
- **Port**: 44818 (UDP)
- **Vendors**: Rockwell Automation (Allen-Bradley), Omron, Schneider Electric
- **Function**: List Identity
- **Use case**: Phát hiện PLC Allen-Bradley ControlLogix, CompactLogix, MicroLogix / Discover Allen-Bradley PLCs

### 4. S7 Protocol (Layer 4)
- **Port**: 102 (TCP)
- **Vendor**: Siemens
- **Function**: COTP Connection + S7 Setup Communication
- **Use case**: Quét trực tiếp PLC Siemens S7 qua giao thức S7 / Direct S7 protocol scan for Siemens PLCs

### 5. BACnet (Layer 4)
- **Port**: 47808 (UDP)
- **Vendors**: Johnson Controls, Honeywell, Siemens, Trane
- **Function**: Who-Is/I-Am broadcast
- **Use case**: Phát hiện thiết bị tự động hóa tòa nhà / Discover building automation devices

### 6. FINS (Layer 4)
- **Port**: 9600 (UDP)
- **Vendor**: Omron
- **Function**: Controller Data Read
- **Use case**: Quét PLC Omron (CJ, CS, NJ series) / Scan Omron PLCs

## Cách sử dụng (Usage)

### Basic Commands

```bash
# Scan Profinet only (legacy mode, chế độ mặc định)
scan

# Show help
scan --help

# Scan network với tất cả protocols
scan 192.168.1.0/24

# Scan với protocols cụ thể
scan 192.168.1.0/24 --protocols modbus,s7,ethernet_ip

# Scan tất cả protocols
scan 192.168.1.0/24 --protocols all
```

### Protocol Selection

Bạn có thể chọn protocols cụ thể để quét:

```bash
# Chỉ Modbus và S7
scan 192.168.1.0/24 --protocols modbus,s7

# Profinet + Modbus + EtherNet/IP
scan 192.168.1.0/24 --protocols profinet,modbus,ethernet_ip

# Tất cả protocols
scan 192.168.1.0/24 --protocols all
```

## Kiến trúc kỹ thuật (Technical Architecture)

### Module Structure

```
s7pwn/
├── commands/
│   └── scan.py              # Scan command interface
├── ext/
│   ├── scan_module.py       # Main scanning orchestrator
│   └── ot_protocol_scanner.py  # Multi-protocol scanner implementation
```

### Protocol Scanner Classes

1. **ModbusTCPScanner**: Implements Modbus TCP device identification
2. **EtherNetIPScanner**: Implements EtherNet/IP List Identity
3. **S7ProtocolScanner**: Implements S7 protocol handshake
4. **BACnetScanner**: Implements BACnet Who-Is/I-Am
5. **FINSScanner**: Implements FINS/UDP frame send
6. **OTProtocolScanner**: Orchestrates multi-protocol scanning with threading

### Scan Flow

```
┌─────────────────────────────────────────┐
│  User Command: scan <network> --protocols │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│     scan_module.scan_network()          │
│  - Parse protocols list                 │
│  - Coordinate Layer 2 & Layer 3/4 scans │
└──────────────┬──────────────────────────┘
               │
       ┌───────┴────────┐
       │                │
       ▼                ▼
┌──────────────┐  ┌──────────────────────┐
│  Profinet    │  │  IP-based Protocols  │
│  DCP Scan    │  │  (Modbus, S7, etc.)  │
│  (Layer 2)   │  │  OTProtocolScanner   │
│              │  │  - ThreadPoolExecutor│
│  Scapy       │  │  - Concurrent scan   │
│  sendp/sniff │  │  - Socket operations │
└──────────────┘  └──────────────────────┘
       │                │
       └───────┬────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  Unified Device List                    │
│  - Protocol identification              │
│  - Device information                   │
│  - Vendor details                       │
└─────────────────────────────────────────┘
```

## Thông tin thiết bị thu thập (Device Information Collected)

### Profinet DCP
- Device name
- IP address
- MAC address
- Vendor (Siemens, Beckhoff, etc.)
- Device model
- Device role (IO-Device, IO-Controller, etc.)
- Device ID
- Type of station

### Modbus TCP
- Vendor name
- Product code
- Product name
- Model name
- Major/Minor revision
- User application name

### EtherNet/IP
- Vendor ID
- Device type
- Product code
- Product name
- Revision
- Serial number

### S7 Protocol
- Device type confirmation
- Connection status

### BACnet
- Object type
- Object instance
- Device ID

### FINS
- Device type (Omron PLC)
- Response status

## Performance Considerations

### Threading
- Multi-threaded scanning với ThreadPoolExecutor
- Default: 20 concurrent workers
- Có thể điều chỉnh trong code: `max_workers` parameter

### Timeouts
- Profinet DCP: 3 seconds (configurable)
- IP protocols: 2 seconds per device (configurable)

### Network Load
- Profinet DCP: Broadcast packets, minimal load
- IP protocols: Direct TCP/UDP to each host
- Large networks: Consider splitting into smaller subnets

## Security Considerations

### Admin Privileges
- **Profinet DCP**: Requires admin/root (raw packet manipulation)
- **IP protocols**: No special privileges required

### Firewall Rules
Các protocols cần firewall rules cho phép:
- Modbus TCP: Port 502/TCP
- EtherNet/IP: Port 44818/UDP
- S7: Port 102/TCP
- BACnet: Port 47808/UDP
- FINS: Port 9600/UDP

### Detection Risk
- Profinet DCP: Broadcast, dễ phát hiện / Broadcast, easily detectable
- IP protocols: Direct connections có thể trigger IDS/IPS / May trigger IDS/IPS
- Recommendation: Chỉ sử dụng trong môi trường được ủy quyền / Only use in authorized environments

## Examples

### Example 1: Comprehensive OT Network Scan

```bash
# Scan toàn bộ subnet với tất cả protocols
scan 192.168.100.0/24 --protocols all
```

**Output:**
```
============================================================
OT NETWORK SCANNER
============================================================
Network: 192.168.100.0/24
Protocols: profinet, modbus, ethernet_ip, s7, bacnet, fins
============================================================

[*] Starting Profinet DCP scan on interface: Ethernet0 (IP: 192.168.100.10)
[*] Sending Profinet DCP packet (attempt 1/2)
[*] Sending Profinet DCP packet (attempt 2/2)
[+] Found 3 Profinet device(s)

[*] Starting IP-based protocol scan on 192.168.100.0/24
[*] Protocols: modbus, ethernet_ip, s7, bacnet, fins
[*] Total hosts to scan: 254
[+] Found Modbus TCP device at 192.168.100.50:502
[+] Found S7 device at 192.168.100.51:102
[+] Found 2 device(s) via IP protocols

============================================================
[+] TOTAL: Found 5 device(s)
============================================================
```

### Example 2: Modbus-only Scan

```bash
# Scan chỉ Modbus devices
scan 10.0.0.0/24 --protocols modbus
```

### Example 3: Siemens-focused Scan

```bash
# Scan Profinet DCP + S7 protocol
scan 192.168.1.0/24 --protocols profinet,s7
```

## Troubleshooting

### Issue: "Admin privileges required"
**Solution**: Chạy tool với quyền administrator/root (cho Profinet DCP)

### Issue: No devices found
**Possible causes:**
1. Sai network range
2. Firewall blocking
3. Devices không online
4. Protocols không được thiết bị hỗ trợ

**Debug steps:**
```bash
# Check connectivity
ping <target_ip>

# Check port accessibility
nmap -p 502 <target_ip>  # Modbus
nmap -p 102 <target_ip>  # S7

# Check logs
tail -f s7pwn.log
```

### Issue: Slow scanning
**Solution**:
- Reduce network range
- Adjust timeout in code
- Use specific protocols instead of "all"

## Future Enhancements

Planned protocol support:
- [ ] DNP3 (port 20000) - SCADA protocol
- [ ] IEC 60870-5-104 - Power grid automation
- [ ] OPC UA (port 4840) - Modern industrial protocol
- [ ] PROFIBUS - Fieldbus protocol
- [ ] CC-Link IE - Mitsubishi protocol

## References

### Protocol Specifications
- Profinet: IEC 61158, IEC 61784
- Modbus: www.modbus.org
- EtherNet/IP: ODVA specification
- S7: Siemens proprietary
- BACnet: ASHRAE 135
- FINS: Omron specification

### Related Tools
- nmap with NSE scripts
- plcscan
- ISF (Industrial Security Framework)
- s7-enumerate

## License & Disclaimer

This tool is for authorized security testing and research only. Users are responsible for compliance with applicable laws and regulations.

---

**Tác giả**: S7.Pwn Development Team
**Version**: 2.0
**Last Updated**: 2025-11-06
