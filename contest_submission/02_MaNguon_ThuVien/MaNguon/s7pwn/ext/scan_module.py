from __future__ import annotations
import logging
import ctypes
import json
import os
import sys
from typing import List, Optional, Tuple, Dict

# WMI is Windows-only, make it optional
try:
    import wmi
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False
    wmi = None

import snap7
from scapy.all import Ether, Raw, sendp, sniff
from s7pwn.ext.ot_protocol_scanner import OTProtocolScanner

logging.basicConfig(filename='s7pwn.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

PLC_FAMILIES = {"S7-1500","S7-1200","S7-300","S7-400"}

# Load device mapping from JSON file
# Handle both frozen (PyInstaller) and unfrozen execution
if getattr(sys, 'frozen', False):
    # Running as compiled executable - files are in sys._MEIPASS
    DEVICE_MAP_FILE = os.path.join(sys._MEIPASS, 's7pwn', 'device_map', 'device_map.json')
else:
    # Running as script - use relative path from this file
    DEVICE_MAP_FILE = os.path.join(os.path.dirname(__file__), '..', 'device_map', 'device_map.json')

with open(DEVICE_MAP_FILE, 'r') as f:
    DEVICE_MAP = json.load(f)

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def hex_to_ip(hexstr: str) -> str:
    try:
        return ".".join(str(int(hexstr[i:i+2], 16)) for i in range(0, 8, 2))
    except Exception:
        return "Unknown"

def get_interfaces() -> List[Tuple[str, str, str]]:
    """
    Get list of network interfaces using Scapy (cross-platform, PyInstaller-compatible)

    Returns:
        List of tuples (name, ip, mac) for each interface
    """
    try:
        from scapy.all import get_working_ifaces, get_if_addr, get_if_hwaddr

        interfaces = []
        working_ifaces = get_working_ifaces()

        for iface in working_ifaces:
            try:
                # Get interface name
                name = iface.name if hasattr(iface, 'name') else str(iface)

                # Get IP address
                ip = iface.ip if hasattr(iface, 'ip') else get_if_addr(name)

                # Skip loopback and interfaces without IP
                if not ip or ip == '0.0.0.0' or ip.startswith('127.'):
                    continue

                # Get MAC address
                try:
                    mac = iface.mac if hasattr(iface, 'mac') else get_if_hwaddr(name)
                    if mac:
                        mac = mac.lower()
                except:
                    mac = '00:00:00:00:00:00'

                # Use description if available, otherwise use name
                description = iface.description if hasattr(iface, 'description') else name

                interfaces.append((description, ip, mac))
            except Exception as e:
                logging.debug(f"Skipping interface {iface}: {e}")
                continue

        return interfaces
    except Exception as e:
        logging.error(f"Failed to get interfaces: {e}")
        return []

def choose_interface(auto_select: bool = False) -> Optional[Tuple[str, str, str]]:
    """
    Choose network interface

    Args:
        auto_select: If True, automatically select first interface without prompting
    """
    interfaces = get_interfaces()
    if not interfaces:
        print("[!] No suitable network interface found")
        return None

    # Auto-select first interface (for web/non-interactive use)
    if auto_select:
        selected = interfaces[0]
        print(f"[*] Auto-selected interface: {selected[0]} (IP: {selected[1]})")
        return selected

    # Interactive selection (for CLI use)
    print("[+] Available network interfaces:")
    for i, (name, ip, _) in enumerate(interfaces, 1):
        print(f"  [{i}] {name} (IP: {ip})")
    while True:
        try:
            idx = int(input(f"Select interface number [1-{len(interfaces)}]: ")) - 1
            if 0 <= idx < len(interfaces):
                return interfaces[idx]
            print("[!] Invalid selection")
        except ValueError:
            print("[!] Please enter a valid number")
        except (KeyboardInterrupt, EOFError):
            # Handle non-interactive environments
            print("\n[*] Non-interactive mode detected, auto-selecting first interface")
            return interfaces[0]

def create_profinet_discovery_packet(src_mac: str, dst_mac: str = "01:0e:cf:00:00:00"):
    payload = bytes.fromhex(
        "fe fe 05 00 04 00 00 03 00 80 00 04 ff ff 00 00"
        + "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        + "00 00 00 00"
    )
    return Ether(dst=dst_mac, src=src_mac, type=0x8892) / Raw(load=payload)

def identify_device(device_id: str) -> str:
    dev = device_id.lower()
    if dev in ("010e","0204"): return "S7-1500"
    if dev in ("010d","0205"): return "S7-1200"
    if dev in ("0101","0203","0207"): return "S7-300"
    if dev in ("0102","0201","0208"): return "S7-400"
    return DEVICE_MAP.get(dev, "Unknown")

def get_rack_slot(device_model: str) -> Tuple[int, int]:
    return {"S7-1500": (0,1), "S7-1200": (0,1), "S7-300": (0,2), "S7-400": (0,2)}.get(device_model, (0,1))

def parse_response(pkt) -> Optional[dict]:
    try:
        if not pkt.haslayer(Raw): return None
        data = bytes(pkt[Raw].load).hex()
        mac = pkt[Ether].src
        name = "Unknown"; ip = "Unknown"; vendor_id = "Unknown"; device_id = "Unknown"; device_role = "Unknown"; type_station = "Unknown"

        if "0202" in data:
            idx = data.find("0202")
            length = int(data[idx+4:idx+8], 16)
            name_hex = data[idx+8:idx+8+length*2]
            try: name = bytearray.fromhex(name_hex).decode(errors='ignore')
            except Exception: pass

        if "0102" in data:
            idx = data.find("0102")
            ip_hex = data[idx+12:idx+20]
            ip = hex_to_ip(ip_hex)

        if "0203" in data:
            idx = data.find("0203")
            vendor_id = data[idx+12:idx+16].lower()
            device_id = data[idx+16:idx+20].lower()

        if "0204" in data:
            idx = data.find("0204")
            role_hex = data[idx+12:idx+14]
            roles = {"01":"IO-Device","02":"IO-Controller","04":"IO-Multidevice","08":"PN-Supervisor"}
            device_role = roles.get(role_hex, "Unknown")

        if "0201" in data:
            idx = data.find("0201")
            length = int(data[idx+4:idx+8], 16)
            type_station_hex = data[idx+8:idx+8+length*2]
            try: type_station = bytearray.fromhex(type_station_hex).decode(errors='ignore')
            except Exception: pass

        vendors = {"002a": "Siemens","000a":"Wago","001c":"Beckhoff","0060":"Phoenix Contact","00a0":"Hirschmann"}
        vendor_name = vendors.get(vendor_id, "Unknown")
        device_model = identify_device(device_id)
        return {"name": name,"ip": ip,"mac": mac,"vendor": vendor_name,"device_model": device_model,
                "role": device_role,"device_id": device_id,"type_station": type_station}
    except Exception as e:
        try: raw_hex = bytes(pkt[Raw].load).hex()
        except Exception: raw_hex = "<no raw>"
        logging.error(f"parse_response error: {e} raw={raw_hex}")
        return None

def get_plc_info(ip: str, device_model: str) -> dict:
    try:
        client = snap7.client.Client()
        rack, slot = get_rack_slot(device_model)
        print(f"[*] Connecting to PLC at {ip} (Rack: {rack}, Slot: {slot})")
        client.connect(ip, rack, slot)
        cpu_info = client.get_cpu_info()
        cpu_state = client.get_cpu_state()
        client.disconnect()

        def _s(x): 
            try:
                return x.decode('utf-8', errors='replace') if isinstance(x, (bytes, bytearray)) else str(x)
            except Exception:
                return str(x)

        return {
            "ModuleTypeName": _s(cpu_info.ModuleTypeName),
            "SerialNumber":    _s(cpu_info.SerialNumber),
            "ASName":          _s(cpu_info.ASName),
            "Copyright":       _s(cpu_info.Copyright),
            "ModuleName":      _s(cpu_info.ModuleName),
            "CPUState":        _s(cpu_state)
        }
    except Exception as e:
        return {"Error": str(e)}

def scan_network(timeout: int = 3, retries: int = 2, protocols: List[str] = None, network_cidr: str = None, auto_select_interface: bool = False, interface_name: str = None, progress_callback=None) -> List[dict]:
    """
    Scan network for OT devices using multiple protocols

    Args:
        timeout: Timeout for Profinet DCP scan
        retries: Number of retries for Profinet DCP scan
        protocols: List of protocols to scan. Options: 'profinet', 'modbus', 'ethernet_ip', 's7', 'bacnet', 'fins'
                   If None, scans Profinet DCP only (legacy behavior)
        network_cidr: Network range in CIDR notation (e.g., "192.168.1.0/24") for IP-based protocols
        auto_select_interface: If True, auto-select first interface (for web/non-interactive use)
        interface_name: Specific interface name to use (overrides auto_select)
        progress_callback: Optional callback function(message: str) for progress updates

    Returns:
        List of discovered devices
    """
    def emit_progress(message: str):
        """Emit progress message to console and callback"""
        print(message)
        if progress_callback:
            progress_callback(message)
    # Default to Profinet only for backward compatibility
    if protocols is None:
        protocols = ['profinet']

    if 'profinet' in protocols and not is_admin():
        print("[!] Admin privileges required for Profinet DCP. Skipping Profinet scan.")
        protocols = [p for p in protocols if p != 'profinet']
        if not protocols:
            return []

    all_devices: List[dict] = []

    # === PROFINET DCP SCAN (Layer 2) ===
    if 'profinet' in protocols:
        # If specific interface name provided, find it
        if interface_name:
            interfaces = get_interfaces()
            itf = None
            for iface in interfaces:
                if iface[0] == interface_name:  # Match by name
                    itf = iface
                    emit_progress(f"[*] Using selected interface: {iface[0]} (IP: {iface[1]})")
                    break
            if not itf:
                emit_progress(f"[!] Interface '{interface_name}' not found, auto-selecting...")
                itf = choose_interface(auto_select=True)
        else:
            # Use original behavior
            itf = choose_interface(auto_select=auto_select_interface)
        if not itf:
            if len(protocols) == 1:
                return []
        else:
            iface_name, ip_addr, mac_addr = itf
            emit_progress(f"\n[*] Starting Profinet DCP scan on interface: {iface_name} (IP: {ip_addr})")

            profinet_devices: List[dict] = []
            for i in range(retries):
                emit_progress(f"[*] Sending Profinet DCP packet (attempt {i+1}/{retries})")
                pkt = create_profinet_discovery_packet(mac_addr)
                sendp(pkt, iface=iface_name, verbose=0)
                def filt(p): return p.haslayer(Ether) and getattr(p, "type", 0) == 0x8892 and p.haslayer(Raw)
                responses = sniff(iface=iface_name, timeout=timeout, lfilter=filt)
                for p in responses:
                    info = parse_response(p)
                    if not info or info['ip'] == "Unknown":
                        continue
                    rec = dict(info)
                    rec['protocol'] = 'Profinet DCP'
                    rec['plc_info'] = None
                    if rec['vendor'] == "Siemens" and rec['device_model'] in PLC_FAMILIES:
                        rec['plc_info'] = get_plc_info(rec['ip'], rec['device_model'])
                    if not any(d['ip']==rec['ip'] and d['mac'].lower()==rec['mac'].lower() for d in profinet_devices):
                        profinet_devices.append(rec)

            if profinet_devices:
                emit_progress(f"[+] Found {len(profinet_devices)} Profinet device(s)")
                all_devices.extend(profinet_devices)
            else:
                emit_progress("[!] No Profinet devices found")

    # === IP-BASED PROTOCOL SCANS (Layer 3/4) ===
    ip_protocols = [p for p in protocols if p in ['modbus', 'ethernet_ip', 's7', 'bacnet', 'fins']]

    if ip_protocols:
        if not network_cidr:
            emit_progress("\n[!] Network CIDR required for IP-based protocol scanning (e.g., 192.168.1.0/24)")
            emit_progress(f"[!] Skipping protocols: {', '.join(ip_protocols)}")
        else:
            emit_progress(f"\n[*] Starting IP-based protocol scan on {network_cidr}")
            emit_progress(f"[*] Protocols: {', '.join(ip_protocols)}")

            ot_devices = OTProtocolScanner.scan_network(
                network_cidr,
                ip_protocols,
                max_workers=20,
                progress_callback=progress_callback
            )

            if ot_devices:
                emit_progress(f"[+] Found {len(ot_devices)} device(s) via IP protocols")

                # Convert OT scanner format to our format
                for ot_dev in ot_devices:
                    rec = {
                        'ip': ot_dev['ip'],
                        'mac': 'Unknown',  # IP-based protocols don't provide MAC
                        'vendor': ot_dev['info'].get('VendorName', 'Unknown'),
                        'device_model': ot_dev['info'].get('ProductName', ot_dev['info'].get('DeviceType', 'Unknown')),
                        'protocol': ot_dev['protocol'],
                        'port': ot_dev['port'],
                        'name': ot_dev['info'].get('ProductName', 'Unknown'),
                        'role': 'Unknown',
                        'device_id': ot_dev['info'].get('DeviceID', 'Unknown'),
                        'type_station': ot_dev['info'].get('ProductName', 'Unknown'),
                        'ot_info': ot_dev['info']
                    }
                    all_devices.append(rec)
            else:
                emit_progress("[!] No devices found via IP protocols")

    # === DISPLAY RESULTS ===
    if not all_devices:
        print("\n[!] No devices found")
        return []

    print(f"\n{'='*60}")
    print(f"[+] TOTAL: Found {len(all_devices)} device(s)")
    print(f"{'='*60}")

    for i, d in enumerate(all_devices, 1):
        protocol = d.get('protocol', 'Unknown')
        vendor = d.get('vendor', 'Unknown')
        model = d.get('device_model', 'Unknown')

        # Determine device kind
        if vendor == "Siemens" and model in PLC_FAMILIES:
            kind = "[+] Siemens PLC"
        elif protocol in ['Modbus TCP', 'S7', 'EtherNet/IP', 'FINS']:
            kind = "[+] Industrial Controller"
        elif protocol == 'BACnet':
            kind = "[+] Building Automation Device"
        elif protocol == 'Profinet DCP':
            kind = "[+] Profinet Device"
        else:
            kind = "[+] OT Device"

        print(f"\n{kind} {i}:")
        print(f"    Protocol: {protocol}")
        print(f"    Name: {d.get('name', 'Unknown')}")
        print(f"    IP: {d['ip']}")
        print(f"    MAC: {d.get('mac', 'N/A')}")
        print(f"    Vendor: {vendor}")
        print(f"    Model: {model}")

        if protocol == 'Profinet DCP':
            print(f"    Role: {d.get('role', 'Unknown')}")
            print(f"    Device ID: {d.get('device_id', 'Unknown')}")
            print(f"    Type of Station: {d.get('type_station', 'Unknown')}")

            if d.get('plc_info'):
                info = d['plc_info']
                if "Error" in info:
                    print(f"    S7 Connection Error: {info['Error']}")
                else:
                    print(f"    Module Type: {info.get('ModuleTypeName', 'N/A')}")
                    print(f"    Serial Number: {info.get('SerialNumber', 'N/A')}")
                    print(f"    AS Name: {info.get('ASName', 'N/A')}")
                    print(f"    CPU State: {info.get('CPUState', 'N/A')}")
        else:
            # Display OT protocol specific info
            if 'ot_info' in d:
                for key, value in d['ot_info'].items():
                    if key not in ['VendorName', 'ProductName', 'DeviceType']:
                        print(f"    {key}: {value}")
            if 'port' in d:
                print(f"    Port: {d['port']}")

        print("    " + "-"*56)

    # Count PLCs
    plc_count = sum(1 for d in all_devices
                   if d.get('vendor') == "Siemens" and d.get('device_model') in PLC_FAMILIES)

    if plc_count > 0:
        print(f"\n[+] Siemens PLCs (1500/1200/300/400): {plc_count}")
        print("[*] Type 'list' to show PLC list, 'select <n>' to set current target.")

    return all_devices
