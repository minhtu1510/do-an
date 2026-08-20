"""
Network Topology Scanner and Mapper
Discovers network topology and visualizes in real-time
"""
from __future__ import annotations
import socket
import struct
import threading
import time
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, TCP, sr
from datetime import datetime


class NetworkDevice:
    """Represents a network device"""

    def __init__(self, ip: str, mac: str = ""):
        self.ip = ip
        self.mac = mac
        self.hostname = ""
        self.vendor = ""
        self.device_type = "Unknown"
        self.open_ports: List[int] = []
        self.services: Dict[int, str] = {}
        self.last_seen = datetime.now()
        self.response_time = 0.0  # ms
        self.is_gateway = False
        self.is_online = True
        self.connected_to: List[str] = []  # IPs of connected devices
        self.ttl = 0
        self.os_guess = ""

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "open_ports": self.open_ports,
            "services": self.services,
            "last_seen": self.last_seen.isoformat(),
            "response_time": self.response_time,
            "is_gateway": self.is_gateway,
            "is_online": self.is_online,
            "connected_to": self.connected_to,
            "ttl": self.ttl,
            "os_guess": self.os_guess,
        }


class NetworkTopology:
    """Network topology manager"""

    def __init__(self):
        self.devices: Dict[str, NetworkDevice] = {}
        self.connections: List[Tuple[str, str]] = []  # (ip1, ip2) pairs
        self.gateway_ip: Optional[str] = None
        self.local_ip: Optional[str] = None
        self.subnet: Optional[str] = None
        self.scan_in_progress = False
        self.last_scan_time: Optional[datetime] = None

    def add_device(self, device: NetworkDevice):
        """Add or update device"""
        self.devices[device.ip] = device

    def add_connection(self, ip1: str, ip2: str):
        """Add connection between devices"""
        conn = tuple(sorted([ip1, ip2]))
        if conn not in self.connections:
            self.connections.append(conn)

    def get_topology_data(self) -> Dict:
        """Get topology data for visualization"""
        nodes = []
        edges = []

        for ip, device in self.devices.items():
            node = {
                "id": ip,
                "label": f"{device.hostname or ip}\n{device.device_type}",
                "title": f"IP: {ip}\nMAC: {device.mac}\nVendor: {device.vendor}\nPorts: {len(device.open_ports)}",
                "group": device.device_type,
                "value": len(device.open_ports) + 1,
                "online": device.is_online,
                "response_time": device.response_time,
            }

            # Set node color/shape based on type
            if device.is_gateway:
                node["shape"] = "star"
                node["color"] = "#FF6B6B"
            elif device.device_type == "PLC":
                node["shape"] = "box"
                node["color"] = "#4ECDC4"
            elif device.device_type == "Switch":
                node["shape"] = "diamond"
                node["color"] = "#95E1D3"
            elif device.device_type == "Computer":
                node["shape"] = "dot"
                node["color"] = "#A8E6CF"
            else:
                node["shape"] = "dot"
                node["color"] = "#CCCCCC"

            if not device.is_online:
                node["color"] = "#AAAAAA"

            nodes.append(node)

        # Add connections
        for ip1, ip2 in self.connections:
            edges.append({
                "from": ip1,
                "to": ip2,
                "width": 2,
            })

        # If no explicit connections, connect everything through gateway
        if not edges and self.gateway_ip:
            for ip in self.devices.keys():
                if ip != self.gateway_ip:
                    edges.append({
                        "from": self.gateway_ip,
                        "to": ip,
                        "width": 1,
                        "dashes": True,
                    })

        return {
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "total_devices": len(self.devices),
                "online_devices": sum(1 for d in self.devices.values() if d.is_online),
                "gateway": self.gateway_ip,
                "local_ip": self.local_ip,
                "subnet": self.subnet,
                "last_scan": self.last_scan_time.isoformat() if self.last_scan_time else None,
            }
        }


class NetworkScanner:
    """Advanced network scanner for topology discovery"""

    def __init__(self):
        self.topology = NetworkTopology()
        self._stop_scan = False

    def get_local_ip_and_subnet(self) -> Tuple[str, str]:
        """Get local IP and subnet"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()

            # Simple subnet detection (assumes /24)
            parts = local_ip.split('.')
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

            return local_ip, subnet
        except:
            return "192.168.1.100", "192.168.1.0/24"

    def get_default_gateway(self) -> Optional[str]:
        """Get default gateway IP"""
        try:
            import platform
            if platform.system() == "Windows":
                import subprocess
                result = subprocess.check_output("ipconfig", shell=True).decode()
                for line in result.split('\n'):
                    if 'Default Gateway' in line or 'Cổng mặc định' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            gateway = parts[1].strip()
                            if gateway and gateway != '':
                                return gateway
            else:
                # Linux/Mac
                with open("/proc/net/route") as f:
                    for line in f:
                        fields = line.strip().split()
                        if fields[1] == '00000000':
                            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
        except:
            pass
        return None

    def arp_scan(self, network: str, timeout: int = 2) -> List[NetworkDevice]:
        """Perform ARP scan to discover devices"""
        devices = []

        try:
            # Create ARP request
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            # Send and receive
            result = srp(packet, timeout=timeout, verbose=False)[0]

            for sent, received in result:
                device = NetworkDevice(ip=received.psrc, mac=received.hwsrc)
                device.last_seen = datetime.now()

                # Try to get hostname
                try:
                    device.hostname = socket.gethostbyaddr(device.ip)[0]
                except:
                    pass

                # Try to identify vendor from MAC
                device.vendor = self._identify_vendor(device.mac)

                devices.append(device)

        except Exception as e:
            print(f"ARP scan error: {e}")

        return devices

    def ping_sweep(self, network: str, timeout: int = 1) -> List[NetworkDevice]:
        """Perform ICMP ping sweep"""
        devices = []

        # Parse network range
        base = network.split('/')[0]
        parts = base.split('.')
        base_ip = '.'.join(parts[:3])

        for i in range(1, 255):
            if self._stop_scan:
                break

            ip = f"{base_ip}.{i}"

            try:
                start_time = time.time()
                pkt = IP(dst=ip) / ICMP()
                reply = sr1(pkt, timeout=timeout, verbose=False)

                if reply:
                    response_time = (time.time() - start_time) * 1000

                    device = NetworkDevice(ip=ip)
                    device.response_time = response_time
                    device.ttl = reply.ttl

                    # Guess OS from TTL
                    if reply.ttl <= 64:
                        device.os_guess = "Linux/Unix"
                    elif reply.ttl <= 128:
                        device.os_guess = "Windows"
                    else:
                        device.os_guess = "Network Device"

                    try:
                        device.hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        pass

                    devices.append(device)

            except:
                continue

        return devices

    def port_scan(self, device: NetworkDevice, ports: List[int] = None):
        """Scan common ports on device"""
        if ports is None:
            # Common ports
            ports = [21, 22, 23, 25, 80, 102, 443, 445, 502, 3389, 8080, 20000]

        open_ports = []
        services = {}

        for port in ports:
            if self._stop_scan:
                break

            try:
                pkt = IP(dst=device.ip) / TCP(dport=port, flags="S")
                reply = sr1(pkt, timeout=0.5, verbose=False)

                if reply and reply.haslayer(TCP):
                    if reply[TCP].flags == 0x12:  # SYN-ACK
                        open_ports.append(port)
                        services[port] = self._identify_service(port)

                        # Send RST to close
                        rst = IP(dst=device.ip) / TCP(dport=port, flags="R")
                        sr1(rst, timeout=0.1, verbose=False)

            except:
                continue

        device.open_ports = sorted(open_ports)
        device.services = services

        # Identify device type from open ports
        device.device_type = self._identify_device_type(open_ports)

    def _identify_vendor(self, mac: str) -> str:
        """Identify vendor from MAC address"""
        mac_prefix = mac.upper()[:8].replace(':', '')

        vendors = {
            "000000": "Xerox",
            "00001D": "Siemens",
            "000578": "Siemens",
            "001109": "Cisco",
            "0050C2": "Siemens",
            "00AE8C": "Siemens",
            "001C06": "Siemens",
            "00E04C": "Realtek",
            "080027": "Oracle VirtualBox",
            "525400": "QEMU/KVM",
        }

        for prefix, vendor in vendors.items():
            if mac_prefix.startswith(prefix):
                return vendor

        return "Unknown"

    def _identify_service(self, port: int) -> str:
        """Identify service from port"""
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            80: "HTTP",
            102: "S7comm",
            443: "HTTPS",
            445: "SMB",
            502: "Modbus",
            3389: "RDP",
            8080: "HTTP-Alt",
            20000: "DNP3",
        }
        return services.get(port, f"Port {port}")

    def _identify_device_type(self, ports: List[int]) -> str:
        """Identify device type from open ports"""
        if 102 in ports:
            return "PLC"
        elif 502 in ports or 20000 in ports:
            return "ICS Device"
        elif 80 in ports or 443 in ports or 8080 in ports:
            if 22 in ports:
                return "Server"
            return "Web Device"
        elif 445 in ports or 3389 in ports:
            return "Computer"
        elif len(ports) > 10:
            return "Switch"
        elif len(ports) > 0:
            return "Network Device"
        else:
            return "Unknown"

    def full_scan(self, network: str = None, quick: bool = False) -> NetworkTopology:
        """Perform full network scan and build topology"""
        self._stop_scan = False
        self.topology.scan_in_progress = True

        if not network:
            local_ip, network = self.get_local_ip_and_subnet()
            self.topology.local_ip = local_ip
            self.topology.subnet = network

        print(f"Scanning network: {network}")

        # Get gateway
        gateway_ip = self.get_default_gateway()
        if gateway_ip:
            self.topology.gateway_ip = gateway_ip

        # Step 1: ARP scan (fastest)
        print("Step 1: ARP scan...")
        devices = self.arp_scan(network)

        # Step 2: ICMP ping sweep (find more devices)
        if not quick:
            print("Step 2: ICMP ping sweep...")
            ping_devices = self.ping_sweep(network)

            # Merge results
            device_ips = {d.ip for d in devices}
            for pd in ping_devices:
                if pd.ip not in device_ips:
                    devices.append(pd)

        # Step 3: Port scanning
        print(f"Step 3: Scanning {len(devices)} devices...")
        for i, device in enumerate(devices):
            if self._stop_scan:
                break

            print(f"  Scanning {device.ip} ({i+1}/{len(devices)})...")

            if quick:
                # Quick scan: only common industrial ports
                self.port_scan(device, ports=[80, 102, 443, 502, 20000])
            else:
                # Full scan
                self.port_scan(device)

            # Mark gateway
            if gateway_ip and device.ip == gateway_ip:
                device.is_gateway = True
                device.device_type = "Gateway"

            # Add to topology
            self.topology.add_device(device)

            # Assume gateway connects to all devices
            if gateway_ip:
                self.topology.add_connection(gateway_ip, device.ip)

        self.topology.scan_in_progress = False
        self.topology.last_scan_time = datetime.now()

        print(f"Scan complete. Found {len(devices)} devices.")

        return self.topology

    def continuous_scan(self, network: str = None, interval: int = 30):
        """Continuously scan network and update topology"""

        def scan_loop():
            while not self._stop_scan:
                self.full_scan(network, quick=True)
                time.sleep(interval)

        thread = threading.Thread(target=scan_loop, daemon=True)
        thread.start()

    def stop_scan(self):
        """Stop scanning"""
        self._stop_scan = True


# Global scanner instance
_scanner = NetworkScanner()


def get_scanner() -> NetworkScanner:
    """Get global scanner instance"""
    return _scanner
