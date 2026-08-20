"""
Network Scanner - nmap-like network discovery and port scanning
Supports ARP scan, ping sweep, port scanning, and service detection
"""
from __future__ import annotations
import socket
import struct
import threading
import time
import logging
import sys
from functools import partial
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, TCP, sr, conf

# Suppress Scapy warnings and verbose output
conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)

# Force flush on all prints (fixes buffering in background threads)
print = partial(print, flush=True)

# Suppress Scapy thread exceptions on Windows (OSError: Bad file descriptor)
# This is a known Scapy issue on Windows and can be safely ignored
def _suppress_scapy_thread_exceptions(args):
    """Custom thread exception handler to suppress Scapy's known Windows issues"""
    exc_type, exc_value, exc_traceback, thread = args.exc_type, args.exc_value, args.exc_traceback, args.thread
    # Suppress OSError from Scapy threads (bad file descriptor on Windows)
    if exc_type == OSError and "Bad file descriptor" in str(exc_value):
        return  # Silently ignore this known issue
    # For other exceptions, use default handler
    sys.__excepthook__(exc_type, exc_value, exc_traceback)

threading.excepthook = _suppress_scapy_thread_exceptions


@dataclass
class NetworkDevice:
    """Represents a discovered network device"""
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    device_type: str = "Unknown"
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    last_seen: datetime = field(default_factory=datetime.now)
    response_time: float = 0.0  # milliseconds
    is_gateway: bool = False
    is_online: bool = True
    ttl: int = 0
    os_guess: str = ""

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
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
            "ttl": self.ttl,
            "os_guess": self.os_guess,
        }


@dataclass
class ScanResult:
    """Result of a network scan"""
    devices: List[NetworkDevice] = field(default_factory=list)
    scan_type: str = "full"
    network: str = ""
    scan_time: datetime = field(default_factory=datetime.now)
    duration: float = 0.0  # seconds
    gateway_ip: Optional[str] = None
    local_ip: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "devices": [d.to_dict() for d in self.devices],
            "scan_type": self.scan_type,
            "network": self.network,
            "scan_time": self.scan_time.isoformat(),
            "duration": self.duration,
            "gateway_ip": self.gateway_ip,
            "local_ip": self.local_ip,
            "total_devices": len(self.devices),
            "online_devices": sum(1 for d in self.devices if d.is_online),
        }


class NetworkScanner:
    """
    Network scanner for device discovery and port scanning
    Provides nmap-like functionality for network reconnaissance
    """

    # Common ports to scan
    QUICK_PORTS = [80, 102, 443, 502, 20000]  # Industrial protocols
    COMMON_PORTS = [21, 22, 23, 25, 80, 102, 443, 445, 502, 3389, 8080, 20000]
    FULL_PORTS = list(range(1, 1024))  # Well-known ports

    def __init__(self):
        self._stop_scan = False
        self._scan_lock = threading.Lock()
        self._last_scan_result: Optional[ScanResult] = None  # Store last scan result
        self._progress_callback = None  # Callback for real-time progress updates

    def set_progress_callback(self, callback):
        """Set callback function for real-time progress updates"""
        self._progress_callback = callback

    def _emit_progress(self, event: str, data: Dict):
        """Emit progress event"""
        if self._progress_callback:
            try:
                self._progress_callback(event, data)
            except Exception as e:
                print(f"Failed to emit progress: {e}")

    def get_local_ip_and_subnet(self) -> Tuple[str, str]:
        """Get local IP address and subnet"""
        try:
            # Connect to public DNS to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]

            # Assume /24 subnet
            parts = local_ip.split('.')
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

            return local_ip, subnet
        except Exception as e:
            # Fallback
            return "192.168.1.100", "192.168.1.0/24"

    def get_default_gateway(self) -> Optional[str]:
        """Get default gateway IP address"""
        try:
            import platform
            if platform.system() == "Windows":
                import subprocess
                result = subprocess.check_output("ipconfig", shell=True).decode()
                for line in result.split('\n'):
                    # Support both English and Vietnamese Windows
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
                        if fields[1] == '00000000':  # Default route
                            gateway_hex = int(fields[2], 16)
                            return socket.inet_ntoa(struct.pack("<L", gateway_hex))
        except Exception:
            pass
        return None

    def parse_target_specification(self, target: str) -> List[str]:
        """
        Parse target specification into list of IPs

        Supports multiple formats:
        - CIDR: 192.168.1.0/24
        - IP range: 192.168.1.10-20
        - IP range with dash: 192.168.1.10-192.168.1.20
        - Multiple IPs: 192.168.1.10,192.168.1.20,192.168.1.30
        - Single IP: 192.168.1.10

        Args:
            target: Target specification string

        Returns:
            List of IP addresses
        """
        ips = []

        # Handle multiple comma-separated targets
        if ',' in target:
            for part in target.split(','):
                ips.extend(self.parse_target_specification(part.strip()))
            return ips

        # Handle CIDR notation (192.168.1.0/24)
        if '/' in target:
            import ipaddress
            try:
                network = ipaddress.ip_network(target, strict=False)
                return [str(ip) for ip in network.hosts()]
            except Exception as e:
                print(f"Invalid CIDR notation: {target} - {e}")
                return []

        # Handle IP range (192.168.1.10-20 or 192.168.1.10-192.168.1.20)
        if '-' in target:
            try:
                parts = target.split('-')
                start_ip = parts[0].strip()
                end_part = parts[1].strip()

                # Check if end_part is a full IP or just the last octet
                if '.' in end_part:
                    # Full IP: 192.168.1.10-192.168.1.20
                    end_ip = end_part
                else:
                    # Last octet only: 192.168.1.10-20
                    start_octets = start_ip.split('.')
                    end_ip = '.'.join(start_octets[:3]) + '.' + end_part

                # Parse start and end IPs
                start_octets = [int(x) for x in start_ip.split('.')]
                end_octets = [int(x) for x in end_ip.split('.')]

                # Generate IP range
                if start_octets[:3] != end_octets[:3]:
                    print(f"Warning: IP range spans multiple subnets, only last octet supported")
                    return []

                start_last = start_octets[3]
                end_last = end_octets[3]

                base = '.'.join([str(x) for x in start_octets[:3]])
                for i in range(start_last, end_last + 1):
                    ips.append(f"{base}.{i}")

                return ips
            except Exception as e:
                print(f"Invalid IP range: {target} - {e}")
                return []

        # Single IP
        try:
            # Validate IP
            socket.inet_aton(target)
            return [target]
        except Exception as e:
            print(f"Invalid IP address: {target} - {e}")
            return []

    def scan_targets(self, targets: str, scan_type: str = "quick",
                    scan_ports: bool = True) -> ScanResult:
        """
        Scan multiple targets (supports various formats)

        Args:
            targets: Target specification (CIDR, range, or comma-separated IPs)
            scan_type: "quick" | "normal" | "full"
            scan_ports: Whether to scan ports

        Returns:
            ScanResult with discovered devices
        """
        print(f"[SCAN_TARGETS] Function called with targets='{targets}', scan_type='{scan_type}', scan_ports={scan_ports}")

        try:
            start_time = time.time()
            self._stop_scan = False

            with self._scan_lock:
                # Parse target specification
                print(f"[SCAN_TARGETS] Calling parse_target_specification('{targets}')...")
                ip_list = self.parse_target_specification(targets)
                print(f"[SCAN_TARGETS] Parsed {len(ip_list)} IPs: {ip_list}")

                if not ip_list:
                    print(f"[!] No valid IPs found in target: {targets}")
                    return ScanResult(
                        devices=[],
                        scan_type=scan_type,
                        network=targets,
                        scan_time=datetime.now(),
                        duration=0.0
                    )

            print(f"[*] Scanning {len(ip_list)} IP(s): {targets}")
            self._emit_progress('scan_started', {
                'network': targets,
                'scan_type': scan_type,
                'total_ips': len(ip_list)
            })

            gateway_ip = self.get_default_gateway()
            local_ip, local_subnet = self.get_local_ip_and_subnet()

            # Debug logging
            print(f"[DEBUG] Local IP: {local_ip}, Local Subnet: {local_subnet}")
            print(f"[DEBUG] Target IPs: {ip_list[:3]}..." if len(ip_list) > 3 else f"[DEBUG] Target IPs: {ip_list}")

            # Step 1: Try ARP scan first for local subnet IPs (much faster and more reliable)
            devices = []
            devices_lock = threading.Lock()
            arp_found_ips = set()

            # Check if any IPs are in local subnet
            if local_ip and local_subnet:
                try:
                    import ipaddress
                    local_network = ipaddress.ip_network(local_subnet, strict=False)
                    local_ips = [ip for ip in ip_list if ipaddress.ip_address(ip) in local_network]

                    print(f"[DEBUG] Local network: {local_network}, matched {len(local_ips)}/{len(ip_list)} IPs")

                    if local_ips:
                        print(f"[*] Step 1/2: ARP scan for {len(local_ips)} local IP(s)...")
                        self._emit_progress('scan_phase', {
                            'phase': 'arp_scan',
                            'message': f'ARP scanning {len(local_ips)} local IPs...',
                            'total_ips': len(local_ips)
                        })

                        # Build ARP packet for each IP
                        from scapy.all import ARP, Ether, srp
                        for ip in local_ips:
                            try:
                                arp = ARP(pdst=ip)
                                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                                packet = ether/arp
                                result = srp(packet, timeout=1, verbose=0)[0]

                                if result:
                                    for sent, received in result:
                                        device = NetworkDevice(
                                            ip=received.psrc,
                                            mac=received.hwsrc,
                                            last_seen=datetime.now()
                                        )
                                        devices.append(device)
                                        arp_found_ips.add(received.psrc)
                                        print(f"[+] ARP found: {received.psrc} ({received.hwsrc})")

                                        self._emit_progress('device_found', {
                                            'ip': device.ip,
                                            'mac': device.mac,
                                            'method': 'ARP',
                                            'current': len(devices)
                                        })
                            except Exception as e:
                                print(f"[!] ARP scan error for {ip}: {e}")

                        print(f"[+] ARP scan found {len(arp_found_ips)} device(s)")
                    else:
                        print(f"[!] No local IPs found in target list, skipping ARP scan")
                except Exception as e:
                    print(f"[!] ARP scan failed: {e}")
                    import traceback
                    traceback.print_exc()
            else:
                print(f"[!] Cannot determine local subnet (local_ip={local_ip}, local_subnet={local_subnet}), skipping ARP scan")

            # Choose ports based on scan type
            ports = None
            if scan_ports:
                if scan_type == "quick":
                    ports = self.QUICK_PORTS
                elif scan_type == "normal":
                    ports = self.COMMON_PORTS
                else:  # full
                    ports = self.FULL_PORTS
                print(f"[*] Step 2/2: Scanning {len(ports)} ports on {len(ip_list)} IP(s)...")
            else:
                print(f"[*] Step 2/2: ICMP ping sweep on {len(ip_list)} IP(s)...")

            # Create lookup for ARP-found devices
            arp_devices_map = {d.ip: d for d in devices}

            # Scan IPs in parallel using ThreadPoolExecutor
            scanned_count = 0
            scanned_lock = threading.Lock()

            def scan_ip_worker(ip: str) -> Optional[NetworkDevice]:
                """Worker function to scan a single IP"""
                nonlocal scanned_count

                if self._stop_scan:
                    return None

                # Emit scanning progress
                with scanned_lock:
                    scanned_count += 1
                    current = scanned_count

                print(f"[*] Scanning {ip} ({current}/{len(ip_list)})...")
                self._emit_progress('scanning_ip', {
                    'ip': ip,
                    'current': current,
                    'total': len(ip_list),
                    'progress': int((current / len(ip_list)) * 100)
                })

                # Check if already found by ARP scan
                device = arp_devices_map.get(ip)
                if device:
                    print(f"[*] {ip} already found by ARP, adding port scan info...")
                    # Add hostname if not present
                    if not device.hostname:
                        try:
                            device.hostname = socket.gethostbyaddr(ip)[0]
                        except Exception:
                            pass

                    # Add port scan
                    if scan_ports:
                        self.port_scan(device, ports)
                else:
                    # Not found by ARP, do full scan
                    device = self.scan_single_ip(ip, scan_ports=scan_ports, ports=ports)

                if device:
                    # Mark gateway
                    if gateway_ip and device.ip == gateway_ip:
                        device.is_gateway = True
                        device.device_type = "Gateway"

                    # Thread-safe update/append
                    with devices_lock:
                        if ip not in arp_devices_map:
                            devices.append(device)
                        device_count = len(devices)

                    # Emit device found (updated info)
                    self._emit_progress('device_found', {
                        'ip': device.ip,
                        'hostname': device.hostname,
                        'mac': device.mac,
                        'device_type': device.device_type,
                        'open_ports': device.open_ports,
                        'services': device.services,
                        'os_guess': device.os_guess,
                        'current': device_count,
                        'total_scanned': current
                    })

                return device

            # Use ThreadPoolExecutor for parallel scanning
            max_workers = min(10, len(ip_list))  # Max 10 concurrent threads
            print(f"[*] Using {max_workers} concurrent threads")

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all scan jobs
                future_to_ip = {executor.submit(scan_ip_worker, ip): ip for ip in ip_list}

                # Wait for completion
                for future in as_completed(future_to_ip):
                    if self._stop_scan:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    try:
                        future.result()
                    except Exception as e:
                        ip = future_to_ip[future]
                        print(f"[!] Error scanning {ip}: {e}")

            duration = time.time() - start_time
            print(f"[+] Scan complete in {duration:.2f}s. Found {len(devices)} active device(s).")

            result = ScanResult(
                devices=devices,
                scan_type=scan_type,
                network=targets,
                scan_time=datetime.now(),
                duration=duration,
                gateway_ip=gateway_ip,
                local_ip=local_ip
            )

            self._last_scan_result = result
            return result

        except Exception as e:
            print(f"[!] EXCEPTION in scan_targets: {e}")
            import traceback
            traceback.print_exc()
            # Return empty result on exception
            return ScanResult(
                devices=[],
                scan_type=scan_type,
                network=targets,
                scan_time=datetime.now(),
                duration=time.time() - start_time
            )

    def get_all_network_interfaces(self) -> List[Dict[str, str]]:
        """
        Get all network interfaces with their IP addresses and subnets

        Returns:
            List of dicts with keys: name, ip, netmask, subnet, description
        """
        interfaces = []

        try:
            import platform
            from scapy.all import get_if_list, get_if_addr, get_if_hwaddr

            # Try to use scapy's get_working_ifaces for better information
            try:
                from scapy.all import get_working_ifaces
                working_ifaces = get_working_ifaces()

                for iface in working_ifaces:
                    try:
                        ip = iface.ip if hasattr(iface, 'ip') else get_if_addr(iface.name)

                        # Skip loopback and interfaces without IP
                        if not ip or ip == '0.0.0.0' or ip.startswith('127.'):
                            continue

                        # Calculate subnet (assume /24 for simplicity, can be improved)
                        netmask = '255.255.255.0'  # Default
                        if hasattr(iface, 'netmask'):
                            netmask = iface.netmask

                        # Calculate network address
                        ip_parts = ip.split('.')
                        mask_parts = netmask.split('.')
                        network_parts = [str(int(ip_parts[i]) & int(mask_parts[i])) for i in range(4)]
                        network_addr = '.'.join(network_parts)

                        # Calculate CIDR prefix
                        cidr = sum([bin(int(x)).count('1') for x in mask_parts])
                        subnet = f"{network_addr}/{cidr}"

                        interfaces.append({
                            'name': iface.name,
                            'ip': ip,
                            'netmask': netmask,
                            'subnet': subnet,
                            'description': iface.description if hasattr(iface, 'description') else iface.name,
                            'mac': get_if_hwaddr(iface.name) if hasattr(iface, 'name') else ''
                        })
                    except Exception as e:
                        continue

            except ImportError:
                # Fallback to basic interface list
                iface_list = get_if_list()

                for iface_name in iface_list:
                    try:
                        ip = get_if_addr(iface_name)

                        # Skip loopback and interfaces without IP
                        if not ip or ip == '0.0.0.0' or ip.startswith('127.'):
                            continue

                        # Assume /24 subnet
                        ip_parts = ip.split('.')
                        subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

                        interfaces.append({
                            'name': iface_name,
                            'ip': ip,
                            'netmask': '255.255.255.0',
                            'subnet': subnet,
                            'description': iface_name,
                            'mac': get_if_hwaddr(iface_name)
                        })
                    except Exception:
                        continue

            # If we found interfaces, return them
            if interfaces:
                return interfaces

        except Exception as e:
            print(f"Error getting network interfaces: {e}")

        # Fallback: return at least the default interface
        try:
            local_ip, subnet = self.get_local_ip_and_subnet()
            return [{
                'name': 'default',
                'ip': local_ip,
                'netmask': '255.255.255.0',
                'subnet': subnet,
                'description': 'Default Interface',
                'mac': ''
            }]
        except Exception:
            return []

    def arp_scan(self, network: str, timeout: int = 3) -> List[NetworkDevice]:
        """
        Perform ARP scan to discover devices on local network
        Fast and reliable for layer 2 discovery

        Args:
            network: Network CIDR (e.g., "192.168.1.0/24")
            timeout: Timeout in seconds

        Returns:
            List of discovered devices
        """
        devices = []

        try:
            # Emit that ARP scan is starting
            self._emit_progress('arp_scan_starting', {
                'network': network,
                'timeout': timeout
            })

            # Create ARP request packet
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            # Emit that ARP requests are being sent
            self._emit_progress('arp_sending', {
                'network': network,
                'message': 'Broadcasting ARP requests...'
            })

            # Send and receive with retry=2 for better reliability
            answered, unanswered = srp(packet, timeout=timeout, verbose=0, retry=2)

            total_responses = len(answered)
            self._emit_progress('arp_responses_received', {
                'total_responses': total_responses,
                'message': f'Received {total_responses} ARP responses, processing...'
            })

            # Process each response
            for idx, (sent, received) in enumerate(answered, 1):
                device = NetworkDevice(
                    ip=received.psrc,
                    mac=received.hwsrc,
                    last_seen=datetime.now()
                )

                # Try to resolve hostname
                try:
                    device.hostname = socket.gethostbyaddr(device.ip)[0]
                except Exception:
                    device.hostname = ""

                # Identify vendor from MAC address
                device.vendor = self._identify_vendor(device.mac)

                devices.append(device)

                # Emit progress for each device found
                self._emit_progress('arp_device_found', {
                    'ip': device.ip,
                    'mac': device.mac,
                    'vendor': device.vendor,
                    'hostname': device.hostname,
                    'current': idx,
                    'total': total_responses,
                    'total_found': len(devices)
                })

        except Exception as e:
            print(f"ARP scan error: {e}")
            self._emit_progress('arp_error', {
                'error': str(e)
            })

        return devices

    def ping_sweep(self, network: str, timeout: int = 1) -> List[NetworkDevice]:
        """
        Perform ICMP ping sweep to discover devices
        Slower than ARP but works across subnets

        Args:
            network: Network CIDR (e.g., "192.168.1.0/24")
            timeout: Timeout in seconds per host

        Returns:
            List of discovered devices
        """
        devices = []

        # Parse network range
        base = network.split('/')[0]
        parts = base.split('.')
        base_ip = '.'.join(parts[:3])

        total_ips = 254  # .1 to .254

        for i in range(1, 255):
            if self._stop_scan:
                break

            ip = f"{base_ip}.{i}"

            # Emit progress for current IP being pinged
            self._emit_progress('pinging_ip', {
                'ip': ip,
                'current': i,
                'total': total_ips,
                'progress': int((i / total_ips) * 100)
            })

            try:
                start_time = time.time()
                pkt = IP(dst=ip) / ICMP()
                reply = sr1(pkt, timeout=timeout, verbose=0)

                if reply:
                    response_time = (time.time() - start_time) * 1000

                    device = NetworkDevice(
                        ip=ip,
                        response_time=response_time,
                        ttl=reply.ttl,
                        last_seen=datetime.now()
                    )

                    # Guess OS from TTL
                    if reply.ttl <= 64:
                        device.os_guess = "Linux/Unix"
                    elif reply.ttl <= 128:
                        device.os_guess = "Windows"
                    else:
                        device.os_guess = "Network Device"

                    # Try to resolve hostname
                    try:
                        device.hostname = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        device.hostname = ""

                    devices.append(device)

                    # Emit when device found
                    self._emit_progress('ping_device_found', {
                        'ip': ip,
                        'response_time': response_time,
                        'os_guess': device.os_guess,
                        'total_found': len(devices)
                    })

            except Exception:
                continue

        return devices

    def port_scan(self, device: NetworkDevice, ports: List[int] = None):
        """
        Scan ports on a device using TCP SYN scan

        Args:
            device: Device to scan
            ports: List of ports to scan (None = use COMMON_PORTS)
        """
        if ports is None:
            ports = self.COMMON_PORTS

        open_ports = []
        services = {}

        # Pre-populate ARP cache if we have MAC address
        if device.mac:
            try:
                # Send ARP request to ensure MAC is in cache
                arp_pkt = Ether(dst=device.mac) / ARP(pdst=device.ip)
                srp(arp_pkt, timeout=0.5, verbose=0, retry=1)
            except Exception:
                pass

        for port in ports:
            if self._stop_scan:
                break

            try:
                # TCP SYN scan with verbose=0 to suppress warnings
                pkt = IP(dst=device.ip) / TCP(dport=port, flags="S")
                reply = sr1(pkt, timeout=0.5, verbose=0)

                if reply and reply.haslayer(TCP):
                    if reply[TCP].flags == 0x12:  # SYN-ACK = port open
                        open_ports.append(port)
                        services[port] = self._identify_service(port)

                        # Send RST to close connection gracefully
                        rst = IP(dst=device.ip) / TCP(dport=port, flags="R")
                        sr1(rst, timeout=0.1, verbose=0)

            except Exception:
                continue

        device.open_ports = sorted(open_ports)
        device.services = services

        # Identify device type based on open ports
        device.device_type = self._identify_device_type(open_ports)

    def scan_single_ip(self, ip: str, scan_ports: bool = True,
                       ports: List[int] = None) -> Optional[NetworkDevice]:
        """
        Scan a single IP address

        Args:
            ip: IP address to scan
            scan_ports: Whether to scan ports
            ports: List of ports to scan (None = use COMMON_PORTS)

        Returns:
            NetworkDevice if host is up, None otherwise
        """
        device = None

        # Try ICMP ping first
        try:
            pkt = IP(dst=ip) / ICMP()
            reply = sr1(pkt, timeout=1, verbose=0)

            if reply:
                device = NetworkDevice(
                    ip=ip,
                    ttl=reply.ttl,
                    last_seen=datetime.now()
                )

                # Guess OS from TTL
                if reply.ttl <= 64:
                    device.os_guess = "Linux/Unix"
                elif reply.ttl <= 128:
                    device.os_guess = "Windows"
                else:
                    device.os_guess = "Network Device"
        except Exception:
            pass

        # If no ICMP reply but port scan requested, try port scan anyway
        # Many PLCs/ICS devices block ICMP but have ports open
        if not device and scan_ports:
            device = NetworkDevice(
                ip=ip,
                last_seen=datetime.now()
            )

        # If we have a device (from ICMP or created for port scan)
        if device:
            # Try to resolve hostname
            try:
                device.hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                device.hostname = ""

            # Port scan if requested
            if scan_ports:
                self.port_scan(device, ports)

                # If no ports found and no ICMP reply, host is probably down
                if not device.open_ports:
                    return None

            return device

        return None

    def scan_network(self, network: str = None, scan_type: str = "quick",
                     scan_ports: bool = True) -> ScanResult:
        """
        Scan an entire network

        Supports multiple formats:
        - CIDR: 192.168.1.0/24
        - IP range: 192.168.210.20-30
        - Multiple IPs: 192.168.1.10,192.168.1.20,192.168.1.30
        - Mixed: 192.168.1.10-20,192.168.2.50

        Args:
            network: Network specification (None = auto-detect local network)
            scan_type: "quick" | "normal" | "full"
            scan_ports: Whether to scan ports

        Returns:
            ScanResult with discovered devices
        """
        print(f"[SCAN_NETWORK] Function called with network='{network}', scan_type='{scan_type}', scan_ports={scan_ports}")

        try:
            start_time = time.time()
            self._stop_scan = False

            with self._scan_lock:
                # Auto-detect network if not specified
                if not network:
                    print(f"[SCAN_NETWORK] Auto-detecting local network...")
                    local_ip, network = self.get_local_ip_and_subnet()
                    print(f"[SCAN_NETWORK] Auto-detected: local_ip={local_ip}, network={network}")
                else:
                    local_ip, _ = self.get_local_ip_and_subnet()
                    print(f"[SCAN_NETWORK] Using provided network: {network}")

                # Check if this is a simple CIDR or custom target specification
                print(f"[SCAN_NETWORK] Checking network format...")
                if '/' in network and ',' not in network and '-' not in network:
                    # Traditional CIDR network scan with ARP/ICMP
                    print(f"[SCAN_NETWORK] Detected CIDR format, calling _scan_network_cidr()")
                    return self._scan_network_cidr(network, scan_type, scan_ports, local_ip)
                else:
                    # Custom target specification - SCAN ONLY TARGET IPs (FAST!)
                    print(f"[SCAN_NETWORK] Detected custom format (range/list)")
                    print(f"[SCAN_NETWORK] Will scan ONLY specified IPs (not entire subnet)")

                    # Parse target IPs
                    target_ips = self.parse_target_specification(network)
                    print(f"[SCAN_NETWORK] Parsed {len(target_ips)} target IPs: {target_ips}")

                    if not target_ips:
                        print(f"[!] No valid IPs found in: {network}")
                        return ScanResult(
                            devices=[],
                            scan_type=scan_type,
                            network=network,
                            scan_time=datetime.now(),
                            duration=0.0
                        )

                    # Get gateway
                    gateway_ip = self.get_default_gateway()

                    # Choose ports
                    if scan_type == "quick":
                        ports = self.QUICK_PORTS
                    elif scan_type == "normal":
                        ports = self.COMMON_PORTS
                    else:
                        ports = self.FULL_PORTS

                    print(f"[SCAN_NETWORK] Step 1/2: ARP scan on {len(target_ips)} target IPs...")

                    # Step 1: ARP scan ONLY target IPs
                    devices = []
                    arp_found = set()

                    from scapy.all import ARP, Ether, srp
                    for ip in target_ips:
                        try:
                            arp = ARP(pdst=ip)
                            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                            packet = ether/arp
                            result = srp(packet, timeout=1, verbose=0)[0]

                            if result:
                                for sent, received in result:
                                    device = NetworkDevice(
                                        ip=received.psrc,
                                        mac=received.hwsrc,
                                        last_seen=datetime.now()
                                    )
                                    devices.append(device)
                                    arp_found.add(received.psrc)
                                    print(f"[+] ARP: {received.psrc} ({received.hwsrc})")
                        except Exception as e:
                            print(f"[!] ARP error {ip}: {e}")

                    print(f"[+] ARP found {len(arp_found)}/{len(target_ips)} devices")
                    print(f"[SCAN_NETWORK] Step 2/2: Port scan on {len(target_ips)} IPs...")

                    # Step 2: Add port scan info
                    devices_map = {d.ip: d for d in devices}

                    for ip in target_ips:
                        if ip in devices_map:
                            device = devices_map[ip]
                            print(f"[*] Port scan {ip} (ARP found)...")
                            try:
                                self.port_scan(device, ports)
                            except Exception as e:
                                # Scapy on Windows sometimes throws thread exceptions (safe to ignore)
                                print(f"[!] Port scan warning for {ip}: {e.__class__.__name__} (continuing...)")
                        else:
                            print(f"[*] Scan {ip} (no ARP, trying ICMP+ports)...")
                            try:
                                device = self.scan_single_ip(ip, scan_ports=True, ports=ports)
                                if device:
                                    devices.append(device)
                            except Exception as e:
                                print(f"[!] Scan error for {ip}: {e.__class__.__name__} (skipping...)")

                    # Mark gateway
                    for d in devices:
                        if gateway_ip and d.ip == gateway_ip:
                            d.is_gateway = True
                            d.device_type = "Gateway"

                    duration = time.time() - start_time
                    print(f"[+] Scan done in {duration:.2f}s. Found {len(devices)} devices")

                    return ScanResult(
                        devices=devices,
                        scan_type=scan_type,
                        network=network,
                        scan_time=datetime.now(),
                        duration=duration,
                        gateway_ip=gateway_ip,
                        local_ip=local_ip
                    )

        except Exception as e:
            print(f"[!] EXCEPTION in scan_network: {e}")
            import traceback
            traceback.print_exc()
            # Return empty result on exception
            return ScanResult(
                devices=[],
                scan_type=scan_type,
                network=network or "unknown",
                scan_time=datetime.now(),
                duration=time.time() - start_time
            )

    def _scan_network_cidr(self, network: str, scan_type: str, scan_ports: bool, local_ip: str) -> ScanResult:
        """Internal method for traditional CIDR network scanning with ARP/ICMP"""
        start_time = time.time()

        gateway_ip = self.get_default_gateway()

        # Step 1: ARP scan (fastest and most reliable)
        print(f"[*] Scanning network: {network}")
        self._emit_progress('scan_started', {
            'network': network,
            'scan_type': scan_type,
            'total_steps': 3
        })

        print(f"[*] Step 1/3: ARP scan...")
        self._emit_progress('scan_phase', {
            'phase': 'arp_scan',
            'step': 1,
            'message': 'Discovering devices with ARP scan...'
        })
        devices = self.arp_scan(network)
        print(f"[+] Found {len(devices)} devices via ARP")
        self._emit_progress('arp_complete', {
            'devices_found': len(devices)
        })

        # Step 2: ICMP ping sweep (for devices that don't respond to ARP)
        if scan_type in ["normal", "full"]:
            print(f"[*] Step 2/3: ICMP ping sweep...")
            self._emit_progress('scan_phase', {
                'phase': 'ping_sweep',
                'step': 2,
                'message': 'Finding additional devices with ping sweep...'
            })
            ping_devices = self.ping_sweep(network)

            # Merge results (avoid duplicates)
            device_ips = {d.ip for d in devices}
            for pd in ping_devices:
                if pd.ip not in device_ips:
                    devices.append(pd)
            print(f"[+] Total devices: {len(devices)}")
            self._emit_progress('ping_complete', {
                'total_devices': len(devices)
            })

        # Step 3: Port scanning
        if scan_ports:
            # Choose ports based on scan type
            if scan_type == "quick":
                ports = self.QUICK_PORTS
            elif scan_type == "normal":
                ports = self.COMMON_PORTS
            else:  # full
                ports = self.FULL_PORTS

            print(f"[*] Step 3/3: Scanning {len(ports)} ports on {len(devices)} devices...")
            self._emit_progress('scan_phase', {
                'phase': 'port_scan',
                'step': 3,
                'message': f'Scanning {len(ports)} ports on {len(devices)} devices...',
                'total_devices': len(devices),
                'ports_to_scan': len(ports)
            })

            for i, device in enumerate(devices):
                if self._stop_scan:
                    break

                print(f"[*] Scanning {device.ip} ({i+1}/{len(devices)})...")
                self._emit_progress('scanning_device', {
                    'ip': device.ip,
                    'current': i + 1,
                    'total': len(devices),
                    'progress': int((i + 1) / len(devices) * 100)
                })

                self.port_scan(device, ports)

                # Mark gateway
                if gateway_ip and device.ip == gateway_ip:
                    device.is_gateway = True
                    device.device_type = "Gateway"

                # Emit device discovery with results
                self._emit_progress('device_scanned', {
                    'ip': device.ip,
                    'hostname': device.hostname,
                    'device_type': device.device_type,
                    'open_ports': device.open_ports,
                    'services': device.services,
                    'vendor': device.vendor,
                    'current': i + 1,
                    'total': len(devices)
                })

        duration = time.time() - start_time
        print(f"[+] Scan complete in {duration:.2f}s. Found {len(devices)} devices.")

        result = ScanResult(
            devices=devices,
            scan_type=scan_type,
            network=network,
            scan_time=datetime.now(),
            duration=duration,
            gateway_ip=gateway_ip,
            local_ip=local_ip
        )

        # Store the result for later retrieval
        self._last_scan_result = result

        return result

    def _identify_vendor(self, mac: str) -> str:
        """Identify vendor from MAC address OUI"""
        mac_prefix = mac.upper()[:8].replace(':', '')

        # Common vendor OUIs (Organizationally Unique Identifiers)
        vendors = {
            "00001D": "Siemens",
            "000578": "Siemens",
            "0050C2": "Siemens",
            "00AE8C": "Siemens",
            "001C06": "Siemens",
            "001109": "Cisco",
            "00E04C": "Realtek",
            "080027": "Oracle VirtualBox",
            "525400": "QEMU/KVM",
            "000C29": "VMware",
            "00155D": "Microsoft Hyper-V",
            "001B21": "Schneider Electric",
            "0004A3": "Schneider Electric",
            "00806E": "Rockwell Automation",
        }

        for prefix, vendor in vendors.items():
            if mac_prefix.startswith(prefix):
                return vendor

        return "Unknown"

    def _identify_service(self, port: int) -> str:
        """Identify common services by port number"""
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            80: "HTTP",
            102: "S7comm (Siemens)",
            443: "HTTPS",
            445: "SMB",
            502: "Modbus TCP",
            3389: "RDP",
            8080: "HTTP-Alt",
            20000: "DNP3",
            44818: "EtherNet/IP",
            2222: "EtherCAT",
            4840: "OPC UA",
        }
        return services.get(port, f"Port {port}")

    def _identify_device_type(self, ports: List[int]) -> str:
        """Classify device type based on open ports"""
        if 102 in ports:
            return "PLC (Siemens S7)"
        elif 502 in ports:
            return "PLC (Modbus)"
        elif 20000 in ports:
            return "RTU (DNP3)"
        elif 44818 in ports:
            return "PLC (EtherNet/IP)"
        elif 4840 in ports:
            return "OPC UA Server"
        elif (80 in ports or 443 in ports or 8080 in ports):
            if 22 in ports:
                return "Server"
            return "HMI/Web Interface"
        elif 445 in ports or 3389 in ports:
            return "Computer/Workstation"
        elif len(ports) > 10:
            return "Switch/Router"
        elif len(ports) > 0:
            return "Network Device"
        else:
            return "Unknown"

    def stop(self):
        """Stop ongoing scan"""
        self._stop_scan = True

    def get_last_scan_result(self) -> Optional[ScanResult]:
        """Get the last scan result if available"""
        return self._last_scan_result

    def clear_last_scan_result(self):
        """Clear the stored scan result"""
        self._last_scan_result = None


# Global scanner instance
_scanner_instance = None
_scanner_lock = threading.Lock()


def get_scanner() -> NetworkScanner:
    """Get global scanner instance (singleton pattern)"""
    global _scanner_instance

    if _scanner_instance is None:
        with _scanner_lock:
            if _scanner_instance is None:
                _scanner_instance = NetworkScanner()

    return _scanner_instance
