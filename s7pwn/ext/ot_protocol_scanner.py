"""
OT Protocol Scanner Module
Supports multiple industrial protocol discovery methods:
- Modbus TCP (port 502)
- EtherNet/IP (port 44818) - Allen-Bradley/Rockwell
- S7 Protocol (port 102) - Siemens
- BACnet (port 47808) - Building automation
- FINS (port 9600) - Omron
"""

from __future__ import annotations
import socket
import struct
import logging
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

logging.basicConfig(filename='s7pwn.log', level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')


class ModbusTCPScanner:
    """Modbus TCP protocol scanner (port 502)"""

    @staticmethod
    def create_read_device_id_request() -> bytes:
        """Create Modbus Read Device Identification request (Function Code 0x2B/0x0E)"""
        transaction_id = 0x0001
        protocol_id = 0x0000
        length = 0x0005
        unit_id = 0x01
        function_code = 0x2B  # Read Device Identification
        mei_type = 0x0E       # MEI Type
        read_device_id_code = 0x01  # Basic device identification
        object_id = 0x00      # Start from first object

        packet = struct.pack('>HHHBBBBB',
                           transaction_id, protocol_id, length, unit_id,
                           function_code, mei_type, read_device_id_code, object_id)
        return packet

    @staticmethod
    def parse_device_identification(data: bytes) -> Dict[str, str]:
        """Parse Modbus Device Identification response"""
        try:
            if len(data) < 9:
                return {}

            # Skip header (7 bytes) + function code (1) + MEI type (1)
            offset = 9
            if len(data) <= offset:
                return {}

            result = {}
            # Read device ID code and conformity level
            if len(data) > offset + 2:
                num_objects = data[offset + 2] if len(data) > offset + 2 else 0
                offset += 3

                # Parse objects
                for _ in range(num_objects):
                    if offset + 2 > len(data):
                        break
                    obj_id = data[offset]
                    obj_len = data[offset + 1]
                    offset += 2

                    if offset + obj_len > len(data):
                        break

                    obj_value = data[offset:offset + obj_len].decode('utf-8', errors='ignore')
                    offset += obj_len

                    # Map object IDs to names
                    obj_names = {
                        0x00: 'VendorName',
                        0x01: 'ProductCode',
                        0x02: 'MajorMinorRevision',
                        0x03: 'VendorUrl',
                        0x04: 'ProductName',
                        0x05: 'ModelName',
                        0x06: 'UserApplicationName'
                    }
                    if obj_id in obj_names:
                        result[obj_names[obj_id]] = obj_value

            return result
        except Exception as e:
            logging.error(f"Error parsing Modbus response: {e}")
            return {}

    @staticmethod
    def scan_device(ip: str, port: int = 502, timeout: float = 2.0) -> Optional[Dict]:
        """Scan single device for Modbus TCP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # Send Read Device Identification request
            request = ModbusTCPScanner.create_read_device_id_request()
            sock.send(request)

            # Receive response
            response = sock.recv(1024)
            sock.close()

            if len(response) > 8 and response[7] == 0x2B:  # Function code 0x2B
                device_info = ModbusTCPScanner.parse_device_identification(response)
                if device_info:
                    return {
                        'ip': ip,
                        'port': port,
                        'protocol': 'Modbus TCP',
                        'info': device_info
                    }
        except socket.timeout:
            pass
        except Exception as e:
            logging.debug(f"Modbus scan error for {ip}: {e}")

        return None


class EtherNetIPScanner:
    """EtherNet/IP protocol scanner (port 44818) - Rockwell/Allen-Bradley"""

    @staticmethod
    def create_list_identity_request() -> bytes:
        """Create EtherNet/IP List Identity request"""
        # Encapsulation Header
        command = 0x0063  # ListIdentity
        length = 0x0000
        session_handle = 0x00000000
        status = 0x00000000
        sender_context = b'\x00' * 8
        options = 0x00000000

        packet = struct.pack('<HHIIQ I',
                           command, length, session_handle, status,
                           int.from_bytes(sender_context, 'little'), options)
        return packet

    @staticmethod
    def parse_list_identity(data: bytes) -> Dict[str, str]:
        """Parse EtherNet/IP List Identity response"""
        try:
            if len(data) < 28:  # Minimum header size
                return {}

            # Skip encapsulation header (24 bytes)
            offset = 24

            # Item count
            if len(data) < offset + 2:
                return {}
            item_count = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2

            result = {}
            for _ in range(item_count):
                if offset + 4 > len(data):
                    break

                item_type = struct.unpack('<H', data[offset:offset+2])[0]
                item_length = struct.unpack('<H', data[offset+2:offset+4])[0]
                offset += 4

                if item_type == 0x000C:  # CIP Identity item
                    if offset + item_length > len(data):
                        break

                    # Parse identity structure
                    if item_length >= 32:
                        protocol_version = struct.unpack('<H', data[offset:offset+2])[0]
                        offset += 2

                        # Socket address
                        offset += 16  # Skip socket address structure

                        vendor_id = struct.unpack('<H', data[offset:offset+2])[0]
                        device_type = struct.unpack('<H', data[offset+2:offset+4])[0]
                        product_code = struct.unpack('<H', data[offset+4:offset+6])[0]
                        revision = data[offset+6:offset+8]
                        status = struct.unpack('<H', data[offset+8:offset+10])[0]
                        serial_number = struct.unpack('<I', data[offset+10:offset+14])[0]
                        product_name_len = data[offset+14]
                        offset += 15

                        if offset + product_name_len <= len(data):
                            product_name = data[offset:offset+product_name_len].decode('utf-8', errors='ignore')

                            result = {
                                'VendorID': f'0x{vendor_id:04X}',
                                'DeviceType': f'0x{device_type:04X}',
                                'ProductCode': str(product_code),
                                'Revision': f'{revision[0]}.{revision[1]}',
                                'SerialNumber': str(serial_number),
                                'ProductName': product_name
                            }

            return result
        except Exception as e:
            logging.error(f"Error parsing EtherNet/IP response: {e}")
            return {}

    @staticmethod
    def scan_device(ip: str, port: int = 44818, timeout: float = 2.0) -> Optional[Dict]:
        """Scan single device for EtherNet/IP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)

            # Send List Identity request
            request = EtherNetIPScanner.create_list_identity_request()
            sock.sendto(request, (ip, port))

            # Receive response
            response, _ = sock.recvfrom(1024)
            sock.close()

            if len(response) > 24 and struct.unpack('<H', response[0:2])[0] == 0x0063:
                device_info = EtherNetIPScanner.parse_list_identity(response)
                if device_info:
                    return {
                        'ip': ip,
                        'port': port,
                        'protocol': 'EtherNet/IP',
                        'info': device_info
                    }
        except socket.timeout:
            pass
        except Exception as e:
            logging.debug(f"EtherNet/IP scan error for {ip}: {e}")

        return None


class S7ProtocolScanner:
    """S7 Protocol scanner (port 102) - Siemens direct"""

    @staticmethod
    def create_cotp_connection_request(slot: int = 1) -> bytes:
        """Create COTP Connection Request"""
        # TPKT Header
        tpkt = struct.pack('!BBH', 3, 0, 22)  # Version 3, Reserved, Length 22

        # COTP Connection Request
        cotp = bytes([
            17,  # Length
            0xE0,  # PDU type: Connection Request
            0x00, 0x00,  # Dest reference
            0x00, 0x01,  # Source reference
            0x00,  # Class/Option
            # Parameters
            0xC0, 0x01, 0x0A,  # tpdu-size = 1024
            0xC1, 0x02, 0x01, 0x00,  # src-tsap
            0xC2, 0x02, 0x01, slot,  # dst-tsap
        ])

        return tpkt + cotp

    @staticmethod
    def create_s7_setup_communication() -> bytes:
        """Create S7 Setup Communication request"""
        # TPKT Header
        tpkt = struct.pack('!BBH', 3, 0, 25)

        # COTP Data
        cotp = bytes([2, 0xF0, 0x80])  # Length, PDU type, TPDU number

        # S7 Header
        s7_header = bytes([
            0x32,  # Protocol ID
            0x01,  # ROSCTR: Job
            0x00, 0x00,  # Redundancy identification
            0x00, 0x00,  # Protocol data unit reference
            0x00, 0x08,  # Parameter length
            0x00, 0x00,  # Data length
        ])

        # S7 Parameters (Setup Communication)
        s7_params = bytes([
            0xF0,  # Function: Setup Communication
            0x00,  # Reserved
            0x00, 0x01,  # Max AMQ calling
            0x00, 0x01,  # Max AMQ called
            0x01, 0xE0,  # PDU length (480)
        ])

        return tpkt + cotp + s7_header + s7_params

    @staticmethod
    def scan_device(ip: str, port: int = 102, timeout: float = 2.0) -> Optional[Dict]:
        """Scan single device for S7 Protocol"""
        for slot in [1, 2]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((ip, port))

                # Send COTP Connection Request
                sock.send(S7ProtocolScanner.create_cotp_connection_request(slot))
                response1 = sock.recv(1024)

                # Check COTP Connection Confirm
                if len(response1) > 5 and response1[5] == 0xD0:
                    # Send S7 Setup Communication
                    sock.send(S7ProtocolScanner.create_s7_setup_communication())
                    response2 = sock.recv(1024)

                    sock.close()

                    # Check for valid S7 response
                    if len(response2) > 7 and response2[7] == 0x32:
                        return {
                            'ip': ip,
                            'port': port,
                            'protocol': 'S7',
                            'info': {
                                'DeviceType': f'Siemens S7 PLC (Slot {slot})',
                                'Status': 'Responding'
                            }
                        }

                sock.close()
            except socket.timeout:
                pass
            except Exception as e:
                logging.debug(f"S7 scan error for {ip} slot {slot}: {e}")

        return None


class BACnetScanner:
    """BACnet protocol scanner (port 47808) - Building automation"""

    @staticmethod
    def create_whois_request() -> bytes:
        """Create BACnet Who-Is broadcast request"""
        # BACnet Virtual Link Control
        bvlc = bytes([
            0x81,  # BVLC Type: BACnet/IP
            0x0B,  # Function: Original-Broadcast-NPDU
            0x00, 0x0C,  # Length
        ])

        # Network Layer Protocol Control Information
        npci = bytes([
            0x01,  # Version
            0x20,  # Control: Expecting reply, no destination
        ])

        # Application Layer PDU
        apdu = bytes([
            0x10,  # PDU Type: Unconfirmed-Request, Who-Is
            0x08,  # Service Choice: Who-Is
        ])

        return bvlc + npci + apdu

    @staticmethod
    def parse_iam_response(data: bytes) -> Dict[str, str]:
        """Parse BACnet I-Am response"""
        try:
            if len(data) < 12:
                return {}

            # Check for I-Am service
            if data[6] == 0x10 and data[7] == 0x00:  # Unconfirmed I-Am
                result = {}
                offset = 8

                # Parse I-Am parameters (simplified)
                if len(data) > offset + 4:
                    # Object ID
                    obj_type = (data[offset + 1] >> 2) & 0x3FF
                    obj_instance = ((data[offset + 1] & 0x03) << 16) | (data[offset + 2] << 8) | data[offset + 3]

                    result['ObjectType'] = str(obj_type)
                    result['ObjectInstance'] = str(obj_instance)
                    result['DeviceID'] = str(obj_instance)

                return result
        except Exception as e:
            logging.error(f"Error parsing BACnet response: {e}")

        return {}

    @staticmethod
    def scan_device(ip: str, port: int = 47808, timeout: float = 2.0) -> Optional[Dict]:
        """Scan single device for BACnet"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)

            # Send Who-Is request
            request = BACnetScanner.create_whois_request()
            sock.sendto(request, (ip, port))

            # Receive I-Am response
            response, _ = sock.recvfrom(1024)
            sock.close()

            if len(response) > 8:
                device_info = BACnetScanner.parse_iam_response(response)
                if device_info:
                    return {
                        'ip': ip,
                        'port': port,
                        'protocol': 'BACnet',
                        'info': device_info
                    }
        except socket.timeout:
            pass
        except Exception as e:
            logging.debug(f"BACnet scan error for {ip}: {e}")

        return None


class FINSScanner:
    """FINS protocol scanner (port 9600) - Omron PLCs"""

    @staticmethod
    def create_fins_frame_request() -> bytes:
        """Create FINS/UDP Frame Send request"""
        # FINS/UDP header
        header = bytes([
            0x46, 0x49, 0x4E, 0x53,  # "FINS"
            0x00, 0x00, 0x00, 0x0C,  # Length
            0x00, 0x00, 0x00, 0x00,  # Command (0 = Frame send)
            0x00, 0x00, 0x00, 0x00,  # Error code
        ])

        # FINS Command (Controller Data Read)
        fins_cmd = bytes([
            0x80,  # ICF
            0x00,  # RSV
            0x02,  # GCT
            0x00,  # DNA (network address)
            0x00,  # DA1 (node address)
            0x00,  # DA2 (unit address)
            0x00,  # SNA
            0x00,  # SA1
            0x00,  # SA2
            0x00,  # SID
            0x05, 0x01,  # Command: Controller Data Read
            0x00,  # Response required
        ])

        return header + fins_cmd

    @staticmethod
    def scan_device(ip: str, port: int = 9600, timeout: float = 2.0) -> Optional[Dict]:
        """Scan single device for FINS protocol"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)

            # Send FINS request
            request = FINSScanner.create_fins_frame_request()
            sock.sendto(request, (ip, port))

            # Receive response
            response, _ = sock.recvfrom(1024)
            sock.close()

            # Check for valid FINS response
            if len(response) > 16 and response[0:4] == b'FINS':
                return {
                    'ip': ip,
                    'port': port,
                    'protocol': 'FINS',
                    'info': {
                        'DeviceType': 'Omron PLC',
                        'Status': 'Responding'
                    }
                }
        except socket.timeout:
            pass
        except Exception as e:
            logging.debug(f"FINS scan error for {ip}: {e}")

        return None


class OTProtocolScanner:
    """Multi-protocol OT scanner"""

    @staticmethod
    def scan_ip(ip: str, protocols: List[str] = None) -> List[Dict]:
        """Scan single IP for multiple OT protocols"""
        if protocols is None:
            protocols = ['modbus', 'ethernet_ip', 's7', 'bacnet', 'fins']

        results = []
        scanners = {
            'modbus': (ModbusTCPScanner.scan_device, 502),
            'ethernet_ip': (EtherNetIPScanner.scan_device, 44818),
            's7': (S7ProtocolScanner.scan_device, 102),
            'bacnet': (BACnetScanner.scan_device, 47808),
            'fins': (FINSScanner.scan_device, 9600),
        }

        for protocol in protocols:
            if protocol in scanners:
                scanner_func, default_port = scanners[protocol]
                result = scanner_func(ip, default_port)
                if result:
                    results.append(result)

        return results

    @staticmethod
    def scan_network(network: str, protocols: List[str] = None, max_workers: int = 20, progress_callback=None) -> List[Dict]:
        """
        Scan network range for OT protocols

        Args:
            network: IP network in CIDR notation (e.g., "192.168.1.0/24")
            protocols: List of protocols to scan (default: all)
            max_workers: Number of concurrent scanning threads
            progress_callback: Optional callback for progress updates

        Returns:
            List of discovered devices
        """
        def emit_progress(message: str):
            """Emit progress message"""
            print(message)
            if progress_callback:
                progress_callback(message)

        try:
            net = ipaddress.ip_network(network, strict=False)
            all_devices = []

            emit_progress(f"[*] Scanning {network} for OT protocols: {protocols or 'all'}")
            emit_progress(f"[*] Total hosts to scan: {net.num_addresses}")

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(OTProtocolScanner.scan_ip, str(ip), protocols): str(ip)
                          for ip in net.hosts()}

                completed = 0
                for future in as_completed(futures):
                    completed += 1
                    if completed % 10 == 0:
                        emit_progress(f"[*] Progress: {completed}/{net.num_addresses} hosts scanned")

                    try:
                        devices = future.result()
                        if devices:
                            all_devices.extend(devices)
                            for device in devices:
                                emit_progress(f"[+] Found {device['protocol']} device at {device['ip']}:{device['port']}")
                    except Exception as e:
                        logging.error(f"Error scanning {futures[future]}: {e}")

            return all_devices

        except Exception as e:
            logging.error(f"Network scan error: {e}")
            return []


def quick_scan(ip_range: str) -> Dict[str, List[Dict]]:
    """
    Quick scan of common OT protocols

    Returns:
        Dictionary grouped by protocol
    """
    devices = OTProtocolScanner.scan_network(ip_range)

    # Group by protocol
    grouped = {}
    for device in devices:
        protocol = device['protocol']
        if protocol not in grouped:
            grouped[protocol] = []
        grouped[protocol].append(device)

    return grouped


if __name__ == '__main__':
    # Example usage
    import sys

    if len(sys.argv) < 2:
        print("Usage: python ot_protocol_scanner.py <network_cidr>")
        print("Example: python ot_protocol_scanner.py 192.168.1.0/24")
        sys.exit(1)

    network = sys.argv[1]
    results = quick_scan(network)

    print("\n" + "="*60)
    print("OT PROTOCOL SCAN RESULTS")
    print("="*60)

    for protocol, devices in results.items():
        print(f"\n[{protocol}] - {len(devices)} device(s) found:")
        for device in devices:
            print(f"  IP: {device['ip']}:{device['port']}")
            for key, value in device['info'].items():
                print(f"    {key}: {value}")
