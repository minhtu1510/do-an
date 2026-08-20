"""Helper utilities for ICSScout"""

import re
import socket
from typing import Optional, Tuple
from ipaddress import ip_address, IPv4Address, IPv4Network


def validate_ip(ip: str) -> bool:
    """
    Validate IP address

    Args:
        ip: IP address string

    Returns:
        True if valid, False otherwise
    """
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    """
    Validate port number

    Args:
        port: Port number

    Returns:
        True if valid (1-65535), False otherwise
    """
    return 1 <= port <= 65535


def validate_network(network: str) -> bool:
    """
    Validate network CIDR notation

    Args:
        network: Network in CIDR notation (e.g., 192.168.1.0/24)

    Returns:
        True if valid, False otherwise
    """
    try:
        IPv4Network(network, strict=False)
        return True
    except ValueError:
        return False


def parse_address(address: str) -> Optional[dict]:
    """
    Parse memory address string

    Supported formats:
    - M0.5 (bit address)
    - MW10 (word address)
    - DB1.DBW0 (data block word)
    - I0 (input byte)
    - Q5 (output byte)

    Args:
        address: Address string

    Returns:
        Parsed address dict or None if invalid
    """
    # Bit address: M0.5, I1.3, Q2.7
    match = re.match(r'^([MIQ])(\d+)\.(\d)$', address.upper())
    if match:
        area, byte_idx, bit_idx = match.groups()
        return {
            'area': area,
            'byte': int(byte_idx),
            'bit': int(bit_idx),
            'type': 'bit'
        }

    # Byte address: M0, I1, Q2
    match = re.match(r'^([MIQ])(\d+)$', address.upper())
    if match:
        area, byte_idx = match.groups()
        return {
            'area': area,
            'byte': int(byte_idx),
            'type': 'byte'
        }

    # Word address: MW0, IW2, QW4
    match = re.match(r'^([MIQ])W(\d+)$', address.upper())
    if match:
        area, byte_idx = match.groups()
        return {
            'area': area,
            'byte': int(byte_idx),
            'type': 'word'
        }

    # DWord address: MD0, ID2, QD4
    match = re.match(r'^([MIQ])D(\d+)$', address.upper())
    if match:
        area, byte_idx = match.groups()
        return {
            'area': area,
            'byte': int(byte_idx),
            'type': 'dword'
        }

    # Data block: DB1.DBW0, DB10.DBD5
    match = re.match(r'^DB(\d+)\.DB([XBWD])(\d+)$', address.upper())
    if match:
        db_num, data_type, offset = match.groups()
        type_map = {'X': 'bit', 'B': 'byte', 'W': 'word', 'D': 'dword'}
        return {
            'area': 'DB',
            'db_number': int(db_num),
            'offset': int(offset),
            'type': type_map[data_type]
        }

    return None


def format_bytes(size: int) -> str:
    """
    Format byte size to human-readable string

    Args:
        size: Size in bytes

    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def is_reachable(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Check if host:port is reachable

    Args:
        host: Hostname or IP
        port: Port number
        timeout: Connection timeout in seconds

    Returns:
        True if reachable, False otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


def parse_modbus_address(address: str) -> Optional[Tuple[str, int]]:
    """
    Parse Modbus address

    Formats:
    - 40001 (holding register 1)
    - 30001 (input register 1)
    - 10001 (coil 1)
    - 00001 (discrete input 1)

    Args:
        address: Modbus address string

    Returns:
        Tuple of (type, address) or None
    """
    if not address.isdigit() or len(address) != 5:
        return None

    prefix = address[0]
    addr = int(address[1:])

    type_map = {
        '0': 'coil',
        '1': 'discrete_input',
        '3': 'input_register',
        '4': 'holding_register'
    }

    reg_type = type_map.get(prefix)
    if reg_type:
        return (reg_type, addr)

    return None


def mac_to_vendor(mac: str) -> str:
    """
    Get vendor from MAC address OUI

    Args:
        mac: MAC address

    Returns:
        Vendor name or "Unknown"
    """
    # OUI database (first 3 bytes)
    oui_db = {
        '00:1B:1B': 'Siemens',
        '00:0E:8C': 'Siemens',
        '00:50:C2': 'Siemens',
        '08:00:06': 'Siemens',
        '00:80:F4': 'Telemecanique (Schneider)',
        '00:C0:F2': 'Schneider Electric',
        '00:06:29': 'Schneider Electric',
        '00:01:05': 'Rockwell Automation',
        '00:00:BC': 'Allen-Bradley (Rockwell)',
        '08:00:0F': 'Rockwell',
    }

    mac_upper = mac.upper()
    oui = ':'.join(mac_upper.split(':')[:3])

    return oui_db.get(oui, 'Unknown')
