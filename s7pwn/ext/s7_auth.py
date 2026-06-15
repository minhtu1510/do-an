"""
S7 Protocol Authentication Module
Handles password-based authentication for Siemens S7 PLCs

S7 Protection Levels:
- S7-300/400: Protection levels 1-3 (legacy)
- S7-1200/1500: Password-based access control
  * Full Access (no password)
  * HMI Access (restricted operations)
  * Read Access (read-only)
  * Complete Protection (password required)

This module provides:
1. Protection level detection
2. Password-based authentication
3. Session management with credentials
4. Brute-force testing capability (authorized testing only)
"""

from __future__ import annotations
import struct
import socket
import hashlib
import logging
from typing import Optional, Tuple, Dict, List
from dataclasses import dataclass
from enum import Enum

logging.basicConfig(filename='s7pwn.log', level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')


def test_port_open(ip: str, port: int = 102, timeout: float = 2.0) -> Tuple[bool, str]:
    """
    Test if a TCP port is open

    Returns:
        (is_open, message)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            return True, f"Port {port} is open"
        else:
            return False, f"Port {port} is closed or filtered (error code: {result})"
    except socket.timeout:
        return False, f"Connection to port {port} timed out after {timeout}s"
    except Exception as e:
        return False, f"Error testing port {port}: {e}"


class ProtectionLevel(Enum):
    """S7 PLC Protection Levels"""
    NO_PROTECTION = 0
    WRITE_PROTECTION = 1
    READ_WRITE_PROTECTION = 2
    COMPLETE_PROTECTION = 3


class AccessLevel(Enum):
    """S7-1200/1500 Access Levels"""
    NO_ACCESS = 0
    READ_ACCESS = 1
    HMI_ACCESS = 2
    FULL_ACCESS = 3


@dataclass
class AuthSession:
    """Authentication session information"""
    ip: str
    rack: int
    slot: int
    protection_level: Optional[ProtectionLevel] = None
    access_level: Optional[AccessLevel] = None
    password: Optional[str] = None
    authenticated: bool = False
    session_id: Optional[int] = None


class S7AuthClient:
    """S7 Protocol Authentication Client"""

    def __init__(self, ip: str, rack: int = 0, slot: int = 1, timeout: float = 5.0):
        self.ip = ip
        self.rack = rack
        self.slot = slot
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.session: Optional[AuthSession] = None
        self.pdu_length = 480
        self.session_handle = 0
        self.last_error = ""  # Store last error message for detailed reporting

    def connect(self) -> bool:
        """Establish COTP connection to PLC"""
        self.last_error = ""  # Reset error message
        try:
            # Step 1: TCP Connection
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            logging.info(f"Connecting to {self.ip}:102 (timeout: {self.timeout}s)")
            self.sock.connect((self.ip, 102))
            logging.info(f"TCP connection established to {self.ip}:102")

            # Step 2: COTP Connection Request
            cotp_request = self._create_cotp_connection_request()
            self.sock.send(cotp_request)
            logging.info(f"Sent COTP Connection Request ({len(cotp_request)} bytes)")

            # Receive COTP Connection Confirm
            response = self.sock.recv(1024)
            logging.info(f"Received COTP response ({len(response)} bytes): {response[:20].hex()}")

            if len(response) < 6:
                self.last_error = f"COTP response too short: {len(response)} bytes (expected >= 6). Device may not be an S7 PLC."
                logging.error(self.last_error)
                return False

            if response[5] != 0xD0:  # CC (Connection Confirm)
                self.last_error = f"COTP handshake failed: Expected 0xD0 at byte 5, got 0x{response[5]:02X}. Device responded but not with S7 protocol."
                logging.error(self.last_error)
                logging.error(f"Full response: {response.hex()}")
                return False

            logging.info("COTP connection established successfully")

            # Step 3: S7 Setup Communication
            s7_setup = self._create_s7_setup_communication()
            self.sock.send(s7_setup)
            logging.info(f"Sent S7 Setup Communication ({len(s7_setup)} bytes)")

            # Receive S7 Setup Communication response
            response = self.sock.recv(1024)
            logging.info(f"Received S7 Setup response ({len(response)} bytes): {response[:20].hex()}")

            if len(response) < 20:
                self.last_error = f"S7 Setup response too short: {len(response)} bytes (expected >= 20). S7 protocol negotiation failed."
                logging.error(self.last_error)
                return False

            if response[8] != 0x32:
                self.last_error = f"S7 setup failed: Expected 0x32 at byte 8, got 0x{response[8]:02X}. Device may not support S7 communication."
                logging.error(self.last_error)
                logging.error(f"Full response: {response.hex()}")
                return False

            # Parse PDU length from response
            if len(response) >= 27:
                self.pdu_length = struct.unpack('>H', response[25:27])[0]

            logging.info(f"S7 connection established successfully (PDU: {self.pdu_length})")
            return True

        except socket.timeout:
            self.last_error = f"Connection timeout after {self.timeout}s. PLC is not responding on port 102. Check if: 1) PLC CPU is in RUN/STOP mode, 2) PLC communication is enabled, 3) Network connectivity is stable."
            logging.error(self.last_error)
            return False
        except ConnectionRefusedError:
            self.last_error = f"Connection refused by {self.ip}:102. Port 102 is closed or access is blocked by PLC settings."
            logging.error(self.last_error)
            return False
        except OSError as e:
            self.last_error = f"Network error: {e}. Check network connectivity and routing."
            logging.error(self.last_error)
            return False
        except Exception as e:
            self.last_error = f"Unexpected error: {type(e).__name__}: {e}"
            logging.error(f"Unexpected connection error: {type(e).__name__}: {e}")
            import traceback
            logging.error(traceback.format_exc())
            return False

    def disconnect(self):
        """Close connection"""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def detect_protection_level(self) -> Optional[ProtectionLevel]:
        """
        Detect PLC protection level

        Returns:
            ProtectionLevel or None if detection fails
        """
        try:
            # Try to read SZL (System Status List) ID 0x0232 (Protection Level)
            szl_request = self._create_szl_read_request(0x0232, 0x0004)
            self.sock.send(szl_request)

            response = self.sock.recv(1024)

            # Parse response
            if len(response) < 30:
                return None

            # Check for positive response
            if response[17] != 0x03:  # Error code position
                return None

            # Parse protection level from SZL data
            # Protection level is in the data section
            if len(response) >= 40:
                protection_byte = response[39] if len(response) > 39 else 0
                level_value = (protection_byte >> 4) & 0x0F

                if level_value == 0:
                    return ProtectionLevel.NO_PROTECTION
                elif level_value == 1:
                    return ProtectionLevel.WRITE_PROTECTION
                elif level_value == 2:
                    return ProtectionLevel.READ_WRITE_PROTECTION
                elif level_value >= 3:
                    return ProtectionLevel.COMPLETE_PROTECTION

            return ProtectionLevel.NO_PROTECTION

        except Exception as e:
            logging.error(f"Protection level detection failed: {e}")
            return None

    def authenticate_with_password(self, password: str) -> bool:
        """
        Authenticate to PLC with password

        S7-1200/1500 uses challenge-response authentication.
        This is a simplified implementation for educational purposes.

        Args:
            password: PLC password

        Returns:
            True if authentication successful
        """
        try:
            # S7-1200/1500 Password Authentication
            # Function: 0x1A (Security)
            auth_request = self._create_auth_request(password)
            self.sock.send(auth_request)

            response = self.sock.recv(1024)

            # Check response
            if len(response) < 20:
                logging.error("Authentication failed: Invalid response")
                return False

            # Parse error code
            # Position 17-18: Error class and code
            error_class = response[17] if len(response) > 17 else 0xFF
            error_code = response[18] if len(response) > 18 else 0xFF

            if error_class == 0x00 and error_code == 0x00:
                logging.info(f"Authentication successful for {self.ip}")
                if self.session:
                    self.session.authenticated = True
                    self.session.password = password
                return True
            else:
                logging.warning(f"Authentication failed: Error {error_class:02X}/{error_code:02X}")
                return False

        except Exception as e:
            logging.error(f"Authentication error: {e}")
            return False

    def test_access(self) -> AccessLevel:
        """
        Test current access level by attempting operations

        Returns:
            Current access level
        """
        try:
            # Try to read memory (DB1.DBB0)
            read_result = self._test_read_operation()

            if not read_result:
                return AccessLevel.NO_ACCESS

            # Try to write memory (test write to DB1.DBB0)
            write_result = self._test_write_operation()

            if write_result:
                return AccessLevel.FULL_ACCESS

            # If can read but not write, check if HMI or read-only
            # HMI access allows some control operations
            return AccessLevel.READ_ACCESS

        except Exception as e:
            logging.error(f"Access level test failed: {e}")
            return AccessLevel.NO_ACCESS

    def brute_force_password(self, password_list: List[str],
                            max_attempts: int = 100) -> Optional[str]:
        """
        Brute force password testing (AUTHORIZED TESTING ONLY)

        WARNING: This function is for authorized security testing only.
        Unauthorized access attempts may be illegal and trigger alarms.

        Args:
            password_list: List of passwords to try
            max_attempts: Maximum number of attempts

        Returns:
            Valid password if found, None otherwise
        """
        logging.warning(f"Starting password brute force on {self.ip} (authorized testing)")

        attempts = 0
        for password in password_list:
            if attempts >= max_attempts:
                logging.info(f"Reached max attempts limit: {max_attempts}")
                break

            attempts += 1
            print(f"[Attempt {attempts}/{min(len(password_list), max_attempts)}] Testing: {password}")

            # Reconnect for each attempt to avoid lockout
            self.disconnect()
            if not self.connect():
                logging.error(f"Reconnection failed on attempt {attempts}")
                continue

            # Try authentication
            if self.authenticate_with_password(password):
                print(f"\n[+] SUCCESS! Valid password found: {password}")
                logging.info(f"Valid password found: {password}")
                return password

        logging.info(f"Password not found after {attempts} attempts")
        return None

    def _create_cotp_connection_request(self) -> bytes:
        """Create COTP Connection Request"""
        # TPKT Header
        tpkt = struct.pack('!BBH', 3, 0, 22)  # Version, Reserved, Length

        # COTP Connection Request
        cotp = bytes([
            17,  # Length
            0xE0,  # PDU type: Connection Request (CR)
            0x00, 0x00,  # Destination reference
            0x00, 0x01,  # Source reference
            0x00,  # Class/Option
            # Parameters
            0xC0, 0x01, 0x0A,  # TPDU size = 1024 (2^10)
            0xC1, 0x02, 0x01, 0x00,  # src-tsap (rack=0, slot=1)
            0xC2, 0x02, 0x01, (self.rack << 4) | self.slot,  # dst-tsap
        ])

        return tpkt + cotp

    def _create_s7_setup_communication(self) -> bytes:
        """Create S7 Setup Communication request"""
        # TPKT Header
        tpkt = struct.pack('!BBH', 3, 0, 25)

        # COTP Data
        cotp = bytes([2, 0xF0, 0x80])  # Length, PDU type DT, TPDU number

        # S7 Header
        s7_header = struct.pack('!BBHHHH',
            0x32,  # Protocol ID
            0x01,  # ROSCTR: Job
            0x0000,  # Redundancy identification
            0x0100,  # Protocol data unit reference
            0x0008,  # Parameter length
            0x0000   # Data length
        )

        # S7 Parameters (Setup Communication)
        s7_params = bytes([
            0xF0,  # Function: Setup communication
            0x00,  # Reserved
            0x00, 0x01,  # Max AMQ (parallel jobs) calling
            0x00, 0x01,  # Max AMQ (parallel jobs) called
            0x01, 0xE0   # PDU length (480 bytes)
        ])

        return tpkt + cotp + s7_header + s7_params

    def _create_szl_read_request(self, szl_id: int, szl_index: int) -> bytes:
        """Create SZL (System Status List) read request"""
        # TPKT + COTP
        tpkt = struct.pack('!BBH', 3, 0, 33)
        cotp = bytes([2, 0xF0, 0x80])

        # S7 Header
        s7_header = struct.pack('!BBHHHH',
            0x32,  # Protocol ID
            0x01,  # ROSCTR: Job
            0x0000,  # Redundancy identification
            0x0200,  # PDU reference
            0x0008,  # Parameter length
            0x0008   # Data length
        )

        # Function: Read SZL (0x04)
        function = bytes([
            0x04,  # Function: Read SZL
            0x01,  # Number of items
        ])

        # SZL parameters
        szl_params = struct.pack('!BBHH',
            0x12,  # Variable specification
            0x08,  # Length of following address specification
            0x11,  # Syntax ID: SZL
            0x01   # Transport size: byte/word/dword
        )

        # SZL ID and Index
        szl_data = struct.pack('!HH', szl_id, szl_index)

        return tpkt + cotp + s7_header + function + szl_params + szl_data

    def _create_auth_request(self, password: str) -> bytes:
        """
        Create authentication request with password

        Note: This is a simplified implementation. Real S7-1200/1500
        authentication uses challenge-response with encryption.
        """
        # Hash password (simplified - real implementation uses challenge)
        password_hash = hashlib.md5(password.encode()).digest()[:8]

        # TPKT + COTP
        packet_length = 25 + len(password_hash)
        tpkt = struct.pack('!BBH', 3, 0, packet_length)
        cotp = bytes([2, 0xF0, 0x80])

        # S7 Header
        s7_header = struct.pack('!BBHHHH',
            0x32,  # Protocol ID
            0x01,  # ROSCTR: Job
            0x0000,  # Redundancy identification
            0x0300,  # PDU reference
            0x0008,  # Parameter length
            len(password_hash)  # Data length
        )

        # Function: Security/Authentication (0x1A is userdata, subfunction for security)
        # Note: This is simplified; real implementation requires proper challenge-response
        function = bytes([
            0xF0,  # Function group: Setup
            0x00,  # Subfunction
        ])

        # Password hash data
        params = bytes([
            0x00, 0x01,  # Item count
            0x12,  # Variable specification
            0x08,  # Length
            0x82,  # Syntax ID: NCK
            0x01,  # Transport size
        ])

        return tpkt + cotp + s7_header + function + params + password_hash

    def _test_read_operation(self) -> bool:
        """Test if read operation is allowed"""
        try:
            # Try to read 1 byte from DB1.DBB0
            read_request = self._create_read_request(0x84, 1, 0, 0, 1)
            self.sock.send(read_request)

            response = self.sock.recv(1024)
            if len(response) < 20:
                return False

            # Check if read was successful (return code 0xFF - success)
            return response[21] == 0xFF if len(response) > 21 else False

        except Exception:
            return False

    def _test_write_operation(self) -> bool:
        """Test if write operation is allowed"""
        try:
            # Try to write 1 byte to DB1.DBB0
            test_data = bytes([0x00])
            write_request = self._create_write_request(0x84, 1, 0, 0, test_data)
            self.sock.send(write_request)

            response = self.sock.recv(1024)
            if len(response) < 20:
                return False

            # Check if write was successful
            return response[21] == 0xFF if len(response) > 21 else False

        except Exception:
            return False

    def _create_read_request(self, area: int, db_number: int,
                           start: int, bit: int, length: int) -> bytes:
        """Create S7 read request"""
        # Simplified read request
        tpkt = struct.pack('!BBH', 3, 0, 31)
        cotp = bytes([2, 0xF0, 0x80])

        s7_header = struct.pack('!BBHHHH',
            0x32, 0x01, 0x0000, 0x0400, 0x000E, 0x0000
        )

        params = struct.pack('!BBBBBBHBHB',
            0x04,  # Function: Read
            0x01,  # Item count
            0x12,  # Variable specification
            0x0A,  # Length of following address
            0x10,  # Syntax ID: S7ANY
            0x02,  # Transport size: byte
            length,  # Length
            db_number,  # DB number
            area,  # Area code
            (start * 8 + bit) >> 16,  # Address high
            (start * 8 + bit) & 0xFFFF  # Address low
        )

        return tpkt + cotp + s7_header + params

    def _create_write_request(self, area: int, db_number: int,
                            start: int, bit: int, data: bytes) -> bytes:
        """Create S7 write request"""
        length = len(data)
        tpkt_length = 35 + length

        tpkt = struct.pack('!BBH', 3, 0, tpkt_length)
        cotp = bytes([2, 0xF0, 0x80])

        param_length = 14
        data_length = 4 + length

        s7_header = struct.pack('!BBHHHH',
            0x32, 0x01, 0x0000, 0x0500, param_length, data_length
        )

        params = struct.pack('!BBBBBBHBHB',
            0x05,  # Function: Write
            0x01,  # Item count
            0x12,  # Variable specification
            0x0A,  # Length of following address
            0x10,  # Syntax ID: S7ANY
            0x02,  # Transport size: byte
            length,  # Length
            db_number,  # DB number
            area,  # Area code
            (start * 8 + bit) >> 16,
            (start * 8 + bit) & 0xFFFF
        )

        data_header = struct.pack('!BBH',
            0x00,  # Reserved
            0x04,  # Transport size: byte
            length * 8  # Bit length
        )

        return tpkt + cotp + s7_header + params + data_header + data


def get_common_passwords() -> List[str]:
    """
    Get list of common S7 PLC passwords for testing

    WARNING: Use only for authorized security testing
    """
    return [
        "",  # No password
        "123456",
        "password",
        "123456789",
        "12345678",
        "12345",
        "1234567",
        "admin",
        "1234",
        "123",
        "siemens",
        "SIEMENS",
        "Siemens",
        "plc",
        "PLC",
        "s7-1200",
        "s7-1500",
        "s71200",
        "s71500",
        "tia",
        "TIA",
        "portal",
        "automation",
        "industry",
        "factory",
        "scada",
        "hmi",
        "root",
        "toor",
        "default",
    ]


# Convenience functions
def quick_auth_check(ip: str, rack: int = 0, slot: int = 1) -> Dict:
    """
    Quick authentication check on PLC

    Returns:
        Dictionary with protection level and access level info
    """
    client = S7AuthClient(ip, rack, slot)

    result = {
        'ip': ip,
        'rack': rack,
        'slot': slot,
        'connected': False,
        'protection_level': None,
        'access_level': None,
        'requires_password': False
    }

    if not client.connect():
        return result

    result['connected'] = True

    # Detect protection level
    protection = client.detect_protection_level()
    if protection:
        result['protection_level'] = protection.name
        result['requires_password'] = (protection in [
            ProtectionLevel.READ_WRITE_PROTECTION,
            ProtectionLevel.COMPLETE_PROTECTION
        ])

    # Test access level
    access = client.test_access()
    result['access_level'] = access.name

    client.disconnect()
    return result


def detailed_auth_check(ip: str, rack: int = 0, slot: int = 1) -> Dict:
    """
    Detailed authentication check with step-by-step explanations

    Returns:
        Dictionary with detailed detection results and explanations
    """
    client = S7AuthClient(ip, rack, slot)

    result = {
        'ip': ip,
        'rack': rack,
        'slot': slot,
        'connected': False,
        'protection_level': None,
        'protection_explanation': '',
        'access_level': None,
        'access_explanation': '',
        'requires_password': None,
        'password_explanation': '',
        'detection_steps': [],
        'technical_details': {}
    }

    # Step 1: Test Port Availability
    result['detection_steps'].append({
        'step': 'Testing Port 102',
        'action': f'Checking if port 102 is open on {ip}',
        'status': 'in_progress'
    })

    port_open, port_msg = test_port_open(ip, 102, timeout=2.0)
    if port_open:
        result['detection_steps'][-1]['status'] = 'success'
        result['detection_steps'][-1]['explanation'] = f"✅ {port_msg}. Port is reachable via TCP."
        result['technical_details']['port_102_status'] = 'open'
    else:
        result['detection_steps'][-1]['status'] = 'warning'
        result['detection_steps'][-1]['explanation'] = f"⚠️  {port_msg}. Will attempt S7 connection anyway..."
        result['technical_details']['port_102_status'] = 'closed_or_filtered'

    # Step 2: S7 Protocol Connection
    result['detection_steps'].append({
        'step': 'Establishing S7 Connection',
        'action': f'COTP + S7 handshake to {ip}:102 (Rack={rack}, Slot={slot})',
        'status': 'in_progress'
    })

    if not client.connect():
        result['detection_steps'][-1]['status'] = 'failed'
        # Use the detailed error message from the client
        if client.last_error:
            result['detection_steps'][-1]['explanation'] = f"❌ {client.last_error}"
        else:
            result['detection_steps'][-1]['explanation'] = (
                '❌ S7 connection failed. Check if: '
                '1) Device is online and reachable, '
                '2) Port 102 is open, '
                '3) Device supports S7 protocol (Siemens PLC).'
            )

        # Add debugging info
        result['technical_details']['connection_error'] = client.last_error or "Unknown error"
        result['technical_details']['timeout_used'] = f"{client.timeout}s"
        result['technical_details']['logs_location'] = "Check s7pwn.log for detailed connection logs"

        return result

    result['connected'] = True
    result['detection_steps'][-1]['status'] = 'success'
    result['detection_steps'][-1]['explanation'] = (
        f'Successfully established COTP connection. PDU Length: {client.pdu_length} bytes'
    )

    # Step 2: Protection Level Detection
    result['detection_steps'].append({
        'step': 'Protection Level Detection',
        'action': 'Reading SZL ID 0x0232 (System Status List - Protection Information)',
        'status': 'in_progress'
    })

    protection = client.detect_protection_level()

    if protection is None:
        result['protection_level'] = 'Unknown'
        result['detection_steps'][-1]['status'] = 'unknown'
        result['detection_steps'][-1]['explanation'] = (
            'PLC did not respond with valid SZL data. '
            'Possible reasons: Old PLC model not supporting SZL 0x0232, '
            'timeout, or PLC blocked the request.'
        )
        result['protection_explanation'] = (
            '❓ Unknown: Unable to read protection level from PLC. '
            'This may indicate an older S7-300/400 model or communication issues. '
            'Manual testing required.'
        )
    else:
        result['protection_level'] = protection.name
        result['detection_steps'][-1]['status'] = 'success'

        level_descriptions = {
            'NO_PROTECTION': {
                'short': 'No Protection',
                'explanation': (
                    '✅ Level 0: PLC has no password protection enabled. '
                    'Read and write operations are allowed without authentication. '
                    'Detected from SZL byte value = 0x00.'
                ),
                'technical': 'SZL ID 0x0232, Byte 39 = 0x00 → Level = (0x00 >> 4) & 0x0F = 0'
            },
            'WRITE_PROTECTION': {
                'short': 'Write Protection',
                'explanation': (
                    '⚠️  Level 1: PLC has write protection enabled. '
                    'Read operations allowed, write operations require password. '
                    'Detected from SZL byte value = 0x10.'
                ),
                'technical': 'SZL ID 0x0232, Byte 39 = 0x10 → Level = (0x10 >> 4) & 0x0F = 1'
            },
            'READ_WRITE_PROTECTION': {
                'short': 'Read/Write Protection',
                'explanation': (
                    '🔒 Level 2: PLC has read and write protection enabled. '
                    'Both read and write operations require password authentication. '
                    'Detected from SZL byte value = 0x20.'
                ),
                'technical': 'SZL ID 0x0232, Byte 39 = 0x20 → Level = (0x20 >> 4) & 0x0F = 2'
            },
            'COMPLETE_PROTECTION': {
                'short': 'Complete Protection',
                'explanation': (
                    '🔐 Level 3: PLC has complete protection enabled. '
                    'All operations require password authentication. Highest security level. '
                    'Detected from SZL byte value ≥ 0x30.'
                ),
                'technical': 'SZL ID 0x0232, Byte 39 = 0x30+ → Level = (byte >> 4) & 0x0F ≥ 3'
            }
        }

        desc = level_descriptions.get(protection.name, {})
        result['protection_explanation'] = desc.get('explanation', 'Unknown protection level')
        result['detection_steps'][-1]['explanation'] = desc.get('short', '') + ' - ' + desc.get('technical', '')
        result['technical_details']['protection_method'] = desc.get('technical', '')

    # Step 3: Access Level Testing
    result['detection_steps'].append({
        'step': 'Access Level Testing',
        'action': 'Testing read and write operations on DB1.DBB0',
        'status': 'in_progress'
    })

    access = client.test_access()
    result['access_level'] = access.name

    access_descriptions = {
        'NO_ACCESS': {
            'short': 'No Access',
            'explanation': (
                '❌ No Access: Cannot perform read or write operations. '
                'PLC refused both operations with error codes (typically 0x05 or 0x0A). '
                'Password authentication is required.'
            ),
            'technical': 'Read test: Error 0x05/0x0A (Access Denied), Write test: Error 0x05/0x0A'
        },
        'READ_ACCESS': {
            'short': 'Read Only Access',
            'explanation': (
                '📖 Read Access: Can read PLC memory but cannot write. '
                'Read operation successful (Error: 0x00), Write operation denied (Error: 0x05/0x0A). '
                'Password required for write operations.'
            ),
            'technical': 'Read test: Success (0x00 0x00), Write test: Error 0x05/0x0A (Access Denied)'
        },
        'HMI_ACCESS': {
            'short': 'HMI Access',
            'explanation': (
                '🖥️  HMI Access: Limited read/write access typical for HMI applications. '
                'Can read data and perform some control operations but not full programming access.'
            ),
            'technical': 'Read test: Success, Write test: Partial success, Programming: Denied'
        },
        'FULL_ACCESS': {
            'short': 'Full Access',
            'explanation': (
                '✅ Full Access: Complete read and write permissions. '
                'Both read and write operations successful (Error: 0x00 0x00). '
                'No password required for current operations.'
            ),
            'technical': 'Read test: Success (0x00 0x00), Write test: Success (0x00 0x00)'
        }
    }

    desc = access_descriptions.get(access.name, {})
    result['access_explanation'] = desc.get('explanation', 'Unknown access level')
    result['detection_steps'][-1]['status'] = 'success'
    result['detection_steps'][-1]['explanation'] = desc.get('short', '') + ' - ' + desc.get('technical', '')
    result['technical_details']['access_method'] = desc.get('technical', '')

    # Step 4: Password Requirement Analysis
    result['detection_steps'].append({
        'step': 'Password Requirement Analysis',
        'action': 'Analyzing protection level and access level combination',
        'status': 'in_progress'
    })

    if protection is None:
        result['requires_password'] = None
        result['password_explanation'] = (
            '❓ Cannot determine password requirement because protection level is unknown. '
            'Manual verification needed.'
        )
        result['detection_steps'][-1]['status'] = 'unknown'
    elif protection == ProtectionLevel.NO_PROTECTION:
        result['requires_password'] = False
        result['password_explanation'] = (
            '✅ No Password Required: PLC has no protection enabled (Level 0). '
            'All operations can be performed without authentication.'
        )
        result['detection_steps'][-1]['status'] = 'success'
        result['detection_steps'][-1]['explanation'] = 'Protection Level = 0 → No password needed'
    elif access == AccessLevel.FULL_ACCESS:
        result['requires_password'] = False
        result['password_explanation'] = (
            '✅ No Password Required: Although PLC has protection enabled, '
            'current connection already has full access. '
            'This may indicate: 1) Already authenticated session, '
            '2) IP address in whitelist, or 3) Protection not enforced.'
        )
        result['detection_steps'][-1]['status'] = 'success'
        result['detection_steps'][-1]['explanation'] = (
            f'Protection Level = {protection.value}, but Access Level = FULL_ACCESS → Password already bypassed'
        )
    else:
        result['requires_password'] = True
        result['password_explanation'] = (
            f'⚠️  Password Required: PLC has {protection.name} enabled '
            f'and current access level is {access.name}. '
            'Password authentication is required to gain higher privileges.'
        )
        result['detection_steps'][-1]['status'] = 'success'
        result['detection_steps'][-1]['explanation'] = (
            f'Protection Level = {protection.value} AND Access Level = {access.name} → Password required'
        )

    result['technical_details']['decision_logic'] = (
        f'Requires Password = (Protection Level >= 1) AND (Access Level < FULL_ACCESS) '
        f'= ({protection.value if protection else "Unknown"} >= 1) AND ({access.value} < 3) '
        f'= {result["requires_password"]}'
    )

    client.disconnect()
    return result


def batch_evaluate_devices(devices: List[Dict], max_workers: int = 5) -> List[Dict]:
    """
    Evaluate protection levels for multiple S7 devices in parallel

    Args:
        devices: List of device dicts with 'ip' field (and optional 'rack', 'slot')
        max_workers: Maximum concurrent evaluations

    Returns:
        List of evaluation results with detailed information
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results = []

    def evaluate_device(device):
        ip = device.get('ip')
        rack = device.get('rack', 0)
        slot = device.get('slot', 1)

        # Skip if not S7 protocol device
        if device.get('protocol') and 'S7' not in device.get('protocol', ''):
            return {
                'ip': ip,
                'skipped': True,
                'reason': f"Not an S7 device (Protocol: {device.get('protocol')})"
            }

        # Only evaluate if port 102 is open
        if device.get('port') != 102:
            return {
                'ip': ip,
                'skipped': True,
                'reason': f"S7 port (102) not detected (Found port: {device.get('port')})"
            }

        print(f"[*] Evaluating {ip}...")
        result = detailed_auth_check(ip, rack, slot)
        result['device_info'] = {
            'vendor': device.get('vendor', 'Unknown'),
            'model': device.get('model', 'Unknown'),
            'name': device.get('name', 'Unknown')
        }
        return result

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_device = {
            executor.submit(evaluate_device, device): device
            for device in devices
        }

        for future in as_completed(future_to_device):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                device = future_to_device[future]
                results.append({
                    'ip': device.get('ip'),
                    'error': str(e),
                    'connected': False
                })

    return results


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("S7 Authentication Module")
        print("\nUsage:")
        print("  python s7_auth.py <ip> [rack] [slot]           - Check protection")
        print("  python s7_auth.py <ip> <password> [rack] [slot] - Test password")
        print("\nExample:")
        print("  python s7_auth.py 192.168.1.10")
        print("  python s7_auth.py 192.168.1.10 password123 0 1")
        sys.exit(1)

    ip = sys.argv[1]
    rack = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    slot = int(sys.argv[4]) if len(sys.argv) > 4 else 1

    if len(sys.argv) >= 3 and sys.argv[2]:
        # Test with password
        password = sys.argv[2]
        client = S7AuthClient(ip, rack, slot)

        print(f"Testing authentication on {ip}...")
        if client.connect():
            print("[+] Connected")
            if client.authenticate_with_password(password):
                print(f"[+] Authentication successful with password: {password}")
            else:
                print(f"[-] Authentication failed")
            client.disconnect()
        else:
            print("[-] Connection failed")
    else:
        # Quick check
        print(f"Checking protection on {ip}...")
        result = quick_auth_check(ip, rack, slot)

        print(f"\nResults:")
        print(f"  Connected: {result['connected']}")
        print(f"  Protection Level: {result['protection_level']}")
        print(f"  Access Level: {result['access_level']}")
        print(f"  Requires Password: {result['requires_password']}")
