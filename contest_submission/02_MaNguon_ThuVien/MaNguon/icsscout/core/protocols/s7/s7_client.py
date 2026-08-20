"""Siemens S7 Protocol Client (S7-300/400/1200/1500)"""

from typing import Optional, Dict, Any, List
from enum import IntEnum
from ctypes import c_int32, c_uint16, c_uint32
import snap7
import struct

# Handle different python-snap7 versions
try:
    # Try python-snap7 v1.x
    from snap7.snap7types import Areas
    from snap7.snap7types import Parameter
except (ImportError, AttributeError):
    try:
        # Try python-snap7 v2.x alternative location
        from snap7.types import Areas
        from snap7.types import Parameter
    except (ImportError, AttributeError):
        # Define Areas ourselves for python-snap7 v2.x
        class Areas:
            """S7 Area constants for python-snap7 v2.x"""
            PE = 0x81  # Process Input
            PA = 0x82  # Process Output
            MK = 0x83  # Marker/Memory
            DB = 0x84  # Data Block
            CT = 0x1C  # Counter
            TM = 0x1D  # Timer

        # Define Parameter constants for python-snap7 v2.x
        class Parameter(IntEnum):
            """S7 Parameter constants for python-snap7 v2.x"""
            LocalPort = 1
            RemotePort = 2
            PingTimeout = 3
            SendTimeout = 4
            RecvTimeout = 5
            WorkInterval = 6
            SrcRef = 7
            DstRef = 8
            SrcTSap = 9
            PDURequest = 10
            MaxClients = 11
            BSendTimeout = 12
            BRecvTimeout = 13
            RecoveryTime = 14
            KeepAliveTime = 15

            @property
            def ctype(self):
                """Return the appropriate ctypes type for this parameter"""
                map_ = {
                    self.LocalPort: c_uint16,
                    self.RemotePort: c_uint16,
                    self.PingTimeout: c_int32,
                    self.SendTimeout: c_int32,
                    self.RecvTimeout: c_int32,
                    self.WorkInterval: c_int32,
                    self.SrcRef: c_uint16,
                    self.DstRef: c_uint16,
                    self.SrcTSap: c_uint16,
                    self.PDURequest: c_int32,
                    self.MaxClients: c_int32,
                    self.BSendTimeout: c_int32,
                    self.BRecvTimeout: c_int32,
                    self.RecoveryTime: c_uint32,
                    self.KeepAliveTime: c_uint32,
                }
                return map_[self]

from icsscout.core.protocols.base import BaseProtocolClient, ConnectionState
from icsscout.domain import Target, Result, MemoryAddress, MemoryArea, DataType
from icsscout.utils.errors import ConnectionError as ICSConnectionError, ProtocolError
from icsscout.utils.logger import get_logger


class S7Client(BaseProtocolClient):
    """
    Siemens S7 Protocol Client

    Supports:
    - S7-300 (Rack 0, Slot 2)
    - S7-400 (Rack 0, Slot 2 or 3)
    - S7-1200 (Rack 0, Slot 1)
    - S7-1500 (Rack 0, Slot 1)
    """

    # Area mapping for snap7
    AREA_MAP = {
        MemoryArea.M: Areas.MK,    # Marker/Memory
        MemoryArea.I: Areas.PE,    # Process Input
        MemoryArea.Q: Areas.PA,    # Process Output
        MemoryArea.DB: Areas.DB,   # Data Block
        MemoryArea.T: Areas.TM,    # Timer
        MemoryArea.C: Areas.CT,    # Counter
    }

    def __init__(self, target: Target):
        """
        Initialize S7 client

        Args:
            target: Target device with IP, rack, slot
        """
        super().__init__(target)
        self.client: Optional[snap7.client.Client] = None
        self.logger = get_logger('S7Client')

    def connect(self) -> Result:
        """
        Connect to S7 PLC

        Returns:
            Result indicating connection success/failure
        """
        try:
            self.state = ConnectionState.CONNECTING
            self.logger.info(f"Connecting to {self.target.connection_string()}")

            # Create snap7 client
            self.client = snap7.client.Client()

            # Set connection timeouts (in milliseconds)
            # Increase timeouts to handle slower PLC connections
            try:
                # Use Parameter enums from snap7.types for proper parameter setting
                # PingTimeout - Time to wait for connection acknowledgment (default 750ms -> 5000ms)
                # SendTimeout - Time to wait for sending data (default 10000ms -> 15000ms)
                # RecvTimeout - Time to wait for receiving data (default 3000ms -> 10000ms)

                self.client.set_param(Parameter.PingTimeout, 5000)   # PingTimeout: 5 seconds
                self.client.set_param(Parameter.RecvTimeout, 10000)  # RecvTimeout: 10 seconds
                self.client.set_param(Parameter.SendTimeout, 15000)  # SendTimeout: 15 seconds

                self.logger.debug(f"Set connection timeouts: Ping=5s, Recv=10s, Send=15s")
            except Exception as e:
                self.logger.warning(f"Could not set timeouts (using defaults): {e}")

            # Connect
            self.client.connect(
                self.target.device.ip,
                self.target.rack,
                self.target.slot
            )

            # Verify connection
            if not self.client.get_connected():
                self.state = ConnectionState.ERROR
                self.last_error = "Connection failed - client not connected"
                return Result.error(self.last_error)

            self.state = ConnectionState.CONNECTED
            from datetime import datetime
            self.connected_at = datetime.now()

            self.logger.info(f"Connected successfully to {self.target.device.ip}")
            return Result.ok("Connected successfully")

        except Exception as e:
            self.state = ConnectionState.ERROR
            self.last_error = str(e)
            self.logger.error(f"Connection failed: {e}")
            return Result.error(f"Connection failed: {e}")

    def disconnect(self) -> Result:
        """
        Disconnect from S7 PLC

        Returns:
            Result indicating disconnection success
        """
        try:
            if self.client:
                self.client.disconnect()
                self.client = None

            self.state = ConnectionState.DISCONNECTED
            self.connected_at = None
            self.logger.info(f"Disconnected from {self.target.device.ip}")

            return Result.ok("Disconnected successfully")

        except Exception as e:
            self.logger.warning(f"Disconnect warning: {e}")
            return Result.ok("Disconnected (with warnings)")

    def read(self, address: str, data_type: str, count: int = 1) -> Result:
        """
        Read data from S7 PLC

        Args:
            address: Memory address (e.g., "M0.5", "MW10", "DB1.DBW0")
            data_type: Data type (bit, byte, int, dint, real)
            count: Number of elements to read

        Returns:
            Result with read data
        """
        try:
            # Ensure connected
            result = self.ensure_connected()
            if not result.success:
                return result

            # Parse address
            try:
                addr = MemoryAddress.from_string(address)
            except ValueError as e:
                return Result.error(f"Invalid address format: {e}")

            # Read based on area
            if addr.area == MemoryArea.DB:
                # Data block read
                data = self.client.db_read(
                    addr.db_number,
                    addr.byte_offset,
                    addr.size_in_bytes() * count
                )
            else:
                # Standard area read
                area_code = self.AREA_MAP.get(addr.area)
                if area_code is None:
                    return Result.error(f"Unsupported memory area: {addr.area}")

                data = self.client.read_area(
                    area_code,
                    0,  # DB number (not used for M/I/Q)
                    addr.byte_offset,
                    addr.size_in_bytes() * count
                )

            # Parse data based on type
            value = self._parse_data(data, data_type, addr.bit_offset, count)

            return Result.ok(
                f"Read {address}: {value}",
                data=value,
                address=address,
                data_type=data_type
            )

        except Exception as e:
            self.logger.error(f"Read failed: {e}")
            return Result.error(f"Read failed: {e}")

    def write(self, address: str, value: Any, data_type: str) -> Result:
        """
        Write data to S7 PLC

        Args:
            address: Memory address
            value: Value to write
            data_type: Data type

        Returns:
            Result indicating write success/failure
        """
        try:
            # Ensure connected
            result = self.ensure_connected()
            if not result.success:
                return result

            # Parse address
            try:
                addr = MemoryAddress.from_string(address)
            except ValueError as e:
                return Result.error(f"Invalid address format: {e}")

            # Convert value to bytes
            data = self._value_to_bytes(value, data_type, addr.bit_offset)

            # Write based on area
            if addr.area == MemoryArea.DB:
                # Data block write
                self.client.db_write(addr.db_number, addr.byte_offset, data)
            else:
                # Standard area write
                area_code = self.AREA_MAP.get(addr.area)
                if area_code is None:
                    return Result.error(f"Unsupported memory area: {addr.area}")

                self.client.write_area(
                    area_code,
                    0,
                    addr.byte_offset,
                    data
                )

            self.logger.info(f"Wrote {address} = {value}")
            return Result.ok(f"Wrote {address} = {value}")

        except Exception as e:
            self.logger.error(f"Write failed: {e}")
            return Result.error(f"Write failed: {e}")

    def get_device_info(self) -> Result:
        """
        Get PLC information (CPU info, state, etc.)

        Returns:
            Result with device information dict
        """
        try:
            # Ensure connected
            result = self.ensure_connected()
            if not result.success:
                return result

            # Get CPU info
            cpu_info = self.client.get_cpu_info()

            # Get CPU state
            cpu_state = self.client.get_cpu_state()

            # Convert to readable format
            def _decode(x):
                if isinstance(x, (bytes, bytearray)):
                    return x.decode('utf-8', errors='replace').strip('\x00')
                return str(x)

            # Extract firmware version from ModuleName or ModuleTypeName
            # Format usually: "CPU 1516-3 PN/DP V2.9" or similar
            firmware = "Unknown"
            module_name = _decode(cpu_info.ModuleName)
            module_type = _decode(cpu_info.ModuleTypeName)

            # Try to extract version from module name
            import re
            version_match = re.search(r'V\s*(\d+\.\d+(?:\.\d+)?)', module_name + ' ' + module_type, re.IGNORECASE)
            if version_match:
                firmware = 'V' + version_match.group(1)

            info = {
                'module_type': module_type,
                'serial_number': _decode(cpu_info.SerialNumber),
                'as_name': _decode(cpu_info.ASName),
                'copyright': _decode(cpu_info.Copyright),
                'module_name': module_name,
                'firmware': firmware,
                'cpu_state': self._decode_cpu_state(cpu_state),
                'rack': self.target.rack,
                'slot': self.target.slot
            }

            self.logger.info(f"Retrieved device info: {info['module_type']}")
            return Result.ok("Device info retrieved", data=info)

        except Exception as e:
            self.logger.error(f"Failed to get device info: {e}")
            return Result.error(f"Failed to get device info: {e}")

    def read_multiple(self, addresses: List[tuple]) -> Result:
        """
        Read multiple addresses in one call (efficient)

        Args:
            addresses: List of (address, data_type) tuples

        Returns:
            Result with dict of address:value pairs
        """
        try:
            result = self.ensure_connected()
            if not result.success:
                return result

            results = {}
            for address, data_type in addresses:
                read_result = self.read(address, data_type)
                if read_result.success:
                    results[address] = read_result.data
                else:
                    results[address] = None

            return Result.ok("Multiple read completed", data=results)

        except Exception as e:
            return Result.error(f"Multiple read failed: {e}")

    def _parse_data(self, data: bytearray, data_type: str, bit_offset: Optional[int], count: int) -> Any:
        """Parse raw data based on type"""
        dt = data_type.lower()

        if dt in ('bit', 'bool'):
            if bit_offset is None:
                bit_offset = 0
            byte_val = data[0]
            return bool((byte_val >> bit_offset) & 1)

        elif dt == 'byte':
            return data[0] if count == 1 else list(data[:count])

        elif dt == 'int':
            return struct.unpack('>h', data[:2])[0]  # Big-endian signed short

        elif dt == 'uint':
            return struct.unpack('>H', data[:2])[0]  # Big-endian unsigned short

        elif dt == 'dint':
            return struct.unpack('>i', data[:4])[0]  # Big-endian signed int

        elif dt == 'real':
            return struct.unpack('>f', data[:4])[0]  # Big-endian float

        elif dt == 'lreal':
            return struct.unpack('>d', data[:8])[0]  # Big-endian double

        elif dt == 'string':
            # S7 string format: [max_len][current_len][chars...]
            max_len = data[0]
            current_len = data[1]
            return data[2:2+current_len].decode('utf-8', errors='replace')

        else:
            # Return raw bytes
            return list(data[:count])

    def _value_to_bytes(self, value: Any, data_type: str, bit_offset: Optional[int] = None) -> bytearray:
        """Convert value to bytes for writing"""
        dt = data_type.lower()

        if dt in ('bit', 'bool'):
            # For bit write, need read-modify-write
            # This is simplified - real implementation should read first
            byte_val = 1 if value else 0
            if bit_offset:
                byte_val = byte_val << bit_offset
            return bytearray([byte_val])

        elif dt == 'byte':
            return bytearray([int(value)])

        elif dt == 'int':
            return bytearray(struct.pack('>h', int(value)))

        elif dt == 'uint':
            return bytearray(struct.pack('>H', int(value)))

        elif dt == 'dint':
            return bytearray(struct.pack('>i', int(value)))

        elif dt == 'real':
            return bytearray(struct.pack('>f', float(value)))

        elif dt == 'lreal':
            return bytearray(struct.pack('>d', float(value)))

        elif dt == 'string':
            # S7 string format
            str_bytes = value.encode('utf-8')
            max_len = 254
            current_len = min(len(str_bytes), max_len)
            result = bytearray([max_len, current_len]) + str_bytes[:current_len]
            return result

        else:
            # Assume list of bytes
            return bytearray(value)

    def _decode_cpu_state(self, state: int) -> str:
        """Decode CPU state code to string"""
        states = {
            0: "UNKNOWN",
            4: "STOP",
            8: "RUN"
        }
        return states.get(state, f"UNKNOWN({state})")

    def get_connection_params(self) -> Dict[str, Any]:
        """Get S7-specific connection parameters"""
        if not self.client:
            return {}

        try:
            # Try to get PDU size parameter - handle different snap7 versions
            try:
                from snap7.types import PduSizeRequested
                pdu_length = self.client.get_param(PduSizeRequested)
            except (ImportError, AttributeError):
                try:
                    from snap7.snap7types import PduSizeRequested
                    pdu_length = self.client.get_param(PduSizeRequested)
                except (ImportError, AttributeError):
                    # Fallback if parameter not available
                    pdu_length = None

            return {
                'pdu_length': pdu_length,
                'connected': self.client.get_connected(),
                'rack': self.target.rack,
                'slot': self.target.slot
            }
        except:
            return {}
