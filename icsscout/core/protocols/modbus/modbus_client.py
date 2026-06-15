"""Modbus TCP Protocol Client"""

from typing import Optional, Dict, Any, List
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException
import struct

from icsscout.core.protocols.base import BaseProtocolClient, ConnectionState
from icsscout.domain import Target, Result
from icsscout.utils.errors import ConnectionError as ICSConnectionError, ProtocolError
from icsscout.utils.logger import get_logger


class ModbusClient(BaseProtocolClient):
    """
    Modbus TCP Protocol Client

    Supports reading/writing:
    - Coils (discrete outputs) - 0x
    - Discrete Inputs - 1x
    - Input Registers - 3x
    - Holding Registers - 4x
    """

    def __init__(self, target: Target):
        """
        Initialize Modbus client

        Args:
            target: Target device with IP, port, unit_id
        """
        super().__init__(target)
        self.client: Optional[ModbusTcpClient] = None
        self.logger = get_logger('ModbusClient')
        self.unit_id = target.unit_id

    def connect(self) -> Result:
        """
        Connect to Modbus device

        Returns:
            Result indicating connection success/failure
        """
        try:
            self.state = ConnectionState.CONNECTING
            self.logger.info(f"Connecting to {self.target.connection_string()}")

            # Create Modbus TCP client
            self.client = ModbusTcpClient(
                host=self.target.device.ip,
                port=self.target.port or 502,
                timeout=5
            )

            # Connect
            if not self.client.connect():
                self.state = ConnectionState.ERROR
                self.last_error = "Connection failed"
                return Result.error("Connection failed")

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
        Disconnect from Modbus device

        Returns:
            Result indicating disconnection success
        """
        try:
            if self.client:
                self.client.close()
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
        Read data from Modbus device

        Args:
            address: Modbus address (e.g., "40001" for holding register 1)
            data_type: Data type (coil, register, int16, float32)
            count: Number of elements to read

        Returns:
            Result with read data
        """
        try:
            # Ensure connected
            result = self.ensure_connected()
            if not result.success:
                return result

            # Parse Modbus address
            addr_info = self._parse_modbus_address(address)
            if not addr_info:
                return Result.error(f"Invalid Modbus address: {address}")

            reg_type, reg_addr = addr_info

            # Read based on register type
            if reg_type == 'coil':
                response = self.client.read_coils(reg_addr, count, slave=self.unit_id)
            elif reg_type == 'discrete_input':
                response = self.client.read_discrete_inputs(reg_addr, count, slave=self.unit_id)
            elif reg_type == 'input_register':
                response = self.client.read_input_registers(reg_addr, count, slave=self.unit_id)
            elif reg_type == 'holding_register':
                response = self.client.read_holding_registers(reg_addr, count, slave=self.unit_id)
            else:
                return Result.error(f"Unknown register type: {reg_type}")

            # Check for errors
            if response.isError():
                return Result.error(f"Modbus read error: {response}")

            # Parse response based on data type
            if reg_type in ('coil', 'discrete_input'):
                value = response.bits[:count]
            else:
                value = self._parse_registers(response.registers, data_type, count)

            return Result.ok(
                f"Read {address}: {value}",
                data=value,
                address=address,
                data_type=data_type
            )

        except ModbusException as e:
            self.logger.error(f"Modbus read failed: {e}")
            return Result.error(f"Modbus read failed: {e}")
        except Exception as e:
            self.logger.error(f"Read failed: {e}")
            return Result.error(f"Read failed: {e}")

    def write(self, address: str, value: Any, data_type: str) -> Result:
        """
        Write data to Modbus device

        Args:
            address: Modbus address
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

            # Parse Modbus address
            addr_info = self._parse_modbus_address(address)
            if not addr_info:
                return Result.error(f"Invalid Modbus address: {address}")

            reg_type, reg_addr = addr_info

            # Write based on register type
            if reg_type == 'coil':
                response = self.client.write_coil(reg_addr, bool(value), slave=self.unit_id)
            elif reg_type == 'holding_register':
                if data_type.lower() in ('int16', 'uint16', 'word'):
                    response = self.client.write_register(reg_addr, int(value), slave=self.unit_id)
                else:
                    # Multi-register write (float, int32, etc.)
                    registers = self._value_to_registers(value, data_type)
                    response = self.client.write_registers(reg_addr, registers, slave=self.unit_id)
            else:
                return Result.error(f"Cannot write to {reg_type}")

            # Check for errors
            if response.isError():
                return Result.error(f"Modbus write error: {response}")

            self.logger.info(f"Wrote {address} = {value}")
            return Result.ok(f"Wrote {address} = {value}")

        except ModbusException as e:
            self.logger.error(f"Modbus write failed: {e}")
            return Result.error(f"Modbus write failed: {e}")
        except Exception as e:
            self.logger.error(f"Write failed: {e}")
            return Result.error(f"Write failed: {e}")

    def get_device_info(self) -> Result:
        """
        Get Modbus device information

        Returns:
            Result with device information dict
        """
        try:
            # Ensure connected
            result = self.ensure_connected()
            if not result.success:
                return result

            info = {
                'protocol': 'Modbus TCP',
                'ip': self.target.device.ip,
                'port': self.target.port,
                'unit_id': self.unit_id,
                'connected': self.is_connected()
            }

            # Try to read device identification (if supported)
            try:
                # Function code 0x2B/0x0E (Read Device Identification)
                # Not all devices support this
                response = self.client.execute(0x2B)
                if not response.isError():
                    info['supports_device_id'] = True
                    # Parse device ID response...
            except:
                info['supports_device_id'] = False

            return Result.ok("Device info retrieved", data=info)

        except Exception as e:
            self.logger.error(f"Failed to get device info: {e}")
            return Result.error(f"Failed to get device info: {e}")

    def scan_unit_ids(self, start: int = 1, end: int = 247) -> Result:
        """
        Scan for available Modbus unit IDs

        Args:
            start: Start unit ID
            end: End unit ID

        Returns:
            Result with list of responding unit IDs
        """
        try:
            result = self.ensure_connected()
            if not result.success:
                return result

            active_units = []
            self.logger.info(f"Scanning unit IDs {start}-{end}...")

            for unit_id in range(start, end + 1):
                try:
                    # Try to read one holding register
                    response = self.client.read_holding_registers(0, 1, slave=unit_id)
                    if not response.isError():
                        active_units.append(unit_id)
                        self.logger.info(f"Found active unit ID: {unit_id}")
                except:
                    pass

            return Result.ok(
                f"Found {len(active_units)} active unit IDs",
                data=active_units
            )

        except Exception as e:
            return Result.error(f"Unit ID scan failed: {e}")

    def _parse_modbus_address(self, address: str) -> Optional[tuple]:
        """
        Parse Modbus address string

        Formats:
        - 00001-09999: Coils
        - 10001-19999: Discrete Inputs
        - 30001-39999: Input Registers
        - 40001-49999: Holding Registers

        Returns:
            Tuple of (register_type, address) or None
        """
        # Try to parse as 5-digit format
        if address.isdigit() and len(address) == 5:
            prefix = address[0]
            addr = int(address[1:]) - 1  # Modbus addresses are 0-indexed internally

            type_map = {
                '0': 'coil',
                '1': 'discrete_input',
                '3': 'input_register',
                '4': 'holding_register'
            }

            reg_type = type_map.get(prefix)
            if reg_type:
                return (reg_type, addr)

        # Try simple numeric address (assume holding register)
        if address.isdigit():
            return ('holding_register', int(address))

        return None

    def _parse_registers(self, registers: List[int], data_type: str, count: int) -> Any:
        """Parse register values based on data type"""
        dt = data_type.lower()

        if dt in ('int16', 'word', 'register'):
            if count == 1:
                return registers[0]
            return registers[:count]

        elif dt == 'uint16':
            if count == 1:
                return registers[0] & 0xFFFF
            return [r & 0xFFFF for r in registers[:count]]

        elif dt == 'int32':
            # Combine two registers (big-endian)
            value = (registers[0] << 16) | registers[1]
            # Convert to signed
            if value >= 0x80000000:
                value -= 0x100000000
            return value

        elif dt == 'uint32':
            return (registers[0] << 16) | registers[1]

        elif dt in ('float32', 'real'):
            # Combine two registers to float (big-endian)
            bytes_data = struct.pack('>HH', registers[0], registers[1])
            return struct.unpack('>f', bytes_data)[0]

        else:
            # Return raw registers
            return registers[:count]

    def _value_to_registers(self, value: Any, data_type: str) -> List[int]:
        """Convert value to register list"""
        dt = data_type.lower()

        if dt in ('int16', 'word'):
            return [int(value) & 0xFFFF]

        elif dt == 'int32':
            val = int(value)
            return [(val >> 16) & 0xFFFF, val & 0xFFFF]

        elif dt == 'uint32':
            val = int(value) & 0xFFFFFFFF
            return [(val >> 16) & 0xFFFF, val & 0xFFFF]

        elif dt in ('float32', 'real'):
            bytes_data = struct.pack('>f', float(value))
            return list(struct.unpack('>HH', bytes_data))

        else:
            # Assume single register
            return [int(value) & 0xFFFF]
