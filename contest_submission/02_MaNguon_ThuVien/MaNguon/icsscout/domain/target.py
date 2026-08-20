"""Target domain model"""

from dataclasses import dataclass
from typing import Optional
from icsscout.domain.device import Device
from icsscout.domain.protocol import ProtocolType


@dataclass
class Target:
    """
    Represents a target device for operations
    """
    device: Device
    protocol: ProtocolType

    # Connection parameters
    port: Optional[int] = None
    rack: int = 0
    slot: int = 1
    unit_id: int = 1  # For Modbus

    # Authentication
    username: Optional[str] = None
    password: Optional[str] = None

    # Connection state
    connected: bool = False

    def __post_init__(self):
        """Post-initialization"""
        # Set default port based on protocol
        if self.port is None:
            from icsscout.domain.protocol import PROTOCOL_PORTS
            self.port = PROTOCOL_PORTS.get(self.protocol, 102)

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'device': self.device.to_dict(),
            'protocol': self.protocol.value,
            'port': self.port,
            'rack': self.rack,
            'slot': self.slot,
            'unit_id': self.unit_id,
            'connected': self.connected
        }

    def connection_string(self) -> str:
        """Get connection string representation"""
        if self.protocol == ProtocolType.S7 or self.protocol == ProtocolType.S7_PLUS:
            return f"{self.device.ip}:{self.port} (Rack {self.rack}, Slot {self.slot})"
        elif self.protocol == ProtocolType.MODBUS_TCP:
            return f"{self.device.ip}:{self.port} (Unit {self.unit_id})"
        elif self.protocol == ProtocolType.OPC_UA:
            return f"opc.tcp://{self.device.ip}:{self.port}"
        else:
            return f"{self.device.ip}:{self.port}"

    def __str__(self) -> str:
        """String representation"""
        return f"Target({self.device.vendor} {self.device.model} @ {self.connection_string()})"

    def __repr__(self) -> str:
        """Debug representation"""
        return f"Target(device={self.device.ip}, protocol={self.protocol.value}, port={self.port})"
