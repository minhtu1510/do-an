"""Device domain models"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime


class DeviceType(Enum):
    """Device type enumeration"""
    PLC = "PLC"
    HMI = "HMI"
    RTU = "RTU"
    SCADA = "SCADA"
    SWITCH = "Switch"
    ROUTER = "Router"
    GATEWAY = "Gateway"
    SENSOR = "Sensor"
    ACTUATOR = "Actuator"
    UNKNOWN = "Unknown"


class DeviceStatus(Enum):
    """Device status enumeration"""
    ONLINE = "Online"
    OFFLINE = "Offline"
    UNREACHABLE = "Unreachable"
    UNKNOWN = "Unknown"


@dataclass
class Device:
    """
    Represents an industrial control device
    """
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vendor: str = "Unknown"
    model: str = "Unknown"
    device_type: DeviceType = DeviceType.UNKNOWN
    status: DeviceStatus = DeviceStatus.UNKNOWN

    # Protocol information
    protocols: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)

    # Firmware/version info
    firmware_version: Optional[str] = None
    serial_number: Optional[str] = None

    # PLC-specific
    rack: Optional[int] = None
    slot: Optional[int] = None
    cpu_state: Optional[str] = None

    # Network info
    ttl: Optional[int] = None
    os_guess: Optional[str] = None

    # Timestamps
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)

    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Post-initialization processing"""
        if isinstance(self.device_type, str):
            self.device_type = DeviceType(self.device_type)
        if isinstance(self.status, str):
            self.status = DeviceStatus(self.status)

    def to_dict(self) -> dict:
        """Convert device to dictionary"""
        return {
            'ip': self.ip,
            'mac': self.mac,
            'hostname': self.hostname,
            'vendor': self.vendor,
            'model': self.model,
            'device_type': self.device_type.value,
            'status': self.status.value,
            'protocols': self.protocols,
            'open_ports': self.open_ports,
            'firmware_version': self.firmware_version,
            'serial_number': self.serial_number,
            'rack': self.rack,
            'slot': self.slot,
            'cpu_state': self.cpu_state,
            'ttl': self.ttl,
            'os_guess': self.os_guess,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'metadata': self.metadata
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Device':
        """Create device from dictionary"""
        device_type = DeviceType(data.get('device_type', 'Unknown'))
        status = DeviceStatus(data.get('status', 'Unknown'))

        return cls(
            ip=data['ip'],
            mac=data.get('mac'),
            hostname=data.get('hostname'),
            vendor=data.get('vendor', 'Unknown'),
            model=data.get('model', 'Unknown'),
            device_type=device_type,
            status=status,
            protocols=data.get('protocols', []),
            open_ports=data.get('open_ports', []),
            firmware_version=data.get('firmware_version'),
            serial_number=data.get('serial_number'),
            rack=data.get('rack'),
            slot=data.get('slot'),
            cpu_state=data.get('cpu_state'),
            ttl=data.get('ttl'),
            os_guess=data.get('os_guess'),
            first_seen=datetime.fromisoformat(data['first_seen']) if 'first_seen' in data else datetime.now(),
            last_seen=datetime.fromisoformat(data['last_seen']) if 'last_seen' in data else datetime.now(),
            metadata=data.get('metadata', {})
        )

    def update_last_seen(self):
        """Update last seen timestamp"""
        self.last_seen = datetime.now()

    def add_protocol(self, protocol: str):
        """Add protocol to device"""
        if protocol not in self.protocols:
            self.protocols.append(protocol)

    def add_port(self, port: int):
        """Add open port to device"""
        if port not in self.open_ports:
            self.open_ports.append(port)

    def is_plc(self) -> bool:
        """Check if device is a PLC"""
        return self.device_type == DeviceType.PLC

    def is_online(self) -> bool:
        """Check if device is online"""
        return self.status == DeviceStatus.ONLINE

    def supports_protocol(self, protocol: str) -> bool:
        """Check if device supports protocol"""
        return protocol.upper() in [p.upper() for p in self.protocols]

    def __str__(self) -> str:
        """String representation"""
        return f"{self.vendor} {self.model} @ {self.ip} ({self.device_type.value})"

    def __repr__(self) -> str:
        """Debug representation"""
        return f"Device(ip='{self.ip}', vendor='{self.vendor}', model='{self.model}', type={self.device_type})"
