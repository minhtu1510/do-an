"""Protocol domain models"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ProtocolType(Enum):
    """Supported protocol types"""
    S7 = "S7"
    S7_PLUS = "S7-PLUS"
    LOGO = "Logo!"
    MODBUS_TCP = "Modbus TCP"
    MODBUS_RTU = "Modbus RTU"
    OPC_UA = "OPC UA"
    PROFINET = "Profinet"
    ETHERNET_IP = "EtherNet/IP"
    BACNET = "BACnet"
    DNP3 = "DNP3"
    IEC104 = "IEC 60870-5-104"
    UNKNOWN = "Unknown"


@dataclass
class Protocol:
    """
    Represents a communication protocol
    """
    protocol_type: ProtocolType
    port: int
    encrypted: bool = False
    version: Optional[str] = None

    def __post_init__(self):
        """Post-initialization"""
        if isinstance(self.protocol_type, str):
            self.protocol_type = ProtocolType(self.protocol_type)

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'protocol': self.protocol_type.value,
            'port': self.port,
            'encrypted': self.encrypted,
            'version': self.version
        }

    def __str__(self) -> str:
        """String representation"""
        enc = " (encrypted)" if self.encrypted else ""
        ver = f" v{self.version}" if self.version else ""
        return f"{self.protocol_type.value}{ver} on port {self.port}{enc}"


# Protocol port mappings
PROTOCOL_PORTS = {
    ProtocolType.S7: 102,
    ProtocolType.S7_PLUS: 102,
    ProtocolType.MODBUS_TCP: 502,
    ProtocolType.OPC_UA: 4840,
    ProtocolType.ETHERNET_IP: 44818,
    ProtocolType.BACNET: 47808,
    ProtocolType.DNP3: 20000,
    ProtocolType.IEC104: 2404,
}


def detect_protocol_by_port(port: int) -> Optional[ProtocolType]:
    """
    Detect protocol by port number

    Args:
        port: Port number

    Returns:
        Protocol type or None
    """
    for proto, proto_port in PROTOCOL_PORTS.items():
        if port == proto_port:
            return proto
    return None
