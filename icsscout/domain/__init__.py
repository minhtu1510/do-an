"""Domain models for ICSScout"""

from icsscout.domain.device import Device, DeviceType, DeviceStatus
from icsscout.domain.protocol import Protocol, ProtocolType
from icsscout.domain.target import Target
from icsscout.domain.memory import MemoryAddress, MemoryArea, DataType
from icsscout.domain.result import Result, OperationResult
from icsscout.domain.vulnerability import Vulnerability, VulnerabilityReport, Severity

__all__ = [
    'Device',
    'DeviceType',
    'DeviceStatus',
    'Protocol',
    'ProtocolType',
    'Target',
    'MemoryAddress',
    'MemoryArea',
    'DataType',
    'Result',
    'OperationResult',
    'Vulnerability',
    'VulnerabilityReport',
    'Severity'
]
