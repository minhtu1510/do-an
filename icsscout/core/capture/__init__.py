"""Packet Capture and Traffic Analysis Module"""

from icsscout.core.capture.packet_capture import (
    PacketCaptureEngine,
    CapturedPacket,
    CaptureStatistics
)
from icsscout.core.capture.traffic_analyzer import TrafficAnalyzer
from icsscout.core.capture.protocol_dissector import (
    DissectorRegistry,
    S7Dissector,
    ModbusDissector,
    OPCUADissector
)

__all__ = [
    'PacketCaptureEngine',
    'CapturedPacket',
    'CaptureStatistics',
    'TrafficAnalyzer',
    'DissectorRegistry',
    'S7Dissector',
    'ModbusDissector',
    'OPCUADissector'
]
