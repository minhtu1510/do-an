"""Packet Capture Engine for OT/ICS protocols"""

from typing import Optional, List, Callable, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import threading
import time

from scapy.all import sniff, wrpcap, PacketList, Packet, Ether, IP, TCP, UDP
from scapy.packet import Raw

from icsscout.utils.logger import get_logger, get_audit_logger
from icsscout.utils.errors import CaptureError
from icsscout.domain import Device


@dataclass
class CaptureStatistics:
    """Statistics for captured packets"""
    total_packets: int = 0
    protocols: Dict[str, int] = field(default_factory=dict)
    devices: Dict[str, int] = field(default_factory=dict)  # IP -> packet count
    bytes_captured: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'total_packets': self.total_packets,
            'protocols': self.protocols,
            'devices': self.devices,
            'bytes_captured': self.bytes_captured,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0
        }


@dataclass
class CapturedPacket:
    """Represents a captured packet with parsed information"""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    size: int
    raw_packet: Packet
    parsed_data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'size': self.size,
            'parsed_data': self.parsed_data
        }


class PacketCaptureEngine:
    """
    Advanced packet capture engine for OT/ICS protocols

    Features:
    - Non-intrusive passive monitoring
    - Real-time protocol parsing
    - Statistical analysis
    - PCAP export
    - Filter support
    """

    # Common OT/ICS ports
    OT_PORTS = {
        102: 'S7',
        502: 'Modbus TCP',
        4840: 'OPC UA',
        44818: 'EtherNet/IP',
        47808: 'BACnet',
        20000: 'DNP3',
        2404: 'IEC 60870-5-104',
        1200: 'S7 Communication'
    }

    def __init__(self, interface: Optional[str] = None):
        """
        Initialize packet capture engine

        Args:
            interface: Network interface to capture on (None = auto-detect)
        """
        self.interface = interface
        self.logger = get_logger('PacketCapture')
        self.audit = get_audit_logger()

        # Capture state
        self.is_capturing = False
        self.capture_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()

        # Captured data
        self.packets: List[CapturedPacket] = []
        self.raw_packets: PacketList = PacketList()
        self.statistics = CaptureStatistics()

        # Callbacks
        self.packet_callbacks: List[Callable] = []

        # Filters
        self.bpf_filter: Optional[str] = None
        self.protocol_filter: List[str] = []

    def start_capture(self,
                     duration: Optional[int] = None,
                     packet_count: Optional[int] = None,
                     filter_expression: Optional[str] = None,
                     protocols: Optional[List[str]] = None) -> None:
        """
        Start packet capture

        Args:
            duration: Capture duration in seconds (None = continuous)
            packet_count: Max packets to capture (None = unlimited)
            filter_expression: BPF filter (e.g., "tcp port 102 or tcp port 502")
            protocols: Protocol filter list (e.g., ["S7", "Modbus"])
        """
        if self.is_capturing:
            raise CaptureError("Capture already in progress")

        # Set filters
        if filter_expression is None:
            # None = use default OT/ICS protocol filter
            self.bpf_filter = self._build_default_filter()
        elif filter_expression == "":
            # Empty string = capture ALL traffic (no filter)
            self.bpf_filter = None
        else:
            # Custom BPF filter
            self.bpf_filter = filter_expression

        self.protocol_filter = protocols or []

        # Reset state
        self.packets.clear()
        self.raw_packets = PacketList()
        self.statistics = CaptureStatistics()
        self.statistics.start_time = datetime.now()
        self.stop_event.clear()

        # Log capture start
        self.logger.info(f"Starting packet capture on {self.interface or 'default interface'}")
        if self.bpf_filter is None:
            self.logger.info("Filter: NONE (Capturing ALL network traffic)")
        else:
            self.logger.info(f"Filter: {self.bpf_filter}")
        self.audit.log_operation(
            'CAPTURE_START',
            self.interface or 'auto',
            {'filter': self.bpf_filter, 'duration': duration, 'max_packets': packet_count}
        )

        # Start capture thread
        self.is_capturing = True
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(duration, packet_count),
            daemon=True
        )
        self.capture_thread.start()

    def stop_capture(self) -> CaptureStatistics:
        """
        Stop packet capture

        Returns:
            Capture statistics
        """
        if not self.is_capturing:
            return self.statistics

        self.logger.info("Stopping packet capture...")
        self.stop_event.set()

        # Wait for capture thread to finish
        if self.capture_thread:
            self.capture_thread.join(timeout=5)

        self.is_capturing = False
        self.statistics.end_time = datetime.now()

        # Log statistics
        self.logger.info(f"Capture complete: {self.statistics.total_packets} packets, "
                        f"{self.statistics.bytes_captured} bytes")
        self.audit.log_operation(
            'CAPTURE_STOP',
            self.interface or 'auto',
            self.statistics.to_dict()
        )

        return self.statistics

    def _capture_loop(self, duration: Optional[int], packet_count: Optional[int]) -> None:
        """Main capture loop (runs in thread)"""
        try:
            # Calculate stop condition
            stop_time = None
            if duration:
                stop_time = time.time() + duration

            packets_captured = 0

            def packet_handler(pkt: Packet):
                nonlocal packets_captured

                # Check stop conditions
                if self.stop_event.is_set():
                    return True  # Stop sniffing

                if stop_time and time.time() >= stop_time:
                    self.logger.info("Duration reached, stopping capture")
                    return True

                if packet_count and packets_captured >= packet_count:
                    self.logger.info("Packet count reached, stopping capture")
                    return True

                # Process packet
                self._process_packet(pkt)
                packets_captured += 1

                return False

            # Start sniffing
            sniff(
                iface=self.interface,
                prn=packet_handler,
                filter=self.bpf_filter,
                store=False,  # Don't store in memory (we handle it)
                stop_filter=packet_handler
            )

        except Exception as e:
            self.logger.error(f"Capture error: {e}")
            raise CaptureError(f"Packet capture failed: {e}")
        finally:
            self.is_capturing = False

    def _process_packet(self, pkt: Packet) -> None:
        """Process captured packet"""
        try:
            # Extract basic info
            if not pkt.haslayer(IP):
                return  # Skip non-IP packets

            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            # Extract transport layer info
            src_port = None
            dst_port = None
            protocol = "Unknown"

            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                protocol = self._identify_protocol(dst_port)
            elif pkt.haslayer(UDP):
                udp_layer = pkt[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                protocol = "UDP"

            # Apply protocol filter
            if self.protocol_filter and protocol not in self.protocol_filter:
                return

            # Create captured packet
            captured = CapturedPacket(
                timestamp=datetime.now(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                size=len(pkt),
                raw_packet=pkt
            )

            # Try to parse protocol-specific data
            if pkt.haslayer(Raw):
                captured.parsed_data = self._parse_protocol_data(protocol, pkt[Raw].load)

            # Store packet
            self.packets.append(captured)
            self.raw_packets.append(pkt)

            # Update statistics
            self.statistics.total_packets += 1
            self.statistics.bytes_captured += len(pkt)
            self.statistics.protocols[protocol] = self.statistics.protocols.get(protocol, 0) + 1
            self.statistics.devices[src_ip] = self.statistics.devices.get(src_ip, 0) + 1

            # Call callbacks
            for callback in self.packet_callbacks:
                try:
                    callback(captured)
                except Exception as e:
                    self.logger.warning(f"Callback error: {e}")

        except Exception as e:
            self.logger.warning(f"Packet processing error: {e}")

    def _identify_protocol(self, port: int) -> str:
        """Identify protocol by port number"""
        return self.OT_PORTS.get(port, f"TCP:{port}")

    def _parse_protocol_data(self, protocol: str, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse protocol-specific data

        This is a basic parser - will be enhanced by protocol parser module
        """
        try:
            if protocol == "S7":
                return self._parse_s7_basic(data)
            elif protocol == "Modbus TCP":
                return self._parse_modbus_basic(data)
            elif protocol == "OPC UA":
                return self._parse_opcua_basic(data)
        except:
            pass

        return None

    def _parse_s7_basic(self, data: bytes) -> Dict[str, Any]:
        """Basic S7 protocol parsing"""
        # S7 TPKT header: Version(1) + Reserved(1) + Length(2)
        if len(data) < 4:
            return {}

        version = data[0]
        length = (data[2] << 8) | data[3]

        return {
            'tpkt_version': version,
            'length': length,
            'data_preview': data[:16].hex()
        }

    def _parse_modbus_basic(self, data: bytes) -> Dict[str, Any]:
        """Basic Modbus TCP parsing"""
        # Modbus TCP: Transaction ID(2) + Protocol ID(2) + Length(2) + Unit ID(1) + Function Code(1)
        if len(data) < 8:
            return {}

        transaction_id = (data[0] << 8) | data[1]
        protocol_id = (data[2] << 8) | data[3]
        length = (data[4] << 8) | data[5]
        unit_id = data[6]
        function_code = data[7]

        function_names = {
            1: "Read Coils",
            2: "Read Discrete Inputs",
            3: "Read Holding Registers",
            4: "Read Input Registers",
            5: "Write Single Coil",
            6: "Write Single Register",
            15: "Write Multiple Coils",
            16: "Write Multiple Registers"
        }

        return {
            'transaction_id': transaction_id,
            'protocol_id': protocol_id,
            'length': length,
            'unit_id': unit_id,
            'function_code': function_code,
            'function_name': function_names.get(function_code, f"Unknown({function_code})")
        }

    def _parse_opcua_basic(self, data: bytes) -> Dict[str, Any]:
        """Basic OPC UA parsing"""
        # OPC UA message header
        if len(data) < 8:
            return {}

        # Message type (3 bytes) + Chunk type (1 byte) + Message size (4 bytes)
        msg_type = data[:3].decode('ascii', errors='ignore')
        chunk_type = chr(data[3])
        msg_size = int.from_bytes(data[4:8], 'little')

        return {
            'message_type': msg_type,
            'chunk_type': chunk_type,
            'message_size': msg_size
        }

    def _build_default_filter(self) -> str:
        """Build default BPF filter for OT protocols"""
        # Filter for common OT ports
        port_filters = [f"tcp port {port}" for port in self.OT_PORTS.keys()]
        return " or ".join(port_filters)

    def export_pcap(self, filepath: str) -> None:
        """
        Export captured packets to PCAP file

        Args:
            filepath: Output PCAP file path
        """
        try:
            output_path = Path(filepath)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            wrpcap(str(output_path), self.raw_packets)

            self.logger.info(f"Exported {len(self.raw_packets)} packets to {filepath}")
            self.audit.log_operation('PCAP_EXPORT', str(output_path), {
                'packet_count': len(self.raw_packets),
                'size_bytes': output_path.stat().st_size if output_path.exists() else 0
            })

        except Exception as e:
            self.logger.error(f"PCAP export failed: {e}")
            raise CaptureError(f"Failed to export PCAP: {e}")

    def get_protocols_detected(self) -> List[str]:
        """Get list of protocols detected in capture"""
        return list(self.statistics.protocols.keys())

    def get_devices_communicating(self) -> List[str]:
        """Get list of device IPs that were communicating"""
        return list(self.statistics.devices.keys())

    def get_packets_by_protocol(self, protocol: str) -> List[CapturedPacket]:
        """Get packets filtered by protocol"""
        return [p for p in self.packets if p.protocol == protocol]

    def get_packets_by_device(self, ip: str) -> List[CapturedPacket]:
        """Get packets involving specific device"""
        return [p for p in self.packets if p.src_ip == ip or p.dst_ip == ip]

    def add_packet_callback(self, callback: Callable[[CapturedPacket], None]) -> None:
        """
        Add callback to be called for each captured packet

        Args:
            callback: Function that takes CapturedPacket as argument
        """
        self.packet_callbacks.append(callback)

    def get_statistics(self) -> CaptureStatistics:
        """Get current capture statistics"""
        return self.statistics

    def get_communication_pairs(self) -> List[tuple]:
        """
        Get list of communicating device pairs

        Returns:
            List of (src_ip, dst_ip, protocol, packet_count) tuples
        """
        pairs = {}
        for pkt in self.packets:
            key = (pkt.src_ip, pkt.dst_ip, pkt.protocol)
            pairs[key] = pairs.get(key, 0) + 1

        return [(src, dst, proto, count) for (src, dst, proto), count in pairs.items()]

    def __str__(self) -> str:
        """String representation"""
        status = "capturing" if self.is_capturing else "stopped"
        return f"PacketCapture({status}, {self.statistics.total_packets} packets)"
