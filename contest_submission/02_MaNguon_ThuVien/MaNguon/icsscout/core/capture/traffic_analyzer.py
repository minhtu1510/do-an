"""Traffic Analysis and Communication Mapping"""

from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

from icsscout.core.capture.packet_capture import CapturedPacket, PacketCaptureEngine
from icsscout.domain import Device, DeviceType
from icsscout.utils.logger import get_logger


@dataclass
class Communication:
    """Represents communication between two devices"""
    src_ip: str
    dst_ip: str
    protocol: str
    packet_count: int = 0
    bytes_transferred: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    src_ports: Set[int] = field(default_factory=set)
    dst_ports: Set[int] = field(default_factory=set)

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'protocol': self.protocol,
            'packet_count': self.packet_count,
            'bytes_transferred': self.bytes_transferred,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'src_ports': list(self.src_ports),
            'dst_ports': list(self.dst_ports)
        }


@dataclass
class MemoryOperation:
    """Represents a memory read/write operation extracted from traffic"""
    timestamp: datetime
    device_ip: str
    operation_type: str  # 'READ' or 'WRITE'
    protocol: str
    address: Optional[str] = None
    value: Optional[Any] = None
    data_type: Optional[str] = None
    success: bool = True

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'device_ip': self.device_ip,
            'operation_type': self.operation_type,
            'protocol': self.protocol,
            'address': self.address,
            'value': self.value,
            'data_type': self.data_type,
            'success': self.success
        }


@dataclass
class TrafficStatistics:
    """Detailed traffic statistics"""
    total_packets: int = 0
    total_bytes: int = 0
    protocols: Dict[str, int] = field(default_factory=dict)
    devices: Dict[str, int] = field(default_factory=dict)
    communications: List[Communication] = field(default_factory=list)
    memory_operations: List[MemoryOperation] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'protocols': self.protocols,
            'device_count': len(self.devices),
            'devices': self.devices,
            'communication_pairs': len(self.communications),
            'memory_operations_count': len(self.memory_operations),
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None
        }


class TrafficAnalyzer:
    """
    Advanced traffic analyzer for OT/ICS communications

    Features:
    - Communication pattern analysis
    - Device role identification
    - Memory operation extraction
    - Protocol behavior profiling
    """

    def __init__(self, capture_engine: Optional[PacketCaptureEngine] = None):
        """
        Initialize traffic analyzer

        Args:
            capture_engine: Optional packet capture engine to analyze
        """
        self.capture_engine = capture_engine
        self.logger = get_logger('TrafficAnalyzer')

        # Analysis data
        self.communications: Dict[tuple, Communication] = {}
        self.memory_operations: List[MemoryOperation] = []
        self.device_behaviors: Dict[str, Dict] = defaultdict(dict)

    def analyze_capture(self, packets: List[CapturedPacket]) -> TrafficStatistics:
        """
        Analyze captured packets

        Args:
            packets: List of captured packets

        Returns:
            Traffic statistics
        """
        self.logger.info(f"Analyzing {len(packets)} packets...")

        stats = TrafficStatistics()
        stats.start_time = packets[0].timestamp if packets else None
        stats.end_time = packets[-1].timestamp if packets else None

        for packet in packets:
            # Update basic statistics
            stats.total_packets += 1
            stats.total_bytes += packet.size

            # Count protocols
            stats.protocols[packet.protocol] = stats.protocols.get(packet.protocol, 0) + 1

            # Count devices
            stats.devices[packet.src_ip] = stats.devices.get(packet.src_ip, 0) + 1
            stats.devices[packet.dst_ip] = stats.devices.get(packet.dst_ip, 0) + 1

            # Track communications
            self._track_communication(packet)

            # Extract memory operations
            if packet.parsed_data:
                mem_op = self._extract_memory_operation(packet)
                if mem_op:
                    self.memory_operations.append(mem_op)
                    stats.memory_operations.append(mem_op)

        # Add communications to stats
        stats.communications = list(self.communications.values())

        self.logger.info(f"Analysis complete: {len(stats.communications)} communication pairs, "
                        f"{len(stats.memory_operations)} memory operations")

        return stats

    def _track_communication(self, packet: CapturedPacket) -> None:
        """Track communication between devices"""
        key = (packet.src_ip, packet.dst_ip, packet.protocol)

        if key not in self.communications:
            self.communications[key] = Communication(
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                protocol=packet.protocol,
                first_seen=packet.timestamp
            )

        comm = self.communications[key]
        comm.packet_count += 1
        comm.bytes_transferred += packet.size
        comm.last_seen = packet.timestamp

        if packet.src_port:
            comm.src_ports.add(packet.src_port)
        if packet.dst_port:
            comm.dst_ports.add(packet.dst_port)

    def _extract_memory_operation(self, packet: CapturedPacket) -> Optional[MemoryOperation]:
        """Extract memory operation from packet data"""
        try:
            if not packet.parsed_data:
                return None

            # Modbus memory operations
            if packet.protocol == "Modbus TCP":
                return self._extract_modbus_operation(packet)

            # S7 memory operations (basic detection)
            elif packet.protocol == "S7":
                return self._extract_s7_operation(packet)

        except Exception as e:
            self.logger.debug(f"Failed to extract memory operation: {e}")

        return None

    def _extract_modbus_operation(self, packet: CapturedPacket) -> Optional[MemoryOperation]:
        """Extract Modbus memory operation"""
        data = packet.parsed_data
        if not data or 'function_code' not in data:
            return None

        function_code = data['function_code']

        # Read operations: 1, 2, 3, 4
        # Write operations: 5, 6, 15, 16
        if function_code in (1, 2, 3, 4):
            op_type = 'READ'
        elif function_code in (5, 6, 15, 16):
            op_type = 'WRITE'
        else:
            return None

        return MemoryOperation(
            timestamp=packet.timestamp,
            device_ip=packet.dst_ip,  # Target device
            operation_type=op_type,
            protocol='Modbus',
            address=None,  # Would need deeper parsing
            value=None,
            data_type=None,
            success=True
        )

    def _extract_s7_operation(self, packet: CapturedPacket) -> Optional[MemoryOperation]:
        """Extract S7 memory operation (basic)"""
        # This would require deeper S7 protocol parsing
        # For now, just detect that S7 communication happened
        return MemoryOperation(
            timestamp=packet.timestamp,
            device_ip=packet.dst_ip,
            operation_type='UNKNOWN',
            protocol='S7',
            success=True
        )

    def identify_device_roles(self) -> Dict[str, str]:
        """
        Identify device roles based on communication patterns

        Returns:
            Dictionary mapping IP to role (SCADA, PLC, HMI, etc.)
        """
        roles = {}

        # Analyze communication patterns
        for comm in self.communications.values():
            src = comm.src_ip
            dst = comm.dst_ip

            # SCADA/HMI typically initiates many connections
            if src not in roles:
                outgoing = sum(1 for c in self.communications.values() if c.src_ip == src)
                incoming = sum(1 for c in self.communications.values() if c.dst_ip == src)

                if outgoing > incoming * 2:
                    roles[src] = 'SCADA/HMI'
                elif incoming > outgoing * 2:
                    roles[src] = 'PLC'
                else:
                    roles[src] = 'Unknown'

        return roles

    def get_communication_graph(self) -> Dict[str, List[Dict]]:
        """
        Get communication graph for visualization

        Returns:
            Dictionary with 'nodes' and 'edges' for graph visualization
        """
        nodes = set()
        edges = []

        for comm in self.communications.values():
            nodes.add(comm.src_ip)
            nodes.add(comm.dst_ip)

            edges.append({
                'source': comm.src_ip,
                'target': comm.dst_ip,
                'protocol': comm.protocol,
                'packets': comm.packet_count,
                'bytes': comm.bytes_transferred
            })

        # Identify roles
        roles = self.identify_device_roles()

        return {
            'nodes': [{'id': ip, 'role': roles.get(ip, 'Unknown')} for ip in nodes],
            'edges': edges
        }

    def get_timeline(self, interval_seconds: int = 60) -> List[Dict]:
        """
        Get traffic timeline aggregated by time intervals

        Args:
            interval_seconds: Interval size in seconds

        Returns:
            List of time interval statistics
        """
        if not self.communications:
            return []

        # Get time range
        all_comms = list(self.communications.values())
        start_time = min(c.first_seen for c in all_comms if c.first_seen)
        end_time = max(c.last_seen for c in all_comms if c.last_seen)

        # Create intervals
        timeline = []
        current = start_time

        while current < end_time:
            interval_end = current + datetime.timedelta(seconds=interval_seconds)

            # Count packets in this interval
            packet_count = 0
            bytes_count = 0

            for comm in all_comms:
                # This is simplified - would need packet-level timestamps
                if comm.first_seen and comm.first_seen >= current and comm.first_seen < interval_end:
                    packet_count += comm.packet_count
                    bytes_count += comm.bytes_transferred

            timeline.append({
                'timestamp': current.isoformat(),
                'packets': packet_count,
                'bytes': bytes_count
            })

            current = interval_end

        return timeline

    def get_protocol_distribution(self) -> Dict[str, float]:
        """
        Get protocol distribution as percentages

        Returns:
            Dictionary mapping protocol to percentage
        """
        total = sum(c.packet_count for c in self.communications.values())
        if total == 0:
            return {}

        protocol_counts = defaultdict(int)
        for comm in self.communications.values():
            protocol_counts[comm.protocol] += comm.packet_count

        return {
            protocol: (count / total) * 100
            for protocol, count in protocol_counts.items()
        }

    def get_busiest_devices(self, top_n: int = 10) -> List[tuple]:
        """
        Get busiest devices by packet count

        Args:
            top_n: Number of top devices to return

        Returns:
            List of (ip, packet_count) tuples
        """
        device_counts = defaultdict(int)

        for comm in self.communications.values():
            device_counts[comm.src_ip] += comm.packet_count
            device_counts[comm.dst_ip] += comm.packet_count

        sorted_devices = sorted(
            device_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return sorted_devices[:top_n]

    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """
        Detect potential anomalies in traffic

        Returns:
            List of detected anomalies
        """
        anomalies = []

        # Check for unusual port usage
        known_ports = {102, 502, 4840, 44818}
        for comm in self.communications.values():
            unknown_ports = comm.dst_ports - known_ports
            if unknown_ports:
                anomalies.append({
                    'type': 'UNUSUAL_PORT',
                    'severity': 'MEDIUM',
                    'description': f"Unusual ports detected: {unknown_ports}",
                    'src_ip': comm.src_ip,
                    'dst_ip': comm.dst_ip
                })

        # Check for devices with too many connections (potential scanner)
        device_connections = defaultdict(set)
        for comm in self.communications.values():
            device_connections[comm.src_ip].add(comm.dst_ip)

        for ip, targets in device_connections.items():
            if len(targets) > 20:  # Threshold for suspicious behavior
                anomalies.append({
                    'type': 'MANY_CONNECTIONS',
                    'severity': 'HIGH',
                    'description': f"Device connecting to {len(targets)} targets",
                    'device_ip': ip,
                    'target_count': len(targets)
                })

        # Check for write operations (if in read-only environment)
        write_ops = [op for op in self.memory_operations if op.operation_type == 'WRITE']
        if write_ops:
            anomalies.append({
                'type': 'WRITE_OPERATION',
                'severity': 'HIGH',
                'description': f"{len(write_ops)} write operations detected",
                'count': len(write_ops)
            })

        return anomalies

    def generate_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive traffic analysis report

        Returns:
            Complete analysis report as dictionary
        """
        return {
            'summary': {
                'total_communications': len(self.communications),
                'total_memory_operations': len(self.memory_operations),
                'unique_devices': len(set(c.src_ip for c in self.communications.values()) |
                                    set(c.dst_ip for c in self.communications.values())),
                'protocols': list(set(c.protocol for c in self.communications.values()))
            },
            'communications': [c.to_dict() for c in self.communications.values()],
            'memory_operations': [op.to_dict() for op in self.memory_operations],
            'device_roles': self.identify_device_roles(),
            'protocol_distribution': self.get_protocol_distribution(),
            'busiest_devices': [{'ip': ip, 'packet_count': count}
                               for ip, count in self.get_busiest_devices()],
            'anomalies': self.detect_anomalies(),
            'communication_graph': self.get_communication_graph()
        }
