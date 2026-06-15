"""Safe Memory Dumper for PLC Devices"""

from typing import Optional, Dict, List, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import struct
import json
import time

from icsscout.core.protocols.base import BaseProtocolClient
from icsscout.domain import Target, MemoryArea, Device
from icsscout.utils.logger import get_logger, get_audit_logger
from icsscout.utils.errors import MemoryError


@dataclass
class MemoryDump:
    """Represents a complete memory dump from a device"""
    device: Device
    timestamp: datetime
    areas: Dict[str, bytes] = field(default_factory=dict)
    data_blocks: Dict[int, bytes] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary (without binary data)"""
        return {
            'device': self.device.to_dict(),
            'timestamp': self.timestamp.isoformat(),
            'areas': {area: len(data) for area, data in self.areas.items()},
            'data_blocks': {db_num: len(data) for db_num, data in self.data_blocks.items()},
            'metadata': self.metadata,
            'total_size_bytes': self.total_size()
        }

    def total_size(self) -> int:
        """Get total size in bytes"""
        size = sum(len(data) for data in self.areas.values())
        size += sum(len(data) for data in self.data_blocks.values())
        return size

    def save_to_file(self, filepath: str) -> None:
        """Save dump to binary file"""
        output_path = Path(filepath)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Create dump structure
        dump_data = {
            'metadata': self.to_dict(),
            'areas': {area: data.hex() for area, data in self.areas.items()},
            'data_blocks': {str(db_num): data.hex() for db_num, data in self.data_blocks.items()}
        }

        with open(output_path, 'w') as f:
            json.dump(dump_data, f, indent=2)

    @classmethod
    def load_from_file(cls, filepath: str) -> 'MemoryDump':
        """Load dump from file"""
        with open(filepath, 'r') as f:
            dump_data = json.load(f)

        # Reconstruct dump
        device = Device.from_dict(dump_data['metadata']['device'])
        timestamp = datetime.fromisoformat(dump_data['metadata']['timestamp'])

        dump = cls(device=device, timestamp=timestamp)

        # Restore areas
        for area, hex_data in dump_data.get('areas', {}).items():
            dump.areas[area] = bytes.fromhex(hex_data)

        # Restore data blocks
        for db_num_str, hex_data in dump_data.get('data_blocks', {}).items():
            dump.data_blocks[int(db_num_str)] = bytes.fromhex(hex_data)

        return dump


@dataclass
class MemoryAnalysis:
    """Results of memory dump analysis"""
    strings: List[str] = field(default_factory=list)
    integers: List[tuple] = field(default_factory=list)  # (offset, value)
    floats: List[tuple] = field(default_factory=list)
    patterns: List[Dict] = field(default_factory=list)
    interesting_data: List[Dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'strings': self.strings[:100],  # Limit output
            'integers': self.integers[:50],
            'floats': self.floats[:50],
            'patterns': self.patterns,
            'interesting_data': self.interesting_data
        }


class MemoryDumper:
    """
    Safe memory dumper for PLC devices

    Features:
    - Progress tracking
    - Configurable chunk sizes and delays
    - Safe mode with conservative parameters
    - Memory analysis tools
    """

    # Default memory sizes for different areas (bytes)
    DEFAULT_AREA_SIZES = {
        'M': 65536,  # Marker: 64 KB
        'I': 1024,   # Input: 1 KB
        'Q': 1024,   # Output: 1 KB
        'T': 2048,   # Timer: 2 KB
        'C': 2048,   # Counter: 2 KB
    }

    def __init__(self, client: BaseProtocolClient, safe_mode: bool = True):
        """
        Initialize memory dumper

        Args:
            client: Protocol client for device
            safe_mode: Use conservative parameters (slower but safer)
        """
        self.client = client
        self.safe_mode = safe_mode
        self.logger = get_logger('MemoryDumper')
        self.audit = get_audit_logger()

        # Configure based on safe mode
        if safe_mode:
            self.chunk_size = 64  # Small chunks
            self.delay = 0.1      # 100ms delay between reads
        else:
            self.chunk_size = 256
            self.delay = 0.01

        # Progress tracking
        self.progress_callback: Optional[Callable] = None
        self.bytes_dumped = 0
        self.total_bytes = 0

    def dump_all_memory(self,
                       areas: List[str] = None,
                       include_data_blocks: bool = True,
                       data_block_range: Optional[tuple] = None) -> MemoryDump:
        """
        Dump all accessible memory from PLC

        Args:
            areas: Memory areas to dump (default: ['M', 'I', 'Q'])
            include_data_blocks: Whether to dump data blocks
            data_block_range: (start_db, end_db) range for DBs

        Returns:
            MemoryDump object
        """
        if areas is None:
            areas = ['M', 'I', 'Q']

        self.logger.info(f"Starting memory dump (safe_mode={self.safe_mode})")
        self.audit.log_operation(
            'MEMORY_DUMP_START',
            str(self.client.target.device.ip),
            {'areas': areas, 'include_dbs': include_data_blocks, 'safe_mode': self.safe_mode}
        )

        # Calculate total size
        self.total_bytes = sum(self.DEFAULT_AREA_SIZES.get(area, 0) for area in areas)
        if include_data_blocks and data_block_range:
            # Estimate DB size (assume 1KB per DB)
            db_count = data_block_range[1] - data_block_range[0] + 1
            self.total_bytes += db_count * 1024

        self.bytes_dumped = 0

        # Create dump
        dump = MemoryDump(
            device=self.client.target.device,
            timestamp=datetime.now()
        )

        # Dump standard areas
        for area in areas:
            self.logger.info(f"Dumping {area} area...")
            try:
                data = self._dump_area(area)
                dump.areas[area] = data
                dump.metadata[f'{area}_size'] = len(data)
            except Exception as e:
                self.logger.error(f"Failed to dump {area} area: {e}")
                dump.metadata[f'{area}_error'] = str(e)

        # Dump data blocks
        if include_data_blocks:
            self.logger.info("Dumping data blocks...")
            try:
                db_list = self._enumerate_data_blocks(data_block_range)
                for db_num in db_list:
                    try:
                        data = self._dump_data_block(db_num)
                        dump.data_blocks[db_num] = data
                        self.logger.info(f"  DB{db_num}: {len(data)} bytes")
                    except Exception as e:
                        self.logger.warning(f"Failed to dump DB{db_num}: {e}")
            except Exception as e:
                self.logger.error(f"Failed to enumerate data blocks: {e}")

        # Finalize
        dump.metadata['dump_duration_seconds'] = (datetime.now() - dump.timestamp).total_seconds()
        dump.metadata['safe_mode'] = self.safe_mode
        dump.metadata['chunk_size'] = self.chunk_size

        self.logger.info(f"Memory dump complete: {dump.total_size()} bytes")
        self.audit.log_operation(
            'MEMORY_DUMP_COMPLETE',
            str(self.client.target.device.ip),
            dump.to_dict()
        )

        return dump

    def _dump_area(self, area: str) -> bytes:
        """Dump entire memory area"""
        area_size = self.DEFAULT_AREA_SIZES.get(area, 1024)
        data = bytearray()

        offset = 0
        while offset < area_size:
            # Calculate chunk size
            chunk = min(self.chunk_size, area_size - offset)

            try:
                # Read chunk
                address = f"{area}{offset}"
                result = self.client.read(address, 'byte', count=chunk)

                if result.success and result.data:
                    if isinstance(result.data, list):
                        data.extend(result.data)
                    else:
                        data.append(result.data)

                    self.bytes_dumped += chunk
                    self._update_progress()
                else:
                    # If read fails, fill with zeros
                    data.extend([0] * chunk)

            except Exception as e:
                self.logger.debug(f"Read failed at {address}: {e}")
                # Fill with zeros on error
                data.extend([0] * chunk)

            offset += chunk

            # Delay to avoid overloading PLC
            if self.delay > 0:
                time.sleep(self.delay)

        return bytes(data)

    def _enumerate_data_blocks(self, db_range: Optional[tuple] = None) -> List[int]:
        """
        Enumerate available data blocks

        Args:
            db_range: (start, end) range or None for auto-detection

        Returns:
            List of DB numbers
        """
        if db_range:
            return list(range(db_range[0], db_range[1] + 1))

        # Auto-detect by trying to read DB info
        # This is simplified - real implementation would query PLC
        db_list = []
        for db_num in range(1, 100):  # Try first 100 DBs
            try:
                # Try to read first byte
                result = self.client.read(f"DB{db_num}.DBB0", 'byte')
                if result.success:
                    db_list.append(db_num)
            except:
                pass

            # Small delay
            time.sleep(0.01)

        return db_list

    def _dump_data_block(self, db_num: int, max_size: int = 65536) -> bytes:
        """
        Dump data block

        Args:
            db_num: Data block number
            max_size: Maximum size to read

        Returns:
            Data block contents
        """
        data = bytearray()
        offset = 0

        while offset < max_size:
            chunk = min(self.chunk_size, max_size - offset)

            try:
                address = f"DB{db_num}.DBB{offset}"
                result = self.client.read(address, 'byte', count=chunk)

                if result.success and result.data:
                    if isinstance(result.data, list):
                        data.extend(result.data)
                    else:
                        data.append(result.data)

                    self.bytes_dumped += chunk
                    self._update_progress()
                else:
                    # End of DB reached
                    break

            except Exception as e:
                # End of DB or error
                break

            offset += chunk

            if self.delay > 0:
                time.sleep(self.delay)

        return bytes(data)

    def _update_progress(self) -> None:
        """Update progress and call callback if set"""
        if self.progress_callback and self.total_bytes > 0:
            progress = (self.bytes_dumped / self.total_bytes) * 100
            self.progress_callback(progress, self.bytes_dumped, self.total_bytes)

    def analyze_dump(self, dump: MemoryDump) -> MemoryAnalysis:
        """
        Analyze memory dump for interesting data

        Args:
            dump: Memory dump to analyze

        Returns:
            Memory analysis results
        """
        self.logger.info("Analyzing memory dump...")

        analysis = MemoryAnalysis()

        # Combine all data
        all_data = bytearray()
        for data in dump.areas.values():
            all_data.extend(data)
        for data in dump.data_blocks.values():
            all_data.extend(data)

        # Extract strings
        analysis.strings = self._extract_strings(all_data)
        self.logger.info(f"Found {len(analysis.strings)} strings")

        # Extract numeric values
        analysis.integers = self._extract_integers(all_data)
        analysis.floats = self._extract_floats(all_data)

        # Find patterns
        analysis.patterns = self._find_patterns(all_data)

        # Identify interesting data
        analysis.interesting_data = self._find_interesting_data(all_data, analysis.strings)

        return analysis

    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings from data"""
        strings = []
        current_string = []

        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string.append(chr(byte))
            else:
                if len(current_string) >= min_length:
                    strings.append(''.join(current_string))
                current_string = []

        # Don't forget last string
        if len(current_string) >= min_length:
            strings.append(''.join(current_string))

        return strings

    def _extract_integers(self, data: bytes) -> List[tuple]:
        """Extract integer values from data"""
        integers = []

        # Extract 16-bit integers
        for i in range(0, len(data) - 1, 2):
            try:
                value = struct.unpack('>h', data[i:i+2])[0]
                if value != 0:  # Skip zeros
                    integers.append((i, value))
            except:
                pass

        return integers[:100]  # Limit results

    def _extract_floats(self, data: bytes) -> List[tuple]:
        """Extract float values from data"""
        floats = []

        # Extract 32-bit floats
        for i in range(0, len(data) - 3, 4):
            try:
                value = struct.unpack('>f', data[i:i+4])[0]
                # Check if it's a reasonable float
                if -1e6 < value < 1e6 and value != 0:
                    floats.append((i, value))
            except:
                pass

        return floats[:100]

    def _find_patterns(self, data: bytes) -> List[Dict]:
        """Find repeated patterns in data"""
        patterns = []

        # Look for repeated byte sequences
        pattern_length = 4
        pattern_counts = {}

        for i in range(len(data) - pattern_length):
            pattern = data[i:i+pattern_length]
            pattern_hex = pattern.hex()
            pattern_counts[pattern_hex] = pattern_counts.get(pattern_hex, 0) + 1

        # Filter significant patterns
        for pattern_hex, count in pattern_counts.items():
            if count > 5:  # Repeated at least 5 times
                patterns.append({
                    'pattern': pattern_hex,
                    'count': count
                })

        return sorted(patterns, key=lambda x: x['count'], reverse=True)[:10]

    def _find_interesting_data(self, data: bytes, strings: List[str]) -> List[Dict]:
        """Identify potentially interesting data"""
        interesting = []

        # Look for IP addresses in strings
        import re
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

        for string in strings:
            if re.search(ip_pattern, string):
                interesting.append({
                    'type': 'IP_ADDRESS',
                    'value': string
                })

        # Look for timestamps
        timestamp_pattern = r'\d{4}-\d{2}-\d{2}'
        for string in strings:
            if re.search(timestamp_pattern, string):
                interesting.append({
                    'type': 'TIMESTAMP',
                    'value': string
                })

        # Look for common keywords
        keywords = ['PASSWORD', 'USER', 'ADMIN', 'KEY', 'SECRET', 'CONFIG', 'SETTINGS']
        for string in strings:
            for keyword in keywords:
                if keyword in string.upper():
                    interesting.append({
                        'type': 'KEYWORD',
                        'keyword': keyword,
                        'value': string
                    })
                    break

        return interesting[:50]  # Limit results

    def set_progress_callback(self, callback: Callable[[float, int, int], None]) -> None:
        """
        Set progress callback function

        Args:
            callback: Function(progress_percent, bytes_done, total_bytes)
        """
        self.progress_callback = callback
