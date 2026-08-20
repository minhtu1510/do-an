"""Memory address and data type models"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Any


class MemoryArea(Enum):
    """Memory area types for S7 PLCs"""
    M = "Marker/Memory"  # Merker
    I = "Input"  # Process Input
    Q = "Output"  # Process Output
    DB = "Data Block"  # Data Block
    T = "Timer"
    C = "Counter"
    PE = "Process Input"  # Peripheral Input
    PA = "Process Output"  # Peripheral Output


class DataType(Enum):
    """Data types for PLC memory"""
    BIT = "bit"
    BYTE = "byte"
    WORD = "word"
    DWORD = "dword"
    INT = "int"
    DINT = "dint"
    REAL = "real"
    STRING = "string"
    BOOL = "bool"


# Data type sizes in bytes
DATA_TYPE_SIZES = {
    DataType.BIT: 0,  # Bit is within a byte
    DataType.BYTE: 1,
    DataType.BOOL: 1,
    DataType.WORD: 2,
    DataType.INT: 2,
    DataType.DWORD: 4,
    DataType.DINT: 4,
    DataType.REAL: 4,
    DataType.STRING: None,  # Variable
}


@dataclass
class MemoryAddress:
    """
    Represents a memory address in a PLC
    """
    area: MemoryArea
    byte_offset: int
    bit_offset: Optional[int] = None
    data_type: DataType = DataType.BYTE
    db_number: Optional[int] = None

    # For array/string types
    length: Optional[int] = None

    def __post_init__(self):
        """Post-initialization"""
        if isinstance(self.area, str):
            self.area = MemoryArea[self.area]
        if isinstance(self.data_type, str):
            self.data_type = DataType(self.data_type)

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'area': self.area.name,
            'byte_offset': self.byte_offset,
            'bit_offset': self.bit_offset,
            'data_type': self.data_type.value,
            'db_number': self.db_number,
            'length': self.length
        }

    def to_string(self) -> str:
        """
        Convert to string representation

        Examples:
            M0.5 (bit)
            MW10 (word)
            DB1.DBW0 (data block word)
        """
        if self.area == MemoryArea.DB:
            prefix = f"DB{self.db_number}.DB"
        else:
            prefix = self.area.name

        if self.bit_offset is not None:
            return f"{prefix}{self.byte_offset}.{self.bit_offset}"
        elif self.data_type == DataType.WORD:
            return f"{prefix}W{self.byte_offset}"
        elif self.data_type == DataType.DWORD:
            return f"{prefix}D{self.byte_offset}"
        else:
            return f"{prefix}{self.byte_offset}"

    @classmethod
    def from_string(cls, address_str: str) -> 'MemoryAddress':
        """
        Parse address string to MemoryAddress

        Examples:
            M0.5 → MemoryAddress(M, 0, 5, BIT)
            MW10 → MemoryAddress(M, 10, None, WORD)
            DB1.DBW0 → MemoryAddress(DB, 0, None, WORD, 1)
        """
        from icsscout.utils.helpers import parse_address

        parsed = parse_address(address_str)
        if not parsed:
            raise ValueError(f"Invalid address format: {address_str}")

        area = MemoryArea[parsed['area']]
        byte_offset = parsed['byte']
        bit_offset = parsed.get('bit')
        db_number = parsed.get('db_number')

        # Determine data type
        type_map = {
            'bit': DataType.BIT,
            'byte': DataType.BYTE,
            'word': DataType.WORD,
            'dword': DataType.DWORD
        }
        data_type = type_map.get(parsed['type'], DataType.BYTE)

        return cls(
            area=area,
            byte_offset=byte_offset,
            bit_offset=bit_offset,
            data_type=data_type,
            db_number=db_number
        )

    def size_in_bytes(self) -> int:
        """Get size in bytes"""
        if self.data_type == DataType.BIT:
            return 1  # Need to read the containing byte

        size = DATA_TYPE_SIZES.get(self.data_type)
        if size is None:
            # String type
            return self.length or 256
        return size

    def __str__(self) -> str:
        """String representation"""
        return self.to_string()

    def __repr__(self) -> str:
        """Debug representation"""
        return f"MemoryAddress({self.to_string()}, type={self.data_type.value})"
