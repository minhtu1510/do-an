"""Result domain models"""

from dataclasses import dataclass, field
from typing import Optional, Any, Dict, List
from datetime import datetime
from enum import Enum


class ResultStatus(Enum):
    """Result status enumeration"""
    SUCCESS = "success"
    FAILURE = "failure"
    WARNING = "warning"
    PARTIAL = "partial"


@dataclass
class Result:
    """
    Generic result object for operations
    """
    success: bool
    message: str = ""
    data: Optional[Any] = None
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def ok(cls, message: str = "", data: Any = None, **kwargs) -> 'Result':
        """Create successful result"""
        return cls(success=True, message=message, data=data, details=kwargs)

    @classmethod
    def error(cls, error: str, **kwargs) -> 'Result':
        """Create error result"""
        return cls(success=False, error=error, details=kwargs)

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'success': self.success,
            'message': self.message,
            'data': self.data,
            'error': self.error,
            'details': self.details
        }


@dataclass
class OperationResult:
    """
    Result of an operation on a device
    """
    operation: str
    target: str
    status: ResultStatus
    timestamp: datetime = field(default_factory=datetime.now)

    # Operation details
    request: Optional[Dict[str, Any]] = None
    response: Optional[Dict[str, Any]] = None

    # Timing
    duration_ms: Optional[float] = None

    # Error information
    error: Optional[str] = None

    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'operation': self.operation,
            'target': self.target,
            'status': self.status.value,
            'timestamp': self.timestamp.isoformat(),
            'request': self.request,
            'response': self.response,
            'duration_ms': self.duration_ms,
            'error': self.error,
            'metadata': self.metadata
        }

    def is_success(self) -> bool:
        """Check if operation was successful"""
        return self.status == ResultStatus.SUCCESS

    def __str__(self) -> str:
        """String representation"""
        status_symbol = "✓" if self.is_success() else "✗"
        return f"[{status_symbol}] {self.operation} on {self.target}: {self.status.value}"


@dataclass
class ScanResult:
    """Result of a network scan"""
    devices: List[Any] = field(default_factory=list)  # List of Device objects
    scan_duration: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    scan_type: str = "unknown"
    network: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'devices': [d.to_dict() for d in self.devices],
            'device_count': len(self.devices),
            'scan_duration': self.scan_duration,
            'timestamp': self.timestamp.isoformat(),
            'scan_type': self.scan_type,
            'network': self.network
        }

    def plc_count(self) -> int:
        """Count PLC devices"""
        return sum(1 for d in self.devices if d.is_plc())

    def __str__(self) -> str:
        """String representation"""
        return f"ScanResult: {len(self.devices)} devices ({self.plc_count()} PLCs) in {self.scan_duration:.2f}s"
