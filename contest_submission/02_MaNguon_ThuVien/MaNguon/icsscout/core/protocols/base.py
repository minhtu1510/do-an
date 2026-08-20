"""Base protocol client interface"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from enum import Enum
from datetime import datetime

from icsscout.domain import Device, Target, Result
from icsscout.utils.logger import get_logger


class ConnectionState(Enum):
    """Connection state enumeration"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"


class BaseProtocolClient(ABC):
    """
    Base class for all protocol clients

    All protocol implementations must inherit from this class
    and implement the abstract methods.
    """

    def __init__(self, target: Target):
        """
        Initialize protocol client

        Args:
            target: Target device configuration
        """
        self.target = target
        self.state = ConnectionState.DISCONNECTED
        self.logger = get_logger(self.__class__.__name__)
        self.connection = None
        self.last_error: Optional[str] = None
        self.connected_at: Optional[datetime] = None

    @abstractmethod
    def connect(self) -> Result:
        """
        Establish connection to device

        Returns:
            Result object indicating success/failure
        """
        pass

    @abstractmethod
    def disconnect(self) -> Result:
        """
        Close connection to device

        Returns:
            Result object indicating success/failure
        """
        pass

    @abstractmethod
    def read(self, address: str, data_type: str, count: int = 1) -> Result:
        """
        Read data from device

        Args:
            address: Memory address to read
            data_type: Data type (e.g., 'int', 'bool', 'real')
            count: Number of elements to read

        Returns:
            Result with read data
        """
        pass

    @abstractmethod
    def write(self, address: str, value: Any, data_type: str) -> Result:
        """
        Write data to device

        Args:
            address: Memory address to write
            value: Value to write
            data_type: Data type

        Returns:
            Result indicating success/failure
        """
        pass

    @abstractmethod
    def get_device_info(self) -> Result:
        """
        Get device information (model, firmware, etc.)

        Returns:
            Result with device information dict
        """
        pass

    def is_connected(self) -> bool:
        """Check if currently connected"""
        return self.state == ConnectionState.CONNECTED

    def ensure_connected(self) -> Result:
        """
        Ensure connection is established

        Returns:
            Result indicating connection state
        """
        if not self.is_connected():
            return self.connect()
        return Result.ok("Already connected")

    def get_connection_info(self) -> Dict[str, Any]:
        """
        Get connection information

        Returns:
            Dictionary with connection details
        """
        return {
            'target': self.target.connection_string(),
            'state': self.state.value,
            'connected_at': self.connected_at.isoformat() if self.connected_at else None,
            'last_error': self.last_error
        }

    def test_connection(self) -> Result:
        """
        Test connection by performing a simple operation

        Returns:
            Result indicating if connection is working
        """
        result = self.connect()
        if result.success:
            info_result = self.get_device_info()
            self.disconnect()
            return info_result
        return result

    def __enter__(self):
        """Context manager entry"""
        result = self.connect()
        if not result.success:
            raise ConnectionError(result.error)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()

    def __str__(self) -> str:
        """String representation"""
        return f"{self.__class__.__name__}({self.target.device.ip}, state={self.state.value})"

    def __repr__(self) -> str:
        """Debug representation"""
        return (f"{self.__class__.__name__}(target={self.target.device.ip}, "
                f"protocol={self.target.protocol.value}, state={self.state.value})")
