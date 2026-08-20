"""Custom exceptions for ICSScout"""

from typing import Optional


class ICSScoutError(Exception):
    """Base exception for ICSScout"""

    def __init__(self, message: str, details: Optional[dict] = None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)


class ConnectionError(ICSScoutError):
    """Raised when connection to device fails"""
    pass


class ProtocolError(ICSScoutError):
    """Raised when protocol communication fails"""
    pass


class ValidationError(ICSScoutError):
    """Raised when input validation fails"""
    pass


class SecurityError(ICSScoutError):
    """Raised when security check fails"""
    pass


class SafetyError(ICSScoutError):
    """Raised when safety check fails"""
    pass


class ScanError(ICSScoutError):
    """Raised when network scan fails"""
    pass


class CaptureError(ICSScoutError):
    """Raised when packet capture fails"""
    pass


class MemoryError(ICSScoutError):
    """Raised when memory operation fails"""
    pass


class VulnerabilityError(ICSScoutError):
    """Raised when vulnerability scan fails"""
    pass
