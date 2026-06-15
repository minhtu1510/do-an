"""Safety Mechanisms for OT Operations"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

from icsscout.domain import Device, Target
from icsscout.utils.logger import get_logger
from icsscout.utils.errors import SafetyError


class RiskLevel(Enum):
    """Risk level enumeration"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SAFE = "SAFE"


@dataclass
class Risk:
    """Represents a safety risk"""
    level: RiskLevel
    message: str
    recommendation: str
    category: str  # 'PRODUCTION', 'SAFETY', 'DATA', 'COMPLIANCE'


@dataclass
class SafetyCheckResult:
    """Result of safety check"""
    safe: bool
    risks: List[Risk]

    def is_critical(self) -> bool:
        """Check if any critical risks exist"""
        return any(r.level == RiskLevel.CRITICAL for r in self.risks)

    def is_high_risk(self) -> bool:
        """Check if any high risks exist"""
        return any(r.level in (RiskLevel.CRITICAL, RiskLevel.HIGH) for r in self.risks)


class SafetyChecker:
    """
    Safety checks before performing operations

    Prevents accidental damage to production systems
    """

    def __init__(self, read_only_mode: bool = True):
        """
        Initialize safety checker

        Args:
            read_only_mode: Enforce read-only operations
        """
        self.read_only_mode = read_only_mode
        self.logger = get_logger('SafetyChecker')

        # Critical addresses (configurable)
        self.critical_addresses: List[str] = []
        self.forbidden_operations: List[str] = []

    def check_read_operation(self, target: Target, address: str) -> SafetyCheckResult:
        """
        Check if read operation is safe

        Args:
            target: Target device
            address: Memory address to read

        Returns:
            Safety check result
        """
        risks = []

        # Reading is generally safe
        # But we can check for potential issues

        # Check if device is in production
        if self._is_production_device(target.device):
            risks.append(Risk(
                level=RiskLevel.LOW,
                message="Reading from production device",
                recommendation="Ensure reads are logged and monitored",
                category="PRODUCTION"
            ))

        return SafetyCheckResult(safe=True, risks=risks)

    def check_write_operation(self,
                             target: Target,
                             address: str,
                             value: Any) -> SafetyCheckResult:
        """
        Check if write operation is safe

        Args:
            target: Target device
            address: Memory address to write
            value: Value to write

        Returns:
            Safety check result
        """
        risks = []

        # Check read-only mode
        if self.read_only_mode:
            risks.append(Risk(
                level=RiskLevel.CRITICAL,
                message="Write operation blocked by read-only mode",
                recommendation="Disable read-only mode if write is necessary",
                category="SAFETY"
            ))
            return SafetyCheckResult(safe=False, risks=risks)

        # Check if device is in RUN mode
        if target.device.cpu_state == "RUN":
            risks.append(Risk(
                level=RiskLevel.HIGH,
                message="Device is in RUN mode. Writing may affect production.",
                recommendation="Switch to STOP mode first or use --force flag",
                category="PRODUCTION"
            ))

        # Check if address is critical
        if self._is_critical_address(address):
            risks.append(Risk(
                level=RiskLevel.CRITICAL,
                message=f"Address {address} is marked as critical in safety config",
                recommendation="Double-check before proceeding. Consider backup first.",
                category="SAFETY"
            ))

        # Check value range (for outputs)
        if address.startswith('Q'):
            risks.append(Risk(
                level=RiskLevel.HIGH,
                message="Writing to output may activate physical equipment",
                recommendation="Ensure all safety procedures are followed",
                category="SAFETY"
            ))

        # Determine overall safety
        safe = not any(r.level == RiskLevel.CRITICAL for r in risks)

        return SafetyCheckResult(safe=safe, risks=risks)

    def check_memory_dump(self, target: Target) -> SafetyCheckResult:
        """Check if memory dump is safe"""
        risks = []

        # Check if device is busy
        if target.device.cpu_state == "RUN":
            risks.append(Risk(
                level=RiskLevel.MEDIUM,
                message="Device is running. Memory dump may impact performance.",
                recommendation="Use safe mode with conservative parameters",
                category="PRODUCTION"
            ))

        return SafetyCheckResult(safe=True, risks=risks)

    def check_scan_operation(self, network: str) -> SafetyCheckResult:
        """Check if network scan is safe"""
        risks = []

        # Passive scans are generally safe
        # Active scans may trigger IDS/IPS

        risks.append(Risk(
            level=RiskLevel.LOW,
            message="Network scanning may be detected by IDS/IPS",
            recommendation="Use passive reconnaissance when possible",
            category="COMPLIANCE"
        ))

        return SafetyCheckResult(safe=True, risks=risks)

    def _is_production_device(self, device: Device) -> bool:
        """Check if device is in production"""
        # Check metadata or CPU state
        return device.cpu_state == "RUN"

    def _is_critical_address(self, address: str) -> bool:
        """Check if address is critical"""
        # Check against configured critical addresses
        for pattern in self.critical_addresses:
            if pattern in address:
                return True
        return False

    def add_critical_address(self, address_pattern: str) -> None:
        """Add critical address pattern"""
        self.critical_addresses.append(address_pattern)

    def set_read_only_mode(self, enabled: bool) -> None:
        """Enable/disable read-only mode"""
        self.read_only_mode = enabled
        self.logger.info(f"Read-only mode: {'enabled' if enabled else 'disabled'}")


class OperationValidator:
    """Validates operations before execution"""

    def __init__(self, safety_checker: SafetyChecker):
        """
        Initialize operation validator

        Args:
            safety_checker: Safety checker instance
        """
        self.safety_checker = safety_checker
        self.logger = get_logger('OperationValidator')

    def validate_and_confirm(self, operation: str, **kwargs) -> bool:
        """
        Validate operation and ask for confirmation if needed

        Args:
            operation: Operation type ('read', 'write', etc.)
            **kwargs: Operation parameters

        Returns:
            True if operation should proceed
        """
        # Perform safety check
        if operation == 'write':
            result = self.safety_checker.check_write_operation(
                kwargs.get('target'),
                kwargs.get('address'),
                kwargs.get('value')
            )
        elif operation == 'read':
            result = self.safety_checker.check_read_operation(
                kwargs.get('target'),
                kwargs.get('address')
            )
        else:
            # Unknown operation - allow with warning
            self.logger.warning(f"Unknown operation type: {operation}")
            return True

        # If critical risks, block operation
        if result.is_critical():
            self.logger.error("Operation blocked due to critical safety risks")
            for risk in result.risks:
                if risk.level == RiskLevel.CRITICAL:
                    self.logger.error(f"  {risk.message}")
            return False

        # If high risks, require confirmation
        if result.is_high_risk():
            self.logger.warning("⚠️  Safety Warning:")
            for risk in result.risks:
                self.logger.warning(f"  [{risk.level.value}] {risk.message}")
                self.logger.warning(f"  → {risk.recommendation}")

            # In automated mode, return False
            # In interactive mode, would prompt user
            return False

        return True
