"""Advanced logging system for ICSScout"""

import logging
import sys
from pathlib import Path
from typing import Optional
from logging.handlers import RotatingFileHandler
from datetime import datetime


# ANSI color codes
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'


class ColoredFormatter(logging.Formatter):
    """Colored console formatter"""

    FORMATS = {
        logging.DEBUG: Colors.CYAN + '%(levelname)s' + Colors.RESET + ' - %(message)s',
        logging.INFO: Colors.GREEN + '%(levelname)s' + Colors.RESET + ' - %(message)s',
        logging.WARNING: Colors.YELLOW + '%(levelname)s' + Colors.RESET + ' - %(message)s',
        logging.ERROR: Colors.RED + '%(levelname)s' + Colors.RESET + ' - %(message)s',
        logging.CRITICAL: Colors.BOLD + Colors.RED + '%(levelname)s' + Colors.RESET + ' - %(message)s',
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt='%H:%M:%S')
        return formatter.format(record)


class StructuredFormatter(logging.Formatter):
    """JSON-like structured formatter for file logging"""

    def format(self, record):
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'level': record.levelname,
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'message': record.getMessage(),
        }

        # Add extra fields if present
        if hasattr(record, 'device'):
            log_data['device'] = record.device
        if hasattr(record, 'protocol'):
            log_data['protocol'] = record.protocol
        if hasattr(record, 'operation'):
            log_data['operation'] = record.operation

        return str(log_data)


def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    console: bool = True
) -> None:
    """
    Setup logging configuration

    Args:
        level: Logging level (default: INFO)
        log_file: Path to log file (default: logs/icsscout.log)
        console: Enable console logging (default: True)
    """
    # Create logs directory
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)

    if log_file is None:
        log_file = log_dir / f'icsscout_{datetime.now():%Y%m%d}.log'

    # Root logger
    logger = logging.getLogger('icsscout')
    logger.setLevel(level)
    logger.handlers.clear()

    # Console handler
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(ColoredFormatter())
        logger.addHandler(console_handler)

    # File handler (rotating)
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(StructuredFormatter())
    logger.addHandler(file_handler)

    logger.info("Logging initialized", extra={
        'log_file': str(log_file),
        'level': logging.getLevelName(level)
    })


def get_logger(name: str) -> logging.Logger:
    """
    Get logger for module

    Args:
        name: Module name

    Returns:
        Logger instance
    """
    return logging.getLogger(f'icsscout.{name}')


# Audit logger for security events
class AuditLogger:
    """Separate audit trail for security-sensitive operations"""

    def __init__(self):
        self.logger = logging.getLogger('icsscout.audit')
        self.logger.setLevel(logging.INFO)

        # Audit log file
        audit_file = Path('logs') / f'audit_{datetime.now():%Y%m%d}.log'
        handler = RotatingFileHandler(
            audit_file,
            maxBytes=50 * 1024 * 1024,  # 50 MB
            backupCount=10
        )
        handler.setFormatter(StructuredFormatter())
        self.logger.addHandler(handler)

    def log_operation(self, operation: str, target: str, details: dict):
        """Log security-sensitive operation"""
        self.logger.info(
            f"Operation: {operation}",
            extra={
                'operation': operation,
                'target': target,
                'details': details,
                'timestamp': datetime.now().isoformat()
            }
        )


# Global audit logger instance
_audit_logger = None


def get_audit_logger() -> AuditLogger:
    """Get global audit logger instance"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger
