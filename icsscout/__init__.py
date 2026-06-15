"""
ICSScout - Industrial Control Systems Reconnaissance Framework

A comprehensive security assessment tool for OT/ICS environments
supporting multiple industrial protocols (S7, Modbus, OPC UA, etc.)

Author: Security Research Team
License: MIT
"""

__version__ = "2.0.0"
__author__ = "ICSScout Team"
__license__ = "MIT"

from icsscout.core import protocols
from icsscout.services import session_manager
from icsscout.utils import logger

# Initialize logging
logger.setup_logging()
