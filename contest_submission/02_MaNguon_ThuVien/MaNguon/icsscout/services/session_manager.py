"""Thread-safe Session Management"""

from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import threading
import json
from pathlib import Path

from icsscout.domain import Device, Target, OperationResult
from icsscout.utils.logger import get_logger


class SessionPhase(Enum):
    """Reconnaissance workflow phases"""
    DISCOVERY = "DISCOVERY"
    IDENTIFICATION = "IDENTIFICATION"
    ENUMERATION = "ENUMERATION"
    ANALYSIS = "ANALYSIS"
    ASSESSMENT = "ASSESSMENT"
    REPORTING = "REPORTING"


@dataclass
class Session:
    """Represents a reconnaissance session"""
    session_id: str
    name: str
    created_at: datetime = field(default_factory=datetime.now)
    current_phase: SessionPhase = SessionPhase.DISCOVERY

    # Discovered data
    devices: List[Device] = field(default_factory=list)
    current_target: Optional[Target] = None

    # Operation history
    operations: List[OperationResult] = field(default_factory=list)

    # Session metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Risk Assessment results
    risk_assessment_results: Optional[Dict[str, Any]] = None

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'session_id': self.session_id,
            'name': self.name,
            'created_at': self.created_at.isoformat(),
            'current_phase': self.current_phase.value,
            'devices': [d.to_dict() for d in self.devices],
            'current_target': self.current_target.to_dict() if self.current_target else None,
            'operation_count': len(self.operations),
            'metadata': self.metadata,
            'risk_assessment_results': self.risk_assessment_results
        }


class SessionManager:
    """
    Thread-safe session management

    Provides:
    - Session persistence
    - Device tracking
    - Target management
    - Operation history
    - Thread-safe access
    """

    def __init__(self, storage_path: Optional[Path] = None):
        """
        Initialize session manager

        Args:
            storage_path: Path to store session data
        """
        self.logger = get_logger('SessionManager')
        self._lock = threading.RLock()

        # Storage
        if storage_path is None:
            storage_path = Path('sessions')
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)

        # Current session
        self._session: Optional[Session] = None

    def create_session(self, name: str) -> Session:
        """
        Create new session

        Args:
            name: Session name

        Returns:
            Created session
        """
        with self._lock:
            session_id = f"session_{datetime.now():%Y%m%d_%H%M%S}"

            self._session = Session(
                session_id=session_id,
                name=name,
                created_at=datetime.now()
            )

            self.logger.info(f"Created session: {session_id}")
            self._save_session()

            return self._session

    def get_current_session(self) -> Optional[Session]:
        """Get current session"""
        with self._lock:
            return self._session

    def add_device(self, device: Device) -> None:
        """Add discovered device to session"""
        with self._lock:
            if not self._session:
                raise ValueError("No active session")

            # Check for duplicates
            existing = next((d for d in self._session.devices if d.ip == device.ip), None)
            if existing:
                # Update existing device
                idx = self._session.devices.index(existing)
                self._session.devices[idx] = device
                self.logger.info(f"Updated device: {device.ip}")
            else:
                self._session.devices.append(device)
                self.logger.info(f"Added device: {device.ip}")

            self._save_session()

    def add_devices(self, devices: List[Device]) -> None:
        """Add multiple devices"""
        for device in devices:
            self.add_device(device)

    def get_devices(self) -> List[Device]:
        """Get all discovered devices"""
        with self._lock:
            if not self._session:
                return []
            return self._session.devices.copy()

    def get_plcs(self) -> List[Device]:
        """Get only PLC devices"""
        devices = self.get_devices()
        return [d for d in devices if d.is_plc()]

    def set_target(self, target: Target) -> None:
        """Set current target"""
        with self._lock:
            if not self._session:
                raise ValueError("No active session")

            self._session.current_target = target
            self.logger.info(f"Set target: {target.device.ip}")
            self._save_session()

    def get_target(self) -> Optional[Target]:
        """Get current target"""
        with self._lock:
            if not self._session:
                return None
            return self._session.current_target

    def add_operation(self, operation: OperationResult) -> None:
        """Add operation to history"""
        with self._lock:
            if not self._session:
                raise ValueError("No active session")

            self._session.operations.append(operation)
            # Don't save after every operation (performance)

    def get_operations(self, limit: Optional[int] = None) -> List[OperationResult]:
        """Get operation history"""
        with self._lock:
            if not self._session:
                return []

            ops = self._session.operations
            if limit:
                ops = ops[-limit:]
            return ops.copy()

    def set_phase(self, phase: SessionPhase) -> None:
        """Set current workflow phase"""
        with self._lock:
            if not self._session:
                raise ValueError("No active session")

            self._session.current_phase = phase
            self.logger.info(f"Advanced to phase: {phase.value}")
            self._save_session()

    def get_phase(self) -> Optional[SessionPhase]:
        """Get current phase"""
        with self._lock:
            if not self._session:
                return None
            return self._session.current_phase

    def set_metadata(self, key: str, value: Any) -> None:
        """Set session metadata"""
        with self._lock:
            if not self._session:
                raise ValueError("No active session")

            self._session.metadata[key] = value
            self._save_session()

    def get_metadata(self, key: str) -> Optional[Any]:
        """Get session metadata"""
        with self._lock:
            if not self._session:
                return None
            return self._session.metadata.get(key)

    def save_risk_assessment(self, results: Dict[str, Any]) -> None:
        """Save risk assessment results to session"""
        with self._lock:
            if not self._session:
                raise ValueError("No active session")

            self._session.risk_assessment_results = results
            self._save_session()
            self.logger.info("Risk assessment results saved to session")

    def get_risk_assessment(self) -> Optional[Dict[str, Any]]:
        """Get risk assessment results from session"""
        with self._lock:
            if not self._session:
                return None
            return self._session.risk_assessment_results

    def save_session(self, filepath: Optional[str] = None) -> str:
        """
        Explicitly save session to file

        Args:
            filepath: Custom filepath (optional)

        Returns:
            Path to saved file
        """
        with self._lock:
            if not self._session:
                raise ValueError("No active session")

            if filepath is None:
                filepath = self.storage_path / f"{self._session.session_id}.json"

            filepath = Path(filepath)
            filepath.parent.mkdir(parents=True, exist_ok=True)

            with open(filepath, 'w') as f:
                json.dump(self._session.to_dict(), f, indent=2, default=str)

            self.logger.info(f"Session saved to {filepath}")
            return str(filepath)

    def load_session(self, filepath: str) -> Session:
        """
        Load session from file

        Args:
            filepath: Path to session file

        Returns:
            Loaded session
        """
        with self._lock:
            with open(filepath, 'r') as f:
                data = json.load(f)

            # Reconstruct session
            session = Session(
                session_id=data['session_id'],
                name=data['name'],
                created_at=datetime.fromisoformat(data['created_at']),
                current_phase=SessionPhase(data['current_phase']),
                metadata=data.get('metadata', {}),
                risk_assessment_results=data.get('risk_assessment_results')
            )

            # Restore devices
            for device_data in data.get('devices', []):
                device = Device.from_dict(device_data)
                session.devices.append(device)

            # Restore target
            if data.get('current_target'):
                target_data = data['current_target']
                device = Device.from_dict(target_data['device'])
                from icsscout.domain.protocol import ProtocolType
                target = Target(
                    device=device,
                    protocol=ProtocolType(target_data['protocol']),
                    port=target_data.get('port'),
                    rack=target_data.get('rack', 0),
                    slot=target_data.get('slot', 1)
                )
                session.current_target = target

            self._session = session
            self.logger.info(f"Session loaded: {session.session_id}")

            return session

    def _save_session(self) -> None:
        """Internal auto-save"""
        if not self._session:
            return

        try:
            self.save_session()
        except Exception as e:
            self.logger.error(f"Failed to auto-save session: {e}")

    def get_session_summary(self) -> Dict[str, Any]:
        """Get session summary"""
        with self._lock:
            if not self._session:
                return {}

            return {
                'session_id': self._session.session_id,
                'name': self._session.name,
                'created_at': self._session.created_at.isoformat(),
                'duration': str(datetime.now() - self._session.created_at),
                'current_phase': self._session.current_phase.value,
                'devices_found': len(self._session.devices),
                'plcs_found': len([d for d in self._session.devices if d.is_plc()]),
                'target_set': self._session.current_target is not None,
                'operations_performed': len(self._session.operations)
            }


# Global session manager instance
_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """Get global session manager instance"""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager(storage_path=Path('data'))

        # Auto-load or create default session
        if not _session_manager.get_current_session():
            # Try to load the most recent session
            try:
                session_files = list(_session_manager.storage_path.glob('*.json'))
                if session_files:
                    # Load most recent
                    latest = max(session_files, key=lambda p: p.stat().st_mtime)
                    _session_manager.load_session(str(latest))
                else:
                    # Create default session
                    _session_manager.create_session('Default Session')
            except Exception as e:
                # Fallback: create new session
                _session_manager.create_session('Default Session')

    return _session_manager
