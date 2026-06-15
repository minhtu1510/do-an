"""
Activity Tracker - Track and broadcast system activities
Provides real-time activity logging with WebSocket support
"""
from __future__ import annotations
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque
import threading
import json
from pathlib import Path


@dataclass
class Activity:
    """Represents a system activity/event"""
    timestamp: datetime
    type: str  # 'scan', 'capture', 'discovery', 'info', 'warning', 'error'
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    icon: str = "fa-info-circle"
    color: str = "blue"  # blue, green, yellow, red, purple

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'type': self.type,
            'message': self.message,
            'details': self.details,
            'icon': self.icon,
            'color': self.color
        }


class ActivityTracker:
    """
    Activity tracking system with real-time broadcasting
    Maintains a rolling log of system activities
    """

    def __init__(self, max_activities: int = 100, storage_path: Optional[Path] = None):
        self._activities: deque = deque(maxlen=max_activities)
        self._lock = threading.Lock()
        self._broadcast_callback = None
        self._max_activities = max_activities

        # Storage
        if storage_path is None:
            storage_path = Path('data')
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._activity_file = self.storage_path / 'activities.json'

        # Load existing activities
        self._load_activities()

    def set_broadcast_callback(self, callback):
        """Set callback function for broadcasting activities via WebSocket"""
        self._broadcast_callback = callback

    def log(self, activity_type: str, message: str, details: Optional[Dict] = None,
            icon: str = None, color: str = None) -> Activity:
        """
        Log a new activity

        Args:
            activity_type: Type of activity ('scan', 'capture', 'discovery', etc.)
            message: Human-readable message
            details: Additional details (optional)
            icon: FontAwesome icon class (optional)
            color: Color theme (optional)

        Returns:
            Created Activity object
        """
        # Auto-assign icon and color based on type
        if icon is None or color is None:
            icon, color = self._get_defaults_for_type(activity_type)

        activity = Activity(
            timestamp=datetime.now(),
            type=activity_type,
            message=message,
            details=details or {},
            icon=icon,
            color=color
        )

        with self._lock:
            self._activities.append(activity)

        # Save to disk
        self._save_activities()

        # Broadcast to connected clients
        if self._broadcast_callback:
            try:
                self._broadcast_callback('activity_logged', activity.to_dict())
            except Exception as e:
                print(f"Failed to broadcast activity: {e}")

        return activity

    def _get_defaults_for_type(self, activity_type: str) -> tuple:
        """Get default icon and color for activity type"""
        defaults = {
            'scan': ('fa-radar', 'blue'),
            'scan_complete': ('fa-check-circle', 'green'),
            'capture': ('fa-network-wired', 'purple'),
            'capture_start': ('fa-play-circle', 'green'),
            'capture_stop': ('fa-stop-circle', 'red'),
            'discovery': ('fa-search', 'blue'),
            'device_found': ('fa-server', 'green'),
            'vulnerability': ('fa-shield-alt', 'orange'),
            'info': ('fa-info-circle', 'blue'),
            'warning': ('fa-exclamation-triangle', 'yellow'),
            'error': ('fa-times-circle', 'red'),
            'success': ('fa-check-circle', 'green'),
        }
        return defaults.get(activity_type, ('fa-circle', 'blue'))

    def get_recent(self, count: int = 50) -> List[Activity]:
        """Get recent activities (most recent first)"""
        with self._lock:
            # Return in reverse order (newest first)
            return list(reversed(list(self._activities)))[:count]

    def get_all(self) -> List[Activity]:
        """Get all activities (most recent first)"""
        with self._lock:
            return list(reversed(list(self._activities)))

    def clear(self):
        """Clear all activities"""
        with self._lock:
            self._activities.clear()
            self._save_activities()

    def _save_activities(self):
        """Save activities to disk"""
        try:
            with self._lock:
                activities_data = [a.to_dict() for a in self._activities]
                with open(self._activity_file, 'w') as f:
                    json.dump(activities_data, f, indent=2)
        except Exception as e:
            print(f"Failed to save activities: {e}")

    def _load_activities(self):
        """Load activities from disk"""
        try:
            if self._activity_file.exists():
                with open(self._activity_file, 'r') as f:
                    activities_data = json.load(f)

                with self._lock:
                    for data in activities_data[-self._max_activities:]:  # Keep only most recent
                        activity = Activity(
                            timestamp=datetime.fromisoformat(data['timestamp']),
                            type=data['type'],
                            message=data['message'],
                            details=data.get('details', {}),
                            icon=data.get('icon', 'fa-info-circle'),
                            color=data.get('color', 'blue')
                        )
                        self._activities.append(activity)
        except Exception as e:
            print(f"Failed to load activities: {e}")

    def log_scan_start(self, network: str, scan_type: str):
        """Log network scan start"""
        return self.log(
            'scan',
            f'Started {scan_type} scan on {network}',
            {'network': network, 'scan_type': scan_type},
            'fa-radar',
            'blue'
        )

    def log_scan_complete(self, network: str, device_count: int, duration: float):
        """Log network scan completion"""
        return self.log(
            'scan_complete',
            f'Scan complete: Found {device_count} device(s) on {network} in {duration:.1f}s',
            {'network': network, 'devices': device_count, 'duration': duration},
            'fa-check-circle',
            'green'
        )

    def log_device_found(self, ip: str, device_type: str, ports: int):
        """Log device discovery"""
        return self.log(
            'device_found',
            f'Found {device_type} at {ip} ({ports} open ports)',
            {'ip': ip, 'device_type': device_type, 'ports': ports},
            'fa-server',
            'green'
        )

    def log_capture_start(self, interface: str, filter: str = None):
        """Log packet capture start"""
        msg = f'Started packet capture on {interface}'
        if filter:
            msg += f' (filter: {filter[:30]}...)'
        return self.log(
            'capture_start',
            msg,
            {'interface': interface, 'filter': filter},
            'fa-play-circle',
            'green'
        )

    def log_capture_stop(self, packet_count: int):
        """Log packet capture stop"""
        return self.log(
            'capture_stop',
            f'Stopped capture: {packet_count} packets captured',
            {'packets': packet_count},
            'fa-stop-circle',
            'red'
        )

    def log_error(self, message: str, details: Dict = None):
        """Log error"""
        return self.log(
            'error',
            message,
            details,
            'fa-times-circle',
            'red'
        )


# Global activity tracker instance
_activity_tracker = None
_tracker_lock = threading.Lock()


def get_activity_tracker() -> ActivityTracker:
    """Get global activity tracker instance (singleton)"""
    global _activity_tracker

    if _activity_tracker is None:
        with _tracker_lock:
            if _activity_tracker is None:
                _activity_tracker = ActivityTracker()

    return _activity_tracker
