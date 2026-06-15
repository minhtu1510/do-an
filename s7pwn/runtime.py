from __future__ import annotations
from typing import Optional, Dict, List

_devices: List[dict] = []
_plc_list: List[dict] = []
_current_target: Optional[Dict[str, object]] = None
_auth_session: Optional[Dict[str, object]] = None  # Authentication session storage

def set_scan_results(devices: List[dict], plc_list: List[dict]) -> None:
    global _devices, _plc_list
    _devices = devices or []
    _plc_list = plc_list or []

def get_devices() -> List[dict]:
    return list(_devices)

def get_plc_list() -> List[dict]:
    return list(_plc_list)

def set_current_target(ip: str, rack: int, slot: int) -> None:
    global _current_target
    _current_target = {"ip": ip, "rack": int(rack), "slot": int(slot)}

def get_current_target() -> Optional[Dict[str, object]]:
    return dict(_current_target) if _current_target else None

def set_auth_session(session: Dict[str, object]) -> None:
    """Store authentication session for current connection"""
    global _auth_session
    _auth_session = dict(session) if session else None

def get_auth_session() -> Optional[Dict[str, object]]:
    """Get authentication session if available"""
    return dict(_auth_session) if _auth_session else None

def clear_auth_session() -> None:
    """Clear authentication session"""
    global _auth_session
    _auth_session = None
