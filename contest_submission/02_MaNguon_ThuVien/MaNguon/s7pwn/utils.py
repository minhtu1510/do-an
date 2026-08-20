from __future__ import annotations
from typing import Optional, Tuple, List
import socket
import snap7
import logging

RACK_SLOT_BY_TYPE = {
    "S7-1200": (0, 1),
    "S7-1500": (0, 1),
    "S7-300":  (0, 2),
    "S7-400":  (0, 2),
}

def get_rack_slot(plc_type: Optional[str]) -> Tuple[int, int]:
    return RACK_SLOT_BY_TYPE.get((plc_type or "S7-1500"), (0, 1))

def reachable(ip: str, port: int = 102, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout): return True
    except OSError:
        return False

def s7_connect(ip: str, rack: int = 0, slot: int = 1, password: Optional[str] = None) -> Optional[snap7.client.Client]:
    """
    Connect to S7 PLC with optional password authentication

    Args:
        ip: PLC IP address
        rack: Rack number
        slot: Slot number
        password: Optional password for authenticated connection

    Returns:
        Connected snap7 client or None if connection fails
    """
    c = snap7.client.Client()
    try:
        c.connect(ip, rack, slot)

        # If password provided, attempt to set password
        # Note: snap7 has limited native password support
        # For full authentication, use S7AuthClient from s7_auth module
        if password:
            try:
                # Try to set password if snap7 supports it
                # This may not work with all PLC models/snap7 versions
                c.set_param(snap7.types.S7_PARAM_PASSWORD, password.encode())
                logging.info(f"Password authentication attempted for {ip}")
            except AttributeError:
                # snap7 version doesn't support password parameter
                logging.warning(f"Password provided but snap7 doesn't support set_param for passwords")
                logging.warning(f"Connection may fail if PLC requires authentication")
            except Exception as e:
                logging.warning(f"Password authentication failed: {e}")

        return c
    except Exception as e:
        logging.error(f"S7 connection failed to {ip}:{rack}/{slot}: {e}")
        try: c.destroy()
        except Exception: pass
        return None

def s7_connect_with_auth() -> Optional[snap7.client.Client]:
    """
    Connect to current target using stored authentication session if available

    Returns:
        Connected snap7 client or None
    """
    from s7pwn.runtime import get_current_target, get_auth_session

    target = get_current_target()
    if not target:
        print("[!] No target selected")
        return None

    ip = target['ip']
    rack = target.get('rack', 0)
    slot = target.get('slot', 1)

    # Check if we have authentication session
    auth_session = get_auth_session()
    password = None

    if auth_session and auth_session.get('authenticated'):
        password = auth_session.get('password')
        if password:
            print(f"[*] Using authenticated connection to {ip}")

    return s7_connect(ip, rack, slot, password)
