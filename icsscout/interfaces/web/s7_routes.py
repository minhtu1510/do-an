"""
S7 OT Protocol and Authentication Routes for ICSScout Web App
Integrates s7pwn OT protocol scanning and S7 authentication into ICSScout
"""

from flask import Blueprint, request, jsonify
from typing import Dict, Any
import logging

# Import s7pwn modules
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from s7pwn.ext.scan_module import scan_network as s7_scan_network, PLC_FAMILIES, get_interfaces
from s7pwn.ext.ot_protocol_scanner import OTProtocolScanner
from s7pwn.ext.s7_auth import S7AuthClient, quick_auth_check, get_common_passwords
from s7pwn import runtime as s7_runtime

logger = logging.getLogger('S7Routes')

# Create Blueprint
s7_bp = Blueprint('s7', __name__, url_prefix='/api/s7')

# Will be injected by app.py
_socketio = None

def set_socketio(socketio):
    """Set SocketIO instance for real-time updates"""
    global _socketio
    _socketio = socketio


@s7_bp.route('/interfaces', methods=['GET'])
def api_get_interfaces():
    """
    Get list of available network interfaces

    Returns:
        {
            "success": true,
            "interfaces": [
                {"name": "...", "ip": "...", "mac": "..."},
                ...
            ]
        }
    """
    try:
        interfaces = get_interfaces()
        interface_list = [
            {
                'name': name,
                'ip': ip,
                'mac': mac,
                'display': f"{name} ({ip})"
            }
            for name, ip, mac in interfaces
        ]

        return jsonify({
            'success': True,
            'interfaces': interface_list
        })
    except Exception as e:
        logger.error(f"Failed to get interfaces: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@s7_bp.route('/scan/ot-protocols', methods=['POST'])
def api_ot_protocol_scan():
    """
    Scan network using OT-specific protocols

    Body:
        {
            "network_cidr": "192.168.1.0/24",
            "protocols": ["profinet", "modbus", "ethernet_ip", "s7", "bacnet", "fins"],
            "interface_name": "Intel(R) Ethernet Connection...",  // Required for Profinet
            "timeout": 3,
            "retries": 2
        }
    """
    try:
        data = request.json or {}
        network_cidr = data.get('network_cidr')
        protocols = data.get('protocols', None)
        interface_name = data.get('interface_name')
        timeout = data.get('timeout', 3)
        retries = data.get('retries', 2)

        # Validate interface for Profinet protocol
        if protocols and 'profinet' in protocols and not interface_name:
            return jsonify({
                'success': False,
                'error': 'Network interface selection required for Profinet DCP scan'
            }), 400

        if not network_cidr and protocols and any(p in protocols for p in ['modbus', 'ethernet_ip', 's7', 'bacnet', 'fins']):
            return jsonify({
                'success': False,
                'error': 'Network CIDR required for IP-based protocols'
            }), 400

        logger.info(f"OT Protocol Scan: network={network_cidr}, protocols={protocols}, interface={interface_name}")

        # Progress callback to emit WebSocket events during scan
        def progress_callback(message: str):
            logger.info(f"Progress: {message[:80]}")
            if _socketio:
                _socketio.emit('ot_scan_progress', {'message': message})

        # Perform scan with user-selected interface (synchronously)
        devices = s7_scan_network(
            timeout=timeout,
            retries=retries,
            protocols=protocols,
            network_cidr=network_cidr,
            interface_name=interface_name,
            progress_callback=progress_callback
        )

        # Format results
        result_devices = []
        for d in devices:
            device_info = {
                'ip': d.get('ip'),
                'mac': d.get('mac', 'Unknown'),
                'vendor': d.get('vendor', 'Unknown'),
                'model': d.get('device_model', 'Unknown'),
                'protocol': d.get('protocol', 'Unknown'),
                'port': d.get('port', 'N/A'),
                'name': d.get('name', 'Unknown'),
                'role': d.get('role', 'Unknown'),
                'device_id': d.get('device_id', 'Unknown'),
                'type_station': d.get('type_station', 'Unknown')
            }

            if 'ot_info' in d:
                device_info['ot_info'] = d['ot_info']
            if d.get('plc_info'):
                device_info['plc_info'] = d['plc_info']

            result_devices.append(device_info)

        logger.info(f"Found {len(result_devices)} devices via OT protocols")

        # Return results in response
        return jsonify({
            'success': True,
            'devices': result_devices,
            'total': len(result_devices),
            'protocols_used': protocols or ['profinet']
        })

    except Exception as e:
        logger.error(f"OT protocol scan failed: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@s7_bp.route('/auth/check', methods=['POST'])
def api_auth_check():
    """
    Check PLC protection level and access level

    Body:
        {
            "ip": "192.168.1.10",
            "rack": 0,
            "slot": 1
        }
    """
    try:
        data = request.json or {}
        ip = data.get('ip')
        rack = data.get('rack', 0)
        slot = data.get('slot', 1)

        if not ip:
            return jsonify({'success': False, 'error': 'IP address required'}), 400

        logger.info(f"Auth Check: {ip}:{rack}/{slot}")

        result = quick_auth_check(ip, rack, slot)

        return jsonify({
            'success': True,
            'result': result,
            'message': 'Protection check completed'
        })

    except Exception as e:
        logger.error(f"Auth check failed: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@s7_bp.route('/auth/login', methods=['POST'])
def api_auth_login():
    """
    Authenticate to PLC with password

    Body:
        {
            "ip": "192.168.1.10",
            "rack": 0,
            "slot": 1,
            "password": "secret123"
        }
    """
    try:
        data = request.json or {}
        ip = data.get('ip')
        rack = data.get('rack', 0)
        slot = data.get('slot', 1)
        password = data.get('password')

        if not ip or not password:
            return jsonify({
                'success': False,
                'error': 'IP address and password required'
            }), 400

        logger.info(f"Auth Login: {ip}:{rack}/{slot}")

        client = S7AuthClient(ip, rack, slot)

        if not client.connect():
            return jsonify({
                'success': False,
                'error': 'Connection failed'
            }), 500

        # Authenticate
        authenticated = client.authenticate_with_password(password)

        if authenticated:
            # Test access level
            access = client.test_access()

            # Store in session
            s7_runtime.set_auth_session({
                'ip': ip,
                'rack': rack,
                'slot': slot,
                'password': password,
                'authenticated': True,
                'access_level': access.name
            })

            client.disconnect()

            logger.info(f"Authentication successful for {ip}, access level: {access.name}")

            return jsonify({
                'success': True,
                'authenticated': True,
                'access_level': access.name,
                'message': 'Authentication successful'
            })
        else:
            client.disconnect()

            return jsonify({
                'success': False,
                'authenticated': False,
                'error': 'Authentication failed - invalid password'
            }), 401

    except Exception as e:
        logger.error(f"Auth login failed: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@s7_bp.route('/auth/bruteforce', methods=['POST'])
def api_auth_bruteforce():
    """
    Brute force password testing (AUTHORIZED ONLY)

    Body:
        {
            "ip": "192.168.1.10",
            "rack": 0,
            "slot": 1,
            "use_common": true,
            "passwords": [],  // optional custom passwords
            "max_attempts": 100
        }
    """
    try:
        data = request.json or {}
        ip = data.get('ip')
        rack = data.get('rack', 0)
        slot = data.get('slot', 1)
        use_common = data.get('use_common', True)
        custom_passwords = data.get('passwords', [])
        max_attempts = data.get('max_attempts', 100)

        if not ip:
            return jsonify({'success': False, 'error': 'IP address required'}), 400

        # Get password list
        if use_common:
            password_list = get_common_passwords()
        else:
            password_list = custom_passwords

        if not password_list:
            return jsonify({
                'success': False,
                'error': 'No passwords to test'
            }), 400

        logger.warning(f"Brute force attempt on {ip}:{rack}/{slot} (AUTHORIZED TESTING)")

        client = S7AuthClient(ip, rack, slot)
        found_password = client.brute_force_password(password_list, max_attempts)

        if found_password:
            # Store in session
            s7_runtime.set_auth_session({
                'ip': ip,
                'rack': rack,
                'slot': slot,
                'password': found_password,
                'authenticated': True,
                'access_level': 'UNKNOWN'
            })

            logger.info(f"Password found for {ip}: {found_password}")

            return jsonify({
                'success': True,
                'found': True,
                'password': found_password,
                'attempts': min(len(password_list), max_attempts),
                'message': f'Password found: {found_password}'
            })
        else:
            return jsonify({
                'success': True,
                'found': False,
                'attempts': min(len(password_list), max_attempts),
                'message': 'Password not found'
            })

    except Exception as e:
        logger.error(f"Brute force failed: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@s7_bp.route('/auth/status', methods=['GET'])
def api_auth_status():
    """Get current authentication session status"""
    try:
        auth_session = s7_runtime.get_auth_session()

        if auth_session and auth_session.get('authenticated'):
            return jsonify({
                'success': True,
                'authenticated': True,
                'target': f"{auth_session.get('ip')}:{auth_session.get('rack')}/{auth_session.get('slot')}",
                'access_level': auth_session.get('access_level', 'Unknown')
            })
        else:
            return jsonify({
                'success': True,
                'authenticated': False
            })

    except Exception as e:
        logger.error(f"Auth status check failed: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@s7_bp.route('/protocols/list', methods=['GET'])
def api_protocol_list():
    """Get list of supported OT protocols"""
    return jsonify({
        'success': True,
        'protocols': [
            {
                'id': 'profinet',
                'name': 'Profinet DCP',
                'description': 'Layer 2 protocol - Siemens, Beckhoff, Wago, etc.',
                'port': 'N/A',
                'requires_admin': True,
                'vendors': ['Siemens', 'Beckhoff', 'Wago', 'Phoenix Contact']
            },
            {
                'id': 'modbus',
                'name': 'Modbus TCP',
                'description': 'Port 502 - Schneider, ABB, Honeywell',
                'port': 502,
                'requires_admin': False,
                'vendors': ['Schneider Electric', 'ABB', 'Honeywell']
            },
            {
                'id': 'ethernet_ip',
                'name': 'EtherNet/IP',
                'description': 'Port 44818 - Rockwell/Allen-Bradley',
                'port': 44818,
                'requires_admin': False,
                'vendors': ['Rockwell Automation', 'Allen-Bradley', 'Schneider']
            },
            {
                'id': 's7',
                'name': 'S7 Protocol',
                'description': 'Port 102 - Siemens direct',
                'port': 102,
                'requires_admin': False,
                'vendors': ['Siemens']
            },
            {
                'id': 'bacnet',
                'name': 'BACnet',
                'description': 'Port 47808 - Building automation',
                'port': 47808,
                'requires_admin': False,
                'vendors': ['Johnson Controls', 'Honeywell', 'Siemens', 'Trane']
            },
            {
                'id': 'fins',
                'name': 'FINS',
                'description': 'Port 9600 - Omron PLCs',
                'port': 9600,
                'requires_admin': False,
                'vendors': ['Omron']
            }
        ]
    })


@s7_bp.route('/auth/check-detailed', methods=['POST'])
def api_auth_check_detailed():
    """
    Detailed protection level check with step-by-step explanations

    Body:
        {
            "ip": "192.168.1.10",
            "rack": 0,
            "slot": 1
        }

    Returns detailed information about:
    - Protection level with explanation
    - Access level with explanation
    - Password requirement with logic
    - Detection steps
    - Technical details
    """
    try:
        from s7pwn.ext.s7_auth import detailed_auth_check

        data = request.json or {}
        ip = data.get('ip')
        rack = data.get('rack', 0)
        slot = data.get('slot', 1)

        if not ip:
            return jsonify({'success': False, 'error': 'IP address required'}), 400

        logger.info(f"Detailed auth check for {ip}:{rack}/{slot}")

        result = detailed_auth_check(ip, rack, slot)

        return jsonify({
            'success': True,
            'result': result
        })

    except Exception as e:
        logger.error(f"Detailed auth check failed: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@s7_bp.route('/auth/batch-evaluate', methods=['POST'])
def api_batch_evaluate():
    """
    Evaluate protection levels for multiple devices

    Body:
        {
            "devices": [
                {"ip": "192.168.1.10", "rack": 0, "slot": 1, "protocol": "S7 Protocol", ...},
                {"ip": "192.168.1.11", "rack": 0, "slot": 1, "protocol": "S7 Protocol", ...}
            ],
            "max_workers": 5
        }

    Returns evaluation results for all S7 devices with detailed explanations
    """
    try:
        from s7pwn.ext.s7_auth import batch_evaluate_devices

        data = request.json or {}
        devices = data.get('devices', [])
        max_workers = data.get('max_workers', 5)

        if not devices:
            return jsonify({'success': False, 'error': 'No devices provided'}), 400

        logger.info(f"Batch evaluating {len(devices)} devices")

        # Emit progress via WebSocket if available
        if _socketio:
            def emit_progress(message):
                _socketio.emit('batch_eval_progress', {'message': message})

            _socketio.emit('batch_eval_progress', {
                'message': f'Starting evaluation of {len(devices)} devices...',
                'total': len(devices)
            })

        results = batch_evaluate_devices(devices, max_workers)

        if _socketio:
            _socketio.emit('batch_eval_progress', {
                'message': 'Evaluation complete',
                'completed': len(results)
            })

        return jsonify({
            'success': True,
            'results': results,
            'total': len(devices),
            'evaluated': len([r for r in results if not r.get('skipped')]),
            'skipped': len([r for r in results if r.get('skipped')])
        })

    except Exception as e:
        logger.error(f"Batch evaluation failed: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
