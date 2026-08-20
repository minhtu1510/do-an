"""
Web GUI for S7Pwn using Flask
Provides a web interface for all S7Pwn functionality
"""
from __future__ import annotations
import json
from flask import Flask, render_template, request, jsonify, send_file
from typing import Dict, Any, List
import threading
import webbrowser
from pathlib import Path
import sys

from s7pwn import runtime
from s7pwn.ext.scan_module import scan_network, get_rack_slot, PLC_FAMILIES
from s7pwn.ext.s7_auth import S7AuthClient, quick_auth_check, get_common_passwords
from s7pwn.utils import s7_connect
from s7pwn.report_exporter import get_exporter
from s7pwn.network_topology import get_scanner
from s7pwn.version import __version__

# Import risk assessment routes
try:
    from icsscout.interfaces.web.routes import setup_risk_assessment_routes
    RISK_ASSESSMENT_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Risk assessment module not available: {e}")
    RISK_ASSESSMENT_AVAILABLE = False

app = Flask(__name__, template_folder='templates', static_folder='static')

# Store operation history
operation_history: List[Dict[str, Any]] = []


def add_operation_log(operation_type: str, details: Dict[str, Any], success: bool = True):
    """Add operation to history log"""
    import datetime
    operation_history.append({
        "timestamp": datetime.datetime.now().isoformat(),
        "type": operation_type,
        "success": success,
        "details": details
    })


@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html', version=__version__)


@app.route('/risk-assessment')
def risk_assessment_page():
    """Risk Assessment Dashboard"""
    return render_template('risk_assessment.html', version=__version__)


@app.route('/api/status')
def api_status():
    """Get current application status"""
    target = runtime.get_current_target()
    devices = runtime.get_devices()
    plc_list = runtime.get_plc_list()

    return jsonify({
        "status": "ok",
        "version": __version__,
        "current_target": target,
        "devices_count": len(devices),
        "plc_count": len(plc_list),
        "operations_count": len(operation_history)
    })


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """Perform network scan with multi-protocol support"""
    try:
        data = request.json or {}
        timeout = data.get('timeout', 3)
        retries = data.get('retries', 2)
        protocols = data.get('protocols', None)  # List of protocols or None for default
        network_cidr = data.get('network_cidr', None)  # Network range for IP protocols

        # Convert protocols list
        if protocols and isinstance(protocols, list):
            protocols = [p.strip() for p in protocols if p.strip()]

        devices = scan_network(
            timeout=timeout,
            retries=retries,
            protocols=protocols,
            network_cidr=network_cidr,
            auto_select_interface=True  # Don't prompt for interface in web mode
        )

        plc_list = []

        for d in devices:
            if d.get("vendor") == "Siemens" and d.get("device_model") in PLC_FAMILIES:
                rack, slot = get_rack_slot(d["device_model"])
                plc_list.append({
                    "ip": d["ip"],
                    "mac": d.get("mac", "Unknown"),
                    "vendor": d["vendor"],
                    "model": d["device_model"],
                    "rack": rack,
                    "slot": slot,
                    "protocol": d.get("protocol", "Unknown")
                })

        runtime.set_scan_results(devices, plc_list)

        add_operation_log("scan", {
            "devices_found": len(devices),
            "plcs_found": len(plc_list),
            "protocols": protocols or ["profinet"],
            "network_cidr": network_cidr
        })

        return jsonify({
            "success": True,
            "devices": devices,
            "plc_list": plc_list,
            "message": f"Found {len(devices)} devices, {len(plc_list)} PLCs",
            "protocols_used": protocols or ["profinet"]
        })
    except Exception as e:
        add_operation_log("scan", {"error": str(e)}, success=False)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/devices')
def api_devices():
    """Get list of discovered devices"""
    devices = runtime.get_devices()
    plc_list = runtime.get_plc_list()

    return jsonify({
        "success": True,
        "devices": devices,
        "plc_list": plc_list
    })


@app.route('/api/target', methods=['GET', 'POST'])
def api_target():
    """Get or set current target"""
    if request.method == 'POST':
        data = request.json
        ip = data.get('ip')
        rack = data.get('rack')
        slot = data.get('slot')

        if not all([ip, rack is not None, slot is not None]):
            return jsonify({"success": False, "error": "Missing parameters"}), 400

        runtime.set_current_target(ip, rack, slot)
        add_operation_log("set_target", {"ip": ip, "rack": rack, "slot": slot})

        return jsonify({
            "success": True,
            "target": {"ip": ip, "rack": rack, "slot": slot}
        })
    else:
        target = runtime.get_current_target()
        return jsonify({
            "success": True,
            "target": target
        })


@app.route('/api/probe', methods=['POST'])
def api_probe():
    """Probe current target"""
    try:
        target = runtime.get_current_target()
        if not target:
            return jsonify({"success": False, "error": "No target selected"}), 400

        ip = target["ip"]
        rack = target["rack"]
        slot = target["slot"]

        conn = s7_connect(ip, rack, slot)
        if not conn:
            add_operation_log("probe", {"target": target, "error": "Connection failed"}, success=False)
            return jsonify({"success": False, "error": "Connection failed"}), 500

        try:
            cpu_info = conn.get_cpu_info()
            cpu_state = conn.get_cpu_state()

            def _s(x):
                try:
                    return x.decode('utf-8', errors='replace') if isinstance(x, (bytes, bytearray)) else str(x)
                except Exception:
                    return str(x)

            info = {
                "ModuleTypeName": _s(cpu_info.ModuleTypeName),
                "SerialNumber": _s(cpu_info.SerialNumber),
                "ASName": _s(cpu_info.ASName),
                "Copyright": _s(cpu_info.Copyright),
                "ModuleName": _s(cpu_info.ModuleName),
                "CPUState": _s(cpu_state),
            }

            add_operation_log("probe", {"target": target, "info": info})

            return jsonify({
                "success": True,
                "target": target,
                "info": info
            })
        finally:
            try:
                conn.disconnect()
            except:
                pass

    except Exception as e:
        add_operation_log("probe", {"error": str(e)}, success=False)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/read', methods=['POST'])
def api_read():
    """Read from PLC memory"""
    try:
        target = runtime.get_current_target()
        if not target:
            return jsonify({"success": False, "error": "No target selected"}), 400

        data = request.json
        area = data.get('area', 'M')  # M, I, Q, DB
        start = data.get('start', 0)
        size = data.get('size', 10)
        db_number = data.get('db_number', 0)

        ip = target["ip"]
        rack = target["rack"]
        slot = target["slot"]

        conn = s7_connect(ip, rack, slot)
        if not conn:
            return jsonify({"success": False, "error": "Connection failed"}), 500

        try:
            # Map area names to snap7 area codes
            area_map = {
                'M': 0x83,  # Merker
                'I': 0x81,  # Input
                'Q': 0x82,  # Output
                'DB': 0x84  # Data block
            }

            area_code = area_map.get(area.upper(), 0x83)

            if area.upper() == 'DB':
                result = conn.db_read(db_number, start, size)
            else:
                result = conn.read_area(area_code, 0, start, size)

            read_data = list(result) if result else []

            operation_details = {
                "target": target,
                "area": area,
                "start": start,
                "size": size,
                "data": read_data
            }

            if area.upper() == 'DB':
                operation_details["db_number"] = db_number

            add_operation_log("read", operation_details)

            return jsonify({
                "success": True,
                "data": read_data,
                "area": area,
                "start": start,
                "size": size
            })
        finally:
            try:
                conn.disconnect()
            except:
                pass

    except Exception as e:
        add_operation_log("read", {"error": str(e)}, success=False)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/write', methods=['POST'])
def api_write():
    """Write to PLC memory"""
    try:
        target = runtime.get_current_target()
        if not target:
            return jsonify({"success": False, "error": "No target selected"}), 400

        data = request.json
        area = data.get('area', 'M')
        start = data.get('start', 0)
        write_data = data.get('data', [])
        db_number = data.get('db_number', 0)

        if not write_data:
            return jsonify({"success": False, "error": "No data to write"}), 400

        ip = target["ip"]
        rack = target["rack"]
        slot = target["slot"]

        conn = s7_connect(ip, rack, slot)
        if not conn:
            return jsonify({"success": False, "error": "Connection failed"}), 500

        try:
            # Convert data to bytearray
            byte_data = bytearray(write_data)

            area_map = {
                'M': 0x83,
                'I': 0x81,
                'Q': 0x82,
                'DB': 0x84
            }

            area_code = area_map.get(area.upper(), 0x83)

            if area.upper() == 'DB':
                result = conn.db_write(db_number, start, byte_data)
            else:
                result = conn.write_area(area_code, 0, start, byte_data)

            operation_details = {
                "target": target,
                "area": area,
                "start": start,
                "data": write_data
            }

            if area.upper() == 'DB':
                operation_details["db_number"] = db_number

            add_operation_log("write", operation_details)

            return jsonify({
                "success": True,
                "message": "Data written successfully"
            })
        finally:
            try:
                conn.disconnect()
            except:
                pass

    except Exception as e:
        add_operation_log("write", {"error": str(e)}, success=False)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/operations')
def api_operations():
    """Get operation history"""
    return jsonify({
        "success": True,
        "operations": operation_history
    })


@app.route('/api/export', methods=['POST'])
def api_export():
    """Export data to file"""
    try:
        data = request.json
        export_type = data.get('type', 'operations')  # scan, probe, operations
        format_type = data.get('format', 'json')  # json, csv, html

        exporter = get_exporter()

        if export_type == 'scan':
            devices = runtime.get_devices()
            plc_list = runtime.get_plc_list()
            filepath = exporter.export_scan_results(devices, plc_list, format_type)

        elif export_type == 'operations':
            filepath = exporter.export_operation_log(operation_history, format_type)

        elif export_type == 'probe':
            target = runtime.get_current_target()
            if not target:
                return jsonify({"success": False, "error": "No target selected"}), 400

            # Get last probe operation from history
            probe_ops = [op for op in operation_history if op['type'] == 'probe' and op['success']]
            if not probe_ops:
                return jsonify({"success": False, "error": "No probe data available"}), 400

            last_probe = probe_ops[-1]
            filepath = exporter.export_probe_results(target, last_probe['details'], format_type)

        else:
            return jsonify({"success": False, "error": f"Unknown export type: {export_type}"}), 400

        return jsonify({
            "success": True,
            "filepath": filepath,
            "message": f"Report exported to {filepath}"
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/export/download/<path:filename>')
def api_export_download(filename):
    """Download exported file"""
    try:
        exporter = get_exporter()
        filepath = exporter.output_dir / filename
        if not filepath.exists():
            return jsonify({"success": False, "error": "File not found"}), 404

        return send_file(filepath, as_attachment=True)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# Authentication Endpoints

@app.route('/api/auth/check', methods=['POST'])
def api_auth_check():
    """Check PLC protection level"""
    try:
        target = runtime.get_current_target()
        if not target:
            return jsonify({"success": False, "error": "No target selected"}), 400

        ip = target["ip"]
        rack = target.get("rack", 0)
        slot = target.get("slot", 1)

        result = quick_auth_check(ip, rack, slot)

        add_operation_log("auth_check", {
            "target": f"{ip}:{rack}/{slot}",
            "protection": result.get('protection_level'),
            "access": result.get('access_level')
        })

        return jsonify({
            "success": True,
            "result": result
        })

    except Exception as e:
        add_operation_log("auth_check", {"error": str(e)}, success=False)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/auth/login', methods=['POST'])
def api_auth_login():
    """Authenticate with password"""
    try:
        target = runtime.get_current_target()
        if not target:
            return jsonify({"success": False, "error": "No target selected"}), 400

        data = request.json or {}
        password = data.get('password')

        if not password:
            return jsonify({"success": False, "error": "Password required"}), 400

        ip = target["ip"]
        rack = target.get("rack", 0)
        slot = target.get("slot", 1)

        client = S7AuthClient(ip, rack, slot)

        if not client.connect():
            return jsonify({"success": False, "error": "Connection failed"}), 500

        # Authenticate
        authenticated = client.authenticate_with_password(password)

        if authenticated:
            # Test access level
            access = client.test_access()

            # Store in session
            runtime.set_auth_session({
                'ip': ip,
                'rack': rack,
                'slot': slot,
                'password': password,
                'authenticated': True,
                'access_level': access.name
            })

            add_operation_log("auth_login", {
                "target": f"{ip}:{rack}/{slot}",
                "success": True,
                "access_level": access.name
            })

            client.disconnect()

            return jsonify({
                "success": True,
                "message": "Authentication successful",
                "access_level": access.name
            })
        else:
            client.disconnect()

            add_operation_log("auth_login", {
                "target": f"{ip}:{rack}/{slot}",
                "success": False
            }, success=False)

            return jsonify({
                "success": False,
                "error": "Authentication failed - invalid password"
            }), 401

    except Exception as e:
        add_operation_log("auth_login", {"error": str(e)}, success=False)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/auth/bruteforce', methods=['POST'])
def api_auth_bruteforce():
    """Brute force password testing (AUTHORIZED ONLY)"""
    try:
        target = runtime.get_current_target()
        if not target:
            return jsonify({"success": False, "error": "No target selected"}), 400

        data = request.json or {}
        use_common = data.get('use_common', True)
        custom_passwords = data.get('passwords', [])
        max_attempts = data.get('max_attempts', 100)

        if use_common:
            password_list = get_common_passwords()
        else:
            password_list = custom_passwords

        if not password_list:
            return jsonify({"success": False, "error": "No passwords to test"}), 400

        ip = target["ip"]
        rack = target.get("rack", 0)
        slot = target.get("slot", 1)

        # Run brute force in background thread
        result_container = {"found": False, "password": None, "attempts": 0}

        def do_bruteforce():
            client = S7AuthClient(ip, rack, slot)
            password = client.brute_force_password(password_list, max_attempts)
            result_container["attempts"] = min(len(password_list), max_attempts)
            if password:
                result_container["found"] = True
                result_container["password"] = password

                # Store in session
                runtime.set_auth_session({
                    'ip': ip,
                    'rack': rack,
                    'slot': slot,
                    'password': password,
                    'authenticated': True,
                    'access_level': 'UNKNOWN'
                })

        # Run synchronously for web (could be async with proper handling)
        do_bruteforce()

        if result_container["found"]:
            add_operation_log("auth_bruteforce", {
                "target": f"{ip}:{rack}/{slot}",
                "attempts": result_container["attempts"],
                "found": True
            })

            return jsonify({
                "success": True,
                "found": True,
                "password": result_container["password"],
                "attempts": result_container["attempts"],
                "message": f"Password found after {result_container['attempts']} attempts"
            })
        else:
            add_operation_log("auth_bruteforce", {
                "target": f"{ip}:{rack}/{slot}",
                "attempts": result_container["attempts"],
                "found": False
            })

            return jsonify({
                "success": True,
                "found": False,
                "attempts": result_container["attempts"],
                "message": f"Password not found after {result_container['attempts']} attempts"
            })

    except Exception as e:
        add_operation_log("auth_bruteforce", {"error": str(e)}, success=False)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/auth/status')
def api_auth_status():
    """Get current authentication status"""
    try:
        auth_session = runtime.get_auth_session()

        if auth_session and auth_session.get('authenticated'):
            return jsonify({
                "success": True,
                "authenticated": True,
                "target": f"{auth_session.get('ip')}:{auth_session.get('rack')}/{auth_session.get('slot')}",
                "access_level": auth_session.get('access_level', 'Unknown')
            })
        else:
            return jsonify({
                "success": True,
                "authenticated": False
            })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# Network Topology Endpoints

@app.route('/topology')
def topology_page():
    """Network topology visualization page"""
    return render_template('topology.html', version=__version__)


@app.route('/api/topology/scan', methods=['POST'])
def api_topology_scan():
    """Perform network topology scan"""
    try:
        data = request.json or {}
        network = data.get('network')  # Optional, auto-detect if not provided
        quick = data.get('quick', False)

        scanner = get_scanner()

        # Run scan in background thread
        def do_scan():
            scanner.full_scan(network=network, quick=quick)

        thread = threading.Thread(target=do_scan, daemon=True)
        thread.start()

        return jsonify({
            "success": True,
            "message": "Topology scan started"
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/topology/data')
def api_topology_data():
    """Get current topology data"""
    try:
        scanner = get_scanner()
        topology_data = scanner.topology.get_topology_data()

        return jsonify({
            "success": True,
            "topology": topology_data
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/topology/continuous', methods=['POST'])
def api_topology_continuous():
    """Start/stop continuous topology scanning"""
    try:
        data = request.json or {}
        action = data.get('action', 'start')  # start or stop
        interval = data.get('interval', 30)  # seconds

        scanner = get_scanner()

        if action == 'start':
            scanner.continuous_scan(interval=interval)
            return jsonify({
                "success": True,
                "message": f"Continuous scan started (interval: {interval}s)"
            })
        elif action == 'stop':
            scanner.stop_scan()
            return jsonify({
                "success": True,
                "message": "Continuous scan stopped"
            })
        else:
            return jsonify({"success": False, "error": "Invalid action"}), 400

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/topology/export', methods=['POST'])
def api_topology_export():
    """Export topology data"""
    try:
        data = request.json or {}
        format_type = data.get('format', 'json')

        scanner = get_scanner()
        exporter = get_exporter()

        topology_data = scanner.topology.get_topology_data()

        # Prepare export data
        export_data = {
            "report_type": "Network Topology",
            "scan_time": topology_data["stats"]["last_scan"],
            "stats": topology_data["stats"],
            "devices": []
        }

        # Add device details
        for ip, device in scanner.topology.devices.items():
            export_data["devices"].append(device.to_dict())

        if format_type == 'json':
            filepath = exporter.export_to_json(export_data, "topology.json")
        elif format_type == 'html':
            filepath = exporter.export_to_html(export_data, "Network Topology Report", "topology.html")
        elif format_type == 'csv':
            filepath = exporter.export_to_csv(export_data["devices"], "topology.csv")
        else:
            return jsonify({"success": False, "error": "Invalid format"}), 400

        return jsonify({
            "success": True,
            "filepath": filepath,
            "message": f"Topology exported to {filepath}"
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


def start_web_gui(host='127.0.0.1', port=5000, debug=False, open_browser=True):
    """Start the Flask web GUI"""

    # Setup risk assessment routes if available
    if RISK_ASSESSMENT_AVAILABLE:
        try:
            setup_risk_assessment_routes(app, runtime)
            print("[✓] Risk Assessment module loaded")
        except Exception as e:
            print(f"[!] Failed to setup Risk Assessment routes: {e}")
    else:
        print("[!] Risk Assessment module not available")

    if open_browser:
        # Open browser after short delay
        def open_browser_delayed():
            import time
            time.sleep(1.5)
            webbrowser.open(f'http://{host}:{port}')

        threading.Thread(target=open_browser_delayed, daemon=True).start()

    print(f"\nS7Pwn Web GUI v{__version__}")
    print(f"Server starting at http://{host}:{port}")
    print("Press Ctrl+C to stop\n")

    app.run(host=host, port=port, debug=debug, use_reloader=False)


if __name__ == '__main__':
    start_web_gui()
