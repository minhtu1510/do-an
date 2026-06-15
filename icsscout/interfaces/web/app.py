"""ICSScout Web Application with Real-time Packet Analyzer"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from pathlib import Path
import threading
import time
from datetime import datetime
from typing import Dict, Any, List
from functools import partial

# Force flush on all prints (fixes buffering in Flask/SocketIO threads)
print = partial(print, flush=True)

from icsscout.core.capture import PacketCaptureEngine, TrafficAnalyzer, CapturedPacket
from icsscout.core.capture.protocol_dissector import DissectorRegistry
from icsscout.core.vulnerability import VulnerabilityScanner
from icsscout.core.protocols.s7 import S7Client
from icsscout.core.protocols.modbus import ModbusClient
from icsscout.core.scanner import get_scanner
from icsscout.domain import Device, Target, DeviceType, DeviceStatus, ProtocolType
from icsscout.services import get_session_manager, get_activity_tracker
from icsscout.utils.logger import setup_logging, get_logger
from icsscout.version import __version__

# Import S7 routes
from icsscout.interfaces.web.s7_routes import s7_bp, set_socketio

# Import Risk Assessment routes
try:
    from icsscout.interfaces.web.routes import setup_risk_assessment_routes
    RISK_ASSESSMENT_AVAILABLE = True
    print("[✓] Risk Assessment module loaded")
except ImportError as e:
    RISK_ASSESSMENT_AVAILABLE = False
    print(f"[!] Risk Assessment module not available: {e}")

# Import OT Protocol Scanner
try:
    import sys
    from pathlib import Path
    # Add s7pwn to path
    s7pwn_path = Path(__file__).parent.parent.parent.parent / 's7pwn'
    if str(s7pwn_path) not in sys.path:
        sys.path.insert(0, str(s7pwn_path))
    from ext.ot_protocol_scanner import OTProtocolScanner
    from ext.scan_module import scan_network as profinet_scan_network, get_plc_info
    OT_SCANNER_AVAILABLE = True
    PROFINET_SCANNER_AVAILABLE = True
    print("[✓] OT Protocol Scanner loaded")
    print("[✓] Profinet DCP Scanner loaded")
except ImportError as e:
    OT_SCANNER_AVAILABLE = False
    PROFINET_SCANNER_AVAILABLE = False
    print(f"[!] OT/Profinet Scanner not available: {e}")

# Initialize Flask app
app = Flask(__name__,
            template_folder='templates',
            static_folder='static')
app.config['SECRET_KEY'] = 'icsscout-secret-key-change-in-production'
CORS(app)

# Register S7 routes blueprint
app.register_blueprint(s7_bp)

# Initialize SocketIO for real-time communication
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Inject SocketIO into S7 routes for real-time progress updates
set_socketio(socketio)

# Setup logging
setup_logging()
logger = get_logger('WebApp')

# Global state
capture_engine: PacketCaptureEngine = None
capture_thread: threading.Thread = None
session_manager = get_session_manager()
activity_tracker = get_activity_tracker()

# Monitoring state
monitoring_sessions: Dict[str, Dict[str, Any]] = {}  # session_id -> {client, monitor, thread}

# Setup activity tracker broadcast callback
def broadcast_activity(event_name, data):
    """Broadcast activity to all connected clients"""
    socketio.emit(event_name, data)

activity_tracker.set_broadcast_callback(broadcast_activity)


@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html', version=__version__)


@app.route('/packet-analyzer')
def packet_analyzer():
    """Packet analyzer page"""
    return render_template('packet_analyzer.html', version=__version__)


@app.route('/vulnerability-scanner')
def vulnerability_scanner():
    """Vulnerability scanner page"""
    return render_template('vulnerability_scanner.html', version=__version__)


@app.route('/device-manager')
def device_manager():
    """Device manager page"""
    return render_template('device_manager.html', version=__version__)


@app.route('/network-scanner')
def network_scanner():
    """Network scanner page"""
    return render_template('network_scanner.html', version=__version__)


@app.route('/monitoring')
def monitoring():
    """PLC monitoring page"""
    return render_template('monitoring.html', version=__version__)


@app.route('/s7-authentication')
def s7_authentication():
    """S7 PLC authentication page"""
    return render_template('s7_authentication.html', version=__version__)


@app.route('/risk-assessment')
def risk_assessment_page():
    """Risk Assessment Dashboard"""
    return render_template('risk_assessment.html', version=__version__)


# ============================================================================
# API Endpoints
# ============================================================================

@app.route('/api/status')
def api_status():
    """Get application status"""
    session = session_manager.get_current_session()

    return jsonify({
        'status': 'ok',
        'version': __version__,
        'session': session.to_dict() if session else None,
        'capturing': capture_engine.is_capturing if capture_engine else False
    })


@app.route('/api/interfaces')
def api_get_interfaces():
    """Get available network interfaces"""
    try:
        from scapy.all import get_if_list, get_working_ifaces

        # Get list of interfaces
        ifaces = []
        try:
            working_ifaces = get_working_ifaces()
            for iface in working_ifaces:
                ifaces.append({
                    'name': iface.name,
                    'description': iface.description if hasattr(iface, 'description') else iface.name
                })
        except:
            # Fallback to simple list
            iface_names = get_if_list()
            ifaces = [{'name': name, 'description': name} for name in iface_names]

        return jsonify({
            'success': True,
            'interfaces': ifaces
        })

    except Exception as e:
        logger.error(f"Failed to get interfaces: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'interfaces': [{'name': None, 'description': 'Auto-detect'}]
        })


@app.route('/api/session/create', methods=['POST'])
def api_create_session_legacy():
    """Create new session (legacy endpoint for backward compatibility)"""
    data = request.json
    name = data.get('name', f'Session_{datetime.now():%Y%m%d_%H%M%S}')

    session = session_manager.create_session(name)

    return jsonify({
        'success': True,
        'session': session.to_dict()
    })


@app.route('/api/capture/start', methods=['POST'])
def api_start_capture():
    """Start packet capture"""
    global capture_engine, capture_thread

    try:
        data = request.json or {}
        interface = data.get('interface')
        duration = data.get('duration')
        protocols = data.get('protocols', ['S7', 'Modbus TCP', 'OPC UA'])
        filter_expression = data.get('filter_expression')  # Can be None, "", or custom BPF

        # Create capture engine
        capture_engine = PacketCaptureEngine(interface=interface)

        # Add callback for real-time updates
        def packet_callback(packet: CapturedPacket):
            # Emit packet to all connected clients
            socketio.emit('new_packet', {
                'timestamp': packet.timestamp.isoformat(),
                'src_ip': packet.src_ip,
                'dst_ip': packet.dst_ip,
                'src_port': packet.src_port,
                'dst_port': packet.dst_port,
                'protocol': packet.protocol,
                'size': packet.size
            })

        capture_engine.add_packet_callback(packet_callback)

        # Start capture in background
        def capture_thread_func():
            capture_engine.start_capture(
                duration=duration,
                protocols=protocols,
                filter_expression=filter_expression  # Pass filter to capture engine
            )

            # Emit capture complete
            socketio.emit('capture_complete', {
                'total_packets': capture_engine.statistics.total_packets,
                'total_bytes': capture_engine.statistics.bytes_captured
            })

        capture_thread = threading.Thread(target=capture_thread_func, daemon=True)
        capture_thread.start()

        logger.info(f"Started packet capture (duration={duration}, protocols={protocols})")

        return jsonify({
            'success': True,
            'message': 'Capture started'
        })

    except Exception as e:
        logger.error(f"Failed to start capture: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/capture/stop', methods=['POST'])
def api_stop_capture():
    """Stop packet capture"""
    global capture_engine

    try:
        if capture_engine and capture_engine.is_capturing:
            stats = capture_engine.stop_capture()

            return jsonify({
                'success': True,
                'statistics': stats.to_dict()
            })
        else:
            return jsonify({
                'success': False,
                'error': 'No active capture'
            }), 400

    except Exception as e:
        logger.error(f"Failed to stop capture: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/capture/status')
def api_capture_status():
    """Get capture status"""
    if capture_engine:
        return jsonify({
            'capturing': capture_engine.is_capturing,
            'statistics': capture_engine.statistics.to_dict()
        })
    else:
        return jsonify({
            'capturing': False,
            'statistics': None
        })


@app.route('/api/packets')
def api_get_packets():
    """Get captured packets"""
    try:
        if not capture_engine:
            return jsonify({'success': False, 'error': 'No capture data'}), 400

        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        protocol_filter = request.args.get('protocol')

        packets = capture_engine.packets

        # Apply filter
        if protocol_filter:
            packets = [p for p in packets if p.protocol == protocol_filter]

        # Paginate
        total = len(packets)
        packets = packets[offset:offset + limit]

        # Convert to JSON
        packet_list = []
        for i, packet in enumerate(packets, start=offset):
            packet_list.append({
                'index': i,
                'timestamp': packet.timestamp.isoformat(),
                'src_ip': packet.src_ip,
                'dst_ip': packet.dst_ip,
                'src_port': packet.src_port,
                'dst_port': packet.dst_port,
                'protocol': packet.protocol,
                'size': packet.size,
                'info': packet.parsed_data.get('function_name') if packet.parsed_data else ''
            })

        return jsonify({
            'success': True,
            'packets': packet_list,
            'total': total,
            'offset': offset,
            'limit': limit
        })

    except Exception as e:
        logger.error(f"Failed to get packets: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/packets/<int:index>')
def api_get_packet_detail(index):
    """Get detailed packet information"""
    try:
        if not capture_engine or index >= len(capture_engine.packets):
            return jsonify({'success': False, 'error': 'Packet not found'}), 404

        packet = capture_engine.packets[index]
        raw_pkt = packet.raw_packet

        # Get raw data safely
        raw_data = b''
        try:
            # Try to get application layer data
            if packet.protocol in ['S7', 'Modbus TCP', 'OPC UA']:
                # For OT protocols, get payload after TCP
                if raw_pkt.haslayer('Raw'):
                    raw_data = bytes(raw_pkt['Raw'].load)
                elif raw_pkt.haslayer('TCP'):
                    raw_data = bytes(raw_pkt['TCP'].payload)
            else:
                # For non-OT protocols, get full packet
                raw_data = bytes(raw_pkt)
        except:
            # Fallback
            raw_data = bytes(raw_pkt)

        # Dissect packet
        if packet.protocol in ['S7', 'Modbus TCP', 'OPC UA']:
            dissected = DissectorRegistry.dissect_packet(packet.protocol, raw_data)
        else:
            # Generic dissection for non-OT protocols
            dissected = {'protocol': packet.protocol, 'layers': []}

            # Add layer info
            if raw_pkt.haslayer('Ether'):
                dissected['layers'].append({
                    'name': 'Ethernet',
                    'fields': {
                        'Source MAC': raw_pkt['Ether'].src,
                        'Destination MAC': raw_pkt['Ether'].dst
                    }
                })

            if raw_pkt.haslayer('IP'):
                dissected['layers'].append({
                    'name': 'IP',
                    'fields': {
                        'Source': raw_pkt['IP'].src,
                        'Destination': raw_pkt['IP'].dst,
                        'TTL': raw_pkt['IP'].ttl
                    }
                })

            if raw_pkt.haslayer('TCP'):
                dissected['layers'].append({
                    'name': 'TCP',
                    'fields': {
                        'Source Port': raw_pkt['TCP'].sport,
                        'Destination Port': raw_pkt['TCP'].dport,
                        'Flags': str(raw_pkt['TCP'].flags)
                    }
                })

            if raw_pkt.haslayer('UDP'):
                dissected['layers'].append({
                    'name': 'UDP',
                    'fields': {
                        'Source Port': raw_pkt['UDP'].sport,
                        'Destination Port': raw_pkt['UDP'].dport
                    }
                })

            if raw_pkt.haslayer('Raw'):
                payload = bytes(raw_pkt['Raw'].load)
                dissected['layers'].append({
                    'name': 'Payload',
                    'fields': {
                        'Length': len(payload),
                        'Data (first 64 bytes)': payload[:64].hex()
                    }
                })

        return jsonify({
            'success': True,
            'packet': {
                'index': index,
                'timestamp': packet.timestamp.isoformat(),
                'src_ip': packet.src_ip,
                'dst_ip': packet.dst_ip,
                'src_port': packet.src_port,
                'dst_port': packet.dst_port,
                'protocol': packet.protocol,
                'size': packet.size,
                'raw_hex': raw_data[:256].hex() if raw_data else bytes(raw_pkt)[:256].hex(),
                'dissected': dissected
            }
        })

    except Exception as e:
        logger.error(f"Failed to get packet detail: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/traffic/analyze', methods=['POST'])
def api_analyze_traffic():
    """Analyze captured traffic"""
    try:
        if not capture_engine:
            return jsonify({'success': False, 'error': 'No capture data'}), 400

        analyzer = TrafficAnalyzer()
        stats = analyzer.analyze_capture(capture_engine.packets)

        # Generate report
        report = analyzer.generate_report()

        return jsonify({
            'success': True,
            'analysis': report
        })

    except Exception as e:
        logger.error(f"Failed to analyze traffic: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/capture/export/<format>')
def api_export_capture(format):
    """Export capture"""
    try:
        if not capture_engine:
            return jsonify({'success': False, 'error': 'No capture data'}), 400

        if format == 'pcap':
            filename = f"capture_{datetime.now():%Y%m%d_%H%M%S}.pcap"
            filepath = f"/tmp/{filename}"
            capture_engine.export_pcap(filepath)

            return send_file(filepath, as_attachment=True, download_name=filename)

        else:
            return jsonify({'success': False, 'error': 'Invalid format'}), 400

    except Exception as e:
        logger.error(f"Failed to export: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices')
def api_get_devices():
    """Get discovered devices"""
    print(f"[API] /api/devices endpoint called")
    devices = session_manager.get_devices()
    print(f"[API] Found {len(devices)} devices in session")
    print(f"[API] Device IPs: {[d.ip for d in devices]}")

    devices_dict = [d.to_dict() for d in devices]
    print(f"[API] Returning {len(devices_dict)} devices")

    return jsonify({
        'success': True,
        'devices': devices_dict
    })


@app.route('/api/devices/scan', methods=['POST'])
def api_scan_devices():
    """Refresh device list from session manager"""
    # Network Scanner already stores devices in session_manager
    # This endpoint just returns the current device list
    try:
        print("[API] /api/devices/scan called (refresh device list)")
        devices = session_manager.get_devices()
        print(f"[API] Found {len(devices)} devices in session manager")

        return jsonify({
            'success': True,
            'devices': [d.to_dict() for d in devices]
        })

    except Exception as e:
        print(f"[API] Error in /api/devices/scan: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/vulnerability/scan', methods=['POST'])
def api_scan_vulnerabilities():
    """Scan devices for vulnerabilities"""
    try:
        data = request.json
        device_ips = data.get('devices', [])

        if not device_ips:
            # Scan all devices
            devices = session_manager.get_devices()
        else:
            # Scan specific devices
            all_devices = session_manager.get_devices()
            devices = [d for d in all_devices if d.ip in device_ips]

        scanner = VulnerabilityScanner()
        reports = {}

        for device in devices:
            report = scanner.scan_device(device)
            reports[device.ip] = report.to_dict()

        return jsonify({
            'success': True,
            'reports': reports
        })

    except Exception as e:
        logger.error(f"Vulnerability scan failed: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# Network Scanner API
# ============================================================================

@app.route('/api/scanner/scan-network', methods=['POST'])
def api_scan_network():
    """
    Scan an entire network for devices

    Body:
        {
            "network": "192.168.1.0/24" (optional, auto-detect if not provided),
            "scan_type": "quick" | "normal" | "full",
            "scan_ports": true/false
        }
    """
    try:
        data = request.json or {}
        network = data.get('network')
        scan_type = data.get('scan_type', 'quick')
        scan_ports = data.get('scan_ports', True)

        print(f"\n{'='*60}")
        print(f"[API] /api/scanner/scan-network endpoint called!")
        print(f"[API] Network: {network}")
        print(f"[API] Scan Type: {scan_type}")
        print(f"[API] Scan Ports: {scan_ports}")
        print(f"{'='*60}\n")

        scanner = get_scanner()

        # Run scan in background thread and return immediately
        def run_scan():
            try:
                # Setup progress callback to emit WebSocket events
                def progress_callback(event, data):
                    socketio.emit('scan_progress', {
                        'event': event,
                        'data': data
                    })

                scanner.set_progress_callback(progress_callback)

                # Log scan start
                display_network = network or "auto-detected network"
                activity_tracker.log_scan_start(display_network, scan_type)

                # Run the scan
                print(f"[SCAN] About to call scanner.scan_network()")
                print(f"[SCAN]   - network: {network}")
                print(f"[SCAN]   - scan_type: {scan_type}")
                print(f"[SCAN]   - scan_ports: {scan_ports}")

                result = scanner.scan_network(
                    network=network,
                    scan_type=scan_type,
                    scan_ports=scan_ports
                )

                print(f"[SCAN] scan_network() returned with {len(result.devices)} devices")
                print(f"[SCAN] Devices: {[d.ip for d in result.devices]}")

                # Save devices to session manager
                logger.info(f"Adding {len(result.devices)} devices to session manager...")
                print(f"[SESSION] Adding {len(result.devices)} devices to session manager...")

                # Ensure session exists
                if not session_manager.get_current_session():
                    logger.warning("No active session, creating default session...")
                    print(f"[SESSION] No active session, creating default session...")
                    session_manager.create_session('Network Scan Session')
                else:
                    print(f"[SESSION] Using existing session: {session_manager.get_current_session().name}")

                devices_added = 0
                for idx, scanned_device in enumerate(result.devices):
                    print(f"[SESSION] Processing device {idx+1}/{len(result.devices)}: {scanned_device.ip}")
                    try:
                        # Map device type from network scanner to domain device type
                        device_type_map = {
                            'PLC': DeviceType.PLC,
                            'HMI': DeviceType.HMI,
                            'RTU': DeviceType.RTU,
                            'SCADA': DeviceType.SCADA,
                            'Gateway': DeviceType.GATEWAY,
                            'Router': DeviceType.ROUTER,
                            'Switch': DeviceType.SWITCH,
                            'Server': DeviceType.UNKNOWN,
                            'Computer': DeviceType.UNKNOWN,
                            'Workstation': DeviceType.UNKNOWN,
                        }

                        # Detect device type
                        device_type = DeviceType.UNKNOWN
                        for key, dtype in device_type_map.items():
                            if key in scanned_device.device_type:
                                device_type = dtype
                                break

                        # Extract protocols from services
                        protocols = []
                        for port, service in scanned_device.services.items():
                            if 'S7' in service or 'Siemens' in service:
                                if 'S7' not in protocols:
                                    protocols.append('S7')
                            elif 'Modbus' in service:
                                if 'Modbus TCP' not in protocols:
                                    protocols.append('Modbus TCP')
                            elif 'OPC UA' in service:
                                if 'OPC UA' not in protocols:
                                    protocols.append('OPC UA')
                            elif 'DNP3' in service:
                                if 'DNP3' not in protocols:
                                    protocols.append('DNP3')
                            elif 'EtherNet/IP' in service:
                                if 'EtherNet/IP' not in protocols:
                                    protocols.append('EtherNet/IP')

                        # Convert NetworkDevice to Domain Device
                        device = Device(
                            ip=scanned_device.ip,
                            mac=scanned_device.mac if scanned_device.mac else None,
                            hostname=scanned_device.hostname if scanned_device.hostname else None,
                            vendor=scanned_device.vendor,
                            device_type=device_type,
                            status=DeviceStatus.ONLINE,
                            protocols=protocols,
                            open_ports=scanned_device.open_ports,
                            ttl=scanned_device.ttl if scanned_device.ttl else None,
                            os_guess=scanned_device.os_guess if scanned_device.os_guess else None
                        )

                        session_manager.add_device(device)
                        devices_added += 1
                        logger.debug(f"Added device {device.ip} ({device.device_type.value}) to session")
                        print(f"[SESSION] ✓ Added device {device.ip} (type={device.device_type.value}, ports={device.open_ports})")

                    except Exception as e:
                        logger.error(f"Failed to add device {scanned_device.ip}: {e}")
                        logger.exception("Full traceback:")
                        print(f"[SESSION] ✗ Failed to add device {scanned_device.ip}: {e}")
                        continue

                    # Log each device found
                    if scanned_device.open_ports:
                        activity_tracker.log_device_found(
                            scanned_device.ip,
                            scanned_device.device_type,
                            len(scanned_device.open_ports)
                        )

                logger.info(f"Successfully added {devices_added} devices to session manager")
                print(f"[SESSION] Successfully added {devices_added} devices to session manager")

                # Check total devices in session
                total_in_session = len(session_manager.get_devices())
                print(f"[SESSION] Total devices in session now: {total_in_session}")
                print(f"[SESSION] Device IPs: {[d.ip for d in session_manager.get_devices()]}")

                # Emit device update event
                print(f"[WEBSOCKET] Emitting 'devices_updated' event...")
                socketio.emit('devices_updated', {
                    'total_devices': total_in_session,
                    'devices_added': devices_added
                })
                print(f"[WEBSOCKET] Event emitted: total={total_in_session}, added={devices_added}")

                # Log scan completion
                activity_tracker.log_scan_complete(
                    result.network,
                    len(result.devices),
                    result.duration
                )

                # Emit results via WebSocket
                socketio.emit('scan_complete', result.to_dict())

            except Exception as e:
                logger.error(f"Network scan failed: {e}")
                logger.exception("Full traceback:")
                activity_tracker.log_error(f"Network scan failed: {str(e)}")
                socketio.emit('scan_error', {'error': str(e)})

        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()

        return jsonify({
            'success': True,
            'message': 'Network scan started',
            'scan_type': scan_type
        })

    except Exception as e:
        logger.error(f"Failed to start network scan: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scanner/scan-ip', methods=['POST'])
def api_scan_single_ip():
    """
    Scan a single IP address

    Body:
        {
            "ip": "192.168.1.100",
            "scan_ports": true/false,
            "ports": [80, 102, 443, 502] (optional)
        }
    """
    try:
        data = request.json
        ip = data.get('ip')
        scan_ports = data.get('scan_ports', True)
        ports = data.get('ports')

        if not ip:
            return jsonify({'success': False, 'error': 'IP address required'}), 400

        scanner = get_scanner()
        device = scanner.scan_single_ip(ip, scan_ports=scan_ports, ports=ports)

        if device:
            return jsonify({
                'success': True,
                'device': device.to_dict()
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Host {ip} is down or unreachable'
            }), 404

    except Exception as e:
        logger.error(f"IP scan failed: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scanner/network-info', methods=['GET'])
def api_get_network_info():
    """Get local network information including all interfaces"""
    try:
        scanner = get_scanner()
        local_ip, subnet = scanner.get_local_ip_and_subnet()
        gateway_ip = scanner.get_default_gateway()
        all_interfaces = scanner.get_all_network_interfaces()

        return jsonify({
            'success': True,
            'local_ip': local_ip,
            'subnet': subnet,
            'gateway': gateway_ip,
            'interfaces': all_interfaces
        })

    except Exception as e:
        logger.error(f"Failed to get network info: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scanner/last-result', methods=['GET'])
def api_get_last_scan_result():
    """Get the last scan result if available"""
    try:
        scanner = get_scanner()
        last_result = scanner.get_last_scan_result()

        if last_result:
            return jsonify({
                'success': True,
                'has_result': True,
                'result': last_result.to_dict()
            })
        else:
            return jsonify({
                'success': True,
                'has_result': False,
                'result': None
            })

    except Exception as e:
        logger.error(f"Failed to get last scan result: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scanner/scan-ot-protocols', methods=['POST'])
def api_scan_ot_protocols():
    """
    Scan devices for OT protocol details (S7, Modbus, EtherNet/IP, BACnet, FINS)

    Body:
        {
            "ip_addresses": ["192.168.1.10", "192.168.1.20"],  // optional, if not provided scan all session devices
            "protocols": ["s7", "modbus", "ethernet_ip", "bacnet", "fins"]  // optional, default all
        }
    """
    if not OT_SCANNER_AVAILABLE:
        return jsonify({
            'success': False,
            'error': 'OT Protocol Scanner not available'
        }), 503

    try:
        data = request.json or {}
        ip_addresses = data.get('ip_addresses')
        protocols = data.get('protocols')

        print(f"\n{'='*60}")
        print(f"[API] /api/scanner/scan-ot-protocols endpoint called!")
        print(f"[API] IP Addresses: {ip_addresses}")
        print(f"[API] Protocols: {protocols}")
        print(f"{'='*60}\n")

        # Get devices to scan
        devices_to_scan = []
        if ip_addresses:
            # Scan specific IPs
            devices_to_scan = [(ip, None) for ip in ip_addresses]
        else:
            # Scan all devices in session (if any)
            session_devices = session_manager.get_devices()
            if session_devices:
                devices_to_scan = [(d.ip, d) for d in session_devices]
                print(f"[OT SCAN] Will scan {len(devices_to_scan)} devices from session")
            else:
                print(f"[OT SCAN] No devices in session - will discover via Profinet DCP scan")

        # Run scan in background thread
        def run_ot_scan():
            try:
                scanned_count = 0
                updated_count = 0

                # STEP 1: Run Profinet DCP scan (broadcast, finds all devices on network)
                if PROFINET_SCANNER_AVAILABLE and not ip_addresses:  # Only if scanning all devices
                    try:
                        print(f"[PROFINET SCAN] Starting Profinet DCP scan...")
                        profinet_devices = profinet_scan_network(
                            timeout=2,
                            retries=1,
                            protocols=['profinet'],
                            auto_select_interface=True
                        )

                        if profinet_devices:
                            print(f"[PROFINET SCAN] Found {len(profinet_devices)} Profinet devices")

                            # Update devices in session with Profinet info
                            for pn_dev in profinet_devices:
                                ip = pn_dev.get('ip')
                                if not ip or ip == 'Unknown' or ip == '0.0.0.0':
                                    continue

                                # Find or create device in session
                                device_obj = next((d for d in session_manager.get_devices() if d.ip == ip), None)

                                if not device_obj:
                                    # CREATE new device from Profinet discovery
                                    plc_info = pn_dev.get('plc_info')

                                    # Determine device type from device_model and role
                                    device_type = DeviceType.UNKNOWN
                                    device_model = pn_dev.get('device_model', '')
                                    role = pn_dev.get('role', '')

                                    if device_model in ['S7-1500', 'S7-1200', 'S7-300', 'S7-400']:
                                        device_type = DeviceType.PLC
                                    elif 'SIMATIC HMI' in device_model or 'TP' in device_model or 'KP' in device_model:
                                        device_type = DeviceType.HMI
                                    elif 'SINAMICS' in device_model or 'G120' in device_model:
                                        device_type = DeviceType.UNKNOWN  # Drive/Inverter (no specific type)
                                    elif 'ET 200' in device_model or 'ET200' in device_model:
                                        device_type = DeviceType.RTU  # Distributed I/O
                                    elif role == 'IO-Controller':
                                        device_type = DeviceType.PLC
                                    elif role == 'IO-Device':
                                        device_type = DeviceType.RTU

                                    device_obj = Device(
                                        ip=ip,
                                        mac=pn_dev.get('mac'),
                                        hostname=pn_dev.get('name'),
                                        vendor=pn_dev.get('vendor', 'Unknown'),
                                        model=plc_info.get('module_type') if plc_info else pn_dev.get('device_model', 'Unknown'),
                                        device_type=device_type,
                                        status=DeviceStatus.ONLINE,
                                        protocols=['Profinet DCP'],
                                        serial_number=plc_info.get('serial_number') if plc_info else None,
                                        firmware_version=plc_info.get('firmware') if plc_info else None,
                                        rack=plc_info.get('rack') if plc_info else None,
                                        slot=plc_info.get('slot') if plc_info else None,
                                        cpu_state=plc_info.get('cpu_state') if plc_info else None
                                    )
                                    print(f"[PROFINET SCAN] ✓ Created new device {ip} ({device_type.value}) from Profinet discovery")
                                else:
                                    # Update existing device
                                    if 'Profinet DCP' not in device_obj.protocols:
                                        device_obj.protocols.append('Profinet DCP')
                                    print(f"[PROFINET SCAN] ✓ Updating existing device {ip}")

                                # Store Profinet info in metadata (for both new and existing)
                                plc_info = pn_dev.get('plc_info')
                                device_obj.metadata['profinet_info'] = {
                                    'name': pn_dev.get('name', 'Unknown'),
                                    'mac': pn_dev.get('mac', 'Unknown'),
                                    'vendor': pn_dev.get('vendor', 'Unknown'),
                                    'device_model': pn_dev.get('device_model', 'Unknown'),
                                    'role': pn_dev.get('role', 'Unknown'),
                                    'device_id': pn_dev.get('device_id', 'Unknown'),
                                    'type_station': pn_dev.get('type_station', 'Unknown')
                                }

                                # Update metadata from PLC info if available
                                if plc_info:
                                    device_obj.metadata['profinet_info']['module_type'] = plc_info.get('module_type')
                                    device_obj.metadata['profinet_info']['serial_number'] = plc_info.get('serial_number')
                                    device_obj.metadata['profinet_info']['firmware'] = plc_info.get('firmware')
                                    device_obj.metadata['profinet_info']['cpu_state'] = plc_info.get('cpu_state')
                                    device_obj.metadata['profinet_info']['rack'] = plc_info.get('rack')
                                    device_obj.metadata['profinet_info']['slot'] = plc_info.get('slot')

                                    # Update top-level device fields from PLC info
                                    if plc_info.get('module_type'):
                                        device_obj.model = plc_info.get('module_type')
                                    if plc_info.get('serial_number'):
                                        device_obj.serial_number = plc_info.get('serial_number')
                                    if plc_info.get('firmware'):
                                        device_obj.firmware_version = plc_info.get('firmware')

                                # Update vendor/model from Profinet even if no PLC info
                                if pn_dev.get('vendor') and pn_dev.get('vendor') != 'Unknown':
                                    device_obj.vendor = pn_dev.get('vendor')
                                if pn_dev.get('device_model') and pn_dev.get('device_model') != 'Unknown':
                                    if not device_obj.model or device_obj.model == 'Unknown':
                                        device_obj.model = pn_dev.get('device_model')

                                # Ensure device_type is updated based on Profinet data
                                if device_obj.device_type == DeviceType.UNKNOWN:
                                    device_model = pn_dev.get('device_model', '')
                                    role = pn_dev.get('role', '')

                                    if device_model in ['S7-1500', 'S7-1200', 'S7-300', 'S7-400']:
                                        device_obj.device_type = DeviceType.PLC
                                    elif 'SIMATIC HMI' in device_model or 'TP' in device_model or 'KP' in device_model:
                                        device_obj.device_type = DeviceType.HMI
                                    elif 'ET 200' in device_model or 'ET200' in device_model:
                                        device_obj.device_type = DeviceType.RTU
                                    elif role == 'IO-Controller':
                                        device_obj.device_type = DeviceType.PLC
                                    elif role == 'IO-Device':
                                        device_obj.device_type = DeviceType.RTU

                                # Add/update device in session (INSIDE the loop!)
                                session_manager.add_device(device_obj)
                                updated_count += 1
                                print(f"[PROFINET SCAN] ✓ Device {ip} added/updated in session")

                            # Save session after Profinet scan completes (OUTSIDE the loop)
                            try:
                                session_manager.save_session()
                                print(f"[PROFINET SCAN] Session saved with {updated_count} Profinet devices")
                            except Exception as save_error:
                                print(f"[PROFINET SCAN] Error saving session: {save_error}")

                    except Exception as e:
                        print(f"[PROFINET SCAN] Error: {e}")
                        logger.error(f"Profinet scan failed: {e}")

                # STEP 2: Run IP-based protocol scans (S7, Modbus, EtherNet/IP, BACnet, FINS)
                for ip, device_obj in devices_to_scan:
                    try:
                        print(f"[OT SCAN] Scanning {ip} for OT protocols...")

                        # Scan this IP for OT protocols
                        results = OTProtocolScanner.scan_ip(ip, protocols)

                        if results:
                            print(f"[OT SCAN] Found {len(results)} OT protocols on {ip}")
                            scanned_count += 1

                            # Get or find device in session
                            if device_obj is None:
                                device_obj = next((d for d in session_manager.get_devices() if d.ip == ip), None)

                            if device_obj:
                                # Update device with OT scan results
                                for result in results:
                                    protocol = result['protocol']
                                    info = result.get('info', {})

                                    # Add protocol if not already there
                                    if protocol not in device_obj.protocols:
                                        device_obj.protocols.append(protocol)

                                    # Store protocol-specific info in metadata
                                    if protocol == 'S7':
                                        device_obj.metadata['s7_info'] = info
                                        device_obj.vendor = 'Siemens'
                                        if 'DeviceType' in info:
                                            device_obj.model = info['DeviceType']
                                    elif protocol == 'Modbus TCP':
                                        device_obj.metadata['modbus_info'] = info
                                        if 'VendorName' in info:
                                            device_obj.vendor = info['VendorName']
                                        if 'ProductName' in info:
                                            device_obj.model = info['ProductName']
                                        elif 'ModelName' in info:
                                            device_obj.model = info['ModelName']
                                        if 'MajorMinorRevision' in info:
                                            device_obj.firmware_version = info['MajorMinorRevision']
                                    elif protocol == 'EtherNet/IP':
                                        device_obj.metadata['ethernet_ip_info'] = info
                                        if 'ProductName' in info:
                                            device_obj.model = info['ProductName']
                                        if 'Revision' in info:
                                            device_obj.firmware_version = info['Revision']
                                        if 'SerialNumber' in info:
                                            device_obj.serial_number = info['SerialNumber']
                                    elif protocol == 'BACnet':
                                        device_obj.metadata['bacnet_info'] = info
                                    elif protocol == 'FINS':
                                        device_obj.metadata['fins_info'] = info
                                        device_obj.vendor = 'Omron'

                                # Update device in session
                                session_manager.add_device(device_obj)
                                updated_count += 1
                                print(f"[OT SCAN] ✓ Updated device {ip} with OT protocol data")
                            else:
                                print(f"[OT SCAN] ⚠ Device {ip} not found in session, skipping metadata update")
                        else:
                            print(f"[OT SCAN] No OT protocols found on {ip}")

                    except Exception as e:
                        print(f"[OT SCAN] Error scanning {ip}: {e}")
                        logger.error(f"Error scanning {ip} for OT protocols: {e}")
                        continue

                # Emit completion event
                socketio.emit('ot_scan_complete', {
                    'scanned': len(devices_to_scan),
                    'found': scanned_count,
                    'updated': updated_count
                })

                # Force save session after OT scan completes
                try:
                    session_manager.save_session()
                    print(f"[OT SCAN] Session saved successfully with {updated_count} updated devices")
                except Exception as save_error:
                    print(f"[OT SCAN] Error saving session: {save_error}")
                    logger.error(f"Failed to save session after OT scan: {save_error}")

                print(f"[OT SCAN] Complete: {scanned_count}/{len(devices_to_scan)} devices with OT protocols, {updated_count} updated")

            except Exception as e:
                logger.error(f"OT protocol scan failed: {e}")
                logger.exception("Full traceback:")
                socketio.emit('ot_scan_error', {'error': str(e)})

        thread = threading.Thread(target=run_ot_scan, daemon=True)
        thread.start()

        if devices_to_scan:
            message = f'OT protocol scan started for {len(devices_to_scan)} devices'
        else:
            message = 'OT protocol scan started - will discover devices via Profinet DCP'

        return jsonify({
            'success': True,
            'message': message,
            'devices_count': len(devices_to_scan)
        })

    except Exception as e:
        logger.error(f"Failed to start OT protocol scan: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/activities', methods=['GET'])
def api_get_activities():
    """Get recent activities"""
    try:
        count = request.args.get('count', 50, type=int)
        activities = activity_tracker.get_recent(count)

        return jsonify({
            'success': True,
            'activities': [a.to_dict() for a in activities],
            'count': len(activities)
        })

    except Exception as e:
        logger.error(f"Failed to get activities: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# Session Management API
# ============================================================================

@app.route('/sessions')
def sessions_page():
    """Session Manager page"""
    return render_template('sessions.html', version=__version__)


@app.route('/api/sessions', methods=['GET'])
def api_list_sessions():
    """List all saved sessions"""
    try:
        from pathlib import Path
        import json

        sessions_dir = Path('data')
        session_files = sorted(sessions_dir.glob('session_*.json'), key=lambda p: p.stat().st_mtime, reverse=True)

        sessions = []
        for session_file in session_files:
            try:
                with open(session_file, 'r') as f:
                    data = json.load(f)
                    sessions.append({
                        'session_id': data.get('session_id'),
                        'name': data.get('name', 'Unnamed Session'),
                        'created_at': data.get('created_at'),
                        'current_phase': data.get('current_phase', 'UNKNOWN'),
                        'device_count': len(data.get('devices', [])),
                        'operation_count': data.get('operation_count', 0),
                        'file_size': session_file.stat().st_size,
                        'is_current': session_manager.get_current_session() and
                                     session_manager.get_current_session().session_id == data.get('session_id'),
                        'has_risk_report': data.get('risk_assessment_results') is not None
                    })
            except Exception as e:
                logger.error(f"Error reading session file {session_file}: {e}")
                continue

        return jsonify({
            'success': True,
            'sessions': sessions,
            'count': len(sessions)
        })

    except Exception as e:
        logger.error(f"Failed to list sessions: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/sessions/current', methods=['GET'])
def api_get_current_session():
    """Get current active session"""
    try:
        current = session_manager.get_current_session()

        if current:
            return jsonify({
                'success': True,
                'session': current.to_dict()
            })
        else:
            return jsonify({
                'success': True,
                'session': None
            })

    except Exception as e:
        logger.error(f"Failed to get current session: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/sessions', methods=['POST'])
def api_create_session():
    """Create new session"""
    try:
        data = request.json or {}
        name = data.get('name', f'Session {datetime.now():%Y-%m-%d %H:%M}')

        session = session_manager.create_session(name)

        logger.info(f"Created new session: {session.name} ({session.session_id})")

        return jsonify({
            'success': True,
            'session': session.to_dict()
        })

    except Exception as e:
        logger.error(f"Failed to create session: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/sessions/<session_id>', methods=['GET'])
def api_get_session(session_id):
    """Get session details"""
    try:
        from pathlib import Path
        import json

        session_file = Path('data') / f'{session_id}.json'

        if not session_file.exists():
            return jsonify({'success': False, 'error': 'Session not found'}), 404

        with open(session_file, 'r') as f:
            data = json.load(f)

        return jsonify({
            'success': True,
            'session': data
        })

    except Exception as e:
        logger.error(f"Failed to get session {session_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/sessions/<session_id>/load', methods=['POST'])
def api_load_session(session_id):
    """Load a saved session"""
    try:
        # Construct the full filepath
        session_file = Path('data') / f'{session_id}.json'

        if not session_file.exists():
            return jsonify({'success': False, 'error': f'Session file not found: {session_id}'}), 404

        session_manager.load_session(str(session_file))

        logger.info(f"Loaded session: {session_id}")

        # Emit event to notify clients
        socketio.emit('session_changed', {
            'session_id': session_id,
            'device_count': len(session_manager.get_devices())
        })

        return jsonify({
            'success': True,
            'session': session_manager.get_current_session().to_dict()
        })

    except Exception as e:
        logger.error(f"Failed to load session {session_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/sessions/<session_id>', methods=['DELETE'])
def api_delete_session(session_id):
    """Delete a session"""
    try:
        from pathlib import Path

        session_file = Path('data') / f'{session_id}.json'

        if not session_file.exists():
            return jsonify({'success': False, 'error': 'Session not found'}), 404

        # Don't delete current session
        current = session_manager.get_current_session()
        if current and current.session_id == session_id:
            return jsonify({'success': False, 'error': 'Cannot delete active session'}), 400

        session_file.unlink()
        logger.info(f"Deleted session: {session_id}")

        return jsonify({
            'success': True,
            'message': 'Session deleted successfully'
        })

    except Exception as e:
        logger.error(f"Failed to delete session {session_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/sessions/<session_id>/risk-report', methods=['GET'])
def api_download_risk_report(session_id):
    """Download risk assessment report from session"""
    try:
        from pathlib import Path
        import json

        session_file = Path('data') / f'{session_id}.json'

        if not session_file.exists():
            return jsonify({'success': False, 'error': 'Session not found'}), 404

        # Load session data
        with open(session_file, 'r') as f:
            session_data = json.load(f)

        # Get risk assessment results
        risk_results = session_data.get('risk_assessment_results')

        if not risk_results:
            return jsonify({'success': False, 'error': 'No risk assessment found in this session'}), 404

        return jsonify({
            'success': True,
            'report': risk_results
        })

    except Exception as e:
        logger.error(f"Failed to get risk report from session {session_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# Monitoring API
# ============================================================================

@app.route('/api/monitoring/scan-slots', methods=['POST'])
def api_monitoring_scan_slots():
    """Scan multiple rack/slot combinations to find available PLCs"""
    try:
        data = request.json
        ip = data.get('ip')
        max_racks = data.get('max_racks', 1)
        max_slots = data.get('max_slots', 8)

        if not ip:
            return jsonify({'success': False, 'error': 'IP address required'}), 400

        logger.info(f"Scanning {ip} for PLCs (Racks: 0-{max_racks-1}, Slots: 0-{max_slots-1})")

        found_plcs = []

        # Scan through rack/slot combinations
        for rack in range(max_racks):
            for slot in range(max_slots):
                try:
                    logger.info(f"Connecting to {ip}:102 (Rack {rack}, Slot {slot})")

                    # Create device and target
                    device = Device(
                        ip=ip,
                        device_type=DeviceType.PLC,
                        vendor="Siemens",
                        model="S7",
                        protocols=["S7"]
                    )

                    target = Target(
                        device=device,
                        protocol=ProtocolType.S7,
                        rack=rack,
                        slot=slot
                    )

                    # Create S7 client
                    client = S7Client(target)
                    result = client.connect()

                    if result.success:
                        # Get PLC info
                        plc_info = {'rack': rack, 'slot': slot}
                        try:
                            info_result = client.get_device_info()
                            if info_result.success:
                                plc_info.update(info_result.data)
                        except Exception as e:
                            logger.warning(f"Could not get PLC info for Rack {rack}, Slot {slot}: {e}")

                        found_plcs.append(plc_info)
                        logger.info(f"Found PLC at Rack {rack}, Slot {slot}")

                        # Disconnect after successful scan
                        client.disconnect()
                    else:
                        logger.error(f"Connection failed: {result.message}")

                except Exception as e:
                    logger.error(f"Error scanning Rack {rack}, Slot {slot}: {e}")

        logger.info(f"Scan complete for {ip}: found {len(found_plcs)} PLC(s)")

        return jsonify({
            'success': True,
            'ip': ip,
            'found': found_plcs,  # Frontend expects 'found' not 'found_plcs'
            'count': len(found_plcs)  # Frontend expects 'count' not 'total_found'
        })

    except Exception as e:
        logger.error(f"Failed to scan slots: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/monitoring/connect', methods=['POST'])
def api_monitoring_connect():
    """Connect to PLC for monitoring"""
    try:
        data = request.json
        ip = data.get('ip')
        protocol = data.get('protocol', 'S7').upper()  # S7, MODBUS, OPCUA

        # Protocol-specific parameters
        rack = data.get('rack', 0)
        slot = data.get('slot', 1)
        port = data.get('port')
        unit_id = data.get('unit_id', 1)

        if not ip:
            return jsonify({'success': False, 'error': 'IP address required'}), 400

        # Create device
        device = Device(
            ip=ip,
            device_type=DeviceType.PLC,
            vendor=data.get('vendor', 'Unknown'),
            model=data.get('model', protocol),
            protocols=[protocol]
        )

        # Create target and client based on protocol
        if protocol == 'S7':
            target = Target(
                device=device,
                protocol=ProtocolType.S7,
                rack=rack,
                slot=slot
            )
            client = S7Client(target)

        elif protocol == 'MODBUS':
            target = Target(
                device=device,
                protocol=ProtocolType.MODBUS_TCP,
                port=port or 502,
                unit_id=unit_id
            )
            from icsscout.core.protocols.modbus import ModbusClient
            client = ModbusClient(target)

        elif protocol == 'OPCUA':
            target = Target(
                device=device,
                protocol=ProtocolType.OPC_UA,
                port=port or 4840
            )
            try:
                from icsscout.core.protocols.opcua import OPCUAClient
                client = OPCUAClient(target)
            except ImportError as e:
                return jsonify({
                    'success': False,
                    'error': 'OPC UA support not installed. Run: pip install opcua'
                }), 500

        else:
            return jsonify({
                'success': False,
                'error': f'Unsupported protocol: {protocol}'
            }), 400

        # Connect
        result = client.connect()

        if not result.success:
            return jsonify({
                'success': False,
                'error': result.message
            }), 500

        # Generate session ID
        import uuid
        session_id = str(uuid.uuid4())

        # Get PLC info
        plc_info = {}
        try:
            info_result = client.get_device_info()
            if info_result.success:
                plc_info = info_result.data
        except Exception as e:
            logger.warning(f"Could not get PLC info: {e}")

        # Store session
        monitoring_sessions[session_id] = {
            'client': client,
            'monitor': None,
            'target': target,
            'connected_at': datetime.now()
        }

        logger.info(f"Monitoring session created: {session_id} for {ip}")

        return jsonify({
            'success': True,
            'session_id': session_id,
            'plc_info': plc_info
        })

    except Exception as e:
        logger.error(f"Failed to connect for monitoring: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/monitoring/start', methods=['POST'])
def api_monitoring_start():
    """Start monitoring"""
    try:
        data = request.json
        session_id = data.get('session_id')
        baseline_duration = data.get('baseline_duration', 60)
        interval = data.get('interval', 1.0)

        if not session_id or session_id not in monitoring_sessions:
            return jsonify({'success': False, 'error': 'Invalid session'}), 400

        session = monitoring_sessions[session_id]
        client = session['client']

        # Create behavior monitor
        from icsscout.core.monitoring import BehaviorMonitor
        monitor = BehaviorMonitor(client, history_size=1000)
        session['monitor'] = monitor

        # Anomaly callback
        def on_anomaly(anomaly):
            socketio.emit('monitoring_anomaly', {
                'session_id': session_id,
                'type': anomaly.type,
                'severity': anomaly.severity,
                'description': anomaly.description,
                'timestamp': anomaly.timestamp.isoformat(),
                'details': anomaly.details
            })

        monitor.add_anomaly_callback(on_anomaly)

        # Start monitoring in background thread
        def monitoring_loop():
            try:
                # Establish baseline
                logger.info(f"Establishing baseline for session {session_id}...")
                samples_target = baseline_duration
                samples = []

                for i in range(samples_target):
                    try:
                        sample = monitor._collect_sample()
                        samples.append(sample)

                        # Emit baseline progress
                        progress = int((i + 1) / samples_target * 100)
                        socketio.emit('monitoring_baseline', {
                            'session_id': session_id,
                            'progress': progress,
                            'complete': False
                        })

                        time.sleep(1.0)
                    except Exception as e:
                        logger.warning(f"Sample collection failed: {e}")

                # Create baseline
                from icsscout.core.monitoring.behavior_monitor import Baseline
                baseline = Baseline.from_samples(samples)
                monitor.baseline = baseline

                # Emit baseline complete
                socketio.emit('monitoring_baseline', {
                    'session_id': session_id,
                    'progress': 100,
                    'complete': True,
                    'baseline': {
                        'cpu_load_mean': baseline.cpu_load_mean,
                        'memory_reads_mean': baseline.memory_reads_mean,
                        'memory_writes_mean': baseline.memory_writes_mean,
                        'sample_count': baseline.sample_count
                    }
                })

                logger.info(f"Baseline established for session {session_id}")

                # Start continuous monitoring
                monitor.start_monitoring(interval=interval)
                logger.info(f"Continuous monitoring started for session {session_id}")

                # Send periodic updates
                sample_count = 0
                while monitor.is_monitoring:
                    try:
                        sample_count += 1

                        # Get latest sample
                        if len(monitor.history) > 0:
                            latest = monitor.history[-1]

                            # Emit sample data
                            socketio.emit('monitoring_sample', {
                                'session_id': session_id,
                                'timestamp': latest.timestamp.isoformat(),
                                'cpu_load': latest.cpu_load,
                                'memory_usage': latest.memory_usage,
                                'memory_reads': latest.memory_reads,
                                'memory_writes': latest.memory_writes,
                                'sample_count': sample_count
                            })

                        time.sleep(interval)
                    except Exception as e:
                        logger.error(f"Monitoring loop error: {e}")

            except Exception as e:
                logger.error(f"Monitoring thread error: {e}")
                socketio.emit('monitoring_error', {
                    'session_id': session_id,
                    'error': str(e)
                })

        # Start thread
        thread = threading.Thread(target=monitoring_loop, daemon=True)
        thread.start()
        session['thread'] = thread

        logger.info(f"Monitoring started for session {session_id}")

        return jsonify({
            'success': True,
            'message': 'Monitoring started'
        })

    except Exception as e:
        logger.error(f"Failed to start monitoring: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/monitoring/stop', methods=['POST'])
def api_monitoring_stop():
    """Stop monitoring"""
    try:
        data = request.json
        session_id = data.get('session_id')

        if not session_id or session_id not in monitoring_sessions:
            return jsonify({'success': False, 'error': 'Invalid session'}), 400

        session = monitoring_sessions[session_id]
        monitor = session.get('monitor')

        if monitor:
            monitor.stop_monitoring()

            # Get summary
            stats = monitor.get_statistics()
            anomalies = monitor.get_anomalies()

            logger.info(f"Monitoring stopped for session {session_id}")

            return jsonify({
                'success': True,
                'summary': {
                    'samples_collected': stats['samples_collected'],
                    'anomalies_detected': stats['anomalies_detected'],
                    'anomalies': [
                        {
                            'type': a.type,
                            'severity': a.severity,
                            'description': a.description,
                            'timestamp': a.timestamp.isoformat()
                        } for a in anomalies[:10]
                    ]
                }
            })
        else:
            return jsonify({'success': False, 'error': 'No active monitoring'}), 400

    except Exception as e:
        logger.error(f"Failed to stop monitoring: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/monitoring/disconnect', methods=['POST'])
def api_monitoring_disconnect():
    """Disconnect from PLC"""
    try:
        data = request.json
        session_id = data.get('session_id')

        if not session_id or session_id not in monitoring_sessions:
            return jsonify({'success': False, 'error': 'Invalid session'}), 400

        session = monitoring_sessions[session_id]

        # Stop monitoring if active
        monitor = session.get('monitor')
        if monitor and monitor.is_monitoring:
            monitor.stop_monitoring()

        # Disconnect client
        client = session.get('client')
        if client:
            client.disconnect()

        # Remove session
        del monitoring_sessions[session_id]

        logger.info(f"Monitoring session disconnected: {session_id}")

        return jsonify({
            'success': True,
            'message': 'Disconnected'
        })

    except Exception as e:
        logger.error(f"Failed to disconnect: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/monitoring/scan-slots', methods=['POST'])
def api_scan_all_slots():
    """
    Scan all possible rack/slot combinations for a given IP

    This will try to connect to all common rack/slot combinations
    and return the ones that have active PLCs
    """
    try:
        data = request.json
        ip = data.get('ip')

        if not ip:
            return jsonify({'success': False, 'error': 'IP address required'}), 400

        logger.info(f"Scanning all slots for {ip}...")

        # Common rack/slot combinations
        # Rack 0 is most common, slots 0-7 cover most scenarios
        combinations = [
            (0, 1),  # S7-1500/1200 default
            (0, 2),  # S7-300/400 default
            (0, 0),  # Sometimes used
            (0, 3),  # Additional slot
            (0, 4),  # Additional slot
            (0, 5),  # Additional slot
            (0, 6),  # Additional slot
            (0, 7),  # Additional slot
        ]

        found_plcs = []

        for rack, slot in combinations:
            try:
                # Create device and target
                device = Device(
                    ip=ip,
                    device_type=DeviceType.PLC,
                    vendor="Siemens",
                    model="S7",
                    protocols=["S7"]
                )

                target = Target(
                    device=device,
                    protocol=ProtocolType.S7,
                    rack=rack,
                    slot=slot
                )

                # Try to connect
                client = S7Client(target)
                result = client.connect()

                if result.success:
                    # Get PLC info
                    plc_info = {}
                    try:
                        info_result = client.get_device_info()
                        if info_result.success:
                            plc_info = info_result.data
                    except Exception as e:
                        logger.warning(f"Could not get PLC info for {ip} rack {rack} slot {slot}: {e}")

                    # Disconnect immediately
                    client.disconnect()

                    found_plcs.append({
                        'rack': rack,
                        'slot': slot,
                        'plc_info': plc_info,
                        'available': True
                    })

                    logger.info(f"Found PLC at {ip} rack {rack} slot {slot}")

            except Exception as e:
                # Connection failed - no PLC at this rack/slot
                logger.debug(f"No PLC at {ip} rack {rack} slot {slot}: {e}")
                continue

        if not found_plcs:
            return jsonify({
                'success': False,
                'error': f'No PLCs found at {ip} on any slot',
                'found': []
            }), 404

        logger.info(f"Scan complete for {ip}: found {len(found_plcs)} PLC(s)")

        return jsonify({
            'success': True,
            'ip': ip,
            'found': found_plcs,
            'count': len(found_plcs)
        })

    except Exception as e:
        logger.error(f"Failed to scan slots: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# WebSocket Events
# ============================================================================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")
    emit('connected', {'message': 'Connected to ICSScout'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")


@socketio.on('request_statistics')
def handle_request_statistics():
    """Send current statistics to client"""
    if capture_engine:
        emit('statistics_update', capture_engine.statistics.to_dict())


# ============================================================================
# Main
# ============================================================================

def start_web_app(host='0.0.0.0', port=5000, debug=False):
    """
    Start ICSScout Web Application

    Args:
        host: Host to bind to
        port: Port to bind to
        debug: Enable debug mode
    """
    # Setup Risk Assessment routes if available
    if RISK_ASSESSMENT_AVAILABLE:
        try:
            # Create a simple runtime module for compatibility
            class RuntimeModule:
                _risk_reports = {}

                @staticmethod
                def get_devices():
                    """Get devices from session manager"""
                    devices = session_manager.get_devices()
                    # Convert to dict format expected by risk assessment
                    return [d.to_dict() for d in devices]

                @staticmethod
                def get_plc_list():
                    """Get PLC devices"""
                    devices = session_manager.get_devices()
                    plcs = [d for d in devices if d.device_type == DeviceType.PLC]
                    return [d.to_dict() for d in plcs]

                @staticmethod
                def get_session_manager():
                    """Get session manager instance"""
                    return session_manager

            runtime = RuntimeModule()
            setup_risk_assessment_routes(app, runtime)
            print("[✓] Risk Assessment routes registered")
        except Exception as e:
            print(f"[!] Failed to setup Risk Assessment routes: {e}")

    logger.info(f"Starting ICSScout Web Application v{__version__}")
    logger.info(f"Server: http://{host}:{port}")

    print("=" * 60)
    print(f"ICSScout Web Application v{__version__}")
    print("=" * 60)
    print(f"Server: http://{host}:{port}")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    print()

    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)


if __name__ == '__main__':
    start_web_app()
