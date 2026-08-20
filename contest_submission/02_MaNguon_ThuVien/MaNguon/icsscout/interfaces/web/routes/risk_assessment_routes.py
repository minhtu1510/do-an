"""
Risk Assessment API Routes

Flask routes for risk assessment functionality
"""

from flask import jsonify, request, send_file
from typing import Dict, Any
import traceback
from datetime import datetime

from ....core.risk_assessment import RiskAssessmentEngine
from ....core.risk_assessment.report_generator import ReportGenerator
from ....core.vulnerability import VulnerabilityScanner
from ....domain.device import Device
from ....domain.risk_assessment import FindingSeverity


def setup_risk_assessment_routes(app, runtime_module):
    """
    Setup risk assessment routes for Flask app

    Args:
        app: Flask application instance
        runtime_module: Runtime module with get_devices(), etc.
    """

    risk_engine = RiskAssessmentEngine()
    report_generator = ReportGenerator()
    vuln_scanner = VulnerabilityScanner()

    @app.route('/api/risk/assess', methods=['POST'])
    def api_risk_assess():
        """
        Perform comprehensive risk assessment

        POST body (optional):
        {
            "include_vulnerability_scan": true,  # Run vulnerability scan first
            "network_topology": {  # Optional network topology info
                "has_segmentation": false,
                "has_firewall": false,
                "has_vlan": false,
                "it_ot_separated": false
            }
        }

        Returns:
        {
            "success": true,
            "report_id": "RISK-20251106-...",
            "overall_risk_score": 75.5,
            "overall_risk_level": "HIGH",
            "summary": {...},
            "report_url": "/api/risk/report/RISK-20251106-..."
        }
        """
        try:
            data = request.json or {}

            # Get devices from runtime
            devices = runtime_module.get_devices()

            if not devices:
                return jsonify({
                    "success": False,
                    "error": "No devices found. Please run a network scan first."
                }), 400

            # Convert to Device objects
            device_objects = _convert_to_device_objects(devices)

            # Run vulnerability scan if requested
            vulnerability_reports = []
            if data.get('include_vulnerability_scan', True):
                for device in device_objects:
                    try:
                        vuln_report = vuln_scanner.scan_device(device)
                        vulnerability_reports.append(vuln_report)
                    except Exception as e:
                        print(f"Error scanning device {device.ip}: {e}")

            # Get network topology info
            network_topology = data.get('network_topology', {})

            # Perform risk assessment
            assessment_report = risk_engine.assess_risk(
                devices=device_objects,
                vulnerability_reports=vulnerability_reports,
                network_topology=network_topology
            )

            # Store report in runtime for later retrieval
            if not hasattr(runtime_module, '_risk_reports'):
                runtime_module._risk_reports = {}

            runtime_module._risk_reports[assessment_report.report_id] = assessment_report

            # Save FULL assessment report to session
            try:
                print(f"[RISK ASSESSMENT] Attempting to save FULL report to session...")
                if hasattr(runtime_module, 'get_session_manager'):
                    session_manager = runtime_module.get_session_manager()
                    print(f"[RISK ASSESSMENT] Got session manager: {session_manager}")

                    # Save COMPLETE report using to_dict() - this includes ALL details:
                    # - Overview with scores and counts
                    # - Full category assessments with all findings
                    # - All device profiles with complete metadata
                    # - Critical devices list
                    # - All findings (critical/high/medium/low) with details
                    # - Compliance status and requirements
                    # - Action plan (immediate/short/medium/long term)
                    # - Risk matrix and metadata
                    full_report_dict = assessment_report.to_dict()

                    print(f"[RISK ASSESSMENT] Full report size: {len(str(full_report_dict))} chars")
                    print(f"[RISK ASSESSMENT] Includes: {list(full_report_dict.keys())}")

                    session_manager.save_risk_assessment(full_report_dict)
                    print(f"[✓] FULL risk assessment report saved to session: {assessment_report.report_id}")
                    print(f"[✓] Report contains {len(full_report_dict.get('device_profiles', []))} device profiles")
                    print(f"[✓] Report contains {len(full_report_dict.get('findings', {}).get('all', []))} total findings")
                else:
                    print(f"[!] runtime_module does not have get_session_manager method")
            except Exception as e:
                import traceback
                print(f"[!] Failed to save risk assessment to session: {e}")
                print(f"[!] Traceback: {traceback.format_exc()}")

            # Return summary
            return jsonify({
                "success": True,
                "report_id": assessment_report.report_id,
                "overall_risk_score": round(assessment_report.overall_risk_score, 2),
                "overall_risk_level": assessment_report.overall_risk_level.value,
                "summary": {
                    "total_devices": assessment_report.total_devices,
                    "critical_findings": assessment_report.critical_count,
                    "high_findings": assessment_report.high_count,
                    "critical_devices": len(assessment_report.critical_devices),
                    "scan_timestamp": assessment_report.scan_timestamp.isoformat(),
                },
                "categories": {
                    "network": {
                        "score": round(assessment_report.network_assessment.score, 2),
                        "risk_level": assessment_report.network_assessment.risk_level.value,
                        "findings_count": len(assessment_report.network_assessment.findings)
                    },
                    "device": {
                        "score": round(assessment_report.device_assessment.score, 2),
                        "risk_level": assessment_report.device_assessment.risk_level.value,
                        "findings_count": len(assessment_report.device_assessment.findings)
                    },
                    "vulnerability": {
                        "score": round(assessment_report.vulnerability_assessment.score, 2),
                        "risk_level": assessment_report.vulnerability_assessment.risk_level.value,
                        "findings_count": len(assessment_report.vulnerability_assessment.findings)
                    },
                    "compliance": {
                        "score": round(assessment_report.compliance_assessment.score, 2),
                        "findings_count": len(assessment_report.compliance_assessment.findings)
                    }
                },
                "report_url": f"/api/risk/report/{assessment_report.report_id}"
            })

        except Exception as e:
            traceback.print_exc()
            return jsonify({
                "success": False,
                "error": str(e),
                "traceback": traceback.format_exc()
            }), 500

    @app.route('/api/risk/report/<report_id>', methods=['GET'])
    def api_risk_report(report_id):
        """
        Get detailed risk assessment report

        Returns full report as JSON

        Tries to get report from:
        1. Runtime memory (_risk_reports)
        2. Current session (if report not in memory)
        """
        try:
            # Try to get from runtime memory first
            if hasattr(runtime_module, '_risk_reports') and report_id in runtime_module._risk_reports:
                report = runtime_module._risk_reports[report_id]
                return jsonify({
                    "success": True,
                    "report": report.to_dict(),
                    "source": "memory"
                })

            # If not in memory, try to get from session
            if hasattr(runtime_module, 'get_session_manager'):
                session_manager = runtime_module.get_session_manager()
                session_risk_data = session_manager.get_risk_assessment()

                if session_risk_data and session_risk_data.get('overview', {}).get('report_id') == report_id:
                    print(f"[RISK API] Loaded report {report_id} from session")
                    return jsonify({
                        "success": True,
                        "report": session_risk_data,
                        "source": "session"
                    })

            return jsonify({
                "success": False,
                "error": f"Report {report_id} not found in memory or session"
            }), 404

        except Exception as e:
            traceback.print_exc()
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500

    @app.route('/api/risk/export/<report_id>/<format>', methods=['GET'])
    def api_risk_export(report_id, format):
        """
        Export risk assessment report

        Formats: pdf, docx, json

        Returns: File download

        Note: For JSON export, can work with session data.
        For PDF/DOCX, requires report object in memory.
        """
        try:
            report = None
            report_dict = None

            # Try to get report object from runtime memory
            if hasattr(runtime_module, '_risk_reports') and report_id in runtime_module._risk_reports:
                report = runtime_module._risk_reports[report_id]

            # If not in memory, try to get from session (for JSON export)
            if not report and hasattr(runtime_module, 'get_session_manager'):
                session_manager = runtime_module.get_session_manager()
                session_risk_data = session_manager.get_risk_assessment()

                if session_risk_data and session_risk_data.get('overview', {}).get('report_id') == report_id:
                    report_dict = session_risk_data
                    print(f"[RISK EXPORT] Using report from session for JSON export")

            # Check if we have report data
            if not report and not report_dict:
                return jsonify({
                    "success": False,
                    "error": f"Report {report_id} not found in memory or session"
                }), 404

            # Generate report in requested format
            if format.lower() == 'json':
                # JSON export can work with dict
                if report:
                    filepath = report_generator.generate_json_report(report)
                elif report_dict:
                    # Generate JSON directly from dict
                    import json
                    import tempfile
                    from pathlib import Path

                    output_dir = Path('reports')
                    output_dir.mkdir(exist_ok=True)
                    filepath = output_dir / f"risk_assessment_{report_id}.json"

                    with open(filepath, 'w') as f:
                        json.dump(report_dict, f, indent=2)

                mimetype = 'application/json'

            elif format.lower() == 'pdf':
                if not report:
                    return jsonify({
                        "success": False,
                        "error": "PDF export requires report in memory. Please run assessment again or load session with full data."
                    }), 400
                filepath = report_generator.generate_pdf_report(report)
                mimetype = 'application/pdf'

            elif format.lower() == 'docx':
                if not report:
                    return jsonify({
                        "success": False,
                        "error": "DOCX export requires report in memory. Please run assessment again or load session with full data."
                    }), 400
                filepath = report_generator.generate_docx_report(report)
                mimetype = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'

            else:
                return jsonify({
                    "success": False,
                    "error": f"Unsupported format: {format}. Use pdf, docx, or json."
                }), 400

            return send_file(
                filepath,
                mimetype=mimetype,
                as_attachment=True,
                download_name=f"risk_assessment_{report_id}.{format}"
            )

        except ImportError as e:
            return jsonify({
                "success": False,
                "error": f"Required library not installed: {str(e)}"
            }), 500
        except Exception as e:
            traceback.print_exc()
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500

    @app.route('/api/risk/reports', methods=['GET'])
    def api_risk_reports_list():
        """
        List all available risk assessment reports

        Includes reports from:
        1. Runtime memory (_risk_reports)
        2. Current session

        Returns:
        {
            "success": true,
            "reports": [
                {
                    "report_id": "RISK-20251106-...",
                    "scan_timestamp": "2025-11-06T10:30:00",
                    "overall_risk_level": "HIGH",
                    "total_devices": 15
                },
                ...
            ]
        }
        """
        try:
            reports_summary = []
            report_ids_seen = set()

            # Get reports from runtime memory
            if hasattr(runtime_module, '_risk_reports'):
                for report_id, report in runtime_module._risk_reports.items():
                    reports_summary.append({
                        "report_id": report.report_id,
                        "scan_timestamp": report.scan_timestamp.isoformat(),
                        "overall_risk_level": report.overall_risk_level.value,
                        "overall_risk_score": round(report.overall_risk_score, 2),
                        "total_devices": report.total_devices,
                        "critical_findings": report.critical_count,
                        "high_findings": report.high_count,
                        "source": "memory"
                    })
                    report_ids_seen.add(report_id)

            # Also get report from current session (if not already in memory)
            if hasattr(runtime_module, 'get_session_manager'):
                session_manager = runtime_module.get_session_manager()
                session_risk_data = session_manager.get_risk_assessment()

                if session_risk_data and 'overview' in session_risk_data:
                    overview = session_risk_data['overview']
                    report_id = overview.get('report_id')

                    if report_id and report_id not in report_ids_seen:
                        reports_summary.append({
                            "report_id": report_id,
                            "scan_timestamp": overview.get('scan_timestamp'),
                            "overall_risk_level": overview.get('overall_risk_level'),
                            "overall_risk_score": overview.get('overall_risk_score'),
                            "total_devices": overview.get('total_devices'),
                            "critical_findings": overview.get('critical_count'),
                            "high_findings": overview.get('high_count'),
                            "source": "session"
                        })

            # Sort by timestamp (newest first)
            reports_summary.sort(key=lambda x: x.get('scan_timestamp', ''), reverse=True)

            return jsonify({
                "success": True,
                "reports": reports_summary
            })

        except Exception as e:
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500

    @app.route('/api/risk/devices', methods=['GET'])
    def api_risk_devices():
        """
        Get risk profiles for all devices

        Query params:
        - report_id: Optional, get devices from specific report
        - min_risk_level: Optional filter (CRITICAL, HIGH, MEDIUM, LOW, INFO)

        Returns:
        {
            "success": true,
            "devices": [
                {
                    "ip": "192.168.1.10",
                    "device_type": "PLC",
                    "risk_score": 85.5,
                    "risk_level": "HIGH",
                    "cve_count": 3,
                    ...
                },
                ...
            ]
        }
        """
        try:
            report_id = request.args.get('report_id')
            min_risk_level = request.args.get('min_risk_level', '').upper()

            if not hasattr(runtime_module, '_risk_reports'):
                return jsonify({
                    "success": False,
                    "error": "No reports found. Run risk assessment first."
                }), 404

            # Get latest report if no report_id specified
            if not report_id:
                if not runtime_module._risk_reports:
                    return jsonify({
                        "success": False,
                        "error": "No reports available"
                    }), 404
                # Get most recent report
                report = max(runtime_module._risk_reports.values(),
                           key=lambda r: r.scan_timestamp)
            else:
                if report_id not in runtime_module._risk_reports:
                    return jsonify({
                        "success": False,
                        "error": f"Report {report_id} not found"
                    }), 404
                report = runtime_module._risk_reports[report_id]

            # Get device profiles
            devices = [d.to_dict() for d in report.device_profiles]

            # Filter by risk level if specified
            if min_risk_level:
                risk_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
                if min_risk_level in risk_order:
                    min_index = risk_order.index(min_risk_level)
                    devices = [d for d in devices
                             if risk_order.index(d['risk_level']) <= min_index]

            return jsonify({
                "success": True,
                "report_id": report.report_id,
                "devices": devices
            })

        except Exception as e:
            traceback.print_exc()
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500

    @app.route('/api/risk/compliance', methods=['GET'])
    def api_risk_compliance():
        """
        Get compliance status

        Query params:
        - report_id: Optional, get compliance from specific report

        Returns:
        {
            "success": true,
            "compliance": [
                {
                    "framework": "IEC 62443-3-3",
                    "overall_compliance": 65.5,
                    "security_level": "SL-2 (Medium)",
                    "gaps": [...]
                },
                ...
            ]
        }
        """
        try:
            report_id = request.args.get('report_id')

            if not hasattr(runtime_module, '_risk_reports'):
                return jsonify({
                    "success": False,
                    "error": "No reports found"
                }), 404

            # Get latest report if no report_id specified
            if not report_id:
                if not runtime_module._risk_reports:
                    return jsonify({
                        "success": False,
                        "error": "No reports available"
                    }), 404
                report = max(runtime_module._risk_reports.values(),
                           key=lambda r: r.scan_timestamp)
            else:
                if report_id not in runtime_module._risk_reports:
                    return jsonify({
                        "success": False,
                        "error": f"Report {report_id} not found"
                    }), 404
                report = runtime_module._risk_reports[report_id]

            # Get compliance status
            compliance = [c.to_dict() for c in report.compliance_status]

            return jsonify({
                "success": True,
                "report_id": report.report_id,
                "compliance": compliance
            })

        except Exception as e:
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500


def _convert_to_device_objects(devices_dict_list):
    """Convert device dictionaries to Device objects"""
    from ....domain.device import DeviceType

    device_objects = []

    for d in devices_dict_list:
        # Determine device type
        device_type_str = d.get('device_type', 'Unknown')
        try:
            device_type = DeviceType[device_type_str.upper().replace(' ', '_').replace('-', '_')]
        except (KeyError, AttributeError):
            device_type = DeviceType.UNKNOWN

        # Create Device object
        device = Device(
            ip=d.get('ip', ''),
            mac=d.get('mac'),
            vendor=d.get('vendor'),
            model=d.get('device_model') or d.get('model'),
            device_type=device_type
        )

        # Set additional attributes
        device.protocols = d.get('protocols', [])
        if isinstance(device.protocols, str):
            device.protocols = [device.protocols]

        device.open_ports = d.get('open_ports', [])
        device.firmware_version = d.get('firmware_version')
        device.serial_number = d.get('serial_number')

        # Copy ALL metadata (OT scan results, network info, etc.)
        if 'metadata' in d and isinstance(d['metadata'], dict):
            device.metadata.update(d['metadata'])
            print(f"[RISK] Copied metadata for {device.ip}: keys={list(d['metadata'].keys())}")

        # Legacy support: copy plc_info if present
        if 'plc_info' in d:
            device.metadata['plc_info'] = d['plc_info']
            print(f"[RISK] Copied plc_info for {device.ip}")

        if 'rack' in d:
            device.rack = d['rack']
        if 'slot' in d:
            device.slot = d['slot']

        device.cpu_state = d.get('cpu_state')

        device_objects.append(device)

    return device_objects
