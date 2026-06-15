#!/usr/bin/env python3
"""
Simple demo webapp for Risk Assessment UI only (no backend)
"""
import sys
from flask import Flask, render_template, jsonify
from datetime import datetime

app = Flask(__name__,
            template_folder='/home/user/S7.Pwn/s7pwn/templates',
            static_folder='/home/user/S7.Pwn/s7pwn/static')

@app.route('/')
def index():
    return render_template('index.html', version='1.0-demo')

@app.route('/risk-assessment')
def risk_assessment_page():
    return render_template('risk_assessment.html', version='1.0-demo')

# Mock API endpoints for demo
@app.route('/api/risk/reports')
def api_risk_reports():
    return jsonify({
        "success": True,
        "reports": []
    })

@app.route('/api/risk/assess', methods=['POST'])
def api_risk_assess():
    # Return mock data
    return jsonify({
        "success": True,
        "report_id": f"RISK-DEMO-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "overall_risk_score": 75.5,
        "overall_risk_level": "HIGH",
        "summary": {
            "total_devices": 15,
            "critical_findings": 5,
            "high_findings": 12,
            "critical_devices": 3,
            "scan_timestamp": datetime.now().isoformat()
        },
        "categories": {
            "network": {"score": 65.5, "risk_level": "MEDIUM", "findings_count": 8},
            "device": {"score": 45.2, "risk_level": "HIGH", "findings_count": 12},
            "vulnerability": {"score": 55.0, "risk_level": "MEDIUM", "findings_count": 7},
            "compliance": {"score": 40.0, "findings_count": 15}
        }
    })

@app.route('/api/risk/report/<report_id>')
def api_risk_report(report_id):
    # Return mock detailed report
    return jsonify({
        "success": True,
        "report": {
            "overview": {
                "scan_timestamp": datetime.now().isoformat(),
                "report_id": report_id,
                "total_devices": 15,
                "overall_risk_score": 75.5,
                "overall_risk_level": "HIGH",
                "total_findings": 32,
                "critical_count": 5,
                "high_count": 12
            },
            "assessments": {
                "network": {
                    "score": 65.5,
                    "risk_level": "MEDIUM",
                    "findings_count": 8
                },
                "device": {
                    "score": 45.2,
                    "risk_level": "HIGH",
                    "findings_count": 12
                },
                "vulnerability": {
                    "score": 55.0,
                    "risk_level": "MEDIUM",
                    "findings_count": 7
                },
                "compliance": {
                    "score": 40.0,
                    "findings_count": 15
                }
            },
            "critical_devices": [
                {
                    "ip": "192.168.1.10",
                    "device_type": "Production PLC",
                    "vendor": "Siemens",
                    "model": "S7-1500",
                    "risk_score": 85.5,
                    "risk_level": "HIGH",
                    "cve_count": 3,
                    "protection_level": 0
                },
                {
                    "ip": "192.168.1.20",
                    "device_type": "SCADA Server",
                    "vendor": "Schneider",
                    "model": "EcoStruxure",
                    "risk_score": 78.2,
                    "risk_level": "HIGH",
                    "cve_count": 2,
                    "protection_level": 1
                },
                {
                    "ip": "192.168.1.30",
                    "device_type": "HMI",
                    "vendor": "Siemens",
                    "model": "WinCC",
                    "risk_score": 72.0,
                    "risk_level": "HIGH",
                    "cve_count": 1,
                    "protection_level": 2
                }
            ],
            "findings": {
                "critical": [
                    {
                        "title": "Critical CVE on Production PLC",
                        "description": "CVE-2022-38465: Remote Code Execution vulnerability",
                        "severity": "CRITICAL",
                        "affected_devices": ["192.168.1.10"]
                    }
                ],
                "high": [],
                "all": []
            },
            "compliance": [
                {
                    "framework": "IEC 62443-3-3",
                    "overall_compliance": 40.0,
                    "security_level": "SL-1 (Basic)",
                    "requirements_met": 11,
                    "requirements_total": 28
                }
            ],
            "risk_matrix": {},
            "action_plan": {
                "immediate": [
                    {
                        "title": "Fix Critical CVE on 192.168.1.10",
                        "description": "Patch CVE-2022-38465 immediately - RCE vulnerability",
                        "affected_devices": ["192.168.1.10"],
                        "timeline": "Within 24 hours"
                    },
                    {
                        "title": "Enable Password Protection on Production PLC",
                        "description": "Set Protection Level 3 with strong password",
                        "affected_devices": ["192.168.1.10"],
                        "timeline": "Within 24 hours"
                    }
                ],
                "short_term": [
                    {
                        "title": "Update Firmware on SCADA Server",
                        "description": "Firmware is 5 years old, update to latest version",
                        "affected_devices": ["192.168.1.20"],
                        "timeline": "Within 1 week"
                    }
                ],
                "medium_term": [
                    {
                        "title": "Implement Network Segmentation",
                        "description": "Separate OT zones with VLANs and firewalls",
                        "affected_devices": [],
                        "timeline": "Within 1 month"
                    }
                ]
            }
        }
    })

if __name__ == '__main__':
    print("\n" + "="*60)
    print("Risk Assessment DEMO Webapp")
    print("="*60)
    print("\nStarting server on http://0.0.0.0:5000")
    print("\nAccess:")
    print("  🏠  Main: http://localhost:5000/")
    print("  🛡️  Risk Assessment: http://localhost:5000/risk-assessment")
    print("\n⚠️  NOTE: This is a DEMO with mock data")
    print("    For real assessment, use the full webapp with all dependencies")
    print("\nPress Ctrl+C to stop\n")

    try:
        app.run(host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        sys.exit(0)
