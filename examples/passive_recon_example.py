#!/usr/bin/env python3
"""
ICSScout - Passive Reconnaissance Example
For OT/ICS environments (e.g., Hydro Plant)

This script demonstrates how to use ICSScout for passive reconnaissance
without any active scanning or interaction with devices.
"""

import sys
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from icsscout.core.capture import PacketCaptureEngine, TrafficAnalyzer
from icsscout.core.vulnerability import VulnerabilityScanner, CVEDatabase
from icsscout.domain import Device, Target, DeviceType, ProtocolType
from icsscout.services import get_session_manager
from icsscout.utils.logger import setup_logging


def main():
    """Main reconnaissance workflow"""

    # Setup logging
    setup_logging()

    print("=" * 60)
    print("ICSScout v2.0 - Passive OT Reconnaissance")
    print("=" * 60)
    print()

    # Step 1: Create session
    print("[1/5] Creating assessment session...")
    session_mgr = get_session_manager()
    session = session_mgr.create_session("Hydro_Plant_Assessment_2025")
    print(f"✓ Session created: {session.session_id}")
    print()

    # Step 2: Passive traffic capture
    print("[2/5] Starting passive traffic capture...")
    print("      Interface: eth0 (auto-detect)")
    print("      Duration: 60 seconds (adjust as needed)")
    print("      Filter: S7, Modbus, OPC UA protocols")
    print()

    capture = PacketCaptureEngine(interface=None)  # None = auto-detect

    # Start capture (60 seconds for demo, use 300-600 for real assessment)
    capture.start_capture(
        duration=60,
        protocols=['S7', 'Modbus TCP', 'OPC UA']
    )

    # Show progress
    print("      Capturing...", end="", flush=True)
    while capture.is_capturing:
        time.sleep(1)
        print(".", end="", flush=True)
    print(" Done!")

    stats = capture.get_statistics()
    print(f"✓ Captured {stats.total_packets} packets ({stats.bytes_captured} bytes)")
    print(f"✓ Protocols detected: {', '.join(stats.protocols.keys())}")
    print(f"✓ Devices communicating: {len(stats.devices)}")
    print()

    # Step 3: Analyze traffic
    print("[3/5] Analyzing captured traffic...")
    analyzer = TrafficAnalyzer()
    traffic_stats = analyzer.analyze_capture(capture.packets)

    print(f"✓ Identified {len(traffic_stats.communications)} communication pairs")
    print(f"✓ Extracted {len(traffic_stats.memory_operations)} memory operations")

    # Identify device roles
    roles = analyzer.identify_device_roles()
    print("\n   Device Roles:")
    for ip, role in roles.items():
        print(f"      {ip:15s} → {role}")
    print()

    # Step 4: Create device objects and scan for vulnerabilities
    print("[4/5] Scanning for vulnerabilities...")
    vuln_scanner = VulnerabilityScanner()

    devices = []
    for ip, packet_count in traffic_stats.devices.items():
        # Create device object
        # In real scenario, would extract more info from traffic
        device = Device(
            ip=ip,
            vendor="Siemens",  # Would detect from traffic
            model="S7-1500",    # Would detect from traffic
            device_type=DeviceType.PLC,
            protocols=["S7"],
            firmware_version="V2.8.0"  # Would detect if possible
        )

        # Scan for vulnerabilities
        report = vuln_scanner.scan_device(device)

        devices.append(device)
        session_mgr.add_device(device)

        # Print summary
        risk_emoji = "🔴" if report.critical_count > 0 else \
                     "🟠" if report.high_count > 0 else \
                     "🟡" if report.medium_count > 0 else "🟢"

        print(f"   {risk_emoji} {ip:15s} - {report.total_count()} vulnerabilities "
              f"(Critical: {report.critical_count}, High: {report.high_count})")

        # Show critical vulnerabilities
        if report.critical_count > 0:
            for vuln in report.vulnerabilities:
                if vuln.severity.value == "CRITICAL":
                    print(f"      └─ {vuln.title}")

    print()

    # Step 5: Export results
    print("[5/5] Exporting results...")

    # Export PCAP
    pcap_file = "hydro_plant_capture.pcap"
    capture.export_pcap(pcap_file)
    print(f"✓ PCAP saved: {pcap_file}")

    # Export session
    session_file = session_mgr.save_session()
    print(f"✓ Session saved: {session_file}")

    # Generate traffic analysis report
    report = analyzer.generate_report()
    import json
    report_file = "traffic_analysis_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    print(f"✓ Traffic report saved: {report_file}")

    print()

    # Summary
    print("=" * 60)
    print("Assessment Summary")
    print("=" * 60)
    print(f"Devices Found:         {len(devices)}")
    print(f"Total Packets:         {stats.total_packets}")
    print(f"Protocols:             {', '.join(stats.protocols.keys())}")
    print(f"Vulnerabilities:       {sum(v.total_count() for v in [vuln_scanner.scan_device(d) for d in devices])}")
    print()
    print("Files Generated:")
    print(f"  - {pcap_file}")
    print(f"  - {session_file}")
    print(f"  - {report_file}")
    print()
    print("✅ Passive reconnaissance complete!")
    print()
    print("Next Steps:")
    print("  1. Review traffic analysis report")
    print("  2. Analyze PCAP file with Wireshark if needed")
    print("  3. Address critical vulnerabilities")
    print("  4. Generate professional report for stakeholders")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
