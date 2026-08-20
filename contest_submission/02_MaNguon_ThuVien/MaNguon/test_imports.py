#!/usr/bin/env python3
"""
Test script to verify all imports work correctly
Run this before starting the web app to catch import errors early
"""

import sys

def test_imports():
    """Test all critical imports"""

    print("Testing ICSScout imports...")
    print("=" * 60)

    tests = [
        ("Domain models", lambda: __import__('icsscout.domain')),
        ("Device, DeviceType", lambda: __import__('icsscout.domain', fromlist=['Device', 'DeviceType'])),
        ("Vulnerability models", lambda: __import__('icsscout.domain', fromlist=['Vulnerability', 'VulnerabilityReport', 'Severity'])),
        ("Protocol base", lambda: __import__('icsscout.core.protocols', fromlist=['BaseProtocolClient'])),
        ("S7 Client", lambda: __import__('icsscout.core.protocols.s7', fromlist=['S7Client'])),
        ("Modbus Client", lambda: __import__('icsscout.core.protocols.modbus', fromlist=['ModbusClient'])),
        ("Packet Capture", lambda: __import__('icsscout.core.capture', fromlist=['PacketCaptureEngine', 'CapturedPacket'])),
        ("Traffic Analyzer", lambda: __import__('icsscout.core.capture', fromlist=['TrafficAnalyzer'])),
        ("Protocol Dissector", lambda: __import__('icsscout.core.capture', fromlist=['DissectorRegistry'])),
        ("Vulnerability Scanner", lambda: __import__('icsscout.core.vulnerability', fromlist=['VulnerabilityScanner'])),
        ("Session Manager", lambda: __import__('icsscout.services', fromlist=['SessionManager', 'get_session_manager'])),
        ("Web App", lambda: __import__('icsscout.interfaces.web.app', fromlist=['start_web_app'])),
    ]

    failed = []
    passed = 0

    for name, test_func in tests:
        try:
            test_func()
            print(f"✓ {name}")
            passed += 1
        except Exception as e:
            print(f"✗ {name}: {e}")
            failed.append((name, str(e)))

    print("=" * 60)
    print(f"Results: {passed}/{len(tests)} passed")

    if failed:
        print("\nFailed imports:")
        for name, error in failed:
            print(f"  - {name}: {error}")
        return False
    else:
        print("\n✅ All imports successful!")
        print("\nYou can now run:")
        print("  python start_webapp.py")
        return True

if __name__ == '__main__':
    success = test_imports()
    sys.exit(0 if success else 1)
