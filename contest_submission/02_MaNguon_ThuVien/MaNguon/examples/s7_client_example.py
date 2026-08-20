#!/usr/bin/env python3
"""
ICSScout - S7 Protocol Client Example
Demonstrates direct S7 PLC interaction
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from icsscout.core.protocols.s7 import S7Client
from icsscout.domain import Device, Target, DeviceType, ProtocolType
from icsscout.core.safety import SafetyChecker
from icsscout.utils.logger import setup_logging


def main():
    """S7 client usage example"""

    # Setup logging
    setup_logging()

    print("=" * 60)
    print("ICSScout - S7 Protocol Client Example")
    print("=" * 60)
    print()

    # Create device and target
    device = Device(
        ip="192.168.1.100",  # Replace with your PLC IP
        vendor="Siemens",
        model="S7-1500",
        device_type=DeviceType.PLC,
        rack=0,
        slot=1
    )

    target = Target(
        device=device,
        protocol=ProtocolType.S7,
        rack=0,
        slot=1
    )

    print(f"Target: {target}")
    print()

    # Safety check
    print("[*] Performing safety checks...")
    safety = SafetyChecker(read_only_mode=True)  # Enable read-only mode for safety

    # Create S7 client
    client = S7Client(target)

    # Example 1: Connect and get device info
    print("\n[1] Connecting to PLC...")
    result = client.connect()

    if result.success:
        print("✓ Connected successfully")

        # Get device info
        print("\n[2] Retrieving device information...")
        info_result = client.get_device_info()

        if info_result.success:
            info = info_result.data
            print(f"   Module Type: {info['module_type']}")
            print(f"   Serial Number: {info['serial_number']}")
            print(f"   CPU State: {info['cpu_state']}")
            print(f"   Module Name: {info['module_name']}")

        # Example 2: Read operations
        print("\n[3] Reading memory values...")

        # Read a byte
        result = client.read("M0", "byte")
        if result.success:
            print(f"   M0 (byte) = {result.data}")

        # Read an integer
        result = client.read("MW10", "int")
        if result.success:
            print(f"   MW10 (int) = {result.data}")

        # Read a bit
        result = client.read("M0.5", "bit")
        if result.success:
            print(f"   M0.5 (bit) = {result.data}")

        # Read from data block
        result = client.read("DB1.DBW0", "int")
        if result.success:
            print(f"   DB1.DBW0 (int) = {result.data}")

        # Example 3: Write operations (if read-only mode disabled)
        print("\n[4] Write operations...")

        # Check safety
        safety_result = safety.check_write_operation(target, "M0", 123)
        if safety_result.safe or safety.read_only_mode:
            if safety.read_only_mode:
                print("   ⚠️  Write operations disabled (read-only mode)")
                print("      To enable writes: safety.set_read_only_mode(False)")
            else:
                # Write a byte
                result = client.write("M0", 123, "byte")
                if result.success:
                    print("   ✓ Wrote M0 = 123")

                # Write a bit
                result = client.write("M0.5", True, "bit")
                if result.success:
                    print("   ✓ Wrote M0.5 = True")
        else:
            print("   ✗ Write operations blocked by safety checks:")
            for risk in safety_result.risks:
                print(f"      - {risk.message}")

        # Disconnect
        print("\n[5] Disconnecting...")
        client.disconnect()
        print("✓ Disconnected")

    else:
        print(f"✗ Connection failed: {result.error}")
        print("\nTroubleshooting:")
        print("  - Check IP address is correct")
        print("  - Check rack/slot configuration")
        print("  - Ensure PLC is reachable on network")
        print("  - Verify firewall allows port 102")

    print()
    print("=" * 60)
    print("Example complete!")
    print()


def advanced_example():
    """Advanced usage with context manager"""

    device = Device(
        ip="192.168.1.100",
        vendor="Siemens",
        model="S7-1500",
        device_type=DeviceType.PLC
    )

    target = Target(device=device, protocol=ProtocolType.S7, rack=0, slot=1)
    client = S7Client(target)

    # Use context manager for automatic connect/disconnect
    try:
        with client:
            # Read multiple values
            values = {}
            for address in ["M0", "M1", "MW10", "M0.5"]:
                result = client.read(address, "byte")
                if result.success:
                    values[address] = result.data

            print("Read values:", values)

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    try:
        main()
        # Uncomment to run advanced example:
        # advanced_example()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
