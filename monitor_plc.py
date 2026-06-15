#!/usr/bin/env python3
"""
PLC Behavior Monitoring Script
Monitor PLC at 192.168.210.211 and detect anomalies
"""

import sys
import time
from datetime import datetime
from icsscout.core.protocols.s7 import S7Client
from icsscout.core.monitoring import BehaviorMonitor
from icsscout.domain import Target, Device, DeviceType

def main():
    # Cấu hình target
    device = Device(
        ip="192.168.210.211",
        device_type=DeviceType.PLC,
        vendor="Siemens",
        model="S7-1500",  # Hoặc S7-1200, S7-300, S7-400
        protocols=["S7"]
    )

    # Target configuration
    target = Target(
        device=device,
        protocol="S7",
        rack=0,  # S7-1500/1200 thường là 0
        slot=1   # S7-1500/1200 thường là 1, S7-300/400 là 2
    )

    print("=" * 60)
    print(f"PLC Behavior Monitoring")
    print("=" * 60)
    print(f"Target: {target.device.ip}")
    print(f"Model: {target.device.model}")
    print(f"Rack/Slot: {target.rack}/{target.slot}")
    print("=" * 60)
    print()

    # Kết nối
    print("[1/4] Connecting to PLC...")
    client = S7Client(target)
    result = client.connect()

    if not result.success:
        print(f"❌ Connection failed: {result.message}")
        print("\nTroubleshooting:")
        print("  - Check IP address is correct")
        print("  - Check Rack/Slot (S7-1500/1200: 0/1, S7-300/400: 0/2)")
        print("  - Ensure PLC is online and reachable")
        print("  - Check firewall settings")
        return 1

    print(f"✅ Connected successfully")

    # Lấy thông tin PLC
    try:
        info_result = client.get_device_info()
        if info_result.success:
            info = info_result.data
            print(f"\nPLC Information:")
            print(f"  Module: {info.get('module_name', 'Unknown')}")
            print(f"  Serial: {info.get('serial_number', 'Unknown')}")
            print(f"  Firmware: {info.get('firmware', 'Unknown')}")
            print(f"  State: {info.get('cpu_state', 'Unknown')}")
    except Exception as e:
        print(f"⚠️  Could not get PLC info: {e}")

    print()

    # Khởi tạo monitor
    print("[2/4] Initializing Behavior Monitor...")
    monitor = BehaviorMonitor(client, history_size=1000)

    # Callback khi phát hiện anomaly
    def on_anomaly_detected(anomaly):
        print()
        print("🚨 " + "=" * 50)
        print(f"ANOMALY DETECTED: {anomaly.type}")
        print("=" * 50)
        print(f"Time: {anomaly.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Severity: {anomaly.severity}")
        print(f"Description: {anomaly.description}")
        if anomaly.details:
            print(f"Details: {anomaly.details}")
        print("=" * 50)
        print()

    monitor.add_anomaly_callback(on_anomaly_detected)

    # Thiết lập baseline
    print("[3/4] Establishing baseline (60 seconds)...")
    print("      This will learn normal PLC behavior...")
    try:
        baseline = monitor.establish_baseline(
            duration=60,  # 1 phút
            interval=1.0
        )
        print(f"✅ Baseline established from {baseline.sample_count} samples")
    except Exception as e:
        print(f"⚠️  Warning: Could not establish full baseline: {e}")
        print("   Continuing with partial baseline...")

    print()

    # Bắt đầu monitoring
    print("[4/4] Starting continuous monitoring...")
    print("      Press Ctrl+C to stop")
    print()
    print("-" * 60)
    print(f"{'Time':<20} {'Status':<15} {'Anomalies':<10}")
    print("-" * 60)

    try:
        monitor.start_monitoring(interval=1.0)

        # Hiển thị status mỗi 5 giây
        while True:
            time.sleep(5)
            stats = monitor.get_statistics()
            anomaly_count = len(monitor.get_anomalies())

            status = "🟢 Monitoring" if monitor.is_monitoring else "🔴 Stopped"
            print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<20} {status:<15} {anomaly_count:<10}")

    except KeyboardInterrupt:
        print()
        print("-" * 60)
        print("\n🛑 Monitoring stopped by user")

        # Hiển thị tóm tắt
        monitor.stop_monitoring()
        stats = monitor.get_statistics()
        anomalies = monitor.get_anomalies()

        print()
        print("=" * 60)
        print("MONITORING SUMMARY")
        print("=" * 60)
        print(f"Samples collected: {stats['samples_collected']}")
        print(f"Anomalies detected: {stats['anomalies_detected']}")
        print(f"Baseline established: {'Yes' if stats['baseline_established'] else 'No'}")
        print()

        if anomalies:
            print("Detected Anomalies:")
            for i, anomaly in enumerate(anomalies[:10], 1):
                print(f"  {i}. [{anomaly.severity}] {anomaly.type}: {anomaly.description}")
                print(f"     Time: {anomaly.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            print("✅ No anomalies detected - PLC behavior is normal")

        print("=" * 60)

    finally:
        print("\nDisconnecting...")
        client.disconnect()
        print("✅ Disconnected")

    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
