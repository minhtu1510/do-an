"""
Export command for S7Pwn CLI
Exports scan results, probe data, and operation logs
"""
from __future__ import annotations
from typing import List
from s7pwn.runtime import get_devices, get_plc_list, get_current_target
from s7pwn.report_exporter import get_exporter


def export_data(args: List[str]) -> None:
    """
    Export data to file
    Usage: export <type> <format>
    Types: scan, devices, plcs
    Formats: json, csv, html
    """
    if len(args) < 2:
        print("Usage: export <type> <format>")
        print("Types: scan, devices, plcs")
        print("Formats: json, csv, html")
        return

    export_type = args[0].lower()
    format_type = args[1].lower()

    if format_type not in ['json', 'csv', 'html']:
        print("Invalid format. Use: json, csv, or html")
        return

    exporter = get_exporter()

    try:
        if export_type == 'scan':
            devices = get_devices()
            plc_list = get_plc_list()

            if not devices and not plc_list:
                print("No scan data available. Run 'scan' first.")
                return

            filepath = exporter.export_scan_results(devices, plc_list, format_type)
            print(f"Scan results exported to: {filepath}")

        elif export_type == 'devices':
            devices = get_devices()

            if not devices:
                print("No device data available. Run 'scan' first.")
                return

            if format_type == 'json':
                data = {
                    "report_type": "All Devices",
                    "total_devices": len(devices),
                    "devices": devices
                }
                filepath = exporter.export_to_json(data, "devices.json")
            elif format_type == 'csv':
                filepath = exporter.export_to_csv(devices, "devices.csv")
            elif format_type == 'html':
                data = {
                    "report_type": "All Devices",
                    "total_devices": len(devices),
                    "devices": devices
                }
                filepath = exporter.export_to_html(data, "All Devices Report", "devices.html")

            print(f"Device data exported to: {filepath}")

        elif export_type == 'plcs':
            plc_list = get_plc_list()

            if not plc_list:
                print("No PLC data available. Run 'scan' first.")
                return

            if format_type == 'json':
                data = {
                    "report_type": "PLC Devices",
                    "total_plcs": len(plc_list),
                    "plcs": plc_list
                }
                filepath = exporter.export_to_json(data, "plcs.json")
            elif format_type == 'csv':
                filepath = exporter.export_to_csv(plc_list, "plcs.csv")
            elif format_type == 'html':
                data = {
                    "report_type": "PLC Devices",
                    "total_plcs": len(plc_list),
                    "plcs": plc_list
                }
                filepath = exporter.export_to_html(data, "PLC Devices Report", "plcs.html")

            print(f"PLC data exported to: {filepath}")

        else:
            print(f"Unknown export type: {export_type}")
            print("Available types: scan, devices, plcs")

    except Exception as e:
        print(f"Export failed: {e}")
