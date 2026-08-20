"""
Report Exporter Module for S7Pwn
Exports scan results, probe data, and operation logs to various formats
"""
from __future__ import annotations
import json
import csv
import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path


class ReportExporter:
    """Handles export of S7Pwn data to various file formats"""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def _get_timestamp(self) -> str:
        """Generate timestamp for filenames"""
        return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    def export_to_json(self, data: Dict[str, Any], filename: Optional[str] = None) -> str:
        """Export data to JSON format"""
        if not filename:
            filename = f"s7pwn_report_{self._get_timestamp()}.json"

        filepath = self.output_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)

        return str(filepath)

    def export_to_csv(self, data: List[Dict[str, Any]], filename: Optional[str] = None) -> str:
        """Export list of records to CSV format"""
        if not data:
            raise ValueError("No data to export")

        if not filename:
            filename = f"s7pwn_report_{self._get_timestamp()}.csv"

        filepath = self.output_dir / filename

        # Get all unique keys from all records
        fieldnames = set()
        for record in data:
            fieldnames.update(record.keys())
        fieldnames = sorted(fieldnames)

        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)

        return str(filepath)

    def export_to_html(self, data: Dict[str, Any], title: str = "S7Pwn Report",
                      filename: Optional[str] = None) -> str:
        """Export data to HTML format"""
        if not filename:
            filename = f"s7pwn_report_{self._get_timestamp()}.html"

        filepath = self.output_dir / filename

        html_content = self._generate_html(data, title)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return str(filepath)

    def _generate_html(self, data: Dict[str, Any], title: str) -> str:
        """Generate HTML content from data"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
            border-left: 4px solid #3498db;
            padding-left: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border: 1px solid #ddd;
        }}
        th {{
            background-color: #3498db;
            color: white;
            font-weight: bold;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        tr:hover {{
            background-color: #f1f1f1;
        }}
        .info {{
            background-color: #e8f4f8;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .timestamp {{
            color: #7f8c8d;
            font-size: 14px;
        }}
        .key {{
            font-weight: bold;
            color: #2980b9;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        <p class="timestamp">Generated: {timestamp}</p>
        {self._dict_to_html(data)}
    </div>
</body>
</html>"""
        return html

    def _dict_to_html(self, data: Any, level: int = 0) -> str:
        """Convert dictionary to HTML representation"""
        if isinstance(data, dict):
            if not data:
                return "<p>No data available</p>"

            # Check if this looks like a list of records (for table display)
            if all(isinstance(v, (dict, list)) for v in data.values()):
                html = ""
                for key, value in data.items():
                    html += f"<h2>{key}</h2>\n"
                    html += self._dict_to_html(value, level + 1)
                return html
            else:
                html = "<table>\n"
                for key, value in data.items():
                    html += "<tr>\n"
                    html += f"<td class='key'>{key}</td>\n"
                    if isinstance(value, (dict, list)):
                        html += f"<td>{self._dict_to_html(value, level + 1)}</td>\n"
                    else:
                        html += f"<td>{value}</td>\n"
                    html += "</tr>\n"
                html += "</table>\n"
                return html

        elif isinstance(data, list):
            if not data:
                return "<p>No items</p>"

            # If list of dicts, create table
            if all(isinstance(item, dict) for item in data):
                if not data:
                    return "<p>No items</p>"

                # Get all keys
                all_keys = set()
                for item in data:
                    all_keys.update(item.keys())
                all_keys = sorted(all_keys)

                html = "<table>\n<thead><tr>\n"
                for key in all_keys:
                    html += f"<th>{key}</th>\n"
                html += "</tr></thead>\n<tbody>\n"

                for item in data:
                    html += "<tr>\n"
                    for key in all_keys:
                        value = item.get(key, "")
                        html += f"<td>{value}</td>\n"
                    html += "</tr>\n"
                html += "</tbody>\n</table>\n"
                return html
            else:
                html = "<ul>\n"
                for item in data:
                    html += f"<li>{item}</li>\n"
                html += "</ul>\n"
                return html
        else:
            return str(data)

    def export_scan_results(self, devices: List[Dict], plc_list: List[Dict],
                          format: str = "json") -> str:
        """Export scan results in specified format"""
        report_data = {
            "report_type": "Network Scan",
            "timestamp": datetime.datetime.now().isoformat(),
            "summary": {
                "total_devices": len(devices),
                "total_plcs": len(plc_list)
            },
            "all_devices": devices,
            "plc_devices": plc_list
        }

        if format.lower() == "json":
            return self.export_to_json(report_data, f"scan_{self._get_timestamp()}.json")
        elif format.lower() == "csv":
            # Export PLCs to CSV (most useful data)
            return self.export_to_csv(plc_list, f"scan_plcs_{self._get_timestamp()}.csv")
        elif format.lower() == "html":
            return self.export_to_html(report_data, "Network Scan Report",
                                      f"scan_{self._get_timestamp()}.html")
        else:
            raise ValueError(f"Unsupported format: {format}")

    def export_probe_results(self, target: Dict[str, Any], probe_data: Dict[str, Any],
                           format: str = "json") -> str:
        """Export probe results in specified format"""
        report_data = {
            "report_type": "Target Probe",
            "timestamp": datetime.datetime.now().isoformat(),
            "target": target,
            "probe_results": probe_data
        }

        if format.lower() == "json":
            return self.export_to_json(report_data, f"probe_{self._get_timestamp()}.json")
        elif format.lower() == "html":
            return self.export_to_html(report_data, "Target Probe Report",
                                      f"probe_{self._get_timestamp()}.html")
        else:
            raise ValueError(f"Unsupported format: {format}")

    def export_operation_log(self, operations: List[Dict[str, Any]],
                           format: str = "json") -> str:
        """Export operation log (read/write/monitor) in specified format"""
        report_data = {
            "report_type": "Operation Log",
            "timestamp": datetime.datetime.now().isoformat(),
            "total_operations": len(operations),
            "operations": operations
        }

        if format.lower() == "json":
            return self.export_to_json(report_data, f"operations_{self._get_timestamp()}.json")
        elif format.lower() == "csv":
            return self.export_to_csv(operations, f"operations_{self._get_timestamp()}.csv")
        elif format.lower() == "html":
            return self.export_to_html(report_data, "Operations Log Report",
                                      f"operations_{self._get_timestamp()}.html")
        else:
            raise ValueError(f"Unsupported format: {format}")


# Global instance
_exporter = ReportExporter()

def get_exporter() -> ReportExporter:
    """Get global ReportExporter instance"""
    return _exporter
