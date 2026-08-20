#!/usr/bin/env python3
"""
label_webhook_server.py – Label Event Receiver (chạy trên máy Logger/Collector)
=================================================================================
Nhận HTTP POST từ Attacker mỗi khi bắt đầu/kết thúc một vector tấn công.
Ghi vào CSV: timestamp_ms, label, action (START/END), day.
Dùng để gán nhãn PCAP sau phiên thu thập.

Chạy:
    python label_webhook_server.py --port 9000 --output /data/labels/day2_timeline.csv
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import csv
import time
import argparse
import os
import sys
import threading

class LabelHandler(BaseHTTPRequestHandler):
    """HTTP handler nhận label events từ attacker."""

    # Shared state – set trước khi start server
    csv_writer: csv.writer = None
    csv_file_handle = None
    write_lock = threading.Lock()
    event_count = 0

    def do_POST(self):
        if self.path == '/label':
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length)
                data = json.loads(body.decode('utf-8'))

                required = {'timestamp', 'label', 'action'}
                if not required.issubset(data.keys()):
                    self._respond(400, f"Thiếu trường: {required - data.keys()}")
                    return

                server_ts = time.time()
                row = [
                    data.get('timestamp'),          # attacker-side ms timestamp
                    data.get('label'),               # e.g. SCAN, FLOOD, NORMAL
                    data.get('action'),              # START hoặc END
                    data.get('day', '?'),            # ngày chạy kịch bản
                    round(server_ts * 1000),         # server-side ms (cross-check)
                    data.get('note', '')             # ghi chú tuỳ chọn
                ]

                with LabelHandler.write_lock:
                    LabelHandler.csv_writer.writerow(row)
                    LabelHandler.csv_file_handle.flush()
                    LabelHandler.event_count += 1

                print(f"[EVENT #{LabelHandler.event_count}] "
                      f"{data['label']:15s} | {data['action']:5s} | "
                      f"Day={data.get('day','?')} | ts={data['timestamp']}")

                self._respond(200, 'OK')

            except json.JSONDecodeError:
                self._respond(400, 'Invalid JSON')
            except Exception as e:
                self._respond(500, str(e))

        elif self.path == '/health':
            # Health check endpoint
            self._respond(200, json.dumps({
                'status': 'ok',
                'events_received': LabelHandler.event_count
            }))

        elif self.path == '/stats':
            self._respond(200, json.dumps({'events': LabelHandler.event_count}))
        else:
            self._respond(404, 'Not found')

    def do_GET(self):
        if self.path == '/health':
            self._respond(200, json.dumps({
                'status': 'ok',
                'events_received': LabelHandler.event_count
            }))
        else:
            self._respond(404, 'Not found')

    def _respond(self, code: int, body: str):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(body.encode('utf-8'))

    def log_message(self, format, *args):
        pass  # Tắt default HTTP access log (chúng ta tự log ở do_POST)


def main():
    parser = argparse.ArgumentParser(
        description='Label Event Webhook Server – ICS Dataset Collection',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--port', type=int, default=9000,
                        help='Cổng lắng nghe (default: 9000)')
    parser.add_argument('--host', default='0.0.0.0',
                        help='Địa chỉ bind (default: 0.0.0.0 = tất cả interface)')
    parser.add_argument('--output', required=True,
                        help='Đường dẫn file CSV lưu label timeline\n'
                             'Ví dụ: /data/labels/day2_timeline.csv')
    args = parser.parse_args()

    # Tạo thư mục nếu chưa có
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)

    # Mở file CSV và ghi header
    is_new = not os.path.exists(args.output)
    fh = open(args.output, 'a', newline='', buffering=1)  # line-buffered
    writer = csv.writer(fh)
    if is_new:
        writer.writerow([
            'attacker_timestamp_ms',  # Timestamp phía attacker (milliseconds)
            'label',                  # Nhãn: NORMAL, SCAN, FLOOD, ...
            'action',                 # START hoặc END
            'day',                    # Ngày thu thập (1–5)
            'server_timestamp_ms',    # Timestamp phía Logger (cross-check)
            'note'                    # Ghi chú tùy chọn
        ])
        fh.flush()

    LabelHandler.csv_writer = writer
    LabelHandler.csv_file_handle = fh

    server = HTTPServer((args.host, args.port), LabelHandler)

    print(f"""
╔══════════════════════════════════════════════════════════╗
║       Label Webhook Server – ICS Dataset Collection      ║
╠══════════════════════════════════════════════════════════╣
║  Lắng nghe  : {args.host}:{args.port:<41} ║
║  Ghi nhãn → : {args.output:<44} ║
╚══════════════════════════════════════════════════════════╝
Endpoint : POST http://{args.host}:{args.port}/label
Health   : GET  http://{args.host}:{args.port}/health

Payload mẫu:
  {{"timestamp": 1713369600000, "label": "FLOOD", "action": "START", "day": 2}}

Nhấn Ctrl+C để dừng server.
""")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[Server] Đã nhận {LabelHandler.event_count} events. Đóng server...")
        fh.close()
        sys.exit(0)


if __name__ == '__main__':
    main()
