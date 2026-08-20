"""
ENG_STATION_PORT_SCAN
TCP port scan nham vao may Engineering/WinCC/TIA Portal -- rong hon SMB thuan
tuy (attacks_ext/smb_enum.py): tim them RDP (truy cap engineering tu xa),
MSSQL (WinCC Runtime DB), S7 local (PLCSIM tren may ky thuat), HTTP/HTTPS
(WinCC Web Navigator). Khong exploit, chi TCP connect-scan thuan tuy.
MITRE: T0846 Remote System Discovery (ICS) / T1046 Network Service Scanning

Gọi từ bash:
  python -m attacks_ext.eng_station_scan \
      --target 192.168.210.31 --duration 120 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import socket
import time
from attacks_ext.config_ext import base_parser, write_label

PORTS = {
    102:  "S7comm (PLCSIM / local engineering S7 service)",
    135:  "MSRPC Endpoint Mapper",
    139:  "NetBIOS Session",
    445:  "SMB",
    1433: "MSSQL (WinCC Runtime DB)",
    3389: "RDP (remote engineering access)",
    80:   "HTTP (WinCC Web Navigator)",
    443:  "HTTPS (WinCC Web Navigator)",
}


def tcp_probe(ip, port, timeout=1.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        is_open = s.connect_ex((ip, port)) == 0
        s.close()
        return is_open
    except Exception:
        return False


def run(args):
    label_prefix = "ENG_STATION_PORT_SCAN"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s target={args.target} ports={len(PORTS)}")

    open_ports = {}
    scan_rounds = 0

    try:
        print(f"[*] Engineering/WinCC/TIA Portal port scan -> {args.target}")
        end_time = time.time() + args.duration

        while time.time() < end_time:
            scan_rounds += 1
            for port, desc in PORTS.items():
                is_open = tcp_probe(args.target, port)
                if is_open:
                    open_ports[port] = desc
                print(f"  [{scan_rounds}] {port:<5} ({desc}) -> {'OPEN' if is_open else 'closed'}")
                time.sleep(0.1)
            time.sleep(2.0)

    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        summary = "; ".join(f"{p}={d}" for p, d in open_ports.items()) or "none"
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"rounds={scan_rounds} open_ports=[{summary}]")


def main():
    p = base_parser("Engineering/WinCC/TIA Portal Station Port Scan")
    p.add_argument("--target", default="192.168.210.31")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
