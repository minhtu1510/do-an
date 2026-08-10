"""
FULL_KILL_CHAIN
Multi-stage attack giả lập APT tấn công ICS (chuỗi liên tục 1 phiên, khác với
cac test rieng le o tests/day8/ va cac module Day 7 khac):
  Stage 1: Initial Access   - ROGUE_EWS_S7 (chiem foothold qua S7)
  Stage 2: Lateral Movement - PIVOT_HMI_ENG (dung foothold do do tham sang
                               may HMI/Engineering, KHONG ghi de PLC nua)

Cac stage OPC UA truoc day (recon/alarm-suppress/fake-display) da bo vi trung
ky thuat voi tests/day8/run_day8.py (OPCUA_NODE_BROWSE, OPCUA_BENIGN_
SUBSCRIPTION, OPCUA_MALICIOUS_WRITE). Stage "Execution: covert write" cu cung
da bo vi trung voi attacks_ext/stealthy_write.py (cung la ghi lech nho vao
PLC roi khoi phuc) -- thay bang Lateral Movement de kill chain nay co gia tri
rieng: the hien dung mach truyen mot foothold OT (PLC qua S7) dan toi hanh
dong tren mot host khac (HMI/Engineering) TRONG CUNG mot phien lien tuc, thay
vi lap lai ky thuat da co o noi khac.

QUAN TRONG ve nhan MITRE cua Stage 2: day la port-scan thuan tuy (TCP connect)
nham vao HMI/Engineering NGAY SAU KHI da co foothold S7 -- khong khai thac
dich vu that, khong dung valid credentials. Ve ban chat ky thuat no van la
T0846 Remote System Discovery, chi khac boi context (thuc hien tu vi tri da
chiem duoc, khong phai tu ben ngoai) nen dat trong narrative Lateral
Movement -- KHONG gan nham T0867 Lateral Tool Transfer / T0866 Exploitation
of Remote Services vi khong co hanh vi thuc su nhu vay.

Gọi từ bash:
  python -m attacks_ext.kill_chain \
      --target 192.168.210.211 --rack 0 --slot 1 \
      --hmi-target 192.168.210.31 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import time
from attacks_ext.config_ext import base_parser, write_label
from attacks_ext.eng_station_scan import PORTS, tcp_probe

STAGES = {
    1: "INITIAL_ACCESS_ROGUE_EWS",
    2: "LATERAL_MOVEMENT_PIVOT_HMI",
}


def log_stage(stage_num, msg):
    print(f"\n{'='*60}")
    print(f"[STAGE {stage_num}] {STAGES[stage_num]}")
    print(f"[INFO]  {msg}")
    print(f"{'='*60}")


def stage1_rogue_access(plc, target, rack, slot):
    log_stage(1, "Kết nối S7 từ IP attacker, đọc thông tin PLC")
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


def stage2_lateral_movement(plc, hmi_target):
    log_stage(2, f"Dùng foothold S7 làm bàn đạp, pivot dò thăm {hmi_target} (HMI/Engineering)")
    open_ports = {}
    if not plc.get_connected():
        print("  [WARN] Đã mất foothold S7 (session không còn) -- vẫn tiếp tục pivot từ máy attacker")
    else:
        print(f"  [+] Foothold S7 vẫn đang mở -- pivot sang {hmi_target} trong cùng phiên tấn công")
    try:
        for port, desc in PORTS.items():
            is_open = tcp_probe(hmi_target, port)
            status = "OPEN" if is_open else "closed"
            if is_open:
                open_ports[port] = desc
            print(f"  [PIVOT] {hmi_target}:{port:<5} ({desc}) -> {status}")
            time.sleep(0.15)
        print(f"  [*] Lateral movement xong: {len(open_ports)}/{len(PORTS)} port mở trên {hmi_target}")
    except Exception as e:
        print(f"  [ERR] {e}")
    return open_ports


def run(args):
    import snap7
    label_prefix = "KILL_CHAIN"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"target={args.target} hmi_target={args.hmi_target}")

    plc = None
    open_ports = {}

    try:
        plc = snap7.client.Client()

        stage1_rogue_access(plc, args.target, args.rack, args.slot)
        time.sleep(3)
        open_ports = stage2_lateral_movement(plc, args.hmi_target)

        print(f"\n[COMPLETE] Kill Chain hoàn tất!")

    except ImportError as e:
        print(f"[ERR] Thiếu thư viện: {e}")
    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        if plc and plc.get_connected():
            plc.disconnect()
        summary = "; ".join(f"{p}={d}" for p, d in open_ports.items()) or "none"
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"hmi_open_ports=[{summary}]")


def main():
    p = base_parser("ICS Kill Chain Simulation (S7 foothold -> lateral movement pivot to HMI)")
    p.add_argument("--target", default="192.168.210.211")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    p.add_argument("--hmi-target", default="192.168.210.31", help="HMI/Engineering host to pivot toward in Stage 2")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
