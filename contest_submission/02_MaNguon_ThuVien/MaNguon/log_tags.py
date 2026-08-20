#!/usr/bin/env python3
"""
log_tags.py  —  Poll toàn bộ tag PLC theo bảng tag TIA Portal chính xác
==========================================================================
Bảng tag PLC (Traffic Light S7-1200):

  Q area (đầu ra vật lý):
    Q0.1 = Running    Q0.2 = Red1    Q0.3 = Red2
    Q0.4 = Yellow1    Q0.5 = Yellow2 Q0.6 = Green1   Q0.7 = Green2

  M area (biến nội bộ):
    M2.1  = START (Bool)
    M2.2  = STOP  (Bool)
    MD3   = TimeR1    (Time → 4 bytes big-endian ms, giá trị setpoint đỏ hướng 1)
    MD8   = TimeR2    (Time → 4 bytes, setpoint đỏ hướng 2)
    MD12  = TimeY1    (Time → 4 bytes, setpoint vàng hướng 1)
    MD16  = TimeY2    (Time → 4 bytes, setpoint vàng hướng 2)
    MD20  = TimeG1    (Time → 4 bytes, setpoint xanh hướng 1)
    MD24  = TimeG2    (Time → 4 bytes, setpoint xanh hướng 2)
    M28.0 = s1  M28.1 = s4  M28.2 = s2  M28.3 = s3  (cảm biến)
    MD30  = Time_R_int  (DInt, timer đỏ thực tế ms)
    MD34  = Time_Y_int  (DInt, timer vàng ms)
    MD38  = Time_G_int  (DInt, timer xanh ms)
    MD42  = Delay_R_int (DInt)   MD46 = Delay_Y_int   MD50 = Delay_G_int
    MD54  = Remain_R    (DInt)   MD58 = Remain_Y       MD62 = Remain_G
    MD66  = TempR       (DInt)   MD70 = TempY          MD74 = TempG
    MD78  = Time        (DInt, timestamp nội bộ PLC)

CHÚ Ý QUAN TRỌNG về SPOOF/RWRITE attack:
  - s7pwn spoof "M10=99.9:real"  → ghi 4 bytes tại M10-M13
    M10-M11 nằm trong MD8 (TimeR2), M12-M13 nằm trong MD12 (TimeY1)
    → TimeR2 và TimeY1 sẽ bị corrupt → feature phát hiện SPOOF
  - s7pwn rwrite "M10=200:byte"  → ghi 1 byte tại M10 (trong MD8/TimeR2)
  - s7pwn rwrite "M0=255:byte" "M1=128:byte" → ghi M0, M1 (không trong tag table)
  - s7pwn rwrite "Q0=36:byte"  → ghi trực tiếp Q output byte

Cách dùng:
  python log_tags.py --target 192.168.1.10 --output /data/tags/day1.csv
  python log_tags.py --target 192.168.1.10 --interval 0.2 --output tags.csv
"""

import argparse
import csv
import os
import sys
import time

import snap7
from snap7.util import get_bool, get_dint
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas


# =============================================================================
#  Mapping chính xác từ bảng tag TIA Portal
# =============================================================================

# ── Q area (PA — Physical Output): đọc Q0 (1 byte = Q0.0–Q0.7) ───────────────
Q_AREA_OFFSET = 0
Q_AREA_SIZE   = 1     # 1 byte đủ cho Q0.1–Q0.7

Q_BITS = {
    # (byte_in_area, bit_index) — bit_index 0=LSB
    'Running': (0, 1),   # Q0.1
    'Red1':    (0, 2),   # Q0.2
    'Red2':    (0, 3),   # Q0.3
    'Yellow1': (0, 4),   # Q0.4
    'Yellow2': (0, 5),   # Q0.5
    'Green1':  (0, 6),   # Q0.6
    'Green2':  (0, 7),   # Q0.7
}

# ── M area (MK — Merker): đọc M0–M82 (82 bytes) ──────────────────────────────
# MD78 + 4 bytes = M82, đọc từ offset 0 là đủ
M_AREA_OFFSET = 0
M_AREA_SIZE   = 82    # bao phủ toàn bộ tag table

# M area Bool bits
M_BITS = {
    'START': (2, 1),    # M2.1
    'STOP':  (2, 2),    # M2.2
    's1':    (28, 0),   # M28.0
    's4':    (28, 1),   # M28.1 (đúng thứ tự trong tag table)
    's2':    (28, 2),   # M28.2
    's3':    (28, 3),   # M28.3
}

# M area Time/DInt (4 bytes, big-endian signed int, đơn vị ms)
# get_dint(bytearray, offset) → đọc 4 bytes tại offset
M_DWORDS = {
    # Time type (TIA Portal Time = signed 32-bit ms, same as DInt)
    'TimeR1':     3,    # MD3  — setpoint đỏ hướng 1
    'TimeR2':     8,    # MD8  — setpoint đỏ hướng 2
    'TimeY1':     12,   # MD12 — setpoint vàng hướng 1
    'TimeY2':     16,   # MD16 — setpoint vàng hướng 2
    'TimeG1':     20,   # MD20 — setpoint xanh hướng 1
    'TimeG2':     24,   # MD24 — setpoint xanh hướng 2
    # DInt type
    'Time_R_int': 30,   # MD30
    'Time_Y_int': 34,   # MD34
    'Time_G_int': 38,   # MD38
    'Delay_R_int':42,   # MD42
    'Delay_Y_int':46,   # MD46
    'Delay_G_int':50,   # MD50
    'Remain_R':   54,   # MD54
    'Remain_Y':   58,   # MD58
    'Remain_G':   62,   # MD62
    'TempR':      66,   # MD66
    'TempY':      70,   # MD70
    'TempG':      74,   # MD74
    'Time':       78,   # MD78
}

# M area raw byte reads (attack targets không có trong tag table nhưng quan trọng)
# s7pwn tấn công nhắm vào M0, M1 (không có trong tag table TIA nhưng vẫn tồn tại trong PLC)
M_BYTES_RAW = {
    'm0_raw': 0,    # s7pwn rwrite "M0=255:byte"
    'm1_raw': 1,    # s7pwn rwrite "M1=128:byte"
    'm2_raw': 2,    # chứa START/STOP bits
    'm10_raw': 10,  # s7pwn spoof/rwrite target (nằm trong MD8/TimeR2)
}

# Q area raw byte
Q_BYTES_RAW = {
    'q0_raw': 0,    # s7pwn rwrite "Q0=36:byte" → ghi thẳng output byte
}

# NORMAL RANGE cho các setpoint (để tính flag anomaly)
# Điều chỉnh theo thiết kế logic của hệ thống đèn giao thông
NORMAL_SETPOINT_MS_MIN = 3_000    # 3 giây
NORMAL_SETPOINT_MS_MAX = 90_000   # 90 giây


# =============================================================================
#  Build CSV header
# =============================================================================

def build_header() -> list:
    cols = [
        'timestamp_ms',
        'poll_seq',
        'plc_connected',
        'plc_mode',           # 1=RUN, 0=STOP/ERROR
        'read_latency_ms',
        'polling_error',
        'q_raw_hex',          # hex dump Q area (debug)
        'm_raw_hex',          # hex dump M area (debug)
    ]

    # Q bits
    cols += sorted(Q_BITS.keys())

    # Q raw bytes
    cols += sorted(Q_BYTES_RAW.keys())

    # M bits
    cols += sorted(M_BITS.keys())

    # M raw bytes (attack targets)
    cols += sorted(M_BYTES_RAW.keys())

    # M dword (Time/DInt)
    cols += sorted(M_DWORDS.keys())

    # Derived features (tính ngay lúc poll)
    cols += [
        # Q output logic violations
        'green_conflict',       # Green1=1 AND Green2=1 → 2 hướng cùng xanh
        'red_green_d1',         # Red1=1 AND Green1=1 → vi phạm safety hướng 1
        'red_green_d2',         # Red2=1 AND Green2=1 → vi phạm safety hướng 2
        'multi_light_d1',       # >1 đèn sáng hướng 1
        'multi_light_d2',       # >1 đèn sáng hướng 2
        'no_light_d1',          # PLC chạy nhưng không đèn nào sáng hướng 1
        'no_light_d2',          # PLC chạy nhưng không đèn nào sáng hướng 2

        # Setpoint anomaly
        'timer_out_of_range',   # bất kỳ setpoint Time nào nằm ngoài [3s, 90s]
        'setpoint_corrupted',   # TimeR2 hoặc TimeY1 bất thường (SPOOF M10 target)

        # Q byte sanity (RWRITE Q0)
        'q_output_unexpected',  # q0_raw không khớp với combination hợp lệ của các đèn
    ]

    return cols



LAST_PLC_TIME = None
PLC_RUNNING_BY_TIME = True

# =============================================================================
#  Poll một lần
# =============================================================================

def poll_once(client: snap7.client.Client, poll_seq: int) -> dict:
    ts_start = int(time.time() * 1000)
    header = build_header()
    row = {col: 0 for col in header}
    row['timestamp_ms'] = ts_start
    row['poll_seq'] = poll_seq
    row['q_raw_hex'] = ''
    row['m_raw_hex'] = ''

    try:
        if not client.get_connected():
            raise ConnectionError("Not connected")

        row['plc_connected'] = 1

        cpu_state_ok = False
        try:
            mode = client.get_cpu_state()
            mode_str = str(mode)
            row['plc_mode'] = 1 if ("Run" in mode_str or mode_str == "8" or mode == 8) else 0
            cpu_state_ok = True
        except Exception:
            # Fallback: Đặt tạm thời là 1, sẽ được cập nhật chính xác bằng Running tag ở phía dưới
            row['plc_mode'] = 1

        # ── Q area ───────────────────────────────────────────────────────────
        q_data = client.read_area(Areas.PA, 0, Q_AREA_OFFSET, Q_AREA_SIZE)
        row['q_raw_hex'] = q_data.hex()

        for name, (byte_off, bit_idx) in Q_BITS.items():
            row[name] = 1 if get_bool(q_data, byte_off, bit_idx) else 0

        for name, offset in Q_BYTES_RAW.items():
            row[name] = q_data[offset] if offset < len(q_data) else 0

        # ── M area ───────────────────────────────────────────────────────────
        m_data = client.read_area(Areas.MK, 0, M_AREA_OFFSET, M_AREA_SIZE)
        row['m_raw_hex'] = m_data.hex()

        for name, (byte_off, bit_idx) in M_BITS.items():
            row[name] = 1 if get_bool(m_data, byte_off, bit_idx) else 0

        for name, offset in M_BYTES_RAW.items():
            row[name] = m_data[offset] if offset < len(m_data) else 0

        for name, offset in M_DWORDS.items():
            if offset + 4 <= len(m_data):
                row[name] = get_dint(m_data, offset)

        # ── Derived features ─────────────────────────────────────────────────

        rn  = row['Running']
        r1  = row['Red1'];    r2  = row['Red2']
        y1  = row['Yellow1']; y2  = row['Yellow2']
        g1  = row['Green1'];  g2  = row['Green2']

        # Nếu không đọc được CPU state trực tiếp (do PLC bảo mật chặn), ta dùng Running tag (Q0.1) làm proxy.
        # Running = 1 nghĩa là PLC đang chạy thực thi logic vòng quét đèn giao thông.
        if not cpu_state_ok:
            row['plc_mode'] = int(rn == 1)

        row['green_conflict'] = int(g1 == 1 and g2 == 1)
        row['red_green_d1']   = int(r1 == 1 and g1 == 1)
        row['red_green_d2']   = int(r2 == 1 and g2 == 1)
        row['multi_light_d1'] = int((r1 + y1 + g1) > 1)
        row['multi_light_d2'] = int((r2 + y2 + g2) > 1)
        row['no_light_d1']    = int((r1 + y1 + g1) == 0 and rn == 1)
        row['no_light_d2']    = int((r2 + y2 + g2) == 0 and rn == 1)

        # Kiểm tra TẤT CẢ setpoint Time (MD3, MD8, MD12, MD16, MD20, MD24)
        # Trong bình thường: 3000ms ≤ setpoint ≤ 90000ms
        setpoint_tags = ['TimeR1', 'TimeR2', 'TimeY1', 'TimeY2', 'TimeG1', 'TimeG2']
        timer_oor = any(
            not (NORMAL_SETPOINT_MS_MIN <= row[t] <= NORMAL_SETPOINT_MS_MAX)
            for t in setpoint_tags if row[t] != 0
        )
        row['timer_out_of_range'] = int(timer_oor)

        # Phát hiện SPOOF M10:
        # s7pwn spoof "M10=99.9:real" ghi 4 bytes IEEE754 vào M10-M13
        # → bytes M10-M11 corrupt MD8 (TimeR2), M12-M13 corrupt MD12 (TimeY1)
        # TimeR2 và TimeY1 sẽ có giá trị bất thường (ví dụ: 1120403456 thay vì 30000)
        tr2 = row.get('TimeR2', 0)
        ty1 = row.get('TimeY1', 0)
        spoof_signal = (
            not (NORMAL_SETPOINT_MS_MIN <= tr2 <= NORMAL_SETPOINT_MS_MAX)
            or not (NORMAL_SETPOINT_MS_MIN <= ty1 <= NORMAL_SETPOINT_MS_MAX)
        ) if (tr2 != 0 or ty1 != 0) else False
        row['setpoint_corrupted'] = int(spoof_signal)

        # Phát hiện RWRITE Q0=36:byte
        # Q0=36 → binary 00100100 → Running=0, Red1=0, Red2=1, Yellow1=0, Yellow2=0, Green1=1, Green2=0
        # Đây là tổ hợp đèn KHÔNG hợp lệ trong traffic light (đỏ hướng 2 + xanh hướng 1 cùng lúc = xung đột)
        # Cách tổng quát: nếu q0_raw không match với 1 trong các state hợp lệ đã biết
        valid_q_states = {
            0b00000000,  # tất cả tắt (PLC dừng)
            0b00000010,  # Running=1, không đèn nào (khởi động)
            0b00000110,  # Running + Red1
            0b00001010,  # Running + Red2
            0b00001110,  # Running + Red1 + Red2 (chuyển)
            0b00100010,  # Running + Yellow1
            0b01000010,  # Running + Yellow2
            0b10000010,  # Running + Green1
            0b00000001 * 128 + 0b00000010,  # Running + Green2
            0b10000010,  # Running + Green1
            0b01000010,  # Running + Green2? — tuỳ logic PLC
        }
        q0_val = row.get('q0_raw', 0)
        row['q_output_unexpected'] = int(q0_val not in valid_q_states)

    except Exception as e:
        row['polling_error'] = 1
        row['plc_connected'] = 0
        print(f"[POLL ERROR] seq={poll_seq}: {e}", file=sys.stderr, flush=True)
        try:
            client.disconnect()
        except Exception:
            pass

    ts_end = int(time.time() * 1000)
    row['read_latency_ms'] = ts_end - ts_start
    return row


# =============================================================================
#  Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='PLC Tag Logger — đọc Q/M area theo bảng tag TIA Portal.',
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument('--target',   required=True, help='PLC IP address')
    parser.add_argument('--rack',     type=int, default=0)
    parser.add_argument('--slot',     type=int, default=1)
    parser.add_argument('--interval', type=float, default=0.5,
                        help='Poll interval (giây). Mặc định 0.5s = 2Hz')
    parser.add_argument('--output',   required=True)
    args = parser.parse_args()

    header = build_header()

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    fh = open(args.output, 'w', newline='', buffering=1)  # line-buffered
    writer = csv.writer(fh)
    writer.writerow(header)
    fh.flush()

    client = snap7.client.Client()
    poll_seq = 0

    print(f"[LOG_TAGS] PLC    : {args.target}  rack={args.rack} slot={args.slot}")
    print(f"[LOG_TAGS] Output : {args.output}")
    print(f"[LOG_TAGS] Poll   : {args.interval}s ({1/args.interval:.0f} Hz)")
    print(f"[LOG_TAGS] Tags   : {len([c for c in header if c not in ('timestamp_ms','poll_seq','plc_connected','plc_mode','read_latency_ms','polling_error','q_raw_hex','m_raw_hex')])} biến")
    print("[LOG_TAGS] Bảng tag: Q0.1-Q0.7 | M2.1-2.2 | MD3-MD78 | M28.0-3")
    print("[LOG_TAGS] Ctrl+C để dừng.\n")

    try:
        while True:
            loop_start = time.time()

            if not client.get_connected():
                try:
                    client.connect(args.target, args.rack, args.slot)
                    print(f"[LOG_TAGS] Connected {args.target}", flush=True)
                except Exception as e:
                    print(f"[LOG_TAGS] Connect fail: {e}  (retry in 2s)", file=sys.stderr, flush=True)
                    time.sleep(2)
                    continue

            row = poll_once(client, poll_seq)
            poll_seq += 1
            writer.writerow([row[col] for col in header])
            fh.flush()

            # Status log mỗi 20 poll
            if poll_seq % 20 == 0:
                print(
                    f"[{poll_seq:6d}] "
                    f"mode={'RUN' if row['plc_mode'] else 'STOP'} "
                    f"lat={row['read_latency_ms']}ms "
                    f"err={row['polling_error']} "
                    f"green_conflict={row['green_conflict']} "
                    f"timer_oor={row['timer_out_of_range']} "
                    f"spoof={row['setpoint_corrupted']} "
                    f"q_bad={row['q_output_unexpected']}",
                    flush=True
                )

            elapsed = time.time() - loop_start
            sleep_time = max(0.0, args.interval - elapsed)
            time.sleep(sleep_time)

    except KeyboardInterrupt:
        print(f"\n[LOG_TAGS] Dừng. Tổng poll: {poll_seq}")
        fh.close()
        sys.exit(0)


if __name__ == '__main__':
    main()
