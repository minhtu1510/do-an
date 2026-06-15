#!/usr/bin/env python3
"""
log_tags_bangtruyen.py  —  Poll tag PLC hệ thống Băng Truyền (Conveyor Belt)
==========================================================================
Bảng tag PLC (Conveyor Belt S7-1500/S7-1200) — Tham chiếu từ bảng tag TIA Portal:

  I area (đầu vào vật lý):
    I0.0 = Start_1              (Nút khởi động)
    I0.1 = Stop_1               (Nút dừng)
    I0.2 = Cam_bien_phat_hien_thung (Cảm biến phát hiện thùng)

  Q area (đầu ra vật lý):
    Q0.0 = BangTai              (1=Băng tải đang chạy, 0=Dừng)

  M area (biến nội bộ):
    M5.0  = START (Bool)
    M5.1  = STOP  (Bool)
    M5.2  = Tag_1 (Bool)
    M5.3  = Tag_2 (Bool)
    M5.4  = Vat_1 (Bool)        (Vật thể 1 đang trên băng)
    M5.5  = Tag_5 (Bool)
    M5.6  = Vat_2 (Bool)        (Vật thể 2 đang trên băng)
    M5.7  = Tag_6 (Bool)
    M6.0  = Vat_3 (Bool)        (Vật thể 3 đang trên băng)
    M6.1  = S1    (Bool)
    M6.2  = Tag_8 (Bool)
    M9.0  = Tag_7 (Bool)
    M10.0 = Tag_9 (Bool)
    M10.1 = Tag_10 (Bool)
    MD50  = Times_1 (DInt, ms)  (Bộ đếm thời gian tổng)
    MD54  = CD1     (Time, ms)  (Countdown timer vật 1)
    MD56  = Tag_4   (Time, ms)  (DISABLED by default: overlaps MD54/MD58 if DInt)
    MD58  = CD2     (Time, ms)  (Countdown timer vật 2)
    MD62  = CD3     (Time, ms)  (Countdown timer vật 3)
    MW70  = Nhap    (Int)       (Giá trị đầu vào đếm thùng)
    MW74  = HienThi (Int)       (Giá trị hiển thị đếm)

Cách dùng:
  python log_tags_bangtruyen.py --target 192.168.1.10 --output logs/day1_bt_s1_tags.csv
  python log_tags_bangtruyen.py --target 192.168.1.10 --interval 0.5 --output tags.csv
"""

import argparse
import csv
import os
import sys
import time

import snap7
from snap7.util import get_bool, get_dint, get_int
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


# =============================================================================
#  Mapping chính xác từ bảng tag TIA Portal — Băng Truyền
# =============================================================================

# ── I area (Physical Input): đọc I0 (1 byte = I0.0–I0.7) ────────────────────
I_AREA_OFFSET = 0
I_AREA_SIZE   = 2     # 2 bytes bao phủ I0 và I1

I_BITS = {
    'Start_1':  (0, 0),   # I0.0 — Nút khởi động
    'Stop_1':   (0, 1),   # I0.1 — Nút dừng
    'Cam_bien': (0, 2),   # I0.2 — Cảm biến phát hiện thùng
}

# ── Q area (Physical Output): đọc Q0 (1 byte = Q0.0–Q0.7) ───────────────────
Q_AREA_OFFSET = 0
Q_AREA_SIZE   = 1

Q_BITS = {
    'BangTai': (0, 0),   # Q0.0 — Động cơ băng tải
}

Q_BYTES_RAW = {
    'q0_raw': 0,         # Dump raw Q0 byte (để phát hiện RWRITE)
}

# ── M area (Merker): đọc M0–M76 ──────────────────────────────────────────────
# MW74 + 2 bytes = M76, đọc từ offset 0 là đủ
M_AREA_OFFSET = 0
M_AREA_SIZE   = 80

# M area Bool bits — (byte_offset, bit_index)
M_BITS = {
    'START':  (5, 0),    # M5.0
    'STOP':   (5, 1),    # M5.1
    'Tag_1':  (5, 2),    # M5.2
    'Tag_2':  (5, 3),    # M5.3
    'Vat_1':  (5, 4),    # M5.4 — Vật thể 1 trên băng
    'Tag_5':  (5, 5),    # M5.5
    'Vat_2':  (5, 6),    # M5.6 — Vật thể 2 trên băng
    'Tag_6':  (5, 7),    # M5.7
    'Vat_3':  (6, 0),    # M6.0 — Vật thể 3 trên băng
    'S1':     (6, 1),    # M6.1
    'Tag_8':  (6, 2),    # M6.2
    'Tag_7':  (9, 0),    # M9.0
    'Tag_9':  (10, 0),   # M10.0
    'Tag_10': (10, 1),   # M10.1
}

# M area DInt/Time (4 bytes big-endian signed int, đơn vị ms)
M_DWORDS = {
    'Times_1': 50,   # MD50 — Thời gian tổng
    'CD1':     54,   # MD54 — Countdown vật 1
    'CD2':     58,   # MD58 — Countdown vật 2
    'CD3':     62,   # MD62 — Countdown vật 3
}

# Tag_4/MD56 is intentionally not logged as a DInt by default because it overlaps
# CD1=MD54 (bytes 54-57) and CD2=MD58 (bytes 58-61) if all are DInt/Time.

# M area Word (2 bytes big-endian signed int)
M_WORDS = {
    'Nhap':    70,   # MW70 — Đầu vào đếm thùng
    'HienThi': 74,   # MW74 — Hiển thị đếm
}

# M area raw bytes (phát hiện tấn công ghi đè vùng nhớ)
M_BYTES_RAW = {
    'm5_raw':  5,    # Byte M5 — chứa START/STOP/Vat bits
    'm6_raw':  6,    # Byte M6 — chứa Vat3/S1/Tag8
}

# Normal range của CD1/CD2/CD3 (thời gian xử lý 1 thùng bình thường)
# Điều chỉnh theo thiết kế logic băng truyền thực tế
NORMAL_CD_MS_MIN = 500       # 0.5 giây
NORMAL_CD_MS_MAX = 30_000    # 30 giây


# =============================================================================
#  Build CSV header
# =============================================================================

def build_header() -> list:
    cols = [
        'timestamp_ms',
        'session_id',
        'host_id',
        'scenario_id',
        'episode_id',
        'day',
        'poll_seq',
        'plc_connected',
        'plc_mode',           # 1=RUN, 0=STOP/ERROR
        'read_latency_ms',
        'polling_error',
        'q0_raw_hex',         # hex dump Q0 (debug)
        'i0_raw_hex',         # hex dump I0 (debug)
    ]

    # I bits (input buttons + sensor)
    cols += sorted(I_BITS.keys())

    # Q bits (motor output)
    cols += sorted(Q_BITS.keys())
    cols += sorted(Q_BYTES_RAW.keys())

    # M bits
    cols += sorted(M_BITS.keys())

    # M raw bytes
    cols += sorted(M_BYTES_RAW.keys())

    # M dwords (timers)
    cols += sorted(M_DWORDS.keys())

    # M words (counters)
    cols += sorted(M_WORDS.keys())

    # Derived anomaly features (phát hiện tấn công)
    cols += [
        # Belt state violations
        'belt_stopped_unexpectedly',  # BangTai=0 nhưng STOP=0 và START=0 (lẽ ra phải chạy)
        'stop_flag_unexpected',       # STOP=1 nhưng không có lệnh dừng hợp lệ (STEALTHY attack)

        # Sensor/object spoofing
        'all_sensors_active',         # Vat1=Vat2=Vat3=1 cùng lúc (bình thường rất hiếm → SPOOF)
        'sensor_vs_belt_conflict',    # Có thùng (Vat=1) nhưng băng tải dừng (BangTai=0)

        # Timer/setpoint anomaly
        'cd_timer_out_of_range',      # CD1/CD2/CD3 nằm ngoài [0.5s, 30s] → SETPOINT ATTACK
        'cd_timer_corrupted',         # CD1 hoặc CD2 bị đặt giá trị bất thường

        # Output write attack
        'q_output_unexpected',        # q0_raw có bit bất thường (ngoài Q0.0) được set → RWRITE
    ]

    return cols


# =============================================================================
#  Poll một lần
# =============================================================================

def poll_once(client: snap7.client.Client, poll_seq: int, metadata: dict) -> dict:
    ts_start = int(time.time() * 1000)
    header = build_header()
    row = {col: 0 for col in header}
    row['timestamp_ms'] = ts_start
    row['session_id']   = metadata.get('session_id', '')
    row['host_id']      = metadata.get('host_id', '')
    row['scenario_id']  = metadata.get('scenario_id', '')
    row['episode_id']   = metadata.get('episode_id', '')
    row['day']          = metadata.get('day', '')
    row['poll_seq']     = poll_seq
    row['q0_raw_hex']   = ''
    row['i0_raw_hex']   = ''

    try:
        if not client.get_connected():
            raise ConnectionError("Not connected")

        row['plc_connected'] = 1

        # Đọc CPU state
        try:
            mode = client.get_cpu_state()
            mode_str = str(mode)
            row['plc_mode'] = 1 if ("Run" in mode_str or mode_str == "8" or mode == 8) else 0
        except Exception:
            row['plc_mode'] = 0  # Conservative fallback: unknown state is not RUN

        # ── I area (Physical Input) ───────────────────────────────────────────
        try:
            i_data = client.read_area(Areas.PE, 0, I_AREA_OFFSET, I_AREA_SIZE)
            row['i0_raw_hex'] = i_data.hex()
            for name, (byte_off, bit_idx) in I_BITS.items():
                row[name] = 1 if get_bool(i_data, byte_off, bit_idx) else 0
        except Exception:
            pass  # I area có thể không đọc được trên một số PLC

        # ── Q area (Physical Output) ──────────────────────────────────────────
        try:
            q_data = client.read_area(Areas.PA, 0, Q_AREA_OFFSET, Q_AREA_SIZE)
            row['q0_raw_hex'] = q_data.hex()

            for name, (byte_off, bit_idx) in Q_BITS.items():
                row[name] = 1 if get_bool(q_data, byte_off, bit_idx) else 0

            for name, offset in Q_BYTES_RAW.items():
                row[name] = q_data[offset] if offset < len(q_data) else 0
        except Exception:
            pass  # S7-1500 protection may block PA reads; keep M-area logging alive

        # ── M area ────────────────────────────────────────────────────────────
        m_data = client.read_area(Areas.MK, 0, M_AREA_OFFSET, M_AREA_SIZE)

        for name, (byte_off, bit_idx) in M_BITS.items():
            row[name] = 1 if get_bool(m_data, byte_off, bit_idx) else 0

        for name, offset in M_BYTES_RAW.items():
            row[name] = m_data[offset] if offset < len(m_data) else 0

        for name, offset in M_DWORDS.items():
            if offset + 4 <= len(m_data):
                row[name] = get_dint(m_data, offset)

        for name, offset in M_WORDS.items():
            if offset + 2 <= len(m_data):
                row[name] = get_int(m_data, offset)

        # ── Derived anomaly features ──────────────────────────────────────────
        bang_tai = row['BangTai']
        start_f  = row['START']
        stop_f   = row['STOP']
        vat1     = row['Vat_1']
        vat2     = row['Vat_2']
        vat3     = row['Vat_3']
        cd1      = row['CD1']
        cd2      = row['CD2']
        cd3      = row['CD3']

        # 1. Băng tải dừng bất thường (không có lệnh STOP, không đang khởi động)
        # Bình thường: nếu STOP=0 và START=0 → băng tải phải đang chạy (BangTai=1)
        # Bất thường: STOP=0 AND START=0 nhưng BangTai=0 → có gì đó ép dừng!
        row['belt_stopped_unexpectedly'] = int(
            bang_tai == 0 and stop_f == 0 and start_f == 0
        )

        # 2. STOP flag bị set bất thường (STEALTHY attack: ghi M5.1=1)
        # Khi STOP=1, băng tải phải dừng. Nhưng nếu không có người nhấn nút Stop_1 thực tế...
        row['stop_flag_unexpected'] = int(stop_f == 1)

        # 3. Tất cả cảm biến đều active cùng lúc (SENSOR_SPOOF attack)
        # Bình thường rất hiếm khi Vat1=Vat2=Vat3=1 đồng thời
        row['all_sensors_active'] = int(vat1 == 1 and vat2 == 1 and vat3 == 1)

        # 4. Có thùng trên băng nhưng băng tải dừng (conflict)
        # Nếu Vat1/2/3 = 1 nhưng BangTai = 0 → thùng bị kẹt!
        any_vat = int(vat1 == 1 or vat2 == 1 or vat3 == 1)
        row['sensor_vs_belt_conflict'] = int(any_vat == 1 and bang_tai == 0)

        # 5. Timer CD bị đặt ngoài ngưỡng bình thường (SETPOINT ATTACK)
        # CD > 30s: băng tải dừng quá lâu → năng suất giảm
        # CD < 0.5s: thùng chưa xử lý xong đã chạy tiếp → lỗi quy trình
        cd_oor_list = []
        for cd_name, cd_val in [('CD1', cd1), ('CD2', cd2), ('CD3', cd3)]:
            if cd_val != 0:
                if not (NORMAL_CD_MS_MIN <= cd_val <= NORMAL_CD_MS_MAX):
                    cd_oor_list.append(cd_name)
        row['cd_timer_out_of_range'] = int(len(cd_oor_list) > 0)

        # 6. CD bị corrupt (giá trị bất thường cực đoan: >60s hoặc âm)
        row['cd_timer_corrupted'] = int(
            cd1 < 0 or cd1 > 60_000 or
            cd2 < 0 or cd2 > 60_000 or
            cd3 < 0 or cd3 > 60_000
        )

        # 7. Q output byte có bit không hợp lệ (RWRITE Q0 attack)
        # Q0.0 = BangTai (bit 0) là bit hợp lệ duy nhất
        # Nếu bit 1-7 của Q0 được set → RWRITE tấn công output byte
        q0_val = row.get('q0_raw', 0)
        # Mask bỏ bit 0 (BangTai hợp lệ), nếu còn bit nào set → bất thường
        row['q_output_unexpected'] = int((q0_val & 0xFE) != 0)

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
        description='PLC Tag Logger — Băng Truyền (Conveyor Belt) S7-1500/S7-1200',
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument('--target',   required=True, help='PLC IP address')
    parser.add_argument('--rack',     type=int, default=0)
    parser.add_argument('--slot',     type=int, default=1)
    parser.add_argument('--interval', type=float, default=0.5,
                        help='Poll interval (giây). Mặc định 0.5s = 2Hz')
    parser.add_argument('--output',   required=True)
    parser.add_argument('--session-id', default='')
    parser.add_argument('--host-id', default='')
    parser.add_argument('--scenario-id', default='BENIGN_READER')
    parser.add_argument('--episode-id', default='')
    parser.add_argument('--day', default='')
    args = parser.parse_args()

    header = build_header()

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    fh = open(args.output, 'w', newline='', buffering=1)
    writer = csv.writer(fh)
    writer.writerow(header)
    fh.flush()

    client = snap7.client.Client()
    poll_seq = 0

    print(f"[LOG_TAGS_BT] PLC    : {args.target}  rack={args.rack} slot={args.slot}")
    print(f"[LOG_TAGS_BT] Output : {args.output}")
    print(f"[LOG_TAGS_BT] Meta   : session={args.session_id} host={args.host_id} day={args.day}")
    print(f"[LOG_TAGS_BT] Poll   : {args.interval}s ({1/args.interval:.0f} Hz)")
    print(f"[LOG_TAGS_BT] Hệ thống: Băng Truyền (Conveyor Belt)")
    print(f"[LOG_TAGS_BT] Tags   : Q0.0(BangTai) | I0.0-I0.2 | M5-M10 | MD50-MD62 | MW70/74")
    print("[LOG_TAGS_BT] Ctrl+C để dừng.\n")

    try:
        while True:
            loop_start = time.time()

            if not client.get_connected():
                try:
                    client.connect(args.target, args.rack, args.slot)
                    print(f"[LOG_TAGS_BT] Connected {args.target}", flush=True)
                except Exception as e:
                    print(f"[LOG_TAGS_BT] Connect fail: {e}  (retry in 2s)", file=sys.stderr, flush=True)
                    time.sleep(2)
                    continue

            row = poll_once(client, poll_seq, {
                'session_id': args.session_id,
                'host_id': args.host_id,
                'scenario_id': args.scenario_id,
                'episode_id': args.episode_id,
                'day': args.day,
            })
            poll_seq += 1
            writer.writerow([row[col] for col in header])
            fh.flush()

            # Status log mỗi 20 poll
            if poll_seq % 20 == 0:
                print(
                    f"[{poll_seq:6d}] "
                    f"mode={'RUN' if row['plc_mode'] else 'STOP'} "
                    f"BangTai={row['BangTai']} "
                    f"lat={row['read_latency_ms']}ms "
                    f"err={row['polling_error']} "
                    f"stop_flag={row['stop_flag_unexpected']} "
                    f"cd_oor={row['cd_timer_out_of_range']} "
                    f"spoof={row['all_sensors_active']} "
                    f"q_bad={row['q_output_unexpected']}",
                    flush=True
                )

            elapsed = time.time() - loop_start
            sleep_time = max(0.0, args.interval - elapsed)
            time.sleep(sleep_time)

    except KeyboardInterrupt:
        print(f"\n[LOG_TAGS_BT] Dừng. Tổng poll: {poll_seq}")
        fh.close()
        sys.exit(0)


if __name__ == '__main__':
    main()
