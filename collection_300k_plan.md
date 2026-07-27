# Kế Hoạch Thu Lại Dataset Khoảng 300k Window

Mục tiêu: thu lại Day 1-6 lâu hơn và đa dạng hơn, nhắm khoảng 300k window nếu dùng window không overlap `2s`.

## Profile Mới

Script `run_day_bangtruyen.sh` có thêm profile:

```bash
--collection-profile extended_300k
```

Profile này giữ nguyên phạm vi Day 1-6, không thêm Day 7/Day 8.

## Ước Tính Window

Ước tính theo `window=2s`, chưa tính sai lệch do random duration/gap và thời gian restore:

| Day | Nội dung chính | Window ước tính |
|---|---|---:|
| Day 1 | Benign baseline dài hơn | ~36k |
| Day 2 | SCAN/ENUMERATION x12 mỗi loại | ~50k |
| Day 3 | RWRITE x20 | ~52k |
| Day 4 | SETPOINT/SPOOF/STEALTHY x12 mỗi loại | ~79k |
| Day 5 | S7_FLOOD/SYN_FLOOD/FUZZ x12 mỗi loại | ~58k |
| Day 6 | Mixed attacks x3 cycle, rate/gap khác | ~35k-50k |
| Tổng | Day 1-6 | ~300k-330k |

## Cách Chạy

Chạy controller và attacker cùng `session-id`, cùng `collection-profile`.

Controller:

```bash
bash run_day_bangtruyen.sh --day <1-6> --role controller \
  --session-id day<N>_bt_s1_ext300k \
  --iface <capture_iface> \
  --collection-profile extended_300k
```

Attacker:

```bash
bash run_day_bangtruyen.sh --day <1-6> --role attacker \
  --session-id day<N>_bt_s1_ext300k \
  --iface <capture_iface> \
  --collection-profile extended_300k
```

## Profile Này Thay Đổi Gì

- Tăng warmup/cooldown/gap để có thêm benign xen kẽ attack.
- Tăng attack repetitions theo ngày.
- Day 6 chạy 3 cycle mixed thay vì 1 cycle.
- Attack rate được làm đa dạng hơn, không chỉ kéo dài cùng một pattern.
- `SETPOINT_ATTACK` dùng thêm nhiều giá trị timer/setpoint.
- `SENSOR_SPOOF` dùng thêm nhiều pattern sensor.
- Flood/fuzz chạy theo burst thưa hơn để tránh dữ liệu chỉ toàn volume spike.
- Controller background kéo dài hơn để tag log phủ đủ phiên dài.
- Controller tự lặp/cắt segment background theo duration của từng day để giảm nguy cơ hụt tag log trong phiên dài.

## Lưu Ý Khi Báo Cáo

- Không báo cáo profile này như kết quả cuối nếu chưa chạy đủ và regenerate dataset.
- Sau khi thu lại, cần merge PCAP, extract feature, merge network/process/fusion và train lại.
- Giữ Day 6 làm external stress test nếu muốn kiểm tra phiên mới; không trộn Day 6 vào train chính khi báo cáo holdout.
- Nếu muốn thêm hard-negative benign write, chỉ bật `HMI_ENABLE_LEGIT_WRITES=1` sau khi kiểm tra an toàn PLC/testbed.

## Regenerate Sau Khi Thu Lại

Nếu dùng session id dạng `day<N>_bt_s1_ext300k`, chạy pipeline với session template tương ứng:

```bash
python rerun_frequency_robust_pipeline.py \
  --session-template "{day}_bt_s1_ext300k" \
  --suffix ext300k \
  --feature-profile hybrid \
  --binary-threshold-mode fbeta \
  --binary-threshold-beta 2
```

Pipeline sẽ tìm tag log theo dạng:

```text
logs/dayN_dayN_bt_s1_ext300k_controller_host_tags.csv
```

và timeline theo dạng:

```text
labels/dayN_dayN_bt_s1_ext300k_attacker_host_timeline.csv
```

Nếu đã tạo file `_timeline_refined.csv`, pipeline sẽ ưu tiên dùng file refined.
