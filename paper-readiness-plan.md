# Paper Readiness Plan

## Goal
Trong 2 tuần tới, chốt được testbed, dataset, kịch bản tấn công và kết quả ML đủ chắc để bắt đầu viết bài báo về IDS cho mạng công nghiệp S7/PLC.

## Claim Chính Cần Làm Rõ
- Testbed không chỉ dựa trên PLC mô phỏng/PLCSIM; hệ thống có PLC thật, HMI/controller thật, máy attacker/controller tách vai trò và capture traffic thực qua TShark/Npcap.
- Trên testbed triển khai bài toán điều khiển thật, có tính đại diện cho công nghiệp diện rộng: điều khiển đèn giao thông đô thị, băng chuyền công nghiệp, và có thể mở rộng sang thủy lợi/phân tán.
- Dataset không chỉ là traffic IT flow L3/L4; pipeline bóc tách ngữ nghĩa giao thức công nghiệp S7comm và trạng thái quá trình vật lý.
- Kết quả AI phải báo cáo trên bản ML-safe: loại bỏ metadata, rule flags, timestamp, host/session IDs và process-rule leakage khỏi input chính.

## Testbed Cần Mô Tả Trong Bài
- Physical layer: PLC Siemens S7-1500/S7-1200 thật, switch công nghiệp/lab switch, máy controller/HMI, máy attacker, máy capture nếu có mirror/SPAN.
- Control problems: traffic light control, conveyor/process control; nhấn mạnh đây là logic điều khiển có actuator/sensor/tag thật, không chỉ sinh packet giả.
- Roles: controller tạo HMI polling, tag logger, TIA Portal/engineering background; attacker chạy scan, enum, write manipulation, setpoint, spoof, DoS/fuzz.
- Data sources: PCAP network traffic, timeline labels, PLC tag/process logs, attack event logs.
- Safety: CPU STOP disabled by default; write attacks dùng Merker/control tags thay vì ghi trực tiếp output vật lý khi chưa được phép.

## Dataset Novelty Cần Chứng Minh
- Semantic S7 features: `s7_read_count`, `s7_write_count`, `s7_cpu_control_count`, memory area DB/M/I/Q, item count, write payload size, repeated command, sequential offset score.
- Process-aware features: PLC tag snapshots/window aggregation từ `log_tags_bangtruyen.py`, gồm state, timer, sensor, output raw values.
- Multi-view dataset: network-only, process-only, fusion, leakage-ablation; dùng `merge_dataset.py` để tách view rõ ràng.
- Labeling: timeline START/END theo scenario, window labeling theo overlap, warmup/gap/cooldown để có benign xen kẽ attack.
- Leakage control: `train_ml.py` drop rule/anomaly outputs và metadata trong safe ML, rule baseline chỉ dùng để so sánh ablation.

## Kịch Bản Thu Dữ Liệu Cần Chạy
- Day 1 Baseline: benign only, controller mixed background gồm normal HMI, sparse HMI, TIA Portal thật, idle quiet; attacker idle capture.
- Day 2 Reconnaissance: TCP/102 scan, S7 tag enumeration, xen kẽ warmup/gap/cooldown.
- Day 3 Integrity impact: RWRITE Merker control bits, optional CPU control nếu lab cho phép.
- Day 4 Process manipulation: setpoint/timer attack, sensor spoof, stealthy low-rate STOP write.
- Day 5 Availability: S7 connection flood, SYN flood, protocol fuzz.
- Day 6 Robustness/OOD: trộn các attack trên với rate thấp hơn, thứ tự random, gap rộng hơn để kiểm tra model không chỉ học lịch cố định.
- Phạm vi báo cáo/dataset chính dừng ở Day 6. Không thêm Day 7/Day 8 vào kịch bản, bảng phân phối hoặc kết quả nếu chưa có dataset và benchmark tương ứng.

## 2 Tuần Tới
- [ ] Chạy pilot 10-15 phút Day 1 mixed có capture thật -> Verify: có PCAP, timeline, tags CSV; `q_bad` gần 0, `cd_oor` giải thích được.
- [ ] Chạy pilot mỗi attack 1-2 repetition -> Verify: timeline có START/END đủ, attack_events có write records cho write-style attacks.
- [ ] Extract network features từ PCAP -> Verify: CSV có S7 semantic columns và label ban đầu chỉ audit, chưa dùng làm label chính.
- [ ] Merge bằng `merge_dataset.py` -> Verify: network/process/fusion CSV có phân phối label hợp lý và transition rows bị drop.
- [ ] Train bằng `train_ml.py` trên safe views -> Verify: có leakage report, confusion matrix, macro-F1, MCC, PR-AUC, FPR/hour.
- [ ] So sánh network-only vs process-only vs fusion vs leakage-ablation -> Verify: kết quả chứng minh lợi ích semantic/process nhưng không overclaim.
- [ ] Ghi lại bảng thông số testbed, timeline từng day, số mẫu/label -> Verify: đủ đưa vào phần Experiment Setup của bài.

## Không Được Overclaim
- Không nói model phát hiện mọi ICS attack; chỉ nói trong phạm vi Siemens S7/PLC lab với các scenario đã thu.
- Không dùng kết quả leakage-ablation làm kết quả chính.
- Không gọi segment TIA Portal là engineering traffic nếu lúc thu không mở TIA Portal thật.
- Không dùng dataset thu khi `capture disabled` làm kết quả network IDS.
