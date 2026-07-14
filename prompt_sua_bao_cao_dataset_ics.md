# Prompt Sửa/Giãn Báo Cáo Dataset Bảo Mật Hệ Thống Điều Khiển Công Nghiệp

Bạn là một chuyên gia viết bài báo khoa học về an toàn, an ninh mạng hệ thống điều khiển công nghiệp, PLC, ICS/SCADA và dataset cho AI/IDS. Hãy viết lại và mở rộng báo cáo/bài báo theo hướng **dataset/benchmark paper**, không phải bài claim mô hình IDS SOTA.

## Mục Tiêu Viết Lại

Hãy viết một báo cáo/bài báo hoàn chỉnh, học thuật, rõ ràng, có thể gửi thầy duyệt để tiến tới viết bài báo. Bài tập trung vào hai trục chính:

1. **Mô hình hệ thống testbed:** Làm nổi bật việc sử dụng PLC thật, không chỉ mô phỏng PLCSIM. Hệ thống triển khai các bài toán điều khiển thực tế, có thể liên hệ với điều khiển đèn giao thông đô thị, hệ thống thủy lợi, trạm bơm, hệ thống cấp thoát nước, băng tải/công nghiệp phân tán.
2. **Xây dựng dataset cho AI trong bảo mật ICS:** Không chỉ thu PCAP, mà còn phân tích ngữ nghĩa traffic công nghiệp, đồng bộ với PLC tag logs, xây dựng dữ liệu benign, dữ liệu tấn công và các view network-only/process-only/fusion để huấn luyện AI.

## Định Vị Bài Viết

Hãy định vị bài là:

```text
Dataset/benchmark paper for industrial control security, not a pure IDS model paper.
```

Không claim mô hình IDS đạt SOTA. Phần train/ML chỉ dùng để chứng minh dataset có thể huấn luyện AI, có benchmark tái lập, có độ khó thực tế và có domain shift.

## Tên Bài Gợi Ý

Tiếng Việt:

```text
Xây dựng bộ dữ liệu an ninh mạng cho hệ thống điều khiển công nghiệp sử dụng PLC thực với dữ liệu mạng, dữ liệu quá trình và các kịch bản tấn công logic
```

Tiếng Anh:

```text
A PLC-based Industrial Control Security Dataset with Network Semantics, Process Logs, and Sparse Logic Attack Scenarios
```

## Cấu Trúc Cần Viết

Hãy viết theo cấu trúc sau:

1. Tóm tắt/Abstract
2. Giới thiệu/Introduction
3. Công trình liên quan/Related Work
4. Mô hình testbed PLC thực
5. Quy trình thu thập và xây dựng dataset
6. Kịch bản tấn công và dữ liệu hoạt động bình thường
7. Trích xuất đặc trưng và mô hình hóa dataset
8. Huấn luyện AI và benchmark baseline
9. Kết quả thực nghiệm và phân tích
10. Hạn chế và hướng phát triển
11. Kết luận

## Bổ Sung Vào Related Work: Đối Chiếu Với Bài Báo S7 Testbed Năm 2025

Trong phần **Related Work** hoặc cuối phần **Dataset Construction**, hãy thêm một mục đối chiếu ngắn với bài báo S7/HIL testbed của Kellerer et al. (2025). Không cần sao chép mô hình nhà máy điện hay risk score của bài đó; chỉ học cách họ mô tả testbed, threat model, normal operation, thống kê dữ liệu, pipeline gán nhãn và protocol đánh giá.

Nội dung tham chiếu cần diễn giải:

```text
Kellerer et al. xây dựng một HIL testbed cho hệ thống năng lượng tái tạo, trong đó các nhà máy được mô phỏng bằng Python nhưng kết nối với nhiều bộ điều khiển Siemens thật. Tác giả thu packet, process data và syslog; triển khai tấn công sửa đổi dữ liệu S7 bằng MITM; công bố 10,002,832 packet trong 3 giờ 52 phút và dùng Random Forest làm baseline. Cấu trúc này là tham chiếu gần với hướng bộ điều khiển thật + quá trình mô phỏng + dữ liệu đa nguồn.
```

Bảng đối chiếu nên đưa vào báo cáo:

| Tiêu chí | Kellerer et al. | Báo cáo hiện tại | Cần bổ sung/nhấn mạnh |
|---|---|---|---|
| Mô hình quá trình | Ba nhà máy năng lượng mô phỏng, nhiều controller Siemens thật. | Một PLC Siemens thật, bài toán băng tải/logic tuần tự ở mức mô phỏng hoặc bench-scale. | Ghi rõ PLC là vật lý, nhưng process/plant chưa phải nhà máy vật lý hoàn chỉnh. |
| Threat model | Insider đã vào mạng và biết topology. | Insider đã vào mạng và biết topology. | Viết rõ giả định attacker: đã truy cập mạng ICS, biết PLC IP/topology, có thể gửi S7/Snap7 command. |
| Nguồn dữ liệu | Packet, process data, syslog, log tín hiệu bị sửa. | PCAP, PLC tag log, attack event log. | Công bố schema, sampling rate, clock synchronization/offset, định dạng file và mapping nguồn dữ liệu. |
| Attack | Một nhóm data-modification được fuzz để tăng biến thiên. | Nhiều class Day 1-6: recon, write, setpoint, spoof, stealthy, flood, fuzz. | Giữ phạm vi Day 1-6; mô tả episode/repetition/gap/restore; mở rộng khác chỉ để future work. |
| Thống kê dataset | Số packet, log, process record, thời lượng và class count cụ thể. | Đã có window count theo day/class/view. | Bổ sung phân phối theo day, class, view; nếu có thể thêm số packet, số tag record và thời lượng raw. |
| Đánh giá | Windowing, grid search, confusion matrix, feature importance. | Grouped CV và external Day 6 holdout. | Chốt window size, split strategy, hyperparameters/search, confusion matrix, PR curve và feature importance. |
| Tái lập | Công bố attack script, simulator và dataset. | Script nội bộ đã có, gói phát hành chưa hoàn chỉnh. | Chuẩn hóa README, config, data dictionary, checksum, version và hướng dẫn reproduce. |

Caption gợi ý:

```text
Bảng 2. Đối chiếu cấu trúc bài báo S7/HIL testbed tham chiếu với hướng nghiên cứu hiện tại.
```

Kết luận đối chiếu cần viết:

```text
The closest reference is an S7 HIL dataset where real Siemens controllers are coupled with simulated processes and multi-source telemetry. Our work follows the same dataset-oriented philosophy but differs in scope: it focuses on one physical PLC testbed with six collection sessions, S7 semantic feature extraction, synchronized tag logs, and leakage-aware benchmark views. We do not claim a fully physical plant or a risk-score model; instead, we emphasize transparent scenario design, dataset distribution, and reproducible IDS baselines.
```

Các yêu cầu bổ sung rút ra từ đối chiếu:

- Mô tả threat model thành một subsection riêng.
- Mô tả normal operation và controller background traffic rõ như một phần của dataset, không chỉ nói benign là không có attack.
- Công bố rõ schema các file chính: PCAP/PCAPNG, tag CSV, timeline CSV, attack event CSV, network/process/fusion CSV.
- Ghi sampling rate của tag logger (`0.5s` mặc định), window size train hiện tại (`2s`) và cách đồng bộ theo timestamp/window.
- Nếu chưa đo clock offset chính xác, viết là các máy cần đồng bộ thời gian và ghi đây là hạn chế/cần chuẩn hóa trong bản phát hành dataset.
- Kèm các artifact tái lập: `testbed.conf` mẫu, lệnh chạy day 1-6, README, data dictionary, checksum và version dataset.

## 1. Nội Dung Cần Nhấn Mạnh Về Testbed

Hãy viết rõ:

- Testbed sử dụng PLC thật, không chỉ mô phỏng PLCSIM.
- PLC thật giúp tạo dữ liệu sát thực hơn vì có chu kỳ quét, độ trễ truyền thông, trạng thái tag, input/output và hành vi giao thức thực tế.
- Hệ thống có controller/HMI, attacker host, capture host hoặc mirror/SPAN, PLC tag logger và mạng công nghiệp.
- Testbed triển khai logic điều khiển có ý nghĩa thực tế, không chỉ tạo traffic giả.
- Cần viết trung thực rằng PLC là phần cứng vật lý, nhưng process/plant hiện tại là băng tải/logic tuần tự mô phỏng hoặc bench-scale, chưa claim là một nhà máy vật lý hoàn chỉnh.
- Có thể liên hệ với các bài toán điều khiển công nghiệp diện rộng và phân tán:
  - điều khiển đèn giao thông đô thị;
  - điều khiển bơm/trạm thủy lợi;
  - cấp thoát nước;
  - băng tải/dây chuyền sản xuất;
  - hệ thống có sensor, actuator, timer, setpoint.

Câu cần đưa vào:

```text
Unlike purely simulated PLC datasets, the proposed dataset is collected from a testbed involving a real PLC and realistic sequential control logic, enabling synchronized observation of network traffic and process-state tags. The process model is currently implemented as a simulated or bench-scale conveyor/control scenario rather than a fully physical industrial plant.
```

## 2. Kiến Trúc Testbed Cần Mô Tả

Mô tả bằng lời và đề xuất hình:

```text
Attacker Host  ----\
                  Switch/Mirror ---- Capture Host ---- PCAP
Controller/HMI ---/       |
                          |
                         PLC ---- Process logic / bench-scale plant state
                          |
                      Tag Logger ---- PLC tag logs
```

Các thành phần:

- PLC thật.
- Controller/HMI hoặc máy điều khiển.
- Attacker host.
- Capture host hoặc mirror/SPAN.
- PLC tag logger.
- Mạng Ethernet công nghiệp.
- Chương trình điều khiển băng tải/logic tuần tự; process/plant chưa cần claim là hệ vật lý hoàn chỉnh.

## 3. Phân Phối Dataset Hiện Tại Cần Đưa Vào Báo Cáo

Hãy tạo một mục **Dataset Distribution**. Trình bày phân phối theo day/session, class và view.

### 3.1. Network-only/Fusion Distribution

Network-only và Fusion hiện có phân phối nhãn giống nhau theo day:

| Day | BENIGN | ENUMERATION | SCAN | RWRITE | SPOOF | SETPOINT_ATTACK | STEALTHY | FLOOD | FUZZ | Total |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Day 1 | 7348 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 7348 |
| Day 2 | 8766 | 945 | 447 | 0 | 0 | 0 | 0 | 0 | 0 | 10158 |
| Day 3 | 11755 | 0 | 0 | 876 | 0 | 0 | 0 | 0 | 0 | 12631 |
| Day 4 | 5662 | 0 | 0 | 0 | 953 | 837 | 6 | 0 | 0 | 7458 |
| Day 5 | 9795 | 0 | 0 | 0 | 0 | 0 | 0 | 914 | 418 | 11127 |
| Day 6 | 5703 | 472 | 465 | 138 | 60 | 38 | 2 | 322 | 124 | 7324 |

Tổng quan cần diễn giải:

- Day 1 là benign-only session.
- Day 2 tập trung reconnaissance: SCAN, ENUMERATION.
- Day 3 tập trung RWRITE.
- Day 4 tập trung logic attacks: SPOOF, SETPOINT_ATTACK, STEALTHY.
- Day 5 tập trung availability/protocol attacks: FLOOD, FUZZ.
- Day 6 là mixed session, dùng như external domain-shift stress test.

### 3.2. Process-only Distribution

Process-only có phân phối khác vì phụ thuộc độ phủ của PLC tag logger:

| Day | BENIGN | SPOOF | STEALTHY | FUZZ | ENUMERATION | SCAN | Total |
|---|---:|---:|---:|---:|---:|---:|---:|
| Day 1 | 1799 | 0 | 0 | 0 | 0 | 0 | 1799 |
| Day 2 | 1800 | 0 | 0 | 0 | 0 | 0 | 1800 |
| Day 3 | 1800 | 0 | 0 | 0 | 0 | 0 | 1800 |
| Day 4 | 1737 | 57 | 6 | 0 | 0 | 0 | 1800 |
| Day 5 | 1793 | 0 | 0 | 7 | 0 | 0 | 1800 |
| Day 6 | 995 | 0 | 2 | 124 | 428 | 251 | 1800 |

Diễn giải cần viết:

- Process-only view phản ánh các window có PLC tag samples.
- Một số attack network-level như FLOOD hoặc RWRITE có thể không hiện rõ trong process-only view nếu không tạo biến động process trực tiếp hoặc tag logger không phủ đúng window.
- Đây là hạn chế cần ghi rõ và là động lực để cải thiện tag logging/feature engineering.

### 3.3. Hình Phân Phối Cần Có

Đề xuất tạo các hình sau:

- **Figure: Class distribution by day for network/fusion view** - stacked bar chart.
- **Figure: Class distribution by day for process-only view** - stacked bar chart.
- **Figure: Total benign vs attack windows per view** - grouped bar chart.
- **Figure: Attack category distribution** - RECON vs AVAILABILITY vs LOGIC_MANIPULATION.

Nếu viết bằng báo cáo, hãy đặt caption:

```text
Figure X. Label distribution across collection sessions. Day 6 contains mixed attack profiles and is used as an external domain-shift stress test.
```

## 4. Kịch Bản Từng Ngày Và Tính Thực Tế

Hãy viết một mục **Collection Sessions and Attack Scenarios**.

Phạm vi bắt buộc của báo cáo chính: **chỉ có Day 1 đến Day 6**. Không tự thêm Day 7, Day 8 hoặc các kịch bản mở rộng như HMI/OPC/DNS/kill-chain nếu không có số liệu dataset tương ứng trong prompt này. Nếu cần nhắc tới mở rộng, chỉ được đưa vào phần future work, không đưa vào bảng dataset, kịch bản chính hoặc kết quả train.

| Day/Session | Nhóm dữ liệu | Mục đích | Tính thực tế |
|---|---|---|---|
| Day 1 | BENIGN | Thu dữ liệu vận hành bình thường | Mô phỏng hệ thống PLC hoạt động ổn định, có sensor/actuator/timer |
| Day 2 | SCAN, ENUMERATION | Reconnaissance | Attacker dò tìm PLC, dịch vụ S7 và vùng nhớ/tag |
| Day 3 | RWRITE | Direct write | Attacker ghi trực tiếp vùng nhớ PLC để thay đổi START/STOP hoặc logic điều khiển |
| Day 4 | SETPOINT_ATTACK, SPOOF, STEALTHY | Logic manipulation | Thay đổi timer/setpoint, giả sensor, gửi lệnh thưa để tránh phát hiện |
| Day 5 | FLOOD, FUZZ | Availability/protocol attacks | Tăng tải truyền thông, gây nhiễu giao thức hoặc phản hồi bất thường |
| Day 6 | Mixed attacks | External domain-shift stress test | Mô phỏng session mới có profile/tần suất khác so với train |

Diễn giải:

```text
Các ngày/session đại diện cho các giai đoạn hoặc nhóm hành vi thường gặp trong tấn công ICS: thăm dò, khai thác logic điều khiển, gây gián đoạn truyền thông và kiểm tra độ lệch phân phối giữa các phiên thu thập.
```

### 4.0. Kịch Bản Cụ Thể Cần Viết Trong Báo Cáo

Không chỉ liệt kê tên class. Hãy viết thành mô tả kịch bản vận hành/tấn công rõ ràng cho từng ngày như sau:

| Day | Kịch bản cần viết rõ | Nhãn/class tương ứng | Ý nghĩa trong dataset |
|---|---|---|---|
| Day 1 | Controller/HMI vận hành bình thường, tag logger ghi trạng thái PLC, attacker chỉ idle/capture, không phát sinh attack. | BENIGN | Baseline để học traffic và trạng thái process bình thường. |
| Day 2 | Sau warmup, attacker thực hiện TCP connect scan tới S7 port `102`, sau đó enumerate vùng nhớ/tag PLC bằng Snap7; giữa các episode có benign gap và cuối ngày có cooldown. | SCAN, ENUMERATION | Giai đoạn reconnaissance: tìm PLC, dịch vụ công nghiệp và map vùng nhớ/tag. |
| Day 3 | Sau warmup, attacker thực hiện `RWRITE_BURST`: ghi Merker control bit `M5.0` START và `M5.1` STOP để can thiệp logic điều khiển; sau mỗi episode script restore PLC. `CPU_STOP` mặc định không chạy. | RWRITE | Direct memory write/process manipulation, mô phỏng rủi ro khi attacker ghi đúng địa chỉ PLC. |
| Day 4 | Attacker lần lượt thay đổi timer/setpoint (`M50`, `M54`, `M58`, `M62`), giả sensor (`M5.4`, `M5.6`, `M6.0`) và gửi low-rate STOP write (`M5.1=True`, `M5.0=False`). | SETPOINT_ATTACK, SPOOF, STEALTHY | Logic/process manipulation: sai tham số, false data injection và sparse attack khó phát hiện bằng volume traffic. |
| Day 5 | Attacker tạo S7 connection flood, TCP connect/SYN-style flood tới port `102`, và gửi malformed TPKT/S7-like payload. | FLOOD, FUZZ | Availability/protocol robustness: tăng tải truyền thông, gây bất thường giao thức hoặc stress PLC communication. |
| Day 6 | Attacker trộn lại các scenario của Day 2-5 theo thứ tự ngẫu nhiên, giảm rate, thay đổi duration và gap rộng hơn so với train sessions. | Mixed: SCAN, ENUMERATION, RWRITE, SETPOINT_ATTACK, SPOOF, STEALTHY, FLOOD, FUZZ | External domain-shift stress test, không dùng để claim generalization hoàn hảo. |

Đoạn văn nên viết trong báo cáo:

```text
The dataset consists of six collection sessions. Day 1 records benign operation only. Days 2-5 isolate major ICS attack families, including reconnaissance, direct PLC memory write, process logic manipulation, and availability/protocol attacks. Day 6 mixes the same attack families with randomized order, lower rates, and wider benign gaps, and is therefore treated as an external domain-shift stress-test session rather than a standard training session.
```

### 4.1. Kịch Bản Triển Khai Thực Tế Theo `run_day_bangtruyen.sh`

Khi viết báo cáo, hãy mô tả rõ rằng kịch bản day 1-6 được thực thi bằng script `run_day_bangtruyen.sh`. Đây là source-of-truth cho lịch chạy hiện tại; `run_attacker.sh` chỉ là script cũ/tham khảo, không dùng để mô tả số liệu day 1-6 nếu có mâu thuẫn. Không dùng `run_day_bangtruyen_ext.sh` cho báo cáo chính vì script đó là hướng mở rộng ngoài phạm vi Day 1-6.

#### Cách chạy trên từng máy

Mỗi ngày/session được chạy đồng thời theo hai vai trò chính:

```bash
# Máy controller/HMI/tag logger
bash run_day_bangtruyen.sh --day <1-6> --role controller --session-id day<N>_bt_s1 --iface <capture_iface>

# Máy attacker
bash run_day_bangtruyen.sh --day <1-6> --role attacker --session-id day<N>_bt_s1 --iface <capture_iface>
```

Nếu không truyền `--session-id`, script tự sinh `day<N>_bt_s1`. Hai máy phải dùng cùng `session_id` để đồng bộ PCAP, timeline và tag logs. PLC target lấy từ `testbed.conf` hoặc CLI, trong dataset hiện tại là `192.168.210.211`, rack `0`, slot `1`.

Các vai trò cần mô tả:

- **Controller host:** chạy capture, PLC tag logger và HMI polling hợp lệ.
- **Attacker host:** chạy capture, sinh nhãn timeline START/END và thực thi attack episodes.
- **Capture/mirror:** PCAP được ghi bằng `tshark` với filter mặc định `host <PLC_IP>`, file theo vai trò như `captures/dayN/<session>_controller.pcapng` và `captures/dayN/<session>_attacker.pcapng`, sau đó có thể merge thành `merged_all.pcapng`.
- **Tag logger:** chạy `log_tags_bangtruyen.py`, mặc định lấy mẫu mỗi `0.5s`, ghi `logs/dayN_<session>_<host>_tags.csv`.
- **Attack event logger:** với các attack ghi PLC, script ghi thêm event chi tiết gồm signal, vùng nhớ, offset, giá trị cũ/mới; file này chỉ dùng refine label, không dùng làm feature ML.

#### Benign/controller background traffic

Controller không chỉ đứng yên. Script tạo nền vận hành hợp lệ bằng:

- HMI observe-only đọc vùng Merker `M0..M79`, output `Q0` và input `I0` với chu kỳ ngẫu nhiên mặc định `1.0-2.0s`.
- PLC tag logger lấy mẫu tag/process mặc định mỗi `0.5s`.
- `mixed` controller profile mặc định gồm `normal_hmi` `5400s`, `sparse_hmi` `3600s`, `tia_portal_only` `3600s`, `idle_quiet` `1800s`.
- Day 4 tự dùng `day4_mixed`: `normal_hmi`, `tia_portal`, `sparse_hmi`, `tia_portal`, `normal_hmi`, `idle_quiet`, mỗi đoạn mặc định `2400s`.
- Trong các đoạn `tia_portal_only`/`tia_portal`, script tắt HMI polling tự động và yêu cầu operator mở TIA Portal để tạo nền engineering hợp lệ.
- HMI legitimate writes bị tắt mặc định (`HMI_ENABLE_LEGIT_WRITES=0`), nên nếu muốn hard-negative benign write phải ghi rõ là tùy chọn/bổ sung.

#### Timing mặc định của collection

Các hằng số mặc định trong script:

- Script khai báo duration mặc định cho day 1/2/4/6 là `14400s` và day 3/5 là `10800s`, nhưng các giá trị này chỉ có hiệu lực trực tiếp với benign/fallback runtime; với attacker day 2-6, thời lượng thực tế là tổng của warmup, attack episodes, benign gaps và cooldown.
- Warmup: `300s`.
- Cooldown cuối ngày: `600s`.
- Benign gap giữa các attack episode: base `300s`, được random trong khoảng `0.75x-1.25x`.
- Attack repetitions: `3` lần cho mỗi scenario ở day 2-5.
- Short attack duration base: `300s`, random khoảng `225-375s`.
- Standard attack duration base: `600s`, random khoảng `450-750s`.

#### Lịch attacker theo ngày trong script

| Day | Lịch thực thi trong `run_day_bangtruyen.sh` | Ghi chú khi viết báo cáo |
|---|---|---|
| Day 1 | Benign toàn phiên, attacker idle | Baseline vận hành bình thường |
| Day 2 | Warmup -> `SCAN_PORT` x3 -> `ENUM_TAGS` x3 -> cooldown | Reconnaissance; `SCAN_PORT` map thành SCAN, `ENUM_TAGS` map thành ENUMERATION |
| Day 3 | Warmup -> optional `CPU_STOP` nếu bật thủ công -> `RWRITE_BURST` x3 -> cooldown | Mặc định CPU_STOP bị tắt để an toàn; RWRITE ghi Merker START/STOP, không ghi output Q |
| Day 4 | Warmup -> `SETPOINT_ATTACK` x3 -> `SENSOR_SPOOF` x3 -> `STEALTHY_WRITE` x3 -> cooldown | Logic/process manipulation |
| Day 5 | Warmup -> `S7_FLOOD` x3 -> `SYN_FLOOD` x3 -> `PROTOCOL_FUZZ` x3 -> cooldown | Availability/protocol attacks; hai flood class có thể gộp thành FLOOD |
| Day 6 | Warmup -> shuffle một lần các scenario `SCAN_PORT`, `ENUM_TAGS`, `RWRITE_BURST`, `SETPOINT_ATTACK`, `SENSOR_SPOOF`, `STEALTHY_WRITE`, `S7_FLOOD`, `SYN_FLOOD`, `PROTOCOL_FUZZ` -> cooldown | External domain-shift stress test: thứ tự ngẫu nhiên, duration/gap/rate khác day 2-5 |

#### Tần suất và hành vi attack cần mô tả

Mô tả các attack theo đúng implementation hiện tại:

- `SCAN_PORT`: TCP connect tới port S7 `102`; profile chuẩn sleep ngẫu nhiên `0.4-1.5s`, day 6 sleep `8-30s`.
- `ENUM_TAGS`: Snap7 đọc Merker `M0..M79`, output `Q0`, input `I0`; profile chuẩn sleep `0.15-0.5s`, day 6 sleep `2-5s`.
- `RWRITE_BURST`: ghi Merker control bit `M5.0` START và `M5.1` STOP, không ghi `PA/Q`; profile chuẩn sleep `0.15-0.45s`, pulse START khoảng `0.12s`, day 6 sleep `8-25s`, pulse khoảng `0.25s`.
- `SETPOINT_ATTACK`: ghi DINT vào Merker offsets `M50` (`Times_1`), `M54` (`CD1`), `M58` (`CD2`), `M62` (`CD3`); giá trị CD chọn trong `[100, 250, 45000, 60000, 90000]`, profile chuẩn sleep `0.4-1.2s`, day 6 sleep `20-60s`.
- `SENSOR_SPOOF`: ghi các bit sensor `M5.4` (`Vat_1`), `M5.6` (`Vat_2`), `M6.0` (`Vat_3`) theo các pattern giả; profile chuẩn sleep `0.4-1.5s`, day 6 sleep `15-45s`.
- `STEALTHY_WRITE`: ghi low-rate STOP bằng `M5.1=True` và `M5.0=False`; profile chuẩn sleep `1.5-3.0s`, day 6 sleep `20-60s`.
- `S7_FLOOD`: nhiều worker Snap7 connect/disconnect; chuẩn `6` worker, day 6 giảm còn tối đa `2` worker và chạy theo burst ngắn có pause `8-25s`.
- `SYN_FLOOD`: nhiều TCP connect worker vào port `102`; chuẩn `20` worker, day 6 giảm còn tối đa `3` worker và chạy theo burst có pause `8-20s`.
- `PROTOCOL_FUZZ`: gửi payload TPKT/S7-like malformed dài `12-80` bytes tới port `102`; chuẩn sleep `0.05-0.25s`, day 6 sleep `5-20s`.
- `CPU_STOP`: bị disable mặc định; chỉ chạy khi operator bật `--enable-cpu-control` hoặc `ENABLE_CPU_CONTROL_ATTACK=1`, vì vậy không claim đây là class mặc định nếu dataset hiện tại không có.

#### Restore và an toàn vận hành

Sau các attack làm thay đổi trạng thái PLC (`RWRITE_BURST`, `SETPOINT_ATTACK`, `SENSOR_SPOOF`, `STEALTHY_WRITE`, `CPU_STOP` nếu bật), script gọi `restore_plc` để đưa hệ thống về trạng thái an toàn:

- reset các bit Merker `M5.*` và `M6.0-M6.2`;
- khôi phục timer `CD1/CD2/CD3` về `5000ms`, `Times_1` về `0`;
- gửi START pulse ngắn trên `M5.0` nếu cấu hình cho phép.

Thông điệp cần viết:

```text
The collection script embeds warmup, randomized attack durations, benign gaps, controller background traffic, and post-attack restoration. This design avoids collecting isolated synthetic attack bursts and instead records attacks under realistic PLC communication and recovery conditions.
```

## 5. Điểm Mới Trong Cách Trích Xuất Đặc Trưng

Hãy viết rõ rằng điểm mới không chỉ là thu PCAP, mà là **giữ lại ngữ nghĩa công nghiệp**.

### 5.1. Feature Mạng Chung

Bao gồm:

- packet count, byte count, packet rate, byte rate;
- TCP flags;
- port/IP diversity;
- payload length, entropy;
- malformed packet;
- flow timing/IAT.

### 5.2. Feature Ngữ Nghĩa S7/PLC

Bao gồm:

- `s7_read_count`
- `s7_write_count`
- `s7_write_read_ratio`
- `s7_db_write_count`
- `s7_merker_write_count`
- `s7_output_write_count`
- `s7_write_unique_offset_count`
- `s7_write_offset_min/max/range`
- `s7_write_unique_command_ratio`
- `s7_write_to_s7_packet_ratio`

Viết ý này:

```text
Instead of treating industrial traffic as generic TCP traffic, the proposed pipeline extracts protocol-aware semantics such as PLC read/write operations, memory areas, and write offsets. These features are critical for sparse logic attacks where only one or a few write commands may alter the process behavior.
```

### 5.3. Feature Process Từ PLC Tag Logs

Bao gồm:

- sensor/actuator/timer mean, min, max, std theo window;
- tag changed flags;
- process change count;
- sensor active sum;
- control active sum;
- timer abs delta sum.

Ví dụ:

```text
proc__Vat_1_mean
proc__BangTai_max
proc__CD1_mean
proc__process_change_count_sum
proc__sensor_active_sum_max
proc__timer_abs_delta_sum_max
```

Ý nghĩa:

```text
Process features allow the dataset to capture the physical/logical effect of attacks, complementing network-level observations.
```

### 5.4. Leakage Control

Viết rõ các cột không đưa vào ML:

- label;
- timestamp/window time;
- session/episode/host IDs;
- identity columns;
- hand-crafted rule/anomaly outputs quá gần label.

Thông điệp:

```text
The dataset construction separates audit metadata from ML-safe features to reduce leakage and support reproducible benchmarking.
```

## 6. Xây Dựng Dữ Liệu Hoạt Động Bình Thường

Hãy thêm mục **Benign Operation Modeling**.

Nội dung cần viết:

- Benign data không chỉ là không có attack, mà phải phản ánh vận hành bình thường.
- Hệ thống có chu kỳ đọc/ghi hợp lệ, sensor thay đổi, actuator thay đổi, timer/setpoint trong ngưỡng bình thường.
- Benign data giúp đo false positive rate.
- Cần hard-negative benign như operator đổi timer/setpoint hợp lệ để tránh model học rằng mọi write đều là attack.

Câu cần có:

```text
Benign data is designed to represent normal control behavior rather than a static idle state, enabling IDS models to distinguish legitimate process changes from malicious manipulation.
```

## 7. Kết Quả Train Hiện Tại Cần Đưa Vào Báo Cáo

Hãy viết mục **Baseline AI Evaluation**. Nhấn mạnh đây là baseline characterization, không phải SOTA model.

### 7.1. Protocol Đánh Giá

Các protocol:

- Grouped CV theo episode/session để tránh leakage.
- Day6 holdout là external domain-shift stress test.
- Binary detection là task chính.
- Multiclass attack attribution là task phụ và khó hơn.
- Network-only, process-only, fusion views.
- Hybrid feature profile.

### 7.2. Bảng Kết Quả Chính

Sử dụng bảng sau trong báo cáo:

| View | Validation | Task | Best model | Macro-F1 | Balanced accuracy | PR-AUC | FPR/hour |
|---|---|---|---|---:|---:|---:|---:|
| Network-only | Grouped CV | Binary | Random Forest | 0.919 | 0.897 | 0.942 | 10.658 |
| Fusion | Grouped CV | Binary | Random Forest | 0.919 | 0.897 | 0.947 | 11.355 |
| Network-only | Grouped CV | Multiclass | Random Forest | 0.701 | 0.732 | 0.734 | 5.151 |
| Fusion | Grouped CV | Multiclass | Random Forest | 0.705 | 0.732 | 0.736 | 3.964 |
| Network-only | Day6 holdout | Binary | Logistic Regression | 0.710 | 0.671 | 0.617 | 8.206 |
| Fusion | Day6 holdout | Binary | Logistic Regression | 0.614 | 0.599 | 0.509 | 7.891 |
| Network-only | Day6 holdout | Multiclass | Logistic Regression | 0.224 | 0.258 | 0.289 | 11.047 |
| Fusion | Day6 holdout | Multiclass | Logistic Regression | 0.224 | 0.257 | 0.287 | 9.469 |

### 7.3. Cách Diễn Giải Điểm Tốt

Hãy viết:

```text
Grouped CV results show strong binary detection performance and moderate multiclass performance, indicating that the dataset contains learnable patterns and can support reproducible AI-based IDS benchmarking.
```

Điểm tốt:

- Binary grouped CV đạt khoảng 0.91-0.92 macro-F1.
- Multiclass grouped CV đạt khoảng 0.70 macro-F1.
- Hybrid features giúp kết hợp volume-based indicators và PLC semantic features.
- Network-only và fusion đều có thể dùng làm benchmark.

### 7.4. Cách Diễn Giải Điểm Chưa Tốt

Hãy viết thẳng thắn:

```text
The external Day 6 holdout reveals a significant cross-session domain shift. Binary detection remains feasible but attack recall is limited, while multiclass attack attribution under this setting remains challenging.
```

Điểm chưa tốt:

- Day6 binary holdout thấp hơn group-CV.
- Day6 multiclass thấp.
- Process-only yếu.
- Fusion chưa luôn tốt hơn network-only trong external holdout.
- Một số attack class ít mẫu, đặc biệt STEALTHY.

Diễn giải đúng:

```text
These results should not be interpreted as a failure of the dataset. Instead, they highlight realistic challenges of ICS IDS evaluation, where cross-session changes in attack cadence, process state, and traffic background can significantly affect model performance.
```

## 8. Hình Ảnh Cần Đưa Vào Báo Cáo

Hãy đề xuất và mô tả các hình sau.

### 8.1. Hình Phân Phối Dataset

- Class distribution by day for network/fusion view.
- Class distribution by day for process-only view.
- Benign vs attack window count per view.
- Attack category distribution: RECON, AVAILABILITY, LOGIC_MANIPULATION.

Caption gợi ý:

```text
Figure X. Dataset label distribution across collection sessions. Day 6 contains mixed attack profiles and is used as an external domain-shift stress test.
```

### 8.2. Hình Pipeline Dataset

Gồm:

```text
PLC Testbed -> PCAP + PLC Tag Logs + Attack Events -> Feature Extraction -> Labeling -> Network/Process/Fusion Views -> AI Baselines
```

### 8.3. Hình Kết Quả Train

- Bar chart macro-F1 theo view/task/model.
- Confusion matrix cho binary day6 holdout.
- Confusion matrix cho multiclass day6 holdout.
- PR curve cho binary detection.
- Feature importance của best model.

### 8.4. Về Hình Loss Curve

Lưu ý quan trọng: hiện baseline chính là Logistic Regression và Random Forest. Hai mô hình này trong pipeline hiện tại **không tạo loss curve epoch-by-epoch như neural network**.

Không được bịa loss curve cho RF/LR.

Nếu báo cáo bắt buộc cần hình loss, có hai cách hợp lệ:

1. Thêm một baseline neural network/MLP và vẽ training loss/validation loss theo epoch.
2. Nếu không thêm neural network, thay hình loss bằng:
   - PR curve;
   - confusion matrix;
   - learning curve theo số mẫu train;
   - validation curve theo threshold;
   - feature importance.

Câu nên viết trong báo cáo:

```text
Since the baseline models are Logistic Regression and Random Forest, epoch-wise loss curves are not reported. Instead, we provide precision-recall curves, confusion matrices, and feature-importance analysis. A neural baseline can be added in future work to analyze training loss dynamics.
```

Nếu muốn thêm MLP baseline, hãy viết thêm một đoạn:

```text
To visualize optimization behavior, an optional MLP baseline can be trained and its training/validation loss curves can be reported. This result is used only as an auxiliary visualization, while the main benchmark remains based on leakage-aware RF/LR baselines.
```

## 9. Cách Claim Cho Đúng

Không claim:

```text
Fusion always outperforms network-only.
The model generalizes well to all unseen days.
The proposed IDS achieves SOTA performance.
```

Nên claim:

```text
The proposed dataset enables reproducible evaluation of network-only, process-only, and fusion-based IDS baselines under both grouped evaluation and external session domain-shift stress testing.
```

Và:

```text
Strong grouped-CV performance demonstrates learnable attack patterns, while the external Day 6 holdout exposes realistic cross-session domain shift, particularly for sparse and low-rate logic attacks.
```

## 10. Văn Phong Mong Muốn

Viết theo phong cách học thuật, rõ ràng, thuyết phục, trung thực về điểm mạnh và hạn chế. Không viết quá quảng cáo. Dùng các thuật ngữ:

- Industrial Control Systems;
- PLC;
- S7 protocol semantics;
- process-aware IDS;
- network/process/fusion views;
- sparse logic attacks;
- leakage-aware evaluation;
- grouped cross-validation;
- external domain-shift stress test.

## 11. Đầu Ra Mong Muốn

Hãy tạo một báo cáo hoàn chỉnh bằng tiếng Việt theo cấu trúc bài báo, gồm:

- Abstract tiếng Việt và tiếng Anh ngắn.
- Mục tiêu và đóng góp.
- Mô tả testbed.
- Bảng phân phối dataset.
- Mô tả kịch bản từng ngày.
- Mô tả feature extraction và điểm mới.
- Mô tả benign data.
- Kết quả train và phân tích tốt/chưa tốt.
- Danh sách hình/bảng cần đưa vào.
- Hạn chế và hướng phát triển.

Không bịa kết quả ngoài các số liệu được cung cấp trong prompt này. Nếu cần nói về loss curve, phải ghi rõ RF/LR không có loss curve epoch-wise và đề xuất thêm MLP nếu muốn hình loss.
