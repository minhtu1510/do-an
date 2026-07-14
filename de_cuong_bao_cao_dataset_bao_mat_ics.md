# Đề Cương Báo Cáo/Bài Báo: Xây Dựng Dataset Bảo Mật Hệ Thống Điều Khiển Công Nghiệp Dựa Trên Testbed PLC Thực

## 1. Tên Dự Kiến

**Hướng tiếng Việt:**

Xây dựng bộ dữ liệu an ninh mạng cho hệ thống điều khiển công nghiệp sử dụng PLC thực với dữ liệu mạng, dữ liệu quá trình và các kịch bản tấn công logic.

**Hướng tiếng Anh:**

A PLC-based Industrial Control Security Dataset with Network Semantics, Process Logs, and Sparse Logic Attack Scenarios.

## 2. Mục Tiêu Của Báo Cáo/Bài Báo

Bài báo hướng tới xây dựng và mô tả một bộ dữ liệu phục vụ nghiên cứu an toàn, an ninh mạng cho hệ thống điều khiển công nghiệp. Điểm nhấn không chỉ nằm ở việc thu thập lưu lượng mạng, mà còn ở việc đồng bộ lưu lượng công nghiệp với trạng thái quá trình điều khiển từ PLC thực.

Các mục tiêu chính:

- Xây dựng testbed điều khiển công nghiệp có sử dụng PLC thật, không chỉ dựa trên mô phỏng PLCSIM.
- Triển khai các bài toán điều khiển có ý nghĩa thực tế, đại diện cho hệ thống công nghiệp phân tán và diện rộng.
- Thu thập dữ liệu đa nguồn gồm PCAP traffic công nghiệp, log trạng thái PLC/tag và nhãn sự kiện tấn công.
- Phân tích ngữ nghĩa của traffic công nghiệp, đặc biệt là S7/PLC command semantics.
- Xây dựng dataset có nhiều view: network-only, process-only và fusion.
- Thiết kế các kịch bản tấn công phản ánh đặc thù ICS: tấn công không nhất thiết tạo nhiều traffic nhưng có thể làm sai logic điều khiển.
- Cung cấp baseline huấn luyện AI/ML có kiểm soát leakage và đánh giá theo grouped CV, external session/domain-shift stress test.

## 3. Đóng Góp Chính Dự Kiến

Bài báo có thể định vị đóng góp theo hướng dataset và benchmark characterization, không định vị là bài đề xuất mô hình IDS SOTA.

Các đóng góp dự kiến:

- Một testbed PLC thực phục vụ nghiên cứu bảo mật hệ thống điều khiển công nghiệp.
- Một bộ dữ liệu đồng bộ giữa lưu lượng mạng công nghiệp và trạng thái quá trình PLC.
- Một quy trình trích xuất đặc trưng có xét đến ngữ nghĩa giao thức công nghiệp, ví dụ read/write command, vùng nhớ PLC, offset ghi, tỷ lệ write/read.
- Một tập kịch bản tấn công bao gồm cả tấn công mạng truyền thống và tấn công logic quá trình.
- Một bộ benchmark baseline cho các view network-only, process-only và fusion.
- Một phân tích cho thấy sự khác biệt giữa đánh giá trong cùng phân phối và external session/domain-shift stress test.

## 3.1. Đối Chiếu Với Bài Báo S7/HIL Testbed Năm 2025

Nên thêm một phần ngắn trong Related Work hoặc Discussion để đối chiếu với bài báo của Kellerer et al. (2025) về S7/HIL testbed. Mục đích là học cách bài tham chiếu trình bày testbed, threat model, nguồn dữ liệu, thống kê dataset và baseline, không phải sao chép mô hình nhà máy điện hay risk score.

Tóm tắt bài tham chiếu:

```text
Kellerer et al. xây dựng HIL testbed cho hệ thống năng lượng tái tạo: các nhà máy được mô phỏng bằng Python nhưng kết nối với nhiều bộ điều khiển Siemens thật. Dataset gồm packet, process data và syslog; attack chính là sửa đổi dữ liệu S7 bằng MITM; bài báo công bố 10,002,832 packet trong 3 giờ 52 phút và dùng Random Forest làm baseline.
```

Bảng đối chiếu nên đưa vào báo cáo:

| Tiêu chí | Kellerer et al. | Báo cáo hiện tại | Cần bổ sung/nhấn mạnh |
|---|---|---|---|
| Mô hình quá trình | Ba nhà máy năng lượng mô phỏng, nhiều controller Siemens thật | Một PLC thật, băng tải/logic tuần tự mô phỏng hoặc bench-scale | Ghi rõ PLC là vật lý nhưng process chưa hoàn toàn vật lý |
| Threat model | Insider đã vào mạng và biết topology | Insider đã vào mạng và biết topology | Viết rõ attacker đã biết PLC IP/topology và có thể gửi S7/Snap7 command |
| Nguồn dữ liệu | Packet, process data, syslog, log tín hiệu bị sửa | PCAP, PLC tag log, attack event log | Công bố schema, sampling rate, clock offset/sync và định dạng file |
| Attack | Data modification bằng MITM/fuzzing | Nhiều class Day 1-6 | Giữ phạm vi Day 1-6, mô tả repetition/gap/restore; mở rộng khác chỉ future work |
| Thống kê dataset | Packet count, log count, process record, duration, class count | Đã có window count theo day/class/view | Bổ sung phân phối theo day/class/view, nếu có thêm số packet/tag record/thời lượng raw |
| Đánh giá | Windowing, grid search, confusion matrix, feature importance | Grouped CV và external Day 6 holdout | Chốt window size, split, hyperparameter, confusion matrix, PR curve, feature importance |
| Tái lập | Công bố attack script, simulator, dataset | Script nội bộ đã có, gói phát hành chưa hoàn chỉnh | Chuẩn hóa README, config, data dictionary, checksum, version |

Caption gợi ý:

```text
Bảng 2. Đối chiếu cấu trúc bài báo S7/HIL testbed tham chiếu với hướng nghiên cứu hiện tại.
```

Kết luận đối chiếu:

```text
Bài tham chiếu cho thấy cách trình bày thuyết phục đối với dataset ICS đa nguồn: phải rõ threat model, normal operation, nguồn dữ liệu, thống kê dữ liệu, pipeline gán nhãn và protocol đánh giá. Báo cáo hiện tại nên học cấu trúc đó, nhưng không claim nhà máy vật lý hoàn chỉnh hoặc risk score nếu chưa có dữ liệu vật lý và ngưỡng an toàn tương ứng.
```

## 4. Nội Dung 1: Mô Hình Hệ Thống Testbed

### 4.1. Động Cơ Xây Dựng Testbed

Phần này cần làm rõ vì sao cần testbed PLC thực thay vì chỉ dùng mô phỏng.

Các ý chính cần triển khai:

- Nhiều nghiên cứu dùng PLCSIM hoặc môi trường mô phỏng, thuận tiện nhưng chưa phản ánh đầy đủ đặc điểm vận hành của hệ thống thật.
- PLC thực có đặc điểm về chu kỳ quét, độ trễ truyền thông, lỗi kết nối, trạng thái tag, phản ứng đầu ra và hành vi giao thức thực tế.
- Dữ liệu từ hệ thống thật giúp dataset có giá trị hơn cho nghiên cứu IDS công nghiệp.
- Cần viết trung thực rằng phần PLC là phần cứng vật lý, còn process/plant hiện tại là băng tải/logic tuần tự mô phỏng hoặc bench-scale, chưa phải nhà máy vật lý hoàn chỉnh.

### 4.2. Kiến Trúc Tổng Thể Testbed

Mô tả sơ đồ hệ thống gồm các thành phần:

- PLC điều khiển thật.
- Thiết bị/chương trình điều khiển quá trình ở mức băng tải/logic tuần tự mô phỏng hoặc bench-scale.
- Máy giám sát/HMI hoặc controller host.
- Máy attacker sinh kịch bản tấn công.
- Máy thu thập traffic mạng hoặc mirror/SPAN capture.
- Bộ ghi log PLC tag/process state.
- Mạng công nghiệp kết nối các thành phần.

Nên có một hình minh họa:

```text
Attacker Host  ----\
                  Switch/Mirror ---- Capture Host ---- PCAP
Controller/HMI ---/       |
                          |
                         PLC ---- Process logic / bench-scale plant state
                          |
                      Tag Logger ---- PLC tag logs
```

### 4.3. Đặc Điểm PLC Thực Và Hệ Thống Điều Khiển

Phần này cần nhấn mạnh hệ thống không chỉ mô phỏng phần mềm.

Các ý cần viết:

- PLC được sử dụng để điều khiển các logic thực tế.
- PLC có trạng thái tag, vùng nhớ, input/output và chu kỳ cập nhật thực.
- Hệ thống cho phép quan sát đồng thời traffic mạng và biến quá trình.
- Điều này giúp đánh giá các tấn công có tác động logic, không chỉ tấn công gây lưu lượng bất thường.
- Không nên viết như thể hệ thống là một nhà máy vật lý đầy đủ; cách viết đúng là physical PLC + simulated/bench-scale process logic.

### 4.4. Các Bài Toán Điều Khiển Được Triển Khai

Phần này cần mở rộng tầm ý nghĩa của testbed, không chỉ là một bài toán nhỏ.

Các hướng mô tả:

- Điều khiển băng tải hoặc dây chuyền phân loại đơn giản.
- Điều khiển tín hiệu hoặc trạng thái tuần tự tương tự bài toán đèn giao thông đô thị.
- Điều khiển các hệ thống công nghiệp phân tán như trạm bơm, thủy lợi, cấp thoát nước hoặc điều phối thiết bị theo trạng thái cảm biến.
- Các bài toán này có đặc điểm chung: điều khiển theo logic, trạng thái cảm biến, đầu ra chấp hành và tham số thời gian/setpoint.

Thông điệp cần nhấn mạnh:

```text
Testbed không chỉ tạo traffic PLC, mà tạo ra bối cảnh điều khiển có logic vận hành, từ đó có thể nghiên cứu các tấn công làm sai lệch logic quá trình.
```

### 4.5. Vai Trò Của Testbed Trong Nghiên Cứu Bảo Mật ICS

Các ý chính:

- Cho phép tạo dữ liệu benign trong điều kiện vận hành bình thường.
- Cho phép tạo dữ liệu attack có tác động đến PLC/process.
- Cho phép so sánh network-only IDS với process-aware/fusion IDS.
- Cho phép đánh giá tấn công sparse, tức chỉ gửi ít lệnh nhưng gây sai lệch logic.

## 5. Nội Dung 2: Thu Thập, Phân Tích Và Xây Dựng Dataset Cho AI

### 5.1. Tổng Quan Quy Trình Xây Dựng Dataset

Quy trình gồm các bước:

1. Vận hành testbed trong trạng thái bình thường.
2. Thu thập traffic mạng công nghiệp dưới dạng PCAP/PCAPNG.
3. Ghi log trạng thái PLC tag/process theo thời gian.
4. Thực thi các kịch bản tấn công có nhãn thời gian.
5. Đồng bộ PCAP, tag log và attack timeline theo window thời gian.
6. Trích xuất đặc trưng mạng, đặc trưng ngữ nghĩa công nghiệp và đặc trưng quá trình.
7. Tạo các dataset view phục vụ huấn luyện AI.

### 5.2. Các Nguồn Dữ Liệu Được Thu Thập

Dataset gồm nhiều nguồn dữ liệu:

- **Network traffic:** PCAP chứa lưu lượng Ethernet/TCP/S7/industrial protocol.
- **PLC process logs:** log các tag như sensor, actuator, timer, setpoint, trạng thái điều khiển.
- **Attack event logs:** thời điểm bắt đầu/kết thúc tấn công và các event ghi lệnh cụ thể.
- **Metadata:** ngày/session, episode, loại kịch bản, vai trò thiết bị.

### 5.3. Trích Xuất Ngữ Nghĩa Traffic Công Nghiệp

Đây là điểm mới cần nhấn mạnh.

Không chỉ dùng feature mạng phổ thông như packet count, byte count, TCP flags. Dataset còn phân tích ngữ nghĩa công nghiệp:

- Có gói S7/PLC hay không.
- Lệnh read/write/setup/cpu-control.
- Tỷ lệ write/read.
- Ghi vào vùng nhớ nào: DB, Merker, Input, Output.
- Offset/vùng nhớ được ghi.
- Số offset write khác nhau.
- Payload/độ dài payload của lệnh write.
- Tần suất và tính lặp lại của command.

Thông điệp cần nhấn mạnh:

```text
Trong ICS, tấn công nguy hiểm không nhất thiết tạo lưu lượng lớn. Một vài lệnh write đúng địa chỉ PLC có thể làm sai lệch logic điều khiển. Vì vậy dataset cần giữ lại ngữ nghĩa của traffic công nghiệp, không chỉ thống kê mạng chung.
```

### 5.4. Xây Dựng Dữ Liệu Hoạt Động Bình Thường

Dữ liệu benign cần bao phủ nhiều trạng thái vận hành.

Các ý cần viết:

- Hệ thống vận hành theo chu kỳ bình thường.
- Có các trạng thái cảm biến khác nhau.
- Có thay đổi đầu ra điều khiển hợp lệ.
- Có traffic đọc/ghi hợp lệ từ controller/HMI nếu có.
- Có warmup, steady-state và cooldown nếu phù hợp.

Mục tiêu:

```text
Tạo baseline hoạt động bình thường đủ đa dạng để tránh model chỉ học một trạng thái tĩnh.
```

### 5.5. Xây Dựng Dữ Liệu Tấn Công

Các nhóm tấn công nên được mô tả theo bản chất ICS:

#### 5.5.1. Reconnaissance Attacks

Ví dụ:

- Port scan.
- S7/PLC discovery.
- Enumeration tag/PLC memory.

Mục tiêu:

- Phát hiện thiết bị PLC.
- Xác định dịch vụ công nghiệp.
- Thu thập thông tin vùng nhớ/tag.

#### 5.5.2. Availability Attacks

Ví dụ:

- SYN flood.
- S7 flood.
- Protocol fuzzing.

Tác động:

- Tăng tải mạng hoặc PLC communication.
- Gây lỗi, độ trễ hoặc bất thường giao thức.

#### 5.5.3. Process Logic Manipulation Attacks

Đây là nhóm quan trọng nhất cho bài báo.

Ví dụ:

- Ghi trực tiếp vùng nhớ PLC để thay đổi START/STOP.
- Ghi sai trạng thái sensor.
- Thay đổi timer hoặc setpoint.
- Ghi lệnh stealthy với tần suất thấp.

Tác động:

- Dừng/chạy thiết bị sai logic.
- Sensor báo trạng thái giả.
- Timer/setpoint lệch khỏi logic an toàn.
- Quá trình vận hành sai nhưng traffic không tăng mạnh.

Thông điệp cần nhấn mạnh:

```text
Các tấn công logic trong ICS thường sparse: chỉ một hoặc vài lệnh write nhưng có tác động lớn đến quá trình điều khiển.
```

### 5.6. Đề Xuất Kịch Bản Tấn Công Thực Tế Hơn

Để tăng tính thuyết phục, nên thiết kế các kịch bản theo chuỗi hành vi thực tế:

#### Kịch Bản 1: Reconnaissance To Logic Manipulation

```text
Scan PLC -> enumerate memory/tag -> write STOP/START bit -> restore state
```

Ý nghĩa:

- Mô phỏng attacker đi từ thăm dò đến thao túng logic.

#### Kịch Bản 2: Sparse Sensor Spoofing

```text
Ghi trạng thái sensor giả đúng thời điểm quá trình đang chuyển trạng thái
```

Ý nghĩa:

- Traffic ít nhưng làm sai chu trình điều khiển.

#### Kịch Bản 3: Setpoint/Timer Manipulation

```text
Thay đổi timer hoặc setpoint trong giới hạn khó phát hiện, sau đó khôi phục
```

Ý nghĩa:

- Gần với tấn công stealthy trong hệ thống công nghiệp.

#### Kịch Bản 4: Availability Attack During Normal Operation

```text
Flood hoặc fuzz trong khi hệ thống đang chạy bình thường
```

Ý nghĩa:

- Kiểm tra khả năng phát hiện tấn công gây nhiễu truyền thông.

#### Kịch Bản 5: Benign Engineering Operation As Hard Negative

```text
Operator thay đổi timer/setpoint hợp lệ trong trạng thái bảo trì
```

Ý nghĩa:

- Tránh để model học đơn giản rằng mọi write đều là attack.

### 5.6.1. Kịch Bản Thu Thập Dữ Liệu Theo Từng Ngày/Session Hiện Tại

Phần này cần đưa vào báo cáo để người đọc thấy dataset không phải tập dữ liệu trộn ngẫu nhiên, mà được thu theo từng session/ngày với mục đích rõ ràng.

| Ngày/Session | Nhóm dữ liệu | Vai trò trong dataset | Ý nghĩa thực tế |
|---|---|---|---|
| Day 1 | Benign operation | Dữ liệu vận hành bình thường | Mô tả trạng thái nền của hệ thống PLC khi không bị tấn công |
| Day 2 | SCAN, ENUMERATION | Reconnaissance attacks | Mô phỏng giai đoạn attacker dò tìm PLC, dịch vụ công nghiệp và vùng nhớ/tag |
| Day 3 | RWRITE | Direct memory write/process manipulation | Mô phỏng attacker ghi trực tiếp vào vùng nhớ PLC để thay đổi logic điều khiển |
| Day 4 | SETPOINT_ATTACK, SPOOF, STEALTHY | Logic/process attacks | Mô phỏng thay đổi tham số điều khiển, giả trạng thái cảm biến và tấn công thưa khó phát hiện |
| Day 5 | FLOOD, FUZZ | Availability/protocol robustness attacks | Mô phỏng tấn công gây quá tải truyền thông hoặc bất thường giao thức |
| Day 6 | Mixed attacks with changed profile | External stress-test session | Mô phỏng một phiên vận hành mới có cường độ/tần suất khác, dùng để kiểm tra domain shift |

Cách diễn giải trong bài:

```text
Các ngày/session không chỉ dùng để chia train/test, mà đại diện cho các điều kiện vận hành và tấn công khác nhau. Day 6 được giữ như một external session/domain-shift stress test nhằm đánh giá độ khó khi mô hình gặp một phiên thu thập mới.
```

#### Triển Khai Thực Nghiệm Theo `run_day_bangtruyen.sh`

Phần báo cáo nên mô tả rõ kịch bản được thực thi bằng script `run_day_bangtruyen.sh`, không chỉ mô tả attack ở mức ý tưởng. Script này là source-of-truth cho day 1-6 hiện tại; `run_attacker.sh` là script cũ/tham khảo nên không dùng nếu có mâu thuẫn về lịch hoặc class.

**Cách chạy trên từng máy:**

```bash
# Controller/HMI/tag logger
bash run_day_bangtruyen.sh --day <1-6> --role controller --session-id day<N>_bt_s1 --iface <capture_iface>

# Attacker
bash run_day_bangtruyen.sh --day <1-6> --role attacker --session-id day<N>_bt_s1 --iface <capture_iface>
```

Hai role dùng cùng `session_id`; nếu không truyền thì script tự sinh `day<N>_bt_s1`. Controller và attacker đều có thể chạy `tshark` capture với filter mặc định `host <PLC_IP>`. Controller ghi PLC tag log bằng `log_tags_bangtruyen.py`; attacker ghi timeline START/END và attack events cho các lệnh write cụ thể.

**Vai trò controller/background benign:**

- Chạy HMI observe-only đọc `M0..M79`, `Q0`, `I0` với chu kỳ ngẫu nhiên mặc định `1.0-2.0s`.
- Chạy tag logger mặc định mỗi `0.5s`, tạo log `logs/dayN_<session>_<host>_tags.csv`.
- Profile `mixed` mặc định gồm `normal_hmi` `5400s`, `sparse_hmi` `3600s`, `tia_portal_only` `3600s`, `idle_quiet` `1800s`.
- Day 4 tự chuyển sang `day4_mixed`: `normal_hmi`, `tia_portal`, `sparse_hmi`, `tia_portal`, `normal_hmi`, `idle_quiet`, mỗi đoạn mặc định `2400s`.
- Trong đoạn `tia_portal_only`/`tia_portal`, HMI polling tự động bị tắt để operator có thể tạo nền engineering hợp lệ bằng TIA Portal.

**Timing mặc định:**

- Script khai báo duration mặc định cho day 1/2/4/6 là `14400s` và day 3/5 là `10800s`, nhưng với attacker day 2-6 thời lượng thực tế là tổng của warmup, attack episodes, benign gaps và cooldown.
- Warmup `300s`, cooldown cuối ngày `600s`.
- Day 2-5 dùng `ATTACK_REPETITIONS=3` cho mỗi scenario.
- Short attack base `300s`, random khoảng `225-375s`; standard attack base `600s`, random khoảng `450-750s`.
- Benign gap base `300s`, random khoảng `225-375s` giữa các episode.

**Lịch attacker theo script:**

| Day | Lịch chạy | Ý nghĩa |
|---|---|---|
| Day 1 | Benign toàn phiên, attacker idle | Baseline |
| Day 2 | Warmup -> `SCAN_PORT` x3 -> `ENUM_TAGS` x3 -> cooldown | Reconnaissance |
| Day 3 | Warmup -> optional `CPU_STOP` nếu bật -> `RWRITE_BURST` x3 -> cooldown | Direct memory write; CPU_STOP tắt mặc định |
| Day 4 | Warmup -> `SETPOINT_ATTACK` x3 -> `SENSOR_SPOOF` x3 -> `STEALTHY_WRITE` x3 -> cooldown | Logic/process manipulation |
| Day 5 | Warmup -> `S7_FLOOD` x3 -> `SYN_FLOOD` x3 -> `PROTOCOL_FUZZ` x3 -> cooldown | Availability/protocol robustness |
| Day 6 | Warmup -> shuffle `SCAN_PORT`, `ENUM_TAGS`, `RWRITE_BURST`, `SETPOINT_ATTACK`, `SENSOR_SPOOF`, `STEALTHY_WRITE`, `S7_FLOOD`, `SYN_FLOOD`, `PROTOCOL_FUZZ` -> cooldown | External domain-shift stress test |

**Tần suất/hành vi từng attack trong implementation:**

- `SCAN_PORT`: TCP connect port `102`; chuẩn sleep `0.4-1.5s`, day 6 sleep `8-30s`.
- `ENUM_TAGS`: đọc `M0..M79`, `Q0`, `I0`; chuẩn sleep `0.15-0.5s`, day 6 sleep `2-5s`.
- `RWRITE_BURST`: ghi `M5.0` START và `M5.1` STOP, không ghi output `Q`; chuẩn sleep `0.15-0.45s`, day 6 sleep `8-25s`.
- `SETPOINT_ATTACK`: ghi `M50` (`Times_1`), `M54` (`CD1`), `M58` (`CD2`), `M62` (`CD3`); chuẩn sleep `0.4-1.2s`, day 6 sleep `20-60s`.
- `SENSOR_SPOOF`: ghi `M5.4`, `M5.6`, `M6.0` theo pattern giả; chuẩn sleep `0.4-1.5s`, day 6 sleep `15-45s`.
- `STEALTHY_WRITE`: ghi `M5.1=True`, `M5.0=False`; chuẩn sleep `1.5-3.0s`, day 6 sleep `20-60s`.
- `S7_FLOOD`: Snap7 connect/disconnect workers; chuẩn `6` worker, day 6 tối đa `2` worker theo burst thưa.
- `SYN_FLOOD`: TCP connect workers tới port `102`; chuẩn `20` worker, day 6 tối đa `3` worker theo burst thưa.
- `PROTOCOL_FUZZ`: gửi malformed TPKT/S7-like payload dài `12-80` bytes; chuẩn sleep `0.05-0.25s`, day 6 sleep `5-20s`.
- `CPU_STOP`: tắt mặc định, chỉ chạy khi operator bật thủ công; không đưa vào class mặc định nếu dataset hiện tại không có nhãn này.

**Restore sau attack:**

Sau các attack ghi PLC, script reset Merker `M5.*`, `M6.0-M6.2`, khôi phục timer `CD1/CD2/CD3=5000ms`, `Times_1=0` và có thể gửi START pulse trên `M5.0`. Điểm này cần viết để chứng minh dataset có recovery phase và vận hành an toàn sau episode.

### 5.6.2. Tính Thực Tế Của Các Kịch Bản Tấn Công

Cần chứng minh các kịch bản không phải tấn công giả tạo chỉ để làm đẹp kết quả, mà có liên hệ với hành vi tấn công ICS thực tế.

Các điểm cần làm rõ:

- **Reconnaissance là giai đoạn phổ biến trước tấn công ICS:** attacker thường phải dò tìm PLC, port công nghiệp và vùng nhớ/tag trước khi thao túng quá trình.
- **Direct write phản ánh rủi ro thực tế của PLC:** nếu attacker có quyền truy cập hoặc khai thác cấu hình yếu, chỉ một lệnh ghi đúng địa chỉ có thể làm thay đổi trạng thái điều khiển.
- **Sensor spoofing là dạng false data injection:** hệ thống điều khiển ra quyết định dựa trên tín hiệu cảm biến; nếu cảm biến bị giả trạng thái, logic vận hành có thể bị sai.
- **Setpoint/timer manipulation phù hợp với hệ điều khiển công nghiệp:** nhiều quá trình công nghiệp phụ thuộc timer, ngưỡng, setpoint hoặc tham số vận hành.
- **Stealthy attack phản ánh đặc thù ICS:** attacker có thể gửi rất ít lệnh để tránh bị phát hiện bởi IDS dựa trên lưu lượng.
- **Flood/fuzz kiểm tra khả năng chống chịu truyền thông:** hệ thống công nghiệp vẫn cần duy trì vận hành ổn định khi có traffic bất thường hoặc gói lỗi.

Liên hệ với các bài toán điều khiển thực tế:

| Kiểu attack trong dataset | Tương ứng trong hệ thống thực tế |
|---|---|
| Ghi START/STOP bit | Dừng bơm, dừng băng tải, thay đổi pha đèn giao thông, ngắt thiết bị chấp hành |
| Ghi sensor state | Giả mực nước, giả xe/vật thể, giả trạng thái cửa/van/cảm biến vị trí |
| Ghi timer/setpoint | Thay đổi thời gian đèn, chu kỳ bơm, ngưỡng mực nước, tốc độ motor |
| Scan/enumeration | Giai đoạn attacker tìm thiết bị PLC và map vùng nhớ/tag |
| Flood/fuzz | Gây gián đoạn truyền thông PLC-HMI/SCADA hoặc làm thiết bị phản hồi bất thường |

Thông điệp cần nhấn mạnh:

```text
Các kịch bản được thiết kế dựa trên đặc trưng vận hành của ICS: tấn công có thể ít gói tin nhưng tác động trực tiếp đến logic điều khiển và trạng thái vật lý/quá trình.
```

### 5.6.3. Kịch Bản Bổ Sung Đề Xuất Để Tăng Tính Thuyết Phục

Nếu còn thời gian thu thêm dữ liệu, nên bổ sung các kịch bản sau để dataset chắc hơn khi gửi báo:

| Kịch bản bổ sung | Mục đích | Vì sao tăng tính thực tế |
|---|---|---|
| Multi-stage attack | Scan -> enumerate -> write -> restore | Mô phỏng chuỗi hành vi attacker thực tế, không chỉ từng attack rời rạc |
| Benign engineering write | Operator thay đổi timer/setpoint hợp lệ | Tạo hard negative, tránh model học rằng mọi write đều là attack |
| Slow setpoint drift | Thay đổi setpoint từng bước nhỏ | Gần với stealthy manipulation trong ICS |
| Repeated sessions per attack | Mỗi class xuất hiện ở nhiều ngày/session | Giảm phụ thuộc session, tăng giá trị benchmark |
| Recovery phase | Sau attack hệ thống trở về bình thường | Phản ánh quy trình vận hành và khôi phục thực tế |

Các bổ sung này không nhằm làm kết quả ML đẹp hơn bằng mọi giá, mà nhằm làm dataset có tính khoa học và khả năng tái sử dụng cao hơn.

### 5.7. Đồng Bộ Và Gán Nhãn Dataset

Phần này cần giải thích rõ để tránh bị reviewer nghi leakage.

Các ý chính:

- Dữ liệu được chia theo time window cố định.
- Attack timeline dùng để gán nhãn ground truth.
- Attack event log chỉ dùng cho label refinement, không đưa vào feature train.
- Sparse attacks được gán nhãn quanh thời điểm lệnh thực sự xảy ra, tránh label cả một đoạn dài toàn traffic bình thường.
- Metadata như session, episode, host không dùng làm feature ML.

### 5.8. Các View Dataset

Dataset có thể xuất thành ba view:

#### Network-only View

Chỉ gồm đặc trưng từ PCAP/traffic công nghiệp.

Dùng để đánh giá IDS chỉ quan sát mạng.

#### Process-only View

Chỉ gồm đặc trưng từ PLC tag/process log.

Dùng để đánh giá monitor trạng thái quá trình.

#### Fusion View

Ghép network features và process features theo cùng window thời gian.

Dùng để đánh giá mô hình kết hợp mạng và quá trình.

### 5.9. Huấn Luyện AI Và Benchmark Baseline

Phần này không định vị là model SOTA, mà là baseline để chứng minh dataset có thể dùng cho AI.

Các mô hình baseline:

- Logistic Regression.
- Random Forest.
- Rule baseline nếu có.

Các task:

- Binary detection: benign vs attack.
- Multiclass classification: phân loại từng kiểu tấn công.

Các protocol đánh giá:

- Grouped CV theo episode/session để tránh leakage.
- External day/session holdout như domain-shift stress test.
- Threshold tuning cho binary IDS để phân tích trade-off giữa false positive và attack recall.

Thông điệp cần viết:

```text
Phần huấn luyện AI nhằm đặc tả độ khó của dataset và cung cấp benchmark tái lập, không nhằm khẳng định mô hình IDS đạt SOTA.
```

### 5.10. Kết Quả Và Diễn Giải Dự Kiến

Các kết quả nên trình bày:

- Grouped CV binary đạt kết quả tốt, cho thấy dataset hỗ trợ benchmark IDS trong cùng phân phối.
- Multiclass khó hơn binary, đặc biệt với các attack sparse hoặc gần nhau về hành vi.
- External day/session holdout thấp hơn group-CV, cho thấy domain shift thực tế giữa các session/ngày.
- Network-only hiệu quả với attack có dấu hiệu mạng rõ như scan/flood/fuzz.
- Process/fusion cần được phân tích kỹ hơn đối với logic attack.
- Sparse logic attacks là thách thức quan trọng trong ICS vì traffic ít nhưng tác động quá trình lớn.

### 5.11. Điểm Mới Trong Cách Trích Xuất Đặc Trưng Và Mô Hình Hóa Dataset

Phần này cần viết rõ để làm nổi bật đóng góp của dataset, tránh bị hiểu là chỉ dùng PCAP rồi chạy ML thông thường.

#### 5.11.1. Không Chỉ Trích Xuất Feature Mạng Chung

Các feature mạng chung gồm:

- Số packet, số byte, packet rate, byte rate.
- TCP flags, SYN/ACK/RST/FIN.
- Số port đích, IP đích, stream TCP.
- Payload length, entropy, malformed packet.

Các feature này hữu ích với scan/flood/fuzz nhưng chưa đủ cho attack logic PLC.

#### 5.11.2. Trích Xuất Ngữ Nghĩa Giao Thức Công Nghiệp

Dataset bổ sung feature ngữ nghĩa S7/PLC:

- `s7_read_count`: số lệnh đọc.
- `s7_write_count`: số lệnh ghi.
- `s7_write_read_ratio`: tỷ lệ ghi/đọc.
- `s7_db_write_count`: số write vào Data Block.
- `s7_merker_write_count`: số write vào vùng Merker/Memory.
- `s7_output_write_count`: số write vào output.
- `s7_write_unique_offset_count`: số offset ghi khác nhau.
- `s7_write_offset_min/max/range`: phân bố địa chỉ ghi.
- `s7_write_unique_command_ratio`: mức đa dạng của lệnh ghi.
- `s7_write_to_s7_packet_ratio`: tỷ lệ write trong toàn bộ traffic S7.

Ý nghĩa khoa học:

```text
Các feature này giữ lại ý nghĩa điều khiển của traffic PLC. Thay vì chỉ biết có bao nhiêu packet, dataset biết cửa sổ thời gian đó có lệnh write hay không, write vào vùng nào và write tới offset nào.
```

#### 5.11.3. Trích Xuất Đặc Trưng Quá Trình Từ PLC Tag Logs

Từ PLC tag logs, dataset tạo các đặc trưng theo window:

- Giá trị trung bình/min/max/std của sensor, actuator, timer, setpoint.
- Số lần thay đổi tag trong window.
- Tổng số sensor đang active.
- Tổng số control bit đang active.
- Tổng biến thiên timer/setpoint.
- Số lần thay đổi trạng thái quá trình.

Ví dụ feature process:

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
Các feature process giúp quan sát tác động của attack lên trạng thái điều khiển, đặc biệt với các tấn công sparse logic mà network traffic không tăng nhiều.
```

#### 5.11.4. Tách Dataset Thành Nhiều View

Dataset được mô hình hóa thành ba view:

| View | Feature source | Mục đích |
|---|---|---|
| Network-only | PCAP/S7/network semantics | Đánh giá IDS chỉ quan sát mạng |
| Process-only | PLC tag/process logs | Đánh giá monitor trạng thái quá trình |
| Fusion | Network + process | Đánh giá IDS kết hợp hai nguồn |

Điểm này giúp dataset có giá trị benchmark rộng hơn, vì nhà nghiên cứu có thể dùng dataset cho nhiều giả định triển khai khác nhau.

#### 5.11.5. Kiểm Soát Leakage Trong Feature

Các trường không được dùng làm feature ML:

- `label`, `label_network`, `label_system`.
- `window_start_ms`, `window_end_ms`.
- `session_id`, `episode_id`, `host_id`.
- IP/MAC/port identity nếu có thể gây học theo thiết bị.
- Các rule/anomaly hand-crafted quá gần với label.

Thông điệp:

```text
Dataset không chỉ tạo feature để đạt kết quả cao, mà có chính sách tách metadata, label và rule output để hạn chế leakage trong benchmark AI.
```

### 5.12. Xây Dựng Dữ Liệu Hoạt Động Thông Thường

Phần này cần viết rõ hơn vì benign data là nền để IDS học được trạng thái vận hành hợp lệ.

#### 5.12.1. Mục Tiêu Của Benign Data

Dữ liệu benign cần phản ánh trạng thái hoạt động bình thường của hệ thống PLC.

Các trạng thái cần có:

- PLC kết nối ổn định.
- Chu kỳ đọc/ghi hợp lệ giữa controller/HMI và PLC.
- Sensor thay đổi theo logic quá trình.
- Actuator thay đổi hợp lệ theo trạng thái điều khiển.
- Timer/setpoint thay đổi trong ngưỡng bình thường.
- Có các giai đoạn warmup, steady-state và cooldown nếu có thể.

#### 5.12.2. Tránh Benign Quá Đơn Giản

Nếu benign chỉ là trạng thái tĩnh, model có thể học sai:

```text
cứ có thay đổi là attack
```

Vì vậy cần có hard-negative benign:

- Operator thay đổi timer hợp lệ.
- Controller ghi lệnh hợp lệ.
- Sensor/actuator chuyển trạng thái bình thường.
- Hệ thống có traffic đọc/ghi hợp lệ trong quá trình vận hành.

#### 5.12.3. Giá Trị Của Benign Data Trong Dataset

Benign data giúp:

- Xác định baseline traffic công nghiệp.
- Xác định baseline process behavior.
- Đánh giá false positive rate.
- Kiểm tra IDS có phân biệt được write hợp lệ và write tấn công hay không.

### 5.13. Kết Quả Huấn Luyện Hiện Tại Và Cách Diễn Giải

Phần này nên viết thẳng thắn: có điểm tốt và điểm chưa tốt. Đây là cách làm dataset paper đáng tin cậy hơn.

#### 5.13.1. Điểm Tốt

Kết quả grouped CV cho thấy dataset hỗ trợ benchmark AI:

| View | Task | Kết quả điển hình |
|---|---|---|
| Network-only | Binary | Macro-F1 khoảng 0.91-0.92 |
| Fusion | Binary | Macro-F1 khoảng 0.91-0.92 |
| Network-only | Multiclass | Macro-F1 khoảng 0.70 |
| Fusion | Multiclass | Macro-F1 khoảng 0.70 |

Diễn giải:

```text
Kết quả grouped CV tốt cho thấy feature và label có khả năng mô tả các trạng thái benign/attack trong cùng phân phối dữ liệu, đồng thời dataset có thể dùng làm benchmark huấn luyện AI.
```

#### 5.13.2. Điểm Chưa Tốt

Kết quả external day/session holdout còn thấp hơn group-CV:

| Evaluation | Nhận xét |
|---|---|
| Day6 binary holdout | Có phát hiện được attack nhưng recall còn hạn chế |
| Day6 multiclass holdout | Còn yếu, nhiều class bị nhầm sang benign |
| Process-only | Chưa mạnh, cần tiếp tục cải thiện process feature/log coverage |
| Fusion external holdout | Chưa luôn tốt hơn network-only |

Diễn giải:

```text
Kết quả day/session holdout thấp không nên che giấu, mà nên trình bày như bằng chứng về domain shift thực tế trong ICS. Điều này cho thấy đánh giá IDS chỉ bằng random split hoặc grouped CV có thể chưa đủ.
```

#### 5.13.3. Ý Nghĩa Đối Với Dataset Paper

Dataset paper không nhất thiết phải cho kết quả rất cao ở mọi setting. Giá trị của dataset nằm ở chỗ:

- Có dữ liệu thực từ PLC/testbed.
- Có attack đa dạng.
- Có sparse logic attacks.
- Có nhiều view dữ liệu.
- Có protocol đánh giá chống leakage.
- Có external stress test cho thấy bài toán còn khó.

Claim phù hợp:

```text
The baseline results characterize both the usability and the difficulty of the dataset. Strong grouped-CV performance demonstrates learnable patterns, while the external session holdout reveals realistic domain shift in industrial control environments.
```

#### 5.13.4. Cách Trình Bày Kết Quả Train Trong Bài

Nên đưa các bảng sau:

| Bảng | Nội dung |
|---|---|
| Baseline grouped CV | Network/process/fusion, binary/multiclass |
| External session holdout | Day6 stress test |
| Confusion matrix | Xem class nào dễ/khó |
| Feature profile ablation | Safe vs hybrid vs frequency-robust |
| Threshold tuning | Precision/recall/FPR trade-off cho binary IDS |

Không nên claim:

```text
Mô hình generalize tốt sang mọi ngày/session.
Fusion luôn vượt network-only.
Dataset đã giải quyết triệt để bài toán multiclass unseen session.
```

Nên claim:

```text
Dataset cung cấp benchmark thực tế, có thể tái lập và cho thấy rõ các thách thức của IDS trong môi trường PLC/ICS, đặc biệt với attack sparse và domain shift giữa các phiên thu thập.
```

### 5.14. Tóm Tắt Logic Thuyết Phục Reviewer

Chuỗi lập luận nên dùng trong bài:

1. ICS/PLC cần dataset thực hơn mô phỏng vì attack tác động đến logic quá trình.
2. Testbed sử dụng PLC thật và bài toán điều khiển có trạng thái vận hành.
3. Dataset thu đồng thời PCAP, PLC tag logs và attack timeline.
4. Feature extraction giữ lại ngữ nghĩa công nghiệp, không chỉ traffic statistics.
5. Dataset có benign, reconnaissance, availability và logic manipulation attacks.
6. Benchmark được tách thành network-only, process-only và fusion.
7. Grouped CV cho thấy dataset học được và có thể dùng huấn luyện AI.
8. External session holdout cho thấy domain shift thực tế, là giá trị của dataset chứ không phải lỗi cần che giấu.
9. Dataset mở ra hướng nghiên cứu tiếp theo về robust IDS, domain adaptation và process-aware detection.

## 6. Những Điểm Cần Làm Nổi Bật Khi Viết Bài

### 6.1. Không Chỉ Là PLCSIM

Câu nhấn mạnh:

```text
Unlike purely simulated PLC datasets, our dataset is collected from a testbed involving a real PLC and realistic control logic, enabling synchronized observation of network traffic and process states.
```

### 6.2. Không Chỉ Là Network Traffic

Câu nhấn mạnh:

```text
The dataset preserves industrial protocol semantics, including PLC read/write operations, memory areas, offsets, and process-state changes, which are essential for studying sparse logic attacks.
```

### 6.3. Dataset Phơi Ra Domain Shift Thật

Câu nhấn mạnh:

```text
The external session holdout is reported as a domain-shift stress test, showing that high grouped-CV performance does not necessarily imply robust cross-session generalization.
```

### 6.4. Attack Sparse Là Điểm Khác Biệt Của ICS

Câu nhấn mạnh:

```text
In industrial control systems, a single write command to a critical PLC memory address can cause unsafe process behavior, making volume-based detection insufficient.
```

## 7. Cấu Trúc Bài Báo Dự Kiến

### Abstract

Tóm tắt vấn đề thiếu dataset ICS có PLC thực, giới thiệu testbed, dữ liệu network/process/fusion, attack scenarios và baseline evaluation.

### 1. Introduction

- Bối cảnh bảo mật ICS/PLC.
- Hạn chế của dataset hiện có hoặc dataset mô phỏng.
- Nhu cầu dataset có PLC thật, process log và attack logic.
- Tóm tắt đóng góp.

### 2. Related Work

- Dataset ICS phổ biến như SWaT, WADI, HAI, BATADAL nếu phù hợp.
- IDS cho ICS network traffic.
- Process-aware IDS và fusion IDS.
- Khoảng trống: PLC real testbed, sparse logic attacks, semantic feature extraction.

### 3. Testbed Design

- Kiến trúc phần cứng/phần mềm.
- PLC, controller, attacker, capture host, tag logger.
- Các bài toán điều khiển triển khai.
- Cơ chế thu thập PCAP và PLC tags.

### 4. Dataset Construction

- Nguồn dữ liệu.
- Benign operation.
- Attack scenarios.
- Labeling/refinement.
- Feature extraction.
- Dataset views.

### 5. Benchmark Evaluation

- Task binary/multiclass.
- Network/process/fusion views.
- Leakage control.
- Grouped CV.
- External session holdout.
- Metrics.

### 6. Results And Discussion

- Kết quả group-CV.
- Kết quả day/session holdout.
- Phân tích sparse logic attacks.
- Phân tích network-only vs process-only vs fusion.
- Bài học về domain shift.

### 7. Limitations

- Một số class còn ít episode.
- Fusion/process chưa luôn vượt network-only.
- External holdout multiclass còn khó.
- Cần mở rộng thêm session và hard-negative benign engineering operations.

### 8. Conclusion

- Tóm tắt dataset, testbed, attack scenarios và baseline.
- Nhấn mạnh giá trị cho nghiên cứu AI/IDS trong ICS.
- Hướng mở rộng.

## 8. Bảng/Hình Nên Có

### Hình

- Sơ đồ kiến trúc testbed.
- Pipeline xây dựng dataset.
- Quy trình gán nhãn và tạo dataset views.

### Bảng

- Thành phần testbed.
- Danh sách PLC tags/process variables.
- Danh sách attack scenarios.
- Thống kê dataset theo day/class/view.
- Benchmark results theo group-CV.
- External session holdout results.
- Ablation network/process/fusion.

## 9. Thông Điệp Đưa Cho Thầy Duyệt

Bài báo sẽ tập trung vào hai trục chính:

1. **Testbed PLC thực cho bảo mật ICS:** Không chỉ dùng mô phỏng PLCSIM, mà xây dựng hệ thống điều khiển thật với PLC, có logic vận hành và trạng thái quá trình quan sát được.
2. **Dataset đa nguồn cho huấn luyện AI:** Không chỉ thu PCAP, mà phân tích ngữ nghĩa traffic công nghiệp, đồng bộ với PLC tag logs, thiết kế dữ liệu benign và attack, tạo các view network/process/fusion và benchmark leakage-aware.

Định vị bài báo:

```text
Dataset/benchmark paper for industrial control security, not a pure IDS model paper.
```

Claim phù hợp:

```text
The proposed dataset enables reproducible evaluation of network-only, process-only, and fusion-based IDS baselines under both grouped evaluation and external session domain-shift stress testing.
```
