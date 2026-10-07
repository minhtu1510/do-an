# Day 7 - Quyết định nghiên cứu và khả năng phát triển case-study

Ngày lập: 2026-09-25

Phạm vi: đọc, kiểm tra và thiết kế từ artifact hiện có. Không sửa Word, không sửa PCAP/dataset/model, không huấn luyện, không chạy lại kịch bản tấn công và không kết nối PLC.

## Kết luận quyết định

**NEEDS ADDITIONAL EVIDENCE** nếu mục tiêu là nâng `CONCEALED_STOP_ATTACK` thành một thực nghiệm có đối chứng về phát hiện bất nhất trạng thái tiến trình với precision/recall/latency.

Bằng chứng hiện có đủ để trình bày Day 7 như một **case-study có số liệu và đối chiếu PCAP**, nhưng chưa đủ để biến thành thực nghiệm phát hiện không nhất quán đa nguồn theo nghĩa khoa học chặt chẽ. Các số nội bộ của module được ghi trong timeline và có thể truy vết về mã nguồn; các chữ ký mạng chính có thể đối chiếu lại từ PCAP. Tuy nhiên repo hiện không có log Day 7 độc lập của PLC process tags, không có log WinCC/HMI thực tế, không có export LAD/TIA Portal để kiểm chứng đầy đủ quan hệ logic, và không có timestamp từng lần STOP/read-back. Vì vậy chưa thể đo duration bất nhất, precision/recall phát hiện theo chu kỳ STOP, hoặc trạng thái HMI thực sự hiển thị theo thời gian.

Nếu không nâng thành thực nghiệm đối chứng, Day 7 có thể tích hợp ngay ở mức **case-study an ninh nâng cao**: SMB recon trên HMI, kill-chain foothold/pivot, và concealed-stop partial success trên kênh OPC UA Anonymous.

## 1. Ma trận nguồn bằng chứng Day 7

| Nguồn | Đường dẫn | Nội dung xác minh được | Timestamp/đồng hồ | Độc lập với client kiểm thử? | Độ đầy đủ |
|---|---|---|---|---|---|
| Timeline Day 7 | `labels/day7_final_timeline.csv` | START/END của `SMB_RECON_ENUM`, `KILL_CHAIN`, `CONCEALED_STOP_ATTACK`; số `probes=140`, `stops=9`, `conceal_attempts=13604`, `readback_still_true=183`, `readback_reverted=843` | epoch ms từ attacker/module | Không; do module/tầng label ghi | Đầy đủ cho số tổng hợp, thiếu timestamp từng STOP/read-back |
| PCAP Day 7 | `data_opc/day7/ot-capture-ot1788454936.zip` | 7 segment PCAP, tổng 10.750.927 byte; đối chiếu được traffic SMB/S7/OPC UA trong interval | timestamp frame trong PCAP | Có đối với lưu lượng trên dây, nhưng không phải ground truth process | Đủ cho quan sát mạng, chưa ghép thành dataset |
| Script concealed stop | `attacks_ext/concealed_stop_attack.py` | Logic probe, 5 writer OPC UA, sampler read-back 0,05s, loop S7 STOP/START dựa trên CD1, tổng hợp counter vào END note | `time.time()`/async loop, không ghi từng sample | Không; chính client kiểm thử tạo counter | Đủ để hiểu cách sinh số; thiếu log chi tiết từng sự kiện |
| Script SMB recon | `attacks_ext/smb_enum.py` | Gửi SMB2 negotiate, probe share và pipe; ghi `probes` vào END note | `time.time()` | Không | Đủ để hiểu `probes=140` |
| Script kill chain | `attacks_ext/kill_chain.py` | S7 foothold, đọc DB, TCP connect scan HMI, ghi open ports vào END note | `time.time()` | Không | Đủ để hiểu stage; thiếu log stdout run thật |
| Mapping tag OPC UA | `config/opcua_tags.yaml` | `BangTai` node `ns=3;s="BangTai"`, mô tả RUN/STOP conveyor, `writable: true`; CD1/CD2/CD3 read-only | cấu hình tĩnh | Có, nhưng là cấu hình ứng dụng | Đủ cho mapping OPC UA, không phải LAD |
| Mapping PLC băng tải | `log_tags_bangtruyen.py` | Q0.0 `BangTai`, M5.0 `START`, M5.1 `STOP`, CD1 MD54, các rule mô tả bất thường như `sensor_vs_belt_conflict` | nếu chạy logger thì timestamp local | Có thể độc lập nếu có output, nhưng repo không có Day 7 output | Script có, log Day 7 thiếu |
| Log HMI/WinCC | `log_hmi_events.py` chỉ là script | Có thể ghi mốc thủ công START/STOP/TIA, nhưng không thấy file output Day 7 | local wall clock khi operator bấm | Có thể độc lập nếu được chạy | Thiếu artifact |
| LAD/TIA/WinCC project export | không thấy trong repo | Không xác minh được quan hệ logic trực tiếp từ LAD | không áp dụng | không áp dụng | Thiếu |
| Tài liệu case-study | `BAO_CAO_DAY7.md`, `CHUONG_CASE_STUDY_DAY7.md` | Diễn giải số liệu, kết luận case-study, các con số PCAP đã được ghi nhận | tài liệu tổng hợp | Không phải nguồn gốc | Có ích để đối chiếu, không thay artifact gốc |

## 2. Kiểm chứng lại số liệu `CONCEALED_STOP_ATTACK`

### 2.1 Timeline và counter nội bộ

`labels/day7_final_timeline.csv` ghi:

| Sự kiện | START UTC | END UTC | Thời lượng từ timestamp | Note |
|---|---|---|---:|---|
| `SMB_RECON_ENUM` | 2026-09-03T17:02:22.821Z | 2026-09-03T17:02:58.881Z | 36,060 s | `probes=140` |
| `KILL_CHAIN` | 2026-09-03T17:05:02.808Z | 2026-09-03T17:05:10.089Z | 7,281 s | 5 port HMI mở |
| `CONCEALED_STOP_ATTACK` | 2026-09-03T17:05:16.542Z | 2026-09-03T17:08:24.815Z | 188,273 s | `dur=180s`; `stops=9`; `conceal_attempts=13604`; `conceal_ok=13604`; `conceal_failed=0`; `readback_still_true=183`; `readback_reverted=843` |

Lưu ý: `dur=180s` là tham số chạy của module. Thời lượng START-END trong timeline là 188,273 giây vì bao gồm probe, setup/teardown và ghi nhãn. Do đó nên viết: "module được cấu hình 180 giây; interval ghi nhãn bao phủ khoảng 188,3 giây".

Từ mã nguồn:

- `conceal_attempts`: tăng tại `attacks_ext/concealed_stop_attack.py`, dòng 130-135, mỗi lần worker gửi `BangTai=True`;
- `conceal_ok/failed`: phản hồi thành công/lỗi của thao tác write OPC UA, dòng 133-139;
- `readback_still_true` và `readback_reverted`: sampler đọc lại định kỳ 0,05s, dòng 144-160;
- `stops`: số lần loop S7 ghi M5.1 STOP, dòng 211-220 và ghi vào note dòng 281-289.

Tỷ lệ "dính" được tính là `183 / (183 + 843) = 183 / 1026 = 17,84%`. Đây là tỷ lệ tại các thời điểm sampler của chính client kiểm thử đọc lại `BangTai`, không phải tỷ lệ thời gian HMI hiển thị RUNNING và không phải xác nhận độc lập về trạng thái vật lý.

### 2.2 Đối chiếu PCAP read-only

PCAP trong ZIP gồm 7 segment. Đối chiếu bằng `tshark` read-only từ các segment cho các interval trong timeline:

| Cửa sổ | Bộ lọc kiểm tra | Kết quả đếm lại | So với tài liệu cũ |
|---|---|---:|---|
| SMB recon | `smb2 && ip.dst == 192.168.210.31 && tcp.port == 445` trong interval recon | 65 gói | Khớp `CHUONG_CASE_STUDY_DAY7.md` |
| Kill-chain pivot | SYN tới HMI `.31` trong interval kill-chain | 15 gói | Khớp tài liệu |
| Kill-chain foothold | `s7comm && ip.addr == 192.168.210.211` trong interval kill-chain | 10 gói hai chiều | Tài liệu ghi 5 gói S7comm; nếu tính một chiều/request thì khác bộ lọc |
| Concealed STOP | `opcua && ip.dst == 192.168.210.211` trong interval concealed | 16.678 gói | Gần số 16.680; sai khác 2 gói do ranh giới/bộ lọc |
| Concealed STOP | `s7comm && ip.dst == 192.168.210.211` trong interval concealed | 162 gói | Khớp tài liệu |
| Concealed STOP | `s7comm && ip.addr == 192.168.210.211` trong interval concealed | 324 gói hai chiều | Gấp đôi số một chiều |
| Concealed STOP | `tcp.port == 102 && ip.addr == 192.168.210.211` trong interval concealed | 3.752 gói TCP/102 hai chiều | Tài liệu ghi 3.702 TLS/S7CommPlus; chưa tái tạo đúng bằng dissector `tls` |

Kết luận: các chữ ký PCAP chính của SMB recon, pivot SYN, OPC UA burst và S7 STOP được xác minh lại ở mức lưu lượng. Riêng số "3.702 gói TLS/S7CommPlus" trong tài liệu cũ nên được viết lại thận trọng hơn: "khoảng 3,7 nghìn gói TCP/102 của kênh WinCC/S7CommPlus-like vẫn hiện diện", trừ khi có bộ lọc/dữ liệu giải mã chính xác hơn.

### 2.3 Phân biệt các loại bằng chứng

| Đại lượng | Nguồn hiện có | Ý nghĩa | Không được diễn giải thành |
|---|---|---|---|
| Yêu cầu ghi `BangTai=True` | counter `conceal_attempts` trong timeline và traffic OPC UA trong PCAP | Client đã gửi nhiều yêu cầu write; server không báo lỗi ở API | HMI chắc chắn hiển thị RUNNING từng lần |
| Phản hồi server | `conceal_ok=13604`, `conceal_failed=0` | API write không ném exception | Giá trị đã tồn tại trong PLC đến cuối chu kỳ scan |
| Read-back | `readback_still_true=183`, `readback_reverted=843` | Client kiểm thử đọc lại thấy True/False tại các mẫu 0,05s | Nguồn độc lập với attacker |
| Trạng thái PLC | suy luận từ loop S7 STOP/START, `stops=9`; PCAP S7comm | Module đã gửi STOP/START và traffic S7 hiện diện | Bằng chứng trực tiếp về state vật lý nếu thiếu tag log/video |
| Trạng thái HMI | mô tả trong tài liệu; không thấy log output | Có nhận định case-study | Timeline hiển thị HMI định lượng |

## 3. Khả năng đồng bộ nhiều nguồn dữ liệu

Có thể dựng lại timeline thô của ba interval chính từ `labels/day7_final_timeline.csv` và PCAP. Không thể dựng timeline từng chu kỳ STOP trong 9 chu kỳ vì repo hiện chỉ có tổng `stops=9`, không có timestamp từng STOP, từng START, từng write hoặc từng read-back.

### Trả lời các câu hỏi trọng tâm

**Có thể xác định trạng thái tiến trình PLC bằng nguồn khác ngoài giá trị `BangTai` do chính client kiểm thử đọc lại không?**

Chưa đủ bằng chứng. Repo có `log_tags_bangtruyen.py` mô tả cách log Q/M/MD và các rule bất thường, nhưng không thấy CSV tag log Day 7. PCAP cho thấy S7/OPC UA traffic nhưng không tự nó chứng minh trạng thái vật lý nếu không giải mã đầy đủ payload và không có mapping/ground truth độc lập.

**Có thể xác định HMI thực sự đã hiển thị trạng thái gì không?**

Chưa đủ bằng chứng định lượng. Có mô tả trong `BAO_CAO_DAY7.md`/`CHUONG_CASE_STUDY_DAY7.md`, nhưng không thấy log HMI/WinCC hoặc ảnh/screenshot timestamped trong repo hiện tại. Script `log_hmi_events.py` tồn tại nhưng không thấy output Day 7.

**Có đủ timestamp để đo thời lượng sai lệch không?**

Không. `readback_still_true=183` và `readback_reverted=843` là tổng số mẫu, nhưng không có timestamp từng mẫu. Vì vậy chỉ tính được tỷ lệ mẫu read-back thấy True, không đo được duration liên tục của sai lệch hay detection latency.

## 4. Phân tích hồi cứu có đối chứng: khả năng và giới hạn

Ba nhóm trạng thái mong muốn:

- A. Vận hành bình thường và chuyển trạng thái hợp lệ;
- B. Giai đoạn STOP/START trong Day 7;
- C. Giai đoạn có write `BangTai=True` từ client kiểm thử.

Với dữ liệu hiện có, nhóm C có thể xác định từ timeline và PCAP. Nhóm B chỉ xác định ở mức tổng số STOP và interval tấn công, không có timestamp từng chu kỳ. Nhóm A thiếu đối chứng Day 7 tương ứng có tag/process log; PCAP ngoài interval tấn công có thể làm nền mạng, nhưng không đủ để xác định process consistency.

Quan hệ logic có căn cứ từ file hiện có:

- `BangTai` là Q0.0, "1 = băng tải chạy, 0 = dừng" trong `log_tags_bangtruyen.py`;
- `START` là M5.0, `STOP` là M5.1;
- `CD1` là MD54, timer vật 1;
- `config/opcua_tags.yaml` ánh xạ `BangTai`, CD1/CD2/CD3 sang node OPC UA;
- `log_tags_bangtruyen.py` có các rule như `sensor_vs_belt_conflict`, `belt_stopped_unexpectedly`, nhưng đây là rule trong logger, chưa có output Day 7.

Không thấy export LAD/TIA nên không nên tự suy diễn thêm quan hệ logic ngoài mapping/script hiện có.

## 5. Khả năng sử dụng IDS OPC UA đã huấn luyện

Về kỹ thuật, PCAP Day 7 có traffic OPC UA tới PLC `.211` trên TCP/4840 và có thể đưa qua bộ trích xuất 61 đặc trưng nếu giải nén/merge segment thành PCAP đầu vào. Bộ trích xuất không cần nhãn hay attacker IP để tính feature nếu chỉ chạy inference; `--attacker-ip` chỉ phục vụ activity-aware labeling. Feature schema có thể khớp `model_opcua/features.json` vì cùng pipeline OPC UA.

Tuy nhiên có ba giới hạn:

1. `CONCEALED_STOP_ATTACK` không phải lớp đã huấn luyện trong Day 8. Model có thể dự đoán các nhãn Day 8 như `OPCUA_MALICIOUS_WRITE` hoặc lớp khác, nhưng không thể tính recall cho "concealed stop" nếu không có protocol hợp lệ.
2. Day 7 PCAP đang nằm trong ZIP nhiều segment; muốn inference cần bước offline giải nén/merge/feature extraction. Đây là xử lý mới, chưa thực hiện trong lượt này.
3. Kết quả inference nếu có chỉ là bằng chứng hỗ trợ quan sát lưu lượng bất thường OPC UA/S7, không thay thế ground truth process/HMI.

Do đó hướng dùng IDS OPC UA là **khả thi như phân tích quan sát PCAP**, không phù hợp để tuyên bố hiệu năng phát hiện Day 7 theo metric Day 8 nếu chưa thiết kế nhãn và tiêu chí riêng.

## 6. Hai hướng phát triển khả thi

### Hướng 1 - Phân tích hồi cứu bất nhất giữa OPC UA và trạng thái tiến trình

| Mục | Đánh giá |
|---|---|
| Câu hỏi nghiên cứu | Khi attacker ghi `BangTai=True` trong lúc STOP thật, có thể phát hiện bất nhất giữa tín hiệu hiển thị và trạng thái tiến trình không? |
| Giả thuyết | Nếu có log process tags độc lập, các cửa sổ STOP+concealment sẽ có `BangTai=True` nhưng timer/stage/sensor không tiến triển hoặc STOP flag/state mâu thuẫn. |
| File đã có | Timeline, PCAP, script concealed, tag mapping, rule logger script. |
| File thiếu | Tag log Day 7, HMI/WinCC log/screenshot timestamped, LAD/TIA export hoặc bằng chứng logic tương đương, timestamp từng STOP/readback. |
| Phương pháp | Dùng tag log độc lập làm ground truth, đối chiếu với OPC UA write/read-back và timeline STOP. |
| Đối chứng | Benign steady và chuyển START/STOP hợp lệ cùng logger. |
| Chỉ số có thể tính hiện tại | Chỉ có tỷ lệ mẫu read-back 183/1026 từ client kiểm thử. |
| Chỉ số cần thêm dữ liệu | precision/recall, delay, duration bất nhất, false positive trên benign. |
| Artifact đầu ra | `day7_inconsistency_windows.csv`, `day7_stop_cycles.csv`, timeline figure. |
| Kết luận có thể chứng minh hiện tại | Client ghi được `BangTai=True` một phần và PCAP có burst OPC UA trong interval STOP. |
| Không thể kết luận hiện tại | HMI hiển thị gì theo thời gian; PLC process state độc lập; duration sai lệch; IDS consistency rule hiệu quả bao nhiêu. |
| Quyết định | Cần bằng chứng bổ sung hoặc chỉ giữ ở mức thiết kế protocol. |

### Hướng 2 - Đánh giá khả năng quan sát chuỗi hành vi Day 7 từ PCAP và IDS hiện có

| Mục | Đánh giá |
|---|---|
| Câu hỏi nghiên cứu | PCAP Day 7 có thể hiện chuỗi recon -> foothold/pivot -> OPC UA burst/S7 STOP đủ rõ để làm case-study quan sát đa giai đoạn không? |
| Giả thuyết | Các interval Day 7 có chữ ký mạng phân biệt được: SMB2 tới HMI, SYN scan tới HMI, S7comm tới PLC, burst OPC UA tới PLC. |
| File đã có | ZIP PCAP, timeline, script SMB/KILL/CONCEALED, model/feature schema OPC UA. |
| Phương pháp | Offline PCAP audit theo interval; tùy chọn trích feature OPC UA 5s và chạy inference model Day 8 như bằng chứng phụ. |
| Đối chứng | Khoảng ngoài attack trong cùng PCAP hoặc PCAP benign khác, nhưng chỉ nên dùng cho lưu lượng mạng, không cho process state. |
| Chỉ số có thể tính | packet count theo giao thức/đích/interval; burst rate; timing giữa stage; có/không có chữ ký. |
| Chỉ số không nên tính | recall `CONCEALED_STOP_ATTACK` bằng model Day 8; precision/recall process inconsistency. |
| Artifact đầu ra | `day7_pcap_observability_audit.csv`, `day7_stage_timeline.md`, hình timeline stage. |
| Kết luận có thể chứng minh | Chuỗi hành vi nhiều giai đoạn hiện diện trên dây và có thể quan sát từ PCAP. |
| Không thể kết luận | Tác động vật lý chi tiết và trạng thái HMI thực tế nếu không có nguồn process/HMI. |
| Quyết định | Có thể phân tích ngay bằng dữ liệu cũ nếu được phê duyệt; cần viết script offline, không cần thu mới. |

## 7. Protocol đề xuất nếu được phê duyệt

Chọn **Hướng 2** làm phân tích bổ sung khả thi nhất bằng dữ liệu cũ.

1. Giải nén PCAP Day 7 vào thư mục tạm hoặc workdir mới trong `experiments/day7_research/pcap_observability/`.
2. Với mỗi interval trong `labels/day7_final_timeline.csv`, chạy `tshark` theo bộ lọc cố định:
   - SMB recon: SMB2/TCP445 tới HMI `.31`;
   - Kill-chain: SYN tới HMI `.31`, S7comm tới PLC `.211`;
   - Concealed stop: OPC UA decoded hoặc TCP/4840 tới PLC, S7comm tới PLC, TCP/102 nền.
3. Xuất CSV gồm `scenario`, `start_ms`, `end_ms`, `filter_name`, `packet_count`, `first_packet`, `last_packet`.
4. Vẽ timeline gồm ba tầng: nhãn timeline, packet counts theo giao thức, và điểm START/END.
5. Nếu cần chạy IDS OPC UA, trích feature 5s từ PCAP merged và chạy inference bằng `model_opcua` nhưng chỉ báo cáo là "Day 8 IDS response to Day 7 traffic", không tính recall class.

Không chạy protocol này trong lượt hiện tại vì người dùng yêu cầu thiết kế và chờ phê duyệt.

## 8. Kế hoạch đưa vào Word

### Mục 3.11

Nên trình bày Day 7 là case-study nâng cao của testbed, không phải dataset ML mới. Cấu trúc gợi ý:

1. Mục tiêu Day 7: kiểm tra khả năng quan sát chuỗi hành vi nhiều giai đoạn và cấu hình bảo mật giữa các kênh.
2. Mô tả ba interval: `SMB_RECON_ENUM`, `KILL_CHAIN`, `CONCEALED_STOP_ATTACK`.
3. Bảng nguồn bằng chứng: timeline, PCAP, script, tag mapping; ghi rõ thiếu log HMI/process độc lập.
4. Kết luận phương pháp: Day 7 bổ sung chiều phân tích case-study, không trộn metric với Day 8.

### Mục 5.9.6

Nên đưa Day 7 vào phần liên hệ/case-study, tập trung vào kết quả:

- SMB recon: 140 probe theo module, 65 gói SMB2 tới HMI trong PCAP;
- Kill-chain: 5/8 port HMI mở theo module, 15 SYN tới HMI trong PCAP;
- Concealed stop: module 180s, interval 188,3s, 9 STOP, 13.604 write OK, 183/1026 read-back còn True, 16.678 OPC UA request decoded tới PLC và 162 S7comm request tới PLC trong PCAP;
- Giới hạn: chưa có process/HMI log độc lập để tính precision/recall inconsistency.

## 9. Bảng và hình cần thiết

| Loại | Nội dung | Nguồn | Mục đích |
|---|---|---|---|
| Bảng | Ma trận nguồn bằng chứng Day 7 | báo cáo này | Chống phản biện "số lấy từ đâu" |
| Bảng | Truy vết số liệu concealed stop | timeline, script, PCAP | Phân biệt write/response/read-back/process/HMI |
| Hình | Timeline 3 stage Day 7 | timeline + PCAP counts | Slide bảo vệ, thể hiện chuỗi hành vi |
| Hình | Concealed stop evidence stack | write attempts, read-back samples, PCAP bursts, thiếu process/HMI | Giải thích vì sao chưa tính precision/recall |
| Bảng | Day 7 vs Day 8 | báo cáo Day 8 và Day 7 | Tách vai trò: Day 8 IDS/dataset, Day 7 case-study đa nguồn |

## 10. So sánh Day 7 và Day 8

Day 8 đã chốt ở trạng thái READY TO INTEGRATE cho nghiên cứu chất lượng bộ dữ liệu OPC UA, đánh giá IDS, ablation feature, leakage audit, episode-level và warm-up analysis. Day 7 không nên lặp lại các thực nghiệm đó.

Day 7 bổ trợ ở hướng khác: nó kiểm tra testbed như một môi trường OT/ICS đa thành phần, có HMI/Engineering, PLC, Web-SCADA, nhiều giao thức và chuỗi hành vi nhiều giai đoạn. Giá trị của Day 7 là quan sát và giải thích một case-study an ninh: kênh OPC UA Anonymous có thể bị ghi một phần, trong khi kênh có xác thực/S7CommPlus không bị can thiệp theo cùng cách; nhưng bằng chứng hiện có chưa đủ để biến quan sát này thành IDS consistency experiment có metric đầy đủ.

Không trộn metric Day 7 với Day 8. Không gọi `CONCEALED_STOP_ATTACK` là lớp đã học của IDS Day 8. Không dùng kết quả prediction Day 8, nếu sau này chạy, để tính recall Day 7 nếu chưa có protocol nhãn riêng.

## 11. Câu hỏi chưa đủ bằng chứng

1. HMI/WinCC thực sự hiển thị gì trong từng thời điểm của 9 chu kỳ STOP?
2. Trạng thái process tags độc lập với client kiểm thử là gì trong từng mẫu 0,05s hoặc từng cửa sổ 5s?
3. Mỗi STOP bắt đầu/kết thúc chính xác khi nào?
4. Mỗi read-back `True` kéo dài bao lâu, hay chỉ xuất hiện tại một mẫu lẻ?
5. Rule consistency dựa trên `BangTai`, CD1/CD2/CD3, STOP/START, sensor có false positive trên vận hành bình thường không?

## 12. Kết luận ngắn

Day 7 hiện đã chứng minh được ba điểm có giá trị: PCAP ghi nhận chuỗi recon/pivot/concealment thật; module `CONCEALED_STOP_ATTACK` gửi 13.604 write OPC UA thành công ở mức API và 183/1026 mẫu read-back còn True; và traffic trên dây trong interval concealed có burst OPC UA cùng các lệnh S7comm tới PLC. Tuy nhiên, bằng chứng hiện tại chưa đủ để kết luận về duration sai lệch, trạng thái HMI thực tế, hoặc hiệu năng phát hiện bất nhất process. Vì vậy, nên tích hợp Day 7 như case-study có kiểm toán nguồn bằng chứng, hoặc xin phê duyệt thêm một phân tích offline PCAP observability. Để nâng thành thực nghiệm đối chứng về inconsistency detection, cần thêm log process/HMI độc lập hoặc artifact tương đương.
