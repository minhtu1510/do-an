# Bản thảo bổ sung nhánh OPC UA

Trạng thái: bản để duyệt, chưa chèn vào `bao-cao/Thao_Tu_OTSecurity_vf.docx`.
Các số thứ tự bảng dưới đây dùng ký hiệu `xx` để tránh xung đột với hệ thống
đánh số hiện tại của đồ án.

## Nội dung đề xuất bổ sung vào Mục 3.10

### 3.10.5. Kiểm toán nhãn theo hoạt động quan sát được

**Câu hỏi nghiên cứu.** Việc gán nhãn chỉ theo khoảng thời gian của episode có
làm xuất hiện các cửa sổ mang nhãn tấn công mặc dù lưu lượng OPC UA liên quan
máy kiểm thử không còn được quan sát hay không; các thay đổi nhãn có thể được
tái kiểm trực tiếp từ PCAP thay vì chỉ đối chiếu hai CSV đã sinh hay không?

**Phương pháp thực nghiệm.** Kiểm toán được thực hiện thành hai lớp. Ở lớp thứ
nhất, bảng gán nhãn theo khoảng thời gian `opcua_harvest_ext.csv` và bảng
activity-aware `opcua_harvest_ext_aa.csv` được ghép theo
`window_start_ms/window_end_ms` để lập manifest cho toàn bộ 3.427 cửa sổ. Ở lớp
thứ hai, script kiểm toán mới đọc lại PCAP gộp Day 8, tính lại bằng chứng packet
cho từng khoảng nửa kín `[window_start, window_end)`, rồi đối chiếu với timeline,
manifest và riêng 29 cửa sổ đã đổi nhãn. Chỉ PCAP gộp được đọc; các PCAP segment
không được nạp đồng thời, tránh đếm lại cùng một bản ghi từ hai nguồn.

Quy tắc được tái áp dụng đúng phạm vi bộ trích xuất gốc: cửa sổ phải vừa giao
với một khoảng attack trong timeline, vừa có ít nhất một gói thuộc bộ lọc
`tcp.port == 4840 && ip.addr == 192.168.210.211` mà nguồn hoặc đích là máy kiểm
thử `192.168.210.32`. Kiểm toán đồng thời tách gói **phát từ** `.32` khỏi gói PLC
`.211` phản hồi về `.32`, ghi số gói IP, số gói TCP có payload, số gói TCP/4840,
số gói OPC UA được TShark giải mã, timestamp đầu/cuối và dấu hiệu dịch vụ. Vì
vậy, “có traffic attacker” trong toàn PCAP và “có traffic thuộc phạm vi quy tắc
activity-aware” là hai đại lượng khác nhau.

**Điều kiện đánh giá.** PCAP chuẩn có tên
`harvest_ot1786331948_merged.pcap`, kích thước 311.442.552 byte và SHA-256
`12abee34d688678cbbc4479b067462dc7c25d73b739b72e1cea7c6b44ac3c42e`.
Địa chỉ được xác minh từ cấu hình và mã thu thập: HMI/Web-SCADA `.31`, máy kiểm
thử `.32`, PLC `.211`. Timeline lưu epoch tuyệt đối; chuỗi thời gian UTC+7 chỉ
dùng để hiển thị. Phép quy đổi epoch sang mili giây và ranh giới cửa sổ giống
pipeline gốc. PCAP gộp có `Strict time order=False`, do đó gán cửa sổ dựa trên
`frame.time_epoch` của từng frame, không dựa trên thứ tự bản ghi. Môi trường
kiểm toán dùng Python 3.12.3 và TShark 4.2.2.

**Kết quả thực tế.** Có 29/3.427 cửa sổ đổi từ nhãn tấn công sang BENIGN, gồm 24
cửa sổ SESSION_BURST, 4 cửa sổ SUBSCRIPTION_FLOOD và 1 cửa sổ PROTOCOL_FUZZ.
Số cửa sổ BENIGN tăng từ 2.680 lên 2.709; số cửa sổ tấn công giảm từ 747 xuống
718; tổng số cửa sổ không đổi. Khi trích xuất lại từ PCAP, 29/29 cửa sổ phù hợp
với quy tắc activity-aware, không có trường hợp không nhất quán và không có cửa
sổ nào trong nhóm 29 thiếu bằng chứng do biên capture. Cả 718 cửa sổ còn giữ
nhãn tấn công đều có ít nhất một gói thuộc phạm vi quy tắc.

**Bảng 3.xx. Kiểm toán nhãn trước và sau activity-aware labeling**

| Nhãn/nhóm | Trước hiệu chỉnh | Sau hiệu chỉnh | Chênh lệch |
| --- | ---: | ---: | ---: |
| BENIGN | 2.680 | 2.709 | +29 |
| SESSION_BURST | 53 | 29 | -24 |
| SUBSCRIPTION_FLOOD | 70 | 66 | -4 |
| PROTOCOL_FUZZ | 28 | 27 | -1 |
| Toàn bộ lớp tấn công | 747 | 718 | -29 |
| Tổng số cửa sổ | 3.427 | 3.427 | 0 |

**Bảng 3.xx. Kết quả trích xuất lại bằng chứng packet-level**

| Nội dung kiểm toán | Kết quả |
| --- | ---: |
| Cửa sổ được đối chiếu | 3.427 |
| Cửa sổ được PCAP bao phủ đầy đủ | 3.425 |
| Cửa sổ ở biên, chỉ được bao phủ một phần | 2 |
| Cửa sổ đổi nhãn phù hợp quy tắc | 29/29 |
| Cửa sổ đổi nhãn không nhất quán | 0 |
| Cửa sổ đổi nhãn chưa đủ bằng chứng | 0 |
| Cửa sổ giữ nhãn attack có traffic thuộc phạm vi quy tắc | 718/718 |
| Sai khác timeline–manifest | 0 |
| Sai khác khi tái áp dụng quy tắc activity-aware | 0 |

Hai trong số 29 cửa sổ vẫn có gói IP **phát từ** `.32`, nên không thể mô tả
29 cửa sổ là “hoàn toàn không có hoạt động của attacker”. Cửa sổ bắt đầu lúc
`2026-08-10T04:54:00Z` có 1 gói không payload; cửa sổ bắt đầu lúc
`2026-08-10T06:05:45Z` có 7 gói, trong đó 3 gói mang tổng cộng 120 byte TCP
payload. Cả tám gói đều đi tới HMI `.31` cổng TCP 7680; không gói nào đi tới
PLC, dùng TCP/4840 hoặc được TShark giải mã là OPC UA. Vì vậy chúng không thỏa
phạm vi quy tắc đang kiểm toán và không phải lý do tự động đổi nhãn ngược lại.

Trên toàn bộ dataset, còn có 118 cửa sổ BENIGN chứa gói liên quan `.32` thuộc
phạm vi PLC/TCP-4840, nhưng cả 118 đều có `timeline_overlap_ms=0`: traffic xuất hiện
ngoài khoảng attack do timeline công bố, chẳng hạn trong warm-up/cooldown. Đây
không phải bất nhất của quy tắc vì quy tắc yêu cầu đồng thời timeline overlap và
traffic attacker; đồng thời kết quả cho thấy không nên đồng nhất nhãn BENIGN với
sự vắng mặt tuyệt đối của máy kiểm thử trên mạng. Hai cửa sổ BENIGN ở đầu và
cuối capture chỉ được PCAP bao phủ một phần và được ghi thành cảnh báo biên,
không được dùng để khẳng định vắng traffic.

**Nhận xét được bằng chứng hỗ trợ.** Kết quả packet-level củng cố tính truy vết
của 29 thay đổi và xác nhận chúng tái tạo được từ PCAP đã thu. Đây là phép trích
xuất lại độc lập về mã nguồn và phép đếm, nhưng vẫn dùng **cùng nguồn PCAP**, nên
không phải một capture xác nhận độc lập. Manifest consistency, sự hiện diện của
gói tin và thành công của hành vi tấn công là ba mức bằng chứng khác nhau. Kết
quả 29/29 chỉ xác nhận tính nhất quán với quy tắc activity-aware; nó không xác
nhận rằng hành vi attack trong timeline đã thực hiện thành công hoặc không thành
công.

**Hạn chế của kết luận.** Vắng gói trong phạm vi PLC/TCP-4840 không chứng minh
vắng mọi hoạt động từ `.32`, như chính hai cửa sổ có traffic tới HMI cho thấy.
Quy tắc giả định IP máy kiểm thử đã biết và không bao quát tấn công qua client
trung gian, địa chỉ thay đổi, traffic không phải IPv4 hoặc hoạt động ngoài điểm
mirror. Khả năng giải mã OPC UA còn phụ thuộc dissector và TCP reassembly. Hai
cửa sổ biên chỉ có coverage một phần. Dataset và manifest cũ vẫn không chứa
`attacker_packet_count`; bằng chứng mới được lưu ở artifact kiểm toán song song,
không được ghi ngược vào dữ liệu gốc.

**Bảng/hình đề xuất.** Ngoài hai bảng trên, đề xuất Hình 3.xx là dải thời gian
29 cửa sổ đổi nhãn cùng cửa sổ kề trong episode, mã hóa màu theo số gói thuộc
phạm vi rule. Dữ liệu hình lấy từ `changed_29_pcap_audit.csv`; hình phải đánh
dấu riêng hai cửa sổ có traffic `.32 -> .31:7680` và hai biên PCAP để tránh diễn
giải “0 gói OPC UA” thành “0 hoạt động attacker”.

**Artifact nguồn cần gắn với bảng:**

- `experiments/opcua_research_v2/label_audit/summary.json`;
- `experiments/opcua_research_v2/label_audit/label_manifest.csv`;
- `experiments/opcua_research_v2/label_audit/changed_windows.csv`;
- `experiments/opcua_research_v2/label_audit/pcap_independent_audit/window_packet_evidence.csv`;
- `experiments/opcua_research_v2/label_audit/pcap_independent_audit/changed_29_pcap_audit.csv`;
- `experiments/opcua_research_v2/label_audit/pcap_independent_audit/audit_discrepancies.csv`;
- `experiments/opcua_research_v2/label_audit/pcap_independent_audit/packet_audit_summary.json`;
- `experiments/opcua_research_v2/label_audit/pcap_independent_audit/PCAP_AUDIT_REPORT.md`;
- quy tắc activity-aware tại `extract_opcua_features_ext.py`, dòng 169–170 và
  370–380;
- trình kiểm toán tại `tools/opcua_label_manifest.py` và
  `tools/opcua_pcap_independent_audit.py`.

## Nội dung đề xuất bổ sung vào Mục 5.10

### 5.10.7. Kiểm chứng độ phụ thuộc vào nhóm đặc trưng cấu trúc nguồn

**Câu hỏi nghiên cứu.** Hiệu năng của bộ phát hiện OPC UA phụ thuộc ở mức nào
vào 11 đặc trưng mô tả số lượng, mức tập trung và giá trị cực đại theo nguồn
client; các đặc trưng này có đủ để kết luận rằng mô hình bị rò rỉ dữ liệu hay
không?

**Phương pháp thực nghiệm.** ExtraTrees được giữ cố định ở 400 cây, độ sâu tối
đa 10, `random_state=0` và không dùng `class_weight`. Nhãn WRITE_DENIED và
INVALID_WRITE được gộp thành MALICIOUS_WRITE như pipeline gốc. Bốn cấu hình
được so sánh: toàn bộ 61 đặc trưng; 50 đặc trưng sau khi loại đúng 11 trường cấu
trúc nguồn; 24 bộ đếm dịch vụ/trạng thái OPC UA; và baseline luật ngưỡng trên 11
đặc trưng, với ngưỡng phân vị 0,99 ước lượng chỉ từ cửa sổ BENIGN của tập phát
triển. Ba cấu hình ExtraTrees được đánh giá bằng GroupKFold 5-fold theo
`episode_id`, sau đó fit trên toàn bộ tập phát triển và áp dụng lên OOD2 và
testclean.

Mười một trường được chia thành ba nhóm chức năng: (i) số lượng nguồn, đích và
client (`unique_src_ip_count`, `unique_dst_ip_count`, `client_src_count`); (ii)
mức tập trung lưu lượng theo client (`max_pkts_by_client`,
`max_bytes_by_client`, `max_services_by_client`, `busiest_client_pkt_frac`);
và (iii) cực đại dịch vụ theo một nguồn (`max_opn_by_single_src`,
`max_read_by_single_src`, `max_create_session_by_single_src`,
`max_browse_by_single_src`). Tất cả đều là số đếm, cực đại hoặc tỷ lệ; không
trường nào lưu giá trị địa chỉ nguồn cụ thể.

**Điều kiện đánh giá.** Mọi cấu hình trong bảng ablation được chạy trong cùng
môi trường scikit-learn 1.9.1 và cùng dữ liệu, nên chênh lệch tương đối giữa các
cấu hình có thể so sánh nội bộ. OOD2 đã được dùng trước đó để so sánh thuật toán
và lựa chọn ExtraTrees; do đó, các chỉ số OOD2 dưới đây là kết quả phát triển và
phân tích sức bền giữa phiên, không phải ước lượng kiểm định cuối trên tập chưa
từng được quan sát.

**Bảng 5.xx. Ablation nhóm đặc trưng OPC UA**

| Cấu hình | Số đặc trưng | Group-CV Macro-F1 | OOD2 Macro-F1 đa lớp | OOD2 precision tấn công | OOD2 recall tấn công | OOD2 F1 tấn công | OOD2 FPR | Testclean Macro-F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Toàn bộ | 61 | 0,961831 | 0,517804 | 0,843537 | 0,992 | 0,911765 | 0,047917 | 0,949340 |
| Loại 11 trường cấu trúc nguồn | 50 | 0,953913 | 0,408665 | 0,473469 | 0,928 | 0,627027 | 0,268750 | 0,940504 |
| Chỉ dịch vụ/trạng thái OPC UA | 24 | 0,891816 | 0,429433 | 0,733333 | 0,440 | 0,550000 | 0,041667 | 0,924602 |
| Baseline ngưỡng giao thức | 11 | – | – | 0,517391 | 0,952 | 0,670423 | 0,231250 | – |

**Kết quả thực tế.** Khi loại 11 trường cấu trúc nguồn, Macro-F1 Group-CV chỉ
giảm từ 0,961831 xuống 0,953913 và Macro-F1 testclean giảm từ 0,949340 xuống
0,940504. Tuy nhiên, trên OOD2, số cảnh báo giả tăng từ 23 lên 129, FPR tăng từ
0,047917 lên 0,268750, còn F1 của lớp tấn công giảm từ 0,911765 xuống 0,627027.
Cấu hình chỉ dùng dịch vụ/trạng thái giữ FPR OOD2 ở 0,041667 nhưng chỉ phát hiện
55/125 cửa sổ tấn công. Baseline ngưỡng đạt recall 0,952 nhưng tạo 111 cảnh báo
giả trên OOD2.

**Nhận xét được bằng chứng hỗ trợ.** Mười một trường bị loại không chứa địa chỉ
IP thô; chúng là số lượng nguồn/đích, số client, tỷ lệ lưu lượng của client bận
nhất và các giá trị cực đại theo nguồn. Kết quả chỉ chứng minh rằng mô hình phụ
thuộc vào thông tin cấu trúc và mức tập trung lưu lượng để hiệu chỉnh quyết định
trên OOD2. Việc loại chúng làm kết quả OOD2 xấu đi, đặc biệt do cảnh báo giả,
nhưng hiện tượng này không chứng minh rò rỉ metadata hay nhận dạng trực tiếp máy
tấn công. Đồng thời, nó cũng chưa chứng minh đã loại bỏ mọi dạng data leakage:
thiết kế hiện tại chưa thay đổi topology, số client, địa chỉ nguồn hoặc công cụ
sinh traffic một cách độc lập giữa train và test.

**Hạn chế của kết luận.** Tên cấu hình `no_client_identity_proxy` trong artifact
chỉ là nhãn kỹ thuật; về bản chất đây là phép loại nhóm đặc trưng cấu trúc nguồn,
không phải phép xóa định danh vì mô hình vốn không nhận IP thô. Để kiểm định
leakage cần một thiết kế riêng, chẳng hạn giữ nguyên hành vi nhưng hoán đổi địa
chỉ/client, tách train–test theo host hoặc topology, và thu thêm phiên với client
benign khác. OOD2 cũng đã tham gia lựa chọn model nên không thể dùng chính mức
suy giảm này làm bằng chứng xác nhận cuối cùng.

**Bảng/hình đề xuất.** Giữ Bảng 5.xx ở trên và bổ sung Hình 5.xx dạng ba panel:
(a) Macro-F1 Group-CV, (b) F1 tấn công OOD2 và (c) FPR OOD2 cho ba tập đặc
trưng. Hình phải ghi chú trực tiếp “OOD2 là cross-session validation đã tham gia
lựa chọn mô hình”, không dùng nhãn “final test”. Nguồn số liệu là
`feature_ablation/ablation_results.csv`.

**Artifact nguồn cần gắn với bảng:**

- `experiments/opcua_research_v2/feature_ablation/ablation_results.csv`;
- `experiments/opcua_research_v2/feature_ablation/feature_groups.json`;
- `experiments/opcua_research_v2/feature_ablation/run_config.json`;
- các confusion matrix và classification report cùng thư mục;
- mã tạo kết quả tại `tools/opcua_feature_ablation.py`.

### 5.10.8. Đánh giá từ cửa sổ đến episode

**Câu hỏi nghiên cứu.** Recall cao ở cấp cửa sổ có chuyển thành khả năng phát
hiện đầy đủ các episode hay không, và kết luận 17/17 episode phải được đặt cạnh
chi phí false-positive episode như thế nào?

**Phương pháp thực nghiệm.** Model ExtraTrees đã lưu được áp dụng lên 605 cửa
sổ OOD2. Ở cấp cửa sổ, nhãn dự đoán được quy về BENIGN/tấn công. Ở cấp episode,
mỗi `episode_id` được coi là dương nếu chứa cửa sổ tấn công và được phát hiện khi
ít nhất một cửa sổ có tổng xác suất các lớp không-BENIGN
`pred_attack_score >= 0,5`. OOD2 có 86 `episode_id`; không có ID nào trộn cửa
sổ benign và tấn công. Vì vậy có thể lập ma trận 17 episode dương và 69
episode/chunk benign âm.

**Điều kiện đánh giá.** Ngưỡng 0,5 và quy tắc “ít nhất một cửa sổ” được dùng cho
phân tích này. Trên toàn bộ 605 cửa sổ, quyết định theo ngưỡng
`pred_attack_score` trùng với quyết định nhị phân suy ra từ lớp argmax. OOD2 là
tập cross-session đã tham gia so sánh thuật toán và chọn ExtraTrees; do đó bảng
này mô tả hành vi của model đã chọn trên tập phát triển cross-session, không phải
một kiểm định cuối độc lập. Precision episode còn phụ thuộc cách timeline chia
69 đơn vị benign.

**Bảng 5.xx. Đối chiếu kết quả cấp cửa sổ và cấp episode trên OOD2**

| Đơn vị đánh giá | Dương thực | Âm thực | TP | FP | TN | FN | Precision | Recall | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Cửa sổ 5 giây | 125 | 480 | 124 | 23 | 457 | 1 | 0,8435 | 0,9920 | 0,0479 |
| `episode_id` / benign chunk | 17 | 69 | 17 | 23 | 46 | 0 | 0,4250 | 1,0000 | 0,3333 |

**Kết quả thực tế.** Ở cấp cửa sổ, model đạt TP/FP/TN/FN = 124/23/457/1.
F1 của lớp tấn công là 0,9118; Macro-F1 nhị phân đang trình bày trong Bảng 5.16
là 0,943, hai giá trị khác nhau do cách lấy trung bình nhưng xuất phát từ cùng
một ma trận nhầm lẫn. Ở cấp episode, cả 17 episode tấn công đều có ít nhất một
cửa sổ vượt ngưỡng, nhưng có thêm 23 false-positive episode/chunk benign, làm
precision episode chỉ còn 0,425. Toàn bộ 23 false-positive episode nằm trong
nhóm warm-up/cooldown; phân rã này được trình bày riêng ở Mục 5.10.9.

**Nhận xét được bằng chứng hỗ trợ.** Kết quả 17/17 chỉ chứng minh recall episode
trên OOD2 theo quy tắc đã nêu; nó không đủ để kết luận hệ thống phát hiện episode
“hoàn hảo” nếu bỏ qua 23 false-positive episode/chunk và precision 0,425. Phân
tích hai mức cho thấy chỉ một cửa sổ tấn công bị bỏ sót nhưng không làm mất toàn
bộ episode tương ứng. Đây là lợi ích của phép tổng hợp theo episode, đồng thời là
cảnh báo rằng quy tắc “một cửa sổ vượt ngưỡng” rất nhạy với false positive.

**Hạn chế của kết luận.** OOD2 đã tham gia quá trình chọn thuật toán và ngưỡng
episode chưa được đánh giá trên một capture frozen mới. Mỗi `episode_id` benign
phản ánh cách chia timeline hiện tại, không nhất thiết tương ứng một sự kiện vận
hành độc lập trong mọi hệ thống. Do đó precision 0,425 là đặc tính của giao thức
đánh giá hiện tại, không phải ước lượng phổ quát cho triển khai thực tế.

**Bảng/hình đề xuất.** Giữ bảng đối chiếu window–episode ở trên. Đề xuất Hình
5.xx biểu diễn mỗi episode bằng số cửa sổ vượt ngưỡng và vị trí cảnh báo đầu
tiên; 17 episode tấn công và 69 benign chunk phải cùng xuất hiện để hình không
chỉ trực quan hóa recall mà bỏ qua precision. Nguồn là
`ood2_episode_results.csv` và `ood2_negative_episode_results.csv`.

**Artifact nguồn cần gắn với bảng:**

- `experiments/opcua_research_v2/warmup_ood/ood2_predictions.csv`;
- `experiments/opcua_research_v2/warmup_ood/ood2_episode_summary.json`;
- `experiments/opcua_research_v2/warmup_ood/ood2_episode_results.csv`;
- `experiments/opcua_research_v2/warmup_ood/ood2_negative_episode_results.csv`;
- mã tại `tools/opcua_export_predictions.py` và
  `tools/opcua_episode_eval.py`.

### 5.10.9. Phân tích lỗi trong warm-up/cooldown

**Câu hỏi nghiên cứu.** Cảnh báo giả OOD2 phân bố như thế nào giữa polling ổn
định và warm-up/cooldown, và các thống kê giao thức quan sát được có hỗ trợ giả
thuyết rằng trạng thái thiết lập phiên dễ bị nhầm với tấn công hay không?

**Phương pháp thực nghiệm.** Dự đoán 605 cửa sổ OOD2 được phân thành ba pha từ
ground truth đi kèm: 125 cửa sổ attack, 444 cửa sổ benign ổn định và 36 cửa sổ
benign warm-up. False positive được tính ở cấp cửa sổ từ `is_fp`. Tám đặc trưng
liên quan thiết lập phiên, subscription và cấu trúc kết nối được tổng hợp theo
mean, p95 và max cho từng pha. Ở cấp episode, 69 đơn vị benign tiếp tục được
chia thành 37 chunk steady và 32 episode/chunk warm-up/cooldown; một đơn vị âm
trở thành false-positive episode nếu có ít nhất một cửa sổ với
`pred_attack_score >= 0,5`.

**Điều kiện đánh giá.** Nhãn pha chỉ dùng cho phân tích hậu nghiệm, không phải
đầu vào của model. Vì vậy phép phân rã này định vị lỗi nhưng chưa cung cấp một cơ
chế triển khai để nhận biết warm-up. Các thống kê đặc trưng là mô tả một biến tại
một thời điểm, không phải feature attribution nhân quả. OOD2 vẫn là tập
cross-session đã tham gia lựa chọn model.

**Bảng 5.xx. False positive cấp cửa sổ theo trạng thái benign**

| Trạng thái | Số cửa sổ benign | False positive | FPR cửa sổ |
| --- | ---: | ---: | ---: |
| Polling ổn định | 444 | 0 | 0,0000 |
| Warm-up/cooldown | 36 | 23 | 0,6389 |
| Tổng benign | 480 | 23 | 0,0479 |

**Bảng 5.xx. False positive cấp episode/chunk theo trạng thái benign**

| Trạng thái benign | Số episode/chunk | False-positive episode | FPR episode |
| --- | ---: | ---: | ---: |
| Polling ổn định | 37 | 0 | 0,0000 |
| Warm-up/cooldown | 32 | 23 | 0,7188 |
| Tổng | 69 | 23 | 0,3333 |

**Bảng 5.xx. Một số đặc trưng trung bình theo pha trên OOD2**

| Đặc trưng | Benign steady | Benign warm-up | Attack |
| --- | ---: | ---: | ---: |
| `opcua_client_src_count` | 1,0000 | 2,0000 | 1,9920 |
| `opcua_create_session_count` | 0,0000 | 0,3056 | 0,4000 |
| `opcua_hel_count` | 0,0000 | 0,3889 | 0,4080 |
| `opcua_opn_count` | 0,0045 | 0,7222 | 0,8000 |
| `opcua_publish_count` | 7,1441 | 10,0556 | 11,3600 |
| `opcua_unique_tcp_stream_count` | 1,7005 | 2,6111 | 4,5040 |

**Kết quả thực tế.** Toàn bộ 23 false positive cấp cửa sổ nằm trong 36 cửa sổ
warm-up; 444 cửa sổ steady không tạo cảnh báo giả. Ở cấp episode/chunk, toàn bộ
23 false positive cũng nằm trong 32 đơn vị warm-up/cooldown; 37 chunk steady
không bị cảnh báo. Các giá trị trung bình cho thấy warm-up gần attack hơn steady
ở số client, HEL, OPN, CreateSession, Publish và số TCP stream. Chẳng hạn mean
OPN tăng từ 0,0045 ở steady lên 0,7222 ở warm-up, gần mức 0,8000 của attack.

**Nhận xét được bằng chứng hỗ trợ.** Bằng chứng hỗ trợ kết luận hẹp rằng lỗi
cảnh báo giả của OOD2 tập trung ở trạng thái thiết lập/khôi phục phiên, thay vì
polling ổn định. Sự gần nhau của các thống kê phiên cung cấp một giải thích khả
dĩ cho lỗi, nhưng chưa chứng minh từng đặc trưng là nguyên nhân quyết định của
model. Kết quả âm tính “0 FP steady” cũng không được suy rộng thành FPR bằng 0
trong vận hành OPC UA nói chung.

**Hạn chế của kết luận.** Chỉ có 36 cửa sổ warm-up trong một tập cross-session;
ranh giới pha được biết từ artifact hậu nghiệm. Chưa có thí nghiệm can thiệp giữ
nguyên mọi yếu tố và chỉ thay đổi trạng thái phiên, chưa có attribution như
permutation/SHAP theo split độc lập, và chưa đánh giá cơ chế giảm cảnh báo giả
trên capture frozen mới.

**Bảng/hình đề xuất.** Đề xuất Hình 5.xx là biểu đồ mean và p95 của sáu đặc
trưng trong bảng theo ba pha, kèm một panel thể hiện FP/total ở cấp cửa sổ và
episode. Nguồn trực tiếp là `phase_feature_summary.csv`, `error_summary.json` và
`ood2_episode_summary.json`.

**Artifact nguồn cần gắn với nội dung:**

- `experiments/opcua_research_v2/warmup_ood/ood2_predictions.csv`;
- `experiments/opcua_research_v2/warmup_ood/error_summary.json`;
- `experiments/opcua_research_v2/warmup_ood/phase_feature_summary.csv`;
- `experiments/opcua_research_v2/warmup_ood/label_support.csv`;
- `experiments/opcua_research_v2/warmup_ood/ood2_episode_summary.json`;
- `experiments/opcua_research_v2/warmup_ood/ood2_negative_episode_results.csv`;
- mã tại `tools/opcua_warmup_error_analysis.py` và
  `tools/opcua_episode_eval.py`.

### 5.10.10. Vai trò của OOD2, giới hạn tổng quát hóa và phạm vi tái lập

**Câu hỏi nghiên cứu.** Những kết quả nào có thể tuyên bố là tái lập từ artifact
hiện có; OOD2 giữ vai trò gì trong lựa chọn mô hình; và dữ liệu hiện tại hỗ trợ
kết luận tổng quát hóa đến đâu?

**Phương pháp thực nghiệm.** Lịch sử mã nguồn được đối chiếu với metadata model,
báo cáo legacy và artifact vòng kiểm chứng. Script
`scratch_try_improve_opcua_ood.py` huấn luyện nhiều thuật toán trên tập phát
triển, chấm trực tiếp trên OOD2 và chọn cấu hình có Macro-F1 OOD2 cao nhất.
`train_opcua_eval.py` sau đó ghi rõ ExtraTrees được chọn từ phép ablation
cross-session này. Model đã lưu được nạp lại để xuất dự đoán từng cửa sổ và so
sánh với báo cáo OOD2/testclean cũ. Một model cùng tham số cũng được huấn luyện
lại trong môi trường mới để kiểm tra Group-CV.

**Điều kiện đánh giá.** Model đã lưu mang marker scikit-learn 1.8.0; các model
ablation mới mang marker 1.9.1. Cả hai dùng 61 đặc trưng theo cùng thứ tự, cùng
phép gộp nhãn và cùng cấu hình ExtraTrees cốt lõi. Tuy nhiên, chưa có lần huấn
luyện lại model trong đúng môi trường 1.8.0 từ đầu đến cuối.

**Kết quả thực tế.** Suy luận bằng model đã lưu tái tạo đúng ma trận OOD2
124/23/457/1, Macro-F1 đa lớp 0,517804 và kết quả testclean 45/0/708/0 với
Macro-F1 0,949340; các giá trị này khớp báo cáo legacy trong giới hạn làm tròn.
Ngược lại, Group-CV khi huấn luyện mới bằng scikit-learn 1.9.1 đạt 0,961831,
trong khi metadata model 1.8.0 ghi 0,959851.

**Nhận xét được bằng chứng hỗ trợ.** Có thể tuyên bố đã tái lập kết quả suy luận
của model đã lưu trên OOD2 và testclean, cũng như tái lập logic tính metric và
thứ tự đặc trưng. Chưa thể tuyên bố tái lập bit-for-bit quá trình huấn luyện hay
điểm Group-CV. Chênh lệch phiên bản thư viện là một nguyên nhân khả dĩ cho sai
khác 0,001980, nhưng chưa được chứng minh là nguyên nhân duy nhất vì chưa chạy
đối chứng hai phiên bản trên cùng môi trường khóa.

**Hạn chế của kết luận.** OOD2 độc lập theo thời gian thu so với tập phát triển
nhưng không độc lập về quyết định mô hình: nó đã được dùng để chọn ExtraTrees.
Vì vậy OOD2 hỗ trợ phân tích cross-session và lỗi warm-up, không cung cấp một
ước lượng kiểm định cuối không thiên lệch. Một kết luận xác nhận cần khóa code,
feature schema, model, phiên bản thư viện và ngưỡng trước khi thu capture mới.

**Bảng/hình đề xuất.** Đề xuất Hình 5.xx là sơ đồ luồng bằng chứng:
`train + Group-CV -> chấm nhiều thuật toán trên OOD2 -> chọn ExtraTrees -> phân
tích ablation/episode/warm-up trên OOD2`. Mũi tên OOD2 đi vào nút chọn model phải
được thể hiện rõ để người đọc không hiểu đây là untouched final test. Kèm bảng
đối chiếu marker scikit-learn 1.8.0/1.9.1 và hai điểm Group-CV
0,959851/0,961831.

**Artifact nguồn cần gắn với nội dung:**

- `scratch_try_improve_opcua_ood.py`, đặc biệt dòng 34–36, 42–90;
- `train_opcua_eval.py`, đặc biệt dòng 13–20 và 61–89;
- `model_opcua/meta.json` và `model_opcua/classifier.joblib`;
- `eval_ood2_extratrees/ood_report.json`;
- `eval_testclean_extratrees/ood_report.json`;
- `experiments/opcua_research_v2/scientific_verification.json`.

## Nội dung đề xuất bổ sung vào Mục 5.12

### 5.12.x. Giới hạn hiệu lực của kiểm chứng khoa học OPC UA

**Câu hỏi nghiên cứu.** Sau chuỗi kiểm toán dữ liệu từ PCAP, ablation đặc trưng,
đánh giá episode, phân tích warm-up và kiểm tra tái lập, phạm vi kết luận nào
được bằng chứng hiện có hỗ trợ; đâu là giới hạn tổng quát hóa phải để lại cho
một thí nghiệm xác nhận mới?

**Phương pháp thực nghiệm.** Chuỗi bằng chứng được tổ chức theo năm tầng. Tầng
một kiểm tra manifest và tái đếm packet từ PCAP cho toàn bộ 3.427 cửa sổ. Tầng
hai ablation đúng 11 đặc trưng cấu trúc nguồn trong cùng runtime. Tầng ba quy tụ
dự đoán cửa sổ thành episode và tính đồng thời TP, FP, TN, FN. Tầng bốn phân rã
lỗi benign theo steady và warm-up/cooldown. Tầng năm đối chiếu lịch sử chọn
model, marker phiên bản scikit-learn và khả năng tái tạo inference. Trình kiểm
chứng cũ tính lại 24 quan hệ về CSV/model/metric; phép kiểm toán PCAP mới là một
lớp bổ sung riêng, không được nhập vào con số 24/24 nếu chưa cập nhật chính
trình kiểm chứng đó.

**Điều kiện đánh giá.** Toàn bộ phân tích dùng lại dữ liệu đã tồn tại, không thu
capture mới, không chạy lại tấn công và không huấn luyện lại model cho vòng kiểm
toán PCAP. “Xác minh từ PCAP” ở đây có nghĩa là trích xuất lại bằng script và
bộ đếm mới từ cùng PCAP đã thu, không phải xác minh bằng một điểm đo hay nguồn
thu độc lập. OOD2 tách theo phiên thu so với tập train nhưng đã tham gia so sánh
thuật toán và chọn ExtraTrees; mọi kết quả OOD2 vì vậy thuộc đánh giá phát triển
cross-session.

**Kết quả thực tế.** Cả 24 phép kiểm tra artifact cũ đều đạt. Bổ sung vào đó,
kiểm toán packet-level xác nhận 29/29 cửa sổ đổi nhãn phù hợp quy tắc, 0 không
nhất quán và 0 thiếu bằng chứng trong nhóm 29. Hai cửa sổ vẫn có traffic `.32`
tới HMI `.31:7680` nhưng không có traffic PLC/TCP-4840 hay OPC UA được giải mã;
118 cửa sổ BENIGN có gói liên quan `.32` trong phạm vi PLC/TCP-4840 nhưng đều nằm ngoài
khoảng attack của timeline; 2/3.427 cửa sổ ở biên chỉ được PCAP bao phủ một
phần. Các kết quả model cũ không thay đổi: ablation chỉ chứng minh feature
dependence; OOD2 đạt 124/125 cửa sổ tấn công; episode recall 1,000 đi cùng
precision 0,425; toàn bộ 23 false positive OOD2 nằm trong warm-up; Group-CV mới
0,961831 không trùng metadata 0,959851.

**Bảng 5.xx. Ranh giới của các kết luận OPC UA sau kiểm chứng**

| Kết luận | Mức bằng chứng hiện có | Cách diễn giải được phép | Không nên khẳng định |
| --- | --- | --- | --- |
| Hiệu chỉnh 29 cửa sổ | Manifest và tái trích xuất cùng PCAP gốc | 29/29 thay đổi phù hợp phạm vi activity-aware; 0 bất nhất | Toàn bộ ground truth hoặc hành vi attack đã được xác minh thành công |
| Hai cửa sổ có traffic tới HMI | Bộ đếm theo nguồn/đích/cổng | Có hoạt động `.32 -> .31:7680` ngoài phạm vi PLC/TCP-4840 | Cả 29 cửa sổ tuyệt đối không có hoạt động attacker |
| 118 cửa sổ BENIGN có gói OPC UA liên quan `.32` | Packet evidence và `timeline_overlap_ms=0` | Traffic tồn tại ngoài khoảng attack công bố; rule vẫn nhất quán | Nhãn BENIGN đồng nghĩa máy kiểm thử vắng mặt, hoặc 118 cửa sổ chắc chắn mislabeled |
| Hai cửa sổ biên PCAP | Coverage `partial_boundary` | Chỉ được bao phủ một phần và phải giữ cờ hạn chế | Vắng traffic đã được xác nhận trong toàn bộ cửa sổ |
| Vai trò 11 đặc trưng cấu trúc nguồn | Ablation cùng runtime | Model phụ thuộc mạnh vào nhóm này trên OOD2 | Đã phát hiện hoặc loại bỏ data leakage |
| OOD2 124/125 cửa sổ tấn công | Dự đoán từng hàng và confusion matrix | Quan sát cross-session của model đã chọn | Hiệu năng cuối không thiên lệch trên dữ liệu chưa dùng |
| Episode 17/17 | 86 ID không trộn nhãn, TP/FP/TN/FN = 17/23/46/0 | Recall episode bằng 1,000 theo quy tắc đã nêu | Phát hiện episode hoàn hảo hoặc sẵn sàng triển khai |
| Warm-up và polling ổn định | 23/36 warm-up FP; 0/444 steady FP | Lỗi quan sát được tập trung ở warm-up của OOD2 | Warm-up là nguyên nhân nhân quả duy nhất hoặc FPR steady luôn bằng 0 |
| Tái lập model | Dự đoán model lưu khớp legacy | Tái lập suy luận trên OOD2/testclean | Tái lập bit-for-bit quá trình huấn luyện/CV |

**Nhận xét được bằng chứng hỗ trợ.** Đóng góp khoa học rõ nhất của nhánh OPC UA
không phải một điểm F1 đơn lẻ, mà là chuỗi kiểm chứng có truy vết từ packet đến
nhãn, đặc trưng, dự đoán cửa sổ, episode và trạng thái phiên. Kiểm toán PCAP làm
mạnh hơn kết luận về tính nhất quán của 29 thay đổi nhưng đồng thời bộc lộ giới
hạn của cách diễn đạt nhị phân “có/không có attacker”: hai cửa sổ có traffic tới
HMI và 118 cửa sổ BENIGN có traffic OPC UA ngoài timeline. Ablation cho thấy mô
hình sử dụng cấu trúc nguồn; episode evaluation cho thấy recall cao nhưng
precision thấp; warm-up analysis định vị false positive; còn lịch sử OOD2 đặt
giới hạn rõ cho mọi tuyên bố tổng quát hóa.

**Hạn chế của kết luận.** Chưa có capture frozen được thu sau khi khóa toàn bộ
pipeline; chưa có thay đổi có hệ thống về client, topology, PLC và
SecurityPolicy; chưa có đối chứng hoán đổi danh tính nguồn để kiểm tra leakage;
và OOD2 đã tham gia lựa chọn mô hình. Bằng chứng packet mới được lưu ở artifact
kiểm toán, nhưng dataset/manifest gốc vẫn không lưu `attacker_packet_count`.
Precision episode phụ thuộc cách định nghĩa benign chunk; phân tích warm-up là
hậu nghiệm; khả năng giải mã OPC UA phụ thuộc TShark/reassembly; hai cửa sổ biên
không có coverage đầy đủ. Đặc biệt, không được diễn giải “không có gói trong
phạm vi rule” thành “không có mọi hoạt động attacker”, hoặc sự hiện diện gói
thành bằng chứng hành vi tấn công đã thành công.

**Hướng kiểm chứng tiếp theo.** Cần khóa dependency bằng môi trường có phiên bản
cụ thể; niêm phong model và ngưỡng trước khi thu capture mới; bổ sung nhiều
client benign, attacker host, PLC và SecurityPolicy; đưa packet evidence vào
pipeline dữ liệu ngay khi trích xuất; đánh giá theo host/topology chưa thấy; và
xây dựng đặc trưng trạng thái phiên để nhận diện warm-up mà không dùng nhãn
ground truth.

**Bảng/hình đề xuất.** Bảng ranh giới kết luận ở trên là bảng tổng hợp bắt buộc.
Đề xuất Hình 5.xx trình bày chuỗi bằng chứng theo trục:
`PCAP -> label audit -> feature ablation -> window prediction -> episode ->
warm-up -> generalization limit`. Mỗi nút phải liên kết artifact nguồn và ghi
nhãn mức suy luận: consistency, packet presence, model performance hoặc attack
success. Nút cuối phải thể hiện OOD2 quay lại bước chọn model, thay vì đứng tách
biệt như final test.

**Artifact nguồn cần gắn với bảng:**

- `experiments/opcua_research_v2/scientific_verification.json`;
- `experiments/opcua_research_v2/NUMBER_ARTIFACT_MATRIX.md`;
- `experiments/opcua_research_v2/label_audit/pcap_independent_audit/packet_audit_summary.json`;
- `experiments/opcua_research_v2/label_audit/pcap_independent_audit/PCAP_AUDIT_REPORT.md`;
- toàn bộ các artifact con trong `label_audit/`, `feature_ablation/` và
  `warmup_ood/`.
