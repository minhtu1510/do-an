# Kết luận khoa học cuối cùng cho thực nghiệm OPC UA Day 8

Ngày lập: 2026-09-25

Phạm vi: tổng hợp cuối cùng từ các artifact hiện có trong `experiments/opcua_research_v2/`, pipeline OPC UA gốc và các script kiểm chứng trong `tools/`. Báo cáo này không dựa trên huấn luyện lại mô hình, không sửa PCAP, dataset, model hoặc DOCX.

## Tóm tắt quyết định

**READY TO INTEGRATE.**

Bằng chứng hiện có đủ để đưa nhánh OPC UA Day 8 vào đồ án tốt nghiệp như một thực nghiệm có kiểm toán dữ liệu, có đánh giá IDS theo cửa sổ và theo episode, và có phân tích giới hạn tổng quát hóa. Các kết luận cần giữ đúng biên: chưa được gọi OOD2 là kiểm định cuối độc lập, chưa được tuyên bố "không có data leakage" tuyệt đối, và không được diễn giải sự phụ thuộc vào đặc trưng source/client như bằng chứng đã chứng minh leakage.

## Kiểm tra cuối về chỉ số đánh giá

Ba chỉ số cần chốt:

| Chỉ số | Giá trị | Nguồn |
|---|---:|---|
| GroupKFold Macro-F1, 61 đặc trưng | 0,961831 | `feature_ablation/ablation_results.csv`; `classification_all_61_train_group_cv.json` |
| OOD2 Macro-F1, 61 đặc trưng | 0,517804 | `feature_ablation/ablation_results.csv`; `classification_all_61_ood2.json`; `warmup_ood/ood2_predictions.csv` |
| OOD2 Binary F1 lớp tấn công | 0,911765 | `feature_ablation/ablation_results.csv`; `warmup_ood/ood2_predictions.csv` |

Hai giá trị Macro-F1 dùng cùng model family/cấu hình cốt lõi, cùng 61 đặc trưng và cùng quy tắc gộp `OPCUA_INVALID_WRITE`, `OPCUA_WRITE_DENIED` vào `OPCUA_MALICIOUS_WRITE`. Tuy nhiên chúng không hoàn toàn tương đương về tập lớp được tính trung bình. GroupKFold có đủ 11 nhãn trong tập train. OOD2 chỉ có 7 nhãn trong ground truth, nhưng prediction có thêm 3 nhãn không xuất hiện trong ground truth, nên artifact `classification_all_61_ood2.json` tính macro trên 10 lớp thuộc `y_true ∪ y_pred`. Lớp `OPCUA_READ_SCRAPING` không xuất hiện trong `y_true` hoặc `y_pred` của OOD2 nên không nằm trong macro 0,517804.

| Cách tính Macro-F1 trên OOD2 từ prediction hiện có | Số lớp | Macro-F1 |
|---|---:|---:|
| Trên `y_true ∪ y_pred`, đúng như artifact scikit-learn | 10 | 0,517804 |
| Chỉ trên các lớp thực sự xuất hiện trong `y_true` OOD2 | 7 | 0,739720 |
| Ép đủ 11 lớp model đã biết, zero-division = 0 | 11 | 0,470731 |

Do đó, mức giảm từ 0,961831 xuống 0,517804 phản ánh đồng thời hai hiện tượng: hiệu quả phân loại chi tiết giảm khi chuyển phiên thu và tác động của tập lớp đánh giá khác nhau. Con số này không nên được đọc như một phép so sánh macro hoàn toàn đối xứng giữa hai tập dữ liệu.

### Bảng theo lớp

| Lớp | GroupKFold P/R/F1/support | OOD2 P/R/F1/support |
|---|---|---|
| `OPCUA_BEHAVIORAL_PROFILING` | 0,940299 / 1,000000 / 0,969231 / 189 | 0,853933 / 1,000000 / 0,921212 / 76 |
| `OPCUA_ENDPOINT_DISCOVERY` | 0,958333 / 0,958333 / 0,958333 / 24 | 0,000000 / 0,000000 / 0,000000 / 0 |
| `OPCUA_MALICIOUS_WRITE` | 1,000000 / 1,000000 / 1,000000 / 50 | 0,000000 / 0,000000 / 0,000000 / 0 |
| `OPCUA_NODE_BROWSE` | 0,952381 / 0,952381 / 0,952381 / 21 | 0,000000 / 0,000000 / 0,000000 / 0 |
| `OPCUA_PROTOCOL_FUZZ` | 1,000000 / 0,962963 / 0,981132 / 27 | 0,333333 / 1,000000 / 0,500000 / 2 |
| `OPCUA_READ_SCRAPING` | 1,000000 / 0,965517 / 0,982456 / 58 | không xuất hiện trong `y_true ∪ y_pred` OOD2 |
| `OPCUA_RECURSIVE_BROWSE` | 1,000000 / 0,975000 / 0,987342 / 80 | 0,750000 / 1,000000 / 0,857143 / 3 |
| `OPCUA_SESSION_BURST` | 0,964286 / 0,931034 / 0,947368 / 29 | 1,000000 / 0,400000 / 0,571429 / 5 |
| `OPCUA_SLOWLORIS` | 1,000000 / 0,988506 / 0,994220 / 174 | 0,911765 / 1,000000 / 0,953846 / 31 |
| `OPCUA_SUBSCRIPTION_FLOOD` | 1,000000 / 0,681818 / 0,810811 / 66 | 1,000000 / 0,250000 / 0,400000 / 8 |
| `benign` | 0,993764 / 1,000000 / 0,996872 / 2709 | 0,997817 / 0,952083 / 0,974414 / 480 |

## Phần A - Những gì Day 8 đã chứng minh

### A1. Bộ dữ liệu OPC UA Day 8 có cấu trúc, có nhãn và có kiểm toán nhất quán

Tập chính sau activity-aware labeling có 3.427 cửa sổ 5 giây, gồm 2.709 cửa sổ benign và 718 cửa sổ tấn công. So với nhãn theo khoảng episode ban đầu, 29 cửa sổ được chuyển từ attack sang benign. Kiểm toán lại từ PCAP gốc xác nhận 29/29 cửa sổ này phù hợp với quy tắc activity-aware; không có cửa sổ đổi nhãn nào bất nhất hoặc thiếu bằng chứng trong phạm vi kiểm toán.

Nguồn: `label_audit/summary.json`, `label_audit/changed_windows.csv`, `label_audit/pcap_independent_audit/packet_audit_summary.json`, `changed_29_pcap_audit.csv`, `window_packet_evidence.csv`.

Quy tắc activity-aware theo `extract_opcua_features_ext.py`: một cửa sổ nằm trong khoảng episode chỉ giữ nhãn attack nếu có traffic thuộc máy attacker trong phạm vi lọc ban đầu của extractor; nếu không, cửa sổ được gán lại benign. Kiểm toán PCAP diễn giải phạm vi này là traffic trong timeline overlap, thuộc phạm vi PLC/TCP-4840 và có IP attacker ở nguồn hoặc đích. Điều này kiểm tra tính nhất quán nhãn, không chứng minh một hành vi tấn công đã thành công ở mức hệ thống.

PCAP bao phủ đầy đủ 3.425/3.427 cửa sổ; 2 cửa sổ benign ở biên chỉ được bao phủ một phần. Đây là giới hạn kỹ thuật của vùng capture, không làm thay đổi kết luận về 29 cửa sổ đổi nhãn.

### A2. GroupKFold không trộn cùng episode giữa train và test

Kiểm toán split cho thấy GroupKFold dùng `episode_id`. Trong phép kiểm tra read-only trên 3.427 cửa sổ, 5 fold đều có 0 group overlap và 0 window ID overlap giữa train/test. Số group là 450; mỗi fold có 90 group test. BENIGN được chia thành nhiều chunk `benign#chunkN`, không bị dồn vào một group benign duy nhất.

Điểm cần ghi rõ: vì split theo group chứ không theo khối thời gian liên tục, vẫn có 220-244 cặp cửa sổ kề 5 giây nằm ở hai phía train/test tùy fold. Không có cặp kề nào cùng `episode_id` bị tách, nhưng GroupKFold vẫn nằm trong cùng phiên Day 8, cùng testbed và cùng baseline benign.

Nguồn: `tools/opcua_feature_ablation.py`, `train_opcua_eval.py`, kiểm toán read-only từ `data_opc/day8_out/opcua_harvest_ext_aa.csv`.

### A3. Pipeline ML không đưa trực tiếp metadata/nhãn vào feature matrix 61 cột

Model OPC UA dùng các cột bắt đầu bằng `opcua_`. `model_opcua/features.json` liệt kê 61 đặc trưng đều là số đo traffic/protocol theo cửa sổ. Các trường `window_start_ms`, `window_end_ms`, `label`, `capture_role`, `plc_ip`, `session_id`, `host_id`, `scenario_id`, `episode_id` không nằm trong feature list. Các script đánh giá dùng `fillna(0)` và ép kiểu số; không thấy bước scaler, feature selector hoặc lọc tương quan học tham số trên toàn bộ dataset trước khi chia fold trong pipeline ablation OPC UA.

Nguồn: `model_opcua/features.json`, `train_opcua_eval.py`, `tools/opcua_feature_ablation.py`.

### A4. Mô hình có năng lực phát hiện tấn công tốt trên OOD2 ở mức nhị phân và episode, nhưng không hoàn hảo

Trên OOD2, ở cấp cửa sổ, ma trận nhị phân là TP/FP/TN/FN = 124/23/457/1. F1 lớp tấn công là 0,911765; recall tấn công là 0,992; FPR cửa sổ là 0,047917. Ở cấp episode/chunk, 17/17 episode tấn công được phát hiện, nhưng có 23 false-positive trong 69 đơn vị benign, dẫn tới episode precision 0,425 và episode FPR 0,3333.

Nguồn: `warmup_ood/ood2_predictions.csv`, `warmup_ood/ood2_episode_summary.json`, `warmup_ood/ood2_episode_results.csv`, `warmup_ood/ood2_negative_episode_results.csv`.

### A5. Lỗi OOD2 tập trung ở warm-up/cooldown, không nằm ở benign steady-state trong artifact hiện có

Trong OOD2, 23/36 cửa sổ benign warm-up bị cảnh báo giả; 0/444 cửa sổ benign steady-state bị cảnh báo giả. Ở cấp episode/chunk, 23 false-positive đều thuộc nhóm warm-up/cooldown; steady-state có 0/37 false-positive chunk.

Nguồn: `warmup_ood/error_summary.json`, `warmup_ood/label_support.csv`, `warmup_ood/phase_feature_summary.csv`, `warmup_ood/ood2_episode_summary.json`.

Kết luận đúng là: với dữ liệu OOD2 hiện có, false positive tập trung ở trạng thái thiết lập/khôi phục phiên. Không được diễn giải rằng hệ thống đã có cơ chế nhận diện warm-up thời gian thực. Nếu loại cảnh báo warm-up bằng ground truth hậu kiểm thì đó là phân tích lỗi, không phải IDS runtime đã được kiểm chứng.

### A6. Ablation chứng minh vai trò lớn của nhóm đặc trưng source/client

Ba cấu hình ablation dùng cùng tập train, cùng quy tắc nhãn, cùng GroupKFold theo `episode_id`, cùng model ExtraTrees cốt lõi và cùng phép đánh giá OOD2/testclean.

| Cấu hình | Số đặc trưng | Group-CV Macro-F1 | OOD2 Macro-F1 | OOD2 attack F1 | OOD2 FPR |
|---|---:|---:|---:|---:|---:|
| 61 đặc trưng | 61 | 0,961831 | 0,517804 | 0,911765 | 0,047917 |
| Bỏ 11 source/client | 50 | 0,953913 | 0,408665 | 0,627027 | 0,268750 |
| Service-only | 24 | 0,891816 | 0,429433 | 0,550000 | 0,041667 |

Kết quả chứng minh mô hình phụ thuộc đáng kể vào nhóm đặc trưng cấu trúc nguồn/client trong điều kiện testbed hiện tại, đặc biệt khi chuyển sang OOD2. Nó không chứng minh mô hình chỉ học địa chỉ attacker và không chứng minh data leakage trực tiếp.

Nguồn: `feature_ablation/ablation_results.csv`, `feature_ablation/feature_groups.json`, `feature_ablation/run_config.json`.

## Phần B - Những gì Day 8 chưa chứng minh

Day 8 chưa chứng minh khả năng tổng quát hóa cuối cùng trên một tập OOD hoàn toàn chưa từng tham gia quyết định mô hình. OOD2 được thu ở phiên khác và cách thời gian, nhưng đã được dùng để so sánh thuật toán và chọn ExtraTrees, nên OOD2 là cross-session validation trong quá trình phát triển, không phải final untouched test.

Day 8 chưa chứng minh đã loại bỏ mọi dạng data leakage. Kiểm toán hiện tại chưa phát hiện rò rỉ trực tiếp qua metadata, nhãn hoặc episode ID trong feature matrix, nhưng chưa có thí nghiệm hoán đổi danh tính nguồn hoặc bố trí testbed để tách feature dependence khỏi leakage tiềm ẩn.

Day 8 chưa chứng minh mô hình phân loại chi tiết mọi subtype attack ổn định qua phiên. OOD2 cho thấy phân loại nhị phân còn tốt, nhưng phân loại chi tiết suy giảm, đặc biệt ở `SESSION_BURST` và `SUBSCRIPTION_FLOOD`; một phần macro cũng chịu ảnh hưởng do tập lớp OOD2 không chứa đủ các lớp train.

Day 8 chưa chứng minh false-positive steady-state luôn bằng 0 trong mọi điều kiện vận hành. Kết quả 0/444 chỉ áp dụng cho OOD2 hiện có.

Day 8 chưa chứng minh hành vi tấn công thành công chỉ bằng packet evidence. Kiểm toán PCAP xác minh sự hiện diện/vắng mặt của traffic theo rule và tính nhất quán của nhãn, không thay thế bằng chứng tác động thành công lên PLC hoặc process.

## Phần C - Giải thích sự chênh lệch GroupKFold và OOD2

Chênh lệch GroupKFold Macro-F1 0,961831 và OOD2 Macro-F1 0,517804 không nên được quy toàn bộ cho data leakage. Bằng chứng hiện tại hỗ trợ ba nguyên nhân cùng tồn tại.

Thứ nhất, GroupKFold nằm trong cùng capture Day 8, cùng testbed, cùng baseline benign và cùng triển khai attacker. Mặc dù không trộn cùng episode giữa train/test, phân bố tổng thể vẫn gần nhau hơn so với OOD2.

Thứ hai, OOD2 thay đổi phân bố. Ở OOD2, 23 false-positive đều rơi vào warm-up/cooldown, nơi các đặc trưng như số source/client, OPN, CreateSession, HEL và số stream gần attack hơn steady benign. Đây là shift trạng thái vận hành, không nhất thiết là leakage.

Thứ ba, Macro-F1 OOD2 không được tính trên đúng cùng tập lớp xuất hiện như GroupKFold. GroupKFold có 11 lớp có support; OOD2 chỉ có 7 lớp trong ground truth. Artifact OOD2 0,517804 tính macro trên 10 lớp thuộc `y_true ∪ y_pred`, bao gồm ba lớp có support 0 nhưng bị dự đoán nhầm; nếu chỉ tính trên 7 lớp có trong `y_true`, macro là 0,739720; nếu ép đủ 11 lớp model, macro là 0,470731. Vì vậy 0,517804 vừa phản ánh lỗi phân loại chi tiết, vừa phản ánh cách định nghĩa tập lớp trong macro.

## Phần D - Kết luận về nguy cơ data leakage

### D1. Rò rỉ dữ liệu trực tiếp

Trong phạm vi đã kiểm toán, chưa phát hiện rò rỉ dữ liệu trực tiếp. Các kiểm tra đã bao gồm:

- GroupKFold theo `episode_id`;
- 0 overlap group và 0 overlap window ID giữa train/test trong kiểm toán split;
- feature matrix của model chỉ gồm 61 cột `opcua_*`;
- metadata và nhãn không nằm trong `model_opcua/features.json`;
- preprocessing trong ablation không fit scaler/selector/correlation trên toàn bộ dataset trước split;
- inference OOD2 dùng model đã lưu và feature list cố định.

Không nên viết "không có data leakage" theo nghĩa tuyệt đối. Cách viết đúng là: "chưa phát hiện rò rỉ dữ liệu trực tiếp trong các thành phần pipeline đã kiểm toán".

### D2. Phụ thuộc đặc trưng cấu trúc nguồn/testbed

Đã có bằng chứng thực nghiệm mạnh về feature dependence. 11 đặc trưng source/client không chứa IP thô, không cần biết trước "đây là attacker", và có thể tính trên traffic chưa gán nhãn. Tuy nhiên chúng mô tả cấu trúc nguồn quan sát được trong testbed: số client, nguồn bận nhất, số packet/byte/service lớn nhất theo client, và số thao tác OPC UA lớn nhất theo source. Khi bỏ nhóm này, OOD2 attack F1 giảm từ 0,911765 xuống 0,627027 và FPR tăng từ 0,047917 lên 0,268750. Đây là bằng chứng mô hình dùng mạnh thông tin cấu trúc nguồn; không phải bằng chứng đã chứng minh leakage.

### D3. OOD2 tham gia lựa chọn mô hình

OOD2 đã được dùng trực tiếp để so sánh các thuật toán và chọn ExtraTrees. Bằng chứng nằm ở `scratch_try_improve_opcua_ood.py` và phần mô tả trong `train_opcua_eval.py`. Vì vậy OOD2 không được gọi là final independent test. Mọi kết quả OOD2 nên được gọi là cross-session validation/development evidence.

## Phần E - Giá trị khoa học của OPC UA Day 8

### E1. Đóng góp về xây dựng bộ dữ liệu

Day 8 xây dựng được bộ dữ liệu OPC UA trên PLC thật, gồm 3.427 cửa sổ 5 giây, 61 đặc trưng giao thức, 11 kịch bản chính thức có episode/PCAP dùng cho học máy, và pipeline gán nhãn có timeline/episode. Bộ dữ liệu bao phủ các nhóm hành vi như discovery, browse, read/monitoring, write probing, session/subscription load và protocol fuzz.

### E2. Đóng góp về kiểm toán dữ liệu

Thực nghiệm không chỉ báo cáo điểm số mô hình mà còn kiểm toán nhãn ở nhiều tầng: so sánh raw/activity-aware manifest, tái áp dụng rule activity-aware, trích xuất lại bằng chứng packet từ PCAP gốc, ghi SHA-256 của đầu vào, và phân biệt nhãn nhất quán với hành vi tấn công thành công. Đây là đóng góp phương pháp đáng đưa vào mục 3.10 và 5.12.

### E3. Đóng góp về đánh giá IDS

Đánh giá không dừng ở GroupKFold window-level. Báo cáo có thêm OOD2 cross-session, testclean cùng ngày, episode-level evaluation, false-positive episode precision, và phân tích warm-up/steady-state. Kết quả quan trọng nhất là: phát hiện tấn công nhị phân trên OOD2 đạt 124/125 cửa sổ attack và 17/17 episode attack, nhưng có 23 false-positive episode/chunk benign, làm precision episode còn 0,425.

### E4. Giới hạn mô hình được phát hiện

Mô hình phụ thuộc mạnh vào đặc trưng cấu trúc nguồn/client; phân loại subtype chi tiết giảm mạnh trên OOD2; false-positive tập trung ở warm-up/cooldown; OOD2 đã tham gia chọn model; và quá trình huấn luyện chưa được tái lập bit-for-bit do khác biệt scikit-learn.

### E5. Có đủ điều kiện kết thúc Day 8 không?

Có. Trong phạm vi đồ án tốt nghiệp, Day 8 đã đủ điều kiện kết thúc vì các kết luận chính đều có artifact hỗ trợ và các giới hạn đã được định vị rõ. Time-blocked Group CV có giá trị khoa học để trả lời câu hỏi "liệu các cửa sổ gần thời gian trong cùng phiên có làm GroupKFold lạc quan không?", nhưng không bắt buộc trước khi tích hợp. Với dữ liệu Day 8, chia khối thời gian có nguy cơ làm lệch support giữa các lớp vì các episode attack phân bố không đều theo thời gian; khi đó phép so sánh có thể kiểm tra temporal robustness nhưng không còn so sánh công bằng với GroupKFold ban đầu. Nên đưa time-blocked Group CV vào mục hạn chế/hướng phát triển, hoặc thực hiện sau nếu hội đồng yêu cầu một kiểm tra bổ sung.

Nếu chỉ được đề xuất một phép kiểm tra bổ sung có giá trị trực tiếp, đề xuất: time-blocked grouped evaluation ở mức nhị phân, báo cáo rõ support từng khối và không dùng để thay thế kết quả chính. Chưa nên chạy trước khi tích hợp nếu mục tiêu hiện tại là chốt đồ án.

## Phần F - Nội dung có thể đưa thẳng vào đồ án

### F1. Đoạn phương pháp cho mục 3.10

Đợt thu OPC UA Day 8 được tổ chức theo chu trình warm-up - thực thi kịch bản - cooldown, với traffic được ghi từ PCAP và timeline lưu START/END của từng episode. Sau khi ghép 286 segment PCAP, pipeline trích xuất cửa sổ 5 giây và 61 đặc trưng OPC UA gồm nhóm khối lượng, chiều gói, TCP dynamics, timing, transport, status code, service count và aggregate theo source/client. Nhãn ban đầu được xác định từ khoảng thời gian episode; sau đó áp dụng quy tắc activity-aware: một cửa sổ nằm trong khoảng episode chỉ giữ nhãn tấn công nếu trong cửa sổ có traffic thuộc phạm vi PLC/TCP-4840 liên quan tới máy attacker; nếu không, cửa sổ được gán benign. Kết quả tạo ra 3.427 cửa sổ, trong đó 29 cửa sổ được chuyển từ attack sang benign. Kiểm toán độc lập bằng cách trích xuất lại từ PCAP gốc xác nhận 29/29 cửa sổ đổi nhãn phù hợp với quy tắc, 0 bất nhất và 0 thiếu bằng chứng trong phạm vi kiểm tra.

### F2. Đoạn phân tích kết quả cho mục 5.10

Với 61 đặc trưng và ExtraTrees, GroupKFold 5-fold theo `episode_id` đạt Macro-F1 0,961831 trên Day 8, cho thấy mô hình phân biệt tốt các lớp trong cùng phiên thu khi không trộn cùng episode giữa train và test. Tuy nhiên, khi đánh giá trên OOD2, Macro-F1 đa lớp còn 0,517804, trong khi phát hiện nhị phân vẫn đạt TP/FP/TN/FN = 124/23/457/1 và F1 lớp tấn công 0,911765. Sự chênh lệch này cần được đọc theo hai lớp ý nghĩa: hiệu quả phân loại subtype chi tiết giảm khi chuyển phiên, và tập lớp OOD2 không trùng hoàn toàn với tập lớp của GroupKFold. Ở cấp episode, 17/17 episode tấn công được phát hiện, nhưng có 23 false-positive trên 69 đơn vị benign, làm precision episode chỉ còn 0,425. Toàn bộ 23 false-positive cửa sổ và episode/chunk benign đều thuộc warm-up/cooldown; 444 cửa sổ benign steady-state không tạo false-positive trong OOD2 hiện có.

### F3. Đoạn hạn chế cho mục 5.12

Các kết quả OPC UA Day 8 không nên được diễn giải như bằng chứng tổng quát hóa cuối cùng. OOD2 là phiên thu khác, nhưng đã được sử dụng trong quá trình so sánh thuật toán và lựa chọn ExtraTrees, vì vậy chỉ nên xem là cross-session validation trong quá trình phát triển. Kiểm toán pipeline chưa phát hiện rò rỉ dữ liệu trực tiếp qua metadata, nhãn, timestamp hoặc episode ID trong feature matrix; tuy nhiên, ablation cho thấy mô hình phụ thuộc mạnh vào 11 đặc trưng cấu trúc nguồn/client. Việc loại nhóm này làm F1 tấn công trên OOD2 giảm từ 0,911765 xuống 0,627027 và FPR tăng từ 0,047917 lên 0,268750. Đây là bằng chứng về feature dependence/testbed dependence, không phải bằng chứng đã chứng minh data leakage. Ngoài ra, kết quả 0 false-positive trên benign steady-state chỉ được xác nhận cho 444 cửa sổ steady của OOD2; chưa có cơ chế IDS thời gian thực đã kiểm chứng để nhận biết và loại riêng warm-up/cooldown.

### F4. Kết luận chung 200-300 từ

Nhánh OPC UA Day 8 tạo ra một bộ dữ liệu thực nghiệm có cấu trúc trên PLC thật, gồm 3.427 cửa sổ 5 giây và 61 đặc trưng giao thức. Điểm mạnh của thực nghiệm không chỉ nằm ở kết quả mô hình, mà còn ở chuỗi kiểm toán dữ liệu: nhãn được gắn theo episode, hiệu chỉnh bằng quy tắc activity-aware và được đối chiếu lại từ PCAP gốc. Kiểm toán packet-level xác nhận 29/29 cửa sổ đổi nhãn phù hợp với quy tắc, nhưng kết quả này chỉ chứng minh tính nhất quán nhãn, không chứng minh hành vi tấn công thành công. Với ExtraTrees và GroupKFold theo `episode_id`, mô hình đạt Macro-F1 0,961831 trong cùng phiên Day 8. Trên OOD2, phát hiện nhị phân vẫn tốt với F1 tấn công 0,911765 và 17/17 episode tấn công được phát hiện, nhưng precision episode chỉ 0,425 do 23 false-positive episode/chunk benign. Các lỗi này tập trung ở warm-up/cooldown, trong khi 444 cửa sổ benign steady-state không tạo false-positive. Ablation cho thấy 11 đặc trưng source/client đóng vai trò lớn; loại chúng làm OOD2 attack F1 giảm còn 0,627027. Vì vậy kết luận khoa học phù hợp là: pipeline hiện chưa phát hiện leakage trực tiếp trong phạm vi kiểm toán, nhưng mô hình còn phụ thuộc vào cấu trúc testbed và OOD2 không phải kiểm định cuối độc lập vì đã tham gia lựa chọn model.

### F5. Năm câu hỏi hội đồng có thể đặt ra

| Câu hỏi | Trả lời dựa trên bằng chứng |
|---|---|
| Vì sao GroupKFold cao nhưng OOD2 Macro-F1 thấp? | GroupKFold nằm trong cùng phiên Day 8; OOD2 thay đổi phân bố và có warm-up/cooldown gây FP. Ngoài ra Macro-F1 OOD2 0,517804 tính trên 10 lớp `y_true ∪ y_pred`, không hoàn toàn tương đương với 11 lớp trong GroupKFold. |
| Có data leakage không? | Chưa phát hiện rò rỉ trực tiếp trong các thành phần đã kiểm toán: feature matrix không chứa metadata/label/episode/timestamp, GroupKFold không trộn episode. Nhưng không được tuyên bố loại bỏ mọi leakage; còn nguy cơ phụ thuộc testbed. |
| Activity-aware labeling có làm đẹp kết quả không? | Quy tắc này sửa các cửa sổ trong khoảng episode nhưng không có traffic attacker thuộc phạm vi rule. 29/29 cửa sổ đổi nhãn được xác nhận lại từ PCAP. Tuy nhiên nó chỉ xác nhận consistency với rule, không chứng minh attack success. |
| 17/17 episode có nghĩa là IDS hoàn hảo không? | Không. 17/17 chỉ là recall episode bằng 1,000 trên OOD2 theo ngưỡng `pred_attack_score >= 0,5`; đồng thời có 23 false-positive benign episode/chunk, precision episode 0,425 và FPR episode 0,3333. |
| Vì sao không chạy thêm time-blocked CV trước khi chốt? | Time-blocked CV trả lời một câu hỏi khác: độ lạc quan do gần thời gian trong cùng phiên. Dữ liệu Day 8 có thể không cân bằng support theo khối thời gian, nên kết quả dễ khó so sánh với GroupKFold. Đây là kiểm tra bổ sung tốt cho hướng phát triển, không phải điều kiện bắt buộc để tích hợp kết quả hiện có. |

## Artifact chính cần trích dẫn

| Nhóm bằng chứng | Artifact |
|---|---|
| Label audit | `experiments/opcua_research_v2/label_audit/summary.json`; `label_manifest.csv`; `changed_windows.csv` |
| PCAP audit | `experiments/opcua_research_v2/label_audit/pcap_independent_audit/packet_audit_summary.json`; `PCAP_AUDIT_REPORT.md`; `window_packet_evidence.csv`; `changed_29_pcap_audit.csv` |
| Ablation | `experiments/opcua_research_v2/feature_ablation/ablation_results.csv`; `feature_groups.json`; `run_config.json` |
| OOD2 prediction | `experiments/opcua_research_v2/warmup_ood/ood2_predictions.csv`; `label_support.csv`; `error_summary.json` |
| Episode evaluation | `experiments/opcua_research_v2/warmup_ood/ood2_episode_summary.json`; `ood2_episode_results.csv`; `ood2_negative_episode_results.csv` |
| Reproducibility | `experiments/opcua_research_v2/scientific_verification.json`; `model_opcua/meta.json`; `model_opcua/features.json` |
| Code | `extract_opcua_features_ext.py`; `train_opcua_eval.py`; `tools/opcua_feature_ablation.py`; `tools/opcua_export_predictions.py`; `tools/opcua_episode_eval.py`; `tools/opcua_warmup_error_analysis.py`; `tools/opcua_pcap_independent_audit.py` |
