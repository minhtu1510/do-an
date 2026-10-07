# Rà soát dữ liệu OOD2

Ngày kiểm tra: 2026-10-02. Kiểm tra chỉ đọc; không sửa nhãn, PCAP hoặc mô hình.

## Nguồn dữ liệu

- Capture gốc: `data_opc/ot-capture-ot1788840784/`.
- PCAP chuẩn dùng kiểm tra: `data_opc/day8_out/ood2_merged.pcap` (348.278 packet).
- Timeline: `test_results/day8/timeline_ood2.csv` (84 đoạn: 56 benign, 28 attack).
- CSV: `data_opc/day8_out/opcua_ood2_ext_aa.csv` (605 cửa sổ 5 giây).

## Cách kiểm tra

Đọc PCAP bằng TShark với bộ lọc của extractor: `tcp.port == 4840 && ip.addr == 192.168.210.211`. Chia cửa sổ theo `int(epoch * 1000) // 5000 * 5000`. Tái đếm packet, byte và sự hiện diện nguồn/đích `192.168.210.32`. Dùng trực tiếp `load_episodes` và `episode_for` trong `extract_opcua_features_ext.py` để tái tính nhãn từ timeline: chọn đoạn overlap lớn nhất, giữ nhãn đoạn nếu có traffic liên quan IP attacker trong cửa sổ; nếu không thì gán `benign`.

## Kết quả trực tiếp

| Kiểm tra | Kết quả |
|---|---:|
| Cửa sổ có traffic đúng phạm vi trong PCAP | 605 |
| Cửa sổ trong CSV | 605 |
| Cửa sổ PCAP thiếu trong CSV | 0 |
| Cửa sổ CSV không có trong PCAP | 0 |
| Cửa sổ sai số packet | 0 |
| Cửa sổ sai số byte | 0 |
| Cửa sổ sai độ dài 5 giây | 0 |
| Nhãn không khớp quy tắc tái tính | 0 |
| Khoảng timeline có end < start | 0 |
| Khoảng timeline vượt vùng cửa sổ capture | 0 |

CSV có 480 cửa sổ benign (444 `benign`, 36 `BENIGN_NORMAL`) và 125 cửa sổ attack. Các khoảng trống giữa cửa sổ không phải cửa sổ có traffic đúng phạm vi bị bỏ khỏi CSV; chúng không có packet thỏa bộ lọc trong lần kiểm tra này. Không suy ra mất capture hay không có traffic ngoài bộ lọc.

## Giới hạn quan trọng của nhãn

Chỉ 17/28 đoạn attack trong timeline có nhãn attack được giữ ở cấp cửa sổ. 11 đoạn còn lại không được chọn làm đoạn overlap lớn nhất ở bất kỳ cửa sổ CSV nào:

- 2 ENDPOINT_DISCOVERY (0,431 và 0,051 giây).
- 1 PROTOCOL_FUZZ (3,038 giây).
- 4 INVALID_WRITE (0,056–0,064 giây).
- 2 WRITE_DENIED (0,048 và 0,053 giây).
- 2 NODE_BROWSE (0,132 giây mỗi đoạn).

Đây là giới hạn biểu diễn của quy tắc chọn overlap lớn nhất trong cửa sổ 5 giây. Nó không chứng minh các hành vi không xảy ra hoặc không có packet. CSV phù hợp quy tắc hiện tại nhưng không đại diện đủ mọi hành vi được ghi trong timeline. Riêng SESSION_BURST đầu có 3 cửa sổ chọn episode, nhưng chỉ 2 cửa sổ giữ attack sau điều kiện có traffic attacker.

## Cách sử dụng trong đồ án

Phân biệt tính nhất quán dữ liệu với chất lượng mô hình: lần kiểm tra này xác nhận sự khớp PCAP–timeline–CSV trong phạm vi quy tắc, không đo hiệu quả IDS hoặc xác nhận attack thành công. Không diễn giải 17/17 episode được IDS phát hiện thành phát hiện đủ 28 đoạn attack đã thực thi. Không dùng OOD2 hiện tại để kết luận chất lượng phát hiện write attack, vì CSV không có cửa sổ ground truth thuộc nhóm write.

Nếu mục tiêu đồ án cần đánh giá các hành vi ngắn, cần xác định và công bố quy tắc nhãn phù hợp trước khi tái tạo dữ liệu; không đổi nhãn dựa vào kết quả dự đoán hoặc để tăng điểm. Chưa thay đổi quy tắc trong lần rà soát này.

## Kiểm toán bổ sung 11 đoạn bị mất nhãn

Script tái lập: `tools/audit_ood2_short_episodes.py`. Bằng chứng theo episode, số frame và cửa sổ liên quan: `experiments/opcua_research_v2/ood2_short_episode_audit.json`.

Đếm trong khoảng `[start, end)` của timeline, với timestamp packet cắt xuống mili giây như pipeline. Cả 11/11 đoạn đều có packet trong phạm vi PLC/TCP-4840, có packet payload phát từ máy kiểm thử:

| Nhóm | Số đoạn | Packet trong phạm vi mỗi đoạn | Bằng chứng |
|---|---:|---|---|
| ENDPOINT_DISCOVERY | 2 | 29, 13 | Giải mã được GetEndpointsResponse (428) |
| PROTOCOL_FUZZ | 1 | 9 | Có payload từ máy kiểm thử; chưa giải mã được service, chưa xác minh nội dung malformed |
| INVALID_WRITE | 4 | 10 mỗi đoạn | WriteRequest (673), WriteResponse (676), kết quả từng thao tác `0x80740000` |
| WRITE_DENIED | 2 | 10, 11 | WriteRequest (673), WriteResponse (676), kết quả từng thao tác `0x80730000` |
| NODE_BROWSE | 2 | 42 mỗi đoạn | Giải mã được BrowseResponse (527), BrowseNextRequest (530), ReadRequest (631) |

Đối chiếu TShark verbose xác nhận `0x80740000 = BadTypeMismatch`, `0x80730000 = BadWriteNotSupported`. Cả sáu WriteResponse có ServiceResult ở header là Good, nhưng kết quả từng thao tác là Bad. Vì vậy chỉ đếm `opcua.ServiceResult`/`opcua.StatusCode` có thể bỏ qua lỗi ghi ở trường `opcua.Results`; cần kiểm tra độ đầy đủ đặc trưng status của extractor trước khi kết luận mô hình phân biệt ghi thành công và bị từ chối. Các đặc trưng hiện tại không trực tiếp đọc `opcua.Results`.

Nhãn WRITE_DENIED được hỗ trợ ở nghĩa rộng là ghi bị từ chối/không được hỗ trợ; PCAP này không chứng minh cụ thể lỗi quyền `BadUserAccessDenied` hoặc `BadNotWritable` như ví dụ trong scenarios.yaml.

Kết luận dữ liệu: có bằng chứng hoạt động thực trong cả 11 đoạn, nhưng cửa sổ chứa chúng hiện mang nhãn benign vì quy tắc chọn overlap lớn nhất. Đây là mất biểu diễn hành vi ngắn ở cấp nhãn cửa sổ, không phải thiếu packet trong capture. Nếu mục tiêu nhãn là đánh dấu mọi cửa sổ chứa hành vi kiểm thử có bằng chứng, quy tắc hiện tại chưa đáp ứng mục tiêu đó. Không kết luận toàn bộ ground truth sai: nhãn vẫn nhất quán với định nghĩa majority-overlap đang dùng. Cần công bố định nghĩa và cân nhắc bản nhãn event-aware trước khi dùng để đánh giá đủ các kịch bản.

## Đối chiếu cùng tiêu chí trên harvest/train

Artifact đối chiếu: `experiments/opcua_research_v2/train_ood2_label_audit/summary.json`, `harvest_findings.csv`, `harvest_episode_audit.csv`, `harvest_boundary_details.json`. Theo tiêu chí attacker-originated payload trong khoảng episode và phạm vi PLC/TCP-4840 (SESSION_BURST chấp nhận SYN), harvest có 3.427 cửa sổ, 224 episode timeline attack và 0 cửa sổ benign có event evidence. Tuy nhiên có **16 cửa sổ đang mang nhãn attack nhưng không có payload attack trong chính khoảng episode**: 12 SUBSCRIPTION_FLOOD, 2 SESSION_BURST, 1 NODE_BROWSE, 1 PROTOCOL_FUZZ. Các cửa sổ này vẫn có packet liên quan IP attacker trong cửa sổ rộng hơn; phần lớn là control-only/no-payload hoặc nằm ngoài khoảng episode. Đây là ứng viên cần rà boundary/traffic cụ thể, không đủ căn cứ tự đổi thành benign.

Điều này khác với 29 cửa sổ activity-aware đã chuyển attack→benign: kiểm toán chuyên biệt trước đó xác nhận 29/29 không có traffic trong phạm vi pipeline trong cửa sổ, 27/29 có cửa sổ cùng episode lân cận mang traffic attacker trong phạm vi, và hai trường hợp còn lại chỉ có packet ngoài phạm vi. Không được gộp “29 đã audit” với “16 cần xem lại”: 29 là thay đổi đã thực hiện theo activity-aware; 16 là nhãn attack còn lại nhưng thiếu payload trong đúng episode theo phép rà event-aware mới.

OOD2 có chiều ngược lại: 22 cửa sổ benign chứa event evidence theo tiêu chí mới. Như vậy không thể nói lỗi chỉ nằm ở OOD2 hoặc train hoàn toàn sạch. Train cũng còn điểm cần giải thích, nhưng kiểu bất nhất và rủi ro nhãn khác OOD2. Cần giữ các thống kê này như kiểm toán dữ liệu, không sửa nhãn tự động và không suy ra từ đó hiệu quả mô hình.
