# Đối chiếu nhãn harvest/train và OOD2

Kết quả dưới đây áp dụng cùng tiêu chí đọc packet đã công bố trong `summary.json`: packet payload phát từ máy kiểm thử tới PLC TCP/4840 trong đúng khoảng timeline attack; riêng SESSION_BURST chấp nhận SYN. Đây là rà soát độc lập với dự đoán model.

| Bộ dữ liệu | Cửa sổ | Timeline attack | Cửa sổ benign có event evidence | Nhãn attack thiếu payload trong đúng episode |
|---|---:|---:|---:|---:|
| Harvest/train | 3.427 | 224 | 0 | 16 |
| OOD2 | 605 | 28 | 22 | 0 theo định nghĩa report này |

Trong 16 cửa sổ harvest/train có nhãn attack nhưng thiếu payload trong đúng khoảng episode: 12 SUBSCRIPTION_FLOOD, 2 SESSION_BURST, 1 NODE_BROWSE, 1 PROTOCOL_FUZZ. Chúng vẫn có packet liên quan IP attacker trong cửa sổ; kiểm tra cho thấy nhóm control-only/no-payload hoặc lệch biên khoảng thời gian. Đây là các trường hợp cần rà bằng ngữ cảnh giao thức/kịch bản; phép kiểm tra hiện tại không đủ để tự kết luận nhãn sai.

Riêng 29 cửa sổ train đã chuyển attack→benign trước đây là một tập khác: PCAP audit chuyên biệt xác nhận 29/29 không có traffic trong phạm vi activity-aware ở cửa sổ đó, 27/29 có cửa sổ cùng episode lân cận với traffic phù hợp, còn 2/29 chỉ có traffic ngoài phạm vi. Vì vậy con số 29 vẫn có cơ sở theo rule đã nêu; 16 trường hợp trên là phần audit boundary mới, không phủ định tự động 29 trường hợp.

## Kết luận

- Không thể kết luận harvest/train “không có vấn đề nhãn”. Nó không có chiều benign chứa event evidence theo tiêu chí này, nhưng còn 16 attack windows chưa có payload trong khoảng attack chính xác.
- OOD2 có 22 benign windows chứa event evidence. Có bất cân xứng giữa quy tắc nhãn cũ và bằng chứng sự kiện; điểm đánh giá OOD2 nhạy với định nghĩa nhãn.
- Chưa được tự động đổi 16 nhãn train hay lấy điểm event-aware OOD2 làm kết quả chính. Packet hiện diện không tự chứng minh tác động attack; timeline là log thực thi, còn packet audit kiểm tra dấu vết mạng.
- Muốn dùng một quy tắc thống nhất cần quyết định mục tiêu nhãn trước: “nhãn chiếm ưu thế thời gian” hay “mọi cửa sổ có hành vi được kích hoạt có bằng chứng”. Sau đó tái tạo cả train và OOD2, rà thủ công các boundary/nhóm protocol, huấn luyện lại nếu nhãn train đổi, rồi đánh giá trên capture chưa dùng chọn model.

Chi tiết theo cửa sổ/episode: `harvest_findings.csv`, `harvest_episode_audit.csv`, `harvest_boundary_details.json`, `ood2_findings.csv`, `ood2_episode_audit.csv`. Tóm tắt máy đọc: `summary.json`.
