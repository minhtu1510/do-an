# Đối chiếu OOD2 theo bằng chứng sự kiện

Ngày thực hiện: 2026-10-02.

## Mục tiêu và quy tắc

Thực nghiệm kiểm tra ảnh hưởng của cách gán nhãn tới kết quả đánh giá; không huấn luyện lại mô hình. Giữ nguyên 605 cửa sổ, 61 đặc trưng, nhãn cũ ở các cửa sổ không đủ điều kiện đổi, và model ExtraTrees đã lưu.

Ưu tiên nhãn attack tại cửa sổ có packet TCP payload **phát từ** `192.168.210.32`, tới PLC `192.168.210.211:4840`, trong chính khoảng `[start, end)` của episode attack. SESSION_BURST cho phép thêm packet SYN phát từ máy kiểm thử, vì tạo kết nối có thể bị PLC trả RST trước khi có payload. Timestamp được cắt xuống mili giây như extractor. Nhãn không được chọn theo dự đoán. Script dừng nếu có nhiều lớp attack cùng đủ điều kiện trong một cửa sổ; lần chạy này không có xung đột.

Đây là bản đối chiếu bổ sung dựa trên sự kiện, không thay thế mặc định định nghĩa majority-overlap của bộ cũ. Giữ lại nhãn attack cũ ngoài điều kiện bổ sung, nên không gọi đây là một bộ ground truth được tái tạo hoàn toàn từ đầu theo duy nhất tiêu chí payload/SYN.

## Kết quả cửa sổ

| Chỉ số | Nhãn cũ | Nhãn sự kiện bổ sung |
|---|---:|---:|
| Attack / benign | 125 / 480 | 147 / 458 |
| TP / FP / TN / FN | 124 / 23 / 457 / 1 | 146 / 1 / 457 / 1 |
| Precision attack | 0,843537 | 0,993197 |
| Recall attack | 0,992000 | 0,993197 |
| F1 attack | 0,911765 | 0,993197 |
| FPR benign | 0,047917 | 0,002183 |
| Macro-F1 trên y_true ∪ y_pred | 0,517804 | 0,872831 |
| Macro-F1 cố định đủ 11 lớp model | 0,470731 | 0,793483 |

22 cửa sổ được đổi từ BENIGN_NORMAL thành attack, gồm: Endpoint Discovery 2, Protocol Fuzz 2, Recursive Browse 1, Behavioral Profiling 6, Invalid Write 4, Slowloris 3, Write Denied 2, Node Browse 2. Các frame bằng chứng được lưu trong `window_label_comparison.csv`. 22 dự đoán không thay đổi; thay đổi là định nghĩa nhãn đối chiếu. Vì thế không diễn giải tăng điểm thành cải tiến mô hình hoặc cơ chế runtime đã loại bỏ warm-up FP.

## Kết quả đủ 28 episode

28/28 episode có bằng chứng traffic theo tiêu chí đã công bố. 28/28 có ít nhất một cửa sổ có bằng chứng được model dự đoán attack; quy tắc argmax và tổng xác suất attack >= 0,5 đều cho 28/28. 27/28 có ít nhất một cửa sổ đúng subtype sau phép gộp INVALID_WRITE/WRITE_DENIED thành MALICIOUS_WRITE. Đây là tiêu chí có ít nhất một cảnh báo, không phải tất cả cửa sổ đúng, không phải precision episode và không chứng minh hành vi thành công.

SESSION_BURST cuối có 15 packet SYN từ máy kiểm thử, mỗi lần PLC trả RST, không có payload trong đoạn. Vì vậy có bằng chứng burst kết nối, nhưng không khẳng định tạo được session OPC UA thành công. Cửa sổ 1788843200000 vẫn là false negative; episode được phát hiện ở cửa sổ khác.

Một false positive còn lại: cửa sổ 1788841495000, nhãn benign, dự đoán BEHAVIORAL_PROFILING. Không tự đổi nhãn cửa sổ này vì không đạt quy tắc bằng chứng trong attack interval.

## Kiểm tra tái lập và giới hạn

- Môi trường scikit-learn 1.8.0 khớp phiên bản model đã lưu.
- Dự đoán của 605 cửa sổ khớp artifact cũ; tái tạo chính xác confusion matrix 124/23/457/1.
- 61 cột đặc trưng không thay đổi; SHA-256 của PCAP, timeline, CSV gốc và model không thay đổi.
- Chưa thêm `opcua.Results` vào đặc trưng, chưa huấn luyện lại và chưa chạy WEB-SCADA.
- Protocol Fuzz có bằng chứng payload, chưa kiểm toán độc lập nội dung malformed. Nhãn hành vi theo kịch bản không tự chứng minh ý đồ hoặc tác động xấu lên PLC.
- Quy tắc bổ sung được xác lập sau khi phân tích lỗi trên OOD2. OOD2 cũng đã tham gia lựa chọn model. Báo cáo cả hai bản như phân tích độ nhạy theo quy tắc nhãn; không gọi điểm mới là kết quả test cuối độc lập hoặc thay thế âm thầm điểm cũ.
- Không kết luận tất cả warm-up là attack: chỉ 22 cửa sổ có packet trong khoảng attack được đổi; các cửa sổ còn lại giữ nguyên.

## Tái chạy

Tại thư mục gốc dự án:

```sh
/home/sus/miniconda3/envs/sus/bin/python tools/reevaluate_ood2_event_labels.py
```

Artifact: `ood2_event_aware.csv`, `window_label_comparison.csv`, `predictions.csv`, `all_28_episode_results.csv`, `classification_report.json`, `confusion_matrix.csv`, `summary.json` trong thư mục báo cáo này.
