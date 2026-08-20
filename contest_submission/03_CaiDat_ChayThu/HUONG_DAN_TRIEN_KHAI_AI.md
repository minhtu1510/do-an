# Hướng dẫn triển khai mô hình AI

Hệ thống AI có 2 phần tách biệt, dùng chung một bộ đặc trưng nhưng phục vụ hai mục
đích khác nhau:

- **`train_ml.py`** (repo gốc) — đánh giá học thuật nhiều mô hình (Random Forest,
  Logistic Regression, XGBoost), nhiều seed, kiểm định chéo theo nhóm chống rò rỉ
  nhãn. Kết quả hiển thị ở trang **Dataset & Model Stats** của Web-SCADA.
- **`train_eval.py`** (repo gốc) — huấn luyện pipeline suy luận 3 tầng (rule-based
  → anomaly detection → ensemble classifier) dùng để **chạy suy luận trực tiếp**
  ngay trong Web-SCADA qua tính năng tải file pcap lên (trang có nút "Upload pcap"
  trong Security/IDS, backend xử lý ở `web_scada/backend/app/ids_upload/`).

Toàn bộ các bước dưới đây chạy từ thư mục gốc mã nguồn (`02_MaNguon_ThuVien/MaNguon/`),
sau khi đã `pip install -r requirements.txt` (script `install.sh`/`install.bat` ở
thư mục này đã cài phần cần cho backend; nếu chạy huấn luyện ngoài backend cần thêm
`pip install pandas numpy scikit-learn xgboost matplotlib seaborn imbalanced-learn`).

## Bước 1 — Thu thập dữ liệu thô

Chạy các kịch bản benign/tấn công đã có sẵn (ví dụ `day1_benign.py`, `day2_dos.py`,
hoặc bộ kịch bản đầy đủ qua `tests/day8/run_day8.py --execute`) trong lúc bắt gói
tin bằng Wireshark/tshark trỏ vào card mạng của testbed. Mỗi lần chạy sinh ra 1 file
`.pcap` gắn nhãn theo kịch bản.

## Bước 2 — Trích xuất đặc trưng

Tuỳ giao thức của lưu lượng bắt được, chạy đúng script:

```bash
python extract_opcua_features.py --pcap capture_day1.pcap --output features_day1.csv --label BENIGN
python extract_s7_features.py    --pcap capture_day2.pcap --output features_day2.csv --plc-ip 192.168.1.10 --label DOS
python extract_dcp_features.py   --pcap capture_day3.pcap --output features_day3.csv --label BENIGN
```

Gộp nhiều file CSV thành một dataset bằng `merge_dataset.py` /
`merge_network_features.py` nếu cần kết hợp nhiều ngày/nhiều giao thức.

## Bước 3a — Huấn luyện & đánh giá học thuật (cho trang Dataset & Model Stats)

```bash
python train_ml.py \
  --network-data "features_day*.csv" \
  --output-dir ml_results \
  --tasks binary multiclass \
  --n-splits 5 \
  --seeds 42 43 44 45 46
```

Kết quả nằm trong `ml_results/` (đường dẫn tự chọn qua `--output-dir`): file
`summary_mean_std.csv` (tổng hợp mean±std theo mô hình), và mỗi lần chạy có
`*_confusion.csv` + `*_feature_importance.csv`.

**Triển khai vào web:** trỏ biến môi trường `ML_RESULTS_DIR` trong
`web_scada/backend/.env` vào thư mục `ml_results` này (hoặc copy thư mục vào máy
chạy backend), sau đó khởi động lại backend. Trang **Dataset & Model Stats**
(`/dataset` trên frontend) sẽ tự đọc và hiển thị — không cần sửa code.

## Bước 3b — Huấn luyện pipeline suy luận 3 tầng (cho tính năng phân tích pcap trực tiếp)

```bash
python train_eval.py --dataset labeled_dataset.csv --mode train --output model/
```

Lệnh này huấn luyện lần lượt: Layer 1 (rule-based), Layer 2 (IsolationForest trên
mẫu BENIGN), Layer 3 (Random Forest + XGBoost ensemble, có SMOTE cân bằng lớp), và
lưu ra thư mục `model/` gồm `layer2_anomaly.joblib`, `layer3_classifier.joblib`,
`features.json`.

Kiểm tra nhanh trên tập test tách riêng trước khi triển khai:

```bash
python train_eval.py --dataset test_dataset.csv --mode eval --model model/
```

**Triển khai vào web:** đặt `IDS_MODEL_DIR` trong `web_scada/backend/.env` trỏ tới
thư mục `model/` này (mặc định backend đã tìm ở `model/` tại thư mục gốc repo, đứng
ngang hàng với `web_scada/`), khởi động lại backend, và cần có `tshark` trong PATH
của máy chạy backend (dùng để trích xuất đặc trưng từ file pcap người dùng tải lên).
Từ đó, mở trang Security/IDS trên Web-SCADA, tải một file `.pcap` bất kỳ lên — hệ
thống tự trích xuất đặc trưng, chạy qua cả 3 tầng, và trả về nhãn dự đoán, độ tin
cậy, và dòng thời gian tấn công ngay trên trình duyệt.

## Lưu ý khi trình diễn trước hội đồng

- Nếu chưa từng chạy Bước 3a, trang Dataset & Model Stats sẽ báo rõ "Not configured"
  thay vì số liệu giả — đây là hành vi đúng, không phải lỗi.
- Nếu chưa từng chạy Bước 3b (`model/` chưa tồn tại), tính năng tải pcap sẽ báo lỗi
  rõ ràng thay vì trả kết quả bịa — hãy huấn luyện trước ít nhất một lần trên máy
  demo và giữ nguyên thư mục `model/` đó.
- Nên chuẩn bị sẵn 1-2 file `.pcap` mẫu (một BENIGN, một tấn công) để demo trực
  tiếp tính năng suy luận AI ngay tại buổi bảo vệ thay vì chỉ trình bày số liệu tĩnh.
