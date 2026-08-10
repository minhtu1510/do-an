# Quy ước thư mục model cho IDS Offline (upload PCAP)

`icsscout/core/ids/model_registry.py` load model theo giao thức, tìm đúng đường dẫn sau:

```
models/<protocol>/model.pkl        # hoặc model.joblib
models/<protocol>/feature_columns.json   # tuỳ chọn
models/<protocol>/label_map.json         # tuỳ chọn
```

`<protocol>` hiện hỗ trợ: `opcua`, `s7` (khớp với `extract_opcua_features.py` /
`extract_s7_features.py`).

## 1. model.pkl / model.joblib (bắt buộc)

Model đã `fit()` xong, load bằng `joblib.load()` (fallback `pickle.load()` nếu
không phải định dạng joblib). Có thể là một sklearn estimator trần hoặc một
`Pipeline` (ví dụ `Pipeline([("scaler", StandardScaler()), ("clf", RandomForestClassifier())])`
giống trong `train_ml.py`).

**Khuyến nghị**: train/fit model bằng một `pandas.DataFrame` (không phải
`numpy.ndarray`) làm `X`. Khi đó sklearn tự lưu `model.feature_names_in_`, và
`model_registry` sẽ dùng đúng danh sách cột + đúng thứ tự này để align với
CSV do extractor sinh ra — không cần file phụ nào khác.

## 2. feature_columns.json (chỉ cần nếu model KHÔNG có feature_names_in_)

Nếu model được fit từ `numpy.ndarray` (không có `feature_names_in_`), cung cấp
danh sách cột đúng thứ tự lúc train:

```json
["opcua_packet_count", "opcua_byte_count", "opcua_frame_len_mean", "..."]
```

Không có file này *và* không có `feature_names_in_` thì hệ thống vẫn chạy,
nhưng dùng nguyên thứ tự cột do extractor sinh ra — **không đảm bảo khớp**
với lúc train, kết quả dự đoán có thể sai lệch. Sẽ có cảnh báo rõ trên UI khi
rơi vào trường hợp này.

## 3. label_map.json (tuỳ chọn)

Chỉ định class nào là "malicious"/"attack" (mặc định đoán tự động: heuristic
theo `model.classes_` — nếu có nhãn dạng "attack"/"malicious"/"1" thì dùng
nhãn đó, hoặc nếu classes là `{0, 1}` thì coi `1` là malicious):

```json
{"positive_class": "attack"}
```

hoặc

```json
{"positive_class": 1}
```

## Ví dụ tối thiểu để tự train + xuất model tương thích

```python
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

df = pd.read_csv("opcua_features_ml_safe.csv")
y = df.pop("label")
X = df  # DataFrame, không convert sang .values

clf = RandomForestClassifier(n_estimators=300, random_state=42)
clf.fit(X, y)

joblib.dump(clf, "models/opcua/model.pkl")
```

Sau khi copy `model.pkl` vào đúng thư mục, trang **IDS (Upload PCAP)**
(`/ids-offline`) sẽ tự nhận diện model có sẵn (không cần restart server —
`model_registry` kiểm tra mtime của file mỗi lần gọi).
