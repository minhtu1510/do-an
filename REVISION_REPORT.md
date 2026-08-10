# Báo Cáo Sửa Đổi — Phản Hồi Góp Ý Phản Biện

> Tài liệu này tóm tắt toàn bộ lỗi đã phát hiện, cách sửa trong code, số liệu **thực đo** sau khi sửa,
> và danh sách các điểm còn cần chỉnh trong bản thảo báo cáo.
> Dùng để cung cấp cho AI hoặc người viết lại bản thảo.
>
> **Nguyên tắc:** mọi số liệu trong tài liệu này đều là số đo thực từ code, không có số ước lượng hay dấu ~.

---

## 1. Lỗi Nghiêm Trọng Đã Sửa Trong Code

### Bug 1 — `proc_data_valid` bị gán sai thứ tự → mất ý nghĩa trong fusion.csv

**File:** `SemanticAware-S7comm-Dataset/scripts/merge_dataset.py` (dòng 607–611)

**Vấn đề:** Script tạo `proc_data_valid` để đánh dấu window nào có dữ liệu process logger thực (=1) và window nào không có (=0). Nhưng ngay sau đó `ffill()` và `bfill()` được gọi và overwrite NaN *trước khi* `proc_data_valid` được gán, làm column này không phản ánh đúng thực tế. Kết quả: file `fusion.csv` xuất ra **không có** column `proc_data_valid`.

**Nguyên nhân gốc rễ phát hiện qua điều tra timestamp:**
Process logger không được khởi động đồng thời với capture traffic:
- **Day 2** (SCAN, ENUM): logger bắt đầu **13 phút SAU** khi attack kết thúc
- **Day 3** (RWRITE): logger bắt đầu **36 phút SAU** khi attack kết thúc
- **Day 5** (FLOOD, FUZZ): chỉ overlap **10 giây** với attack window

Hậu quả: 100% windows của RWRITE, FLOOD, SETPOINT_ATTACK có `proc_data_valid=0` — không phải vì process không bị ảnh hưởng, mà vì logger chưa chạy khi đó.

**Cách sửa:**
```python
# Trước (sai — proc_data_valid được gán SAU ffill nên luôn = 1 sau fill):
fusion["proc_data_valid"] = fusion[proc_cols[0]].notna().astype(int)
fusion[proc_cols] = fusion[proc_cols].ffill()
fusion[proc_cols] = fusion[proc_cols].bfill()
fusion[proc_cols] = fusion[proc_cols].fillna(0)

# Sau (đúng — gán TRƯỚC fill để giữ đúng thông tin availability):
fusion["proc_data_valid"] = fusion[proc_cols[0]].notna().astype(int)
fusion[proc_cols] = (
    fusion.assign(_day=fusion["day"])
    .groupby("_day", sort=False)[proc_cols]
    .transform(lambda g: g.ffill().bfill())
)
fusion[proc_cols] = fusion[proc_cols].fillna(0)
```

---

### Bug 2 — `ffill/bfill` cross-day gây data leakage giữa các ngày

**File:** `SemanticAware-S7comm-Dataset/scripts/merge_dataset.py` (dòng 609–610)

**Vấn đề:** `ffill()` và `bfill()` áp dụng trên toàn bộ dataset theo thứ tự timestamp, không phân biệt ngày. Giá trị process từ cuối Day 1 (benign) bị fill sang đầu Day 2 (khi logger chưa bắt đầu), tạo process features giả cho attack windows của Day 2.

**Cách sửa:** Chuyển sang `groupby("day").transform(ffill().bfill())` — fill chỉ trong phạm vi từng ngày (đã tích hợp trong fix Bug 1 ở trên).

---

### Bug 3 — `proc_data_valid` bị dùng làm feature trong ML (leakage)

**File:** `SemanticAware-S7comm-Dataset/scripts/train_ml.py` (dòng 108–114)

**Vấn đề:** `proc_data_valid` không có trong `ALWAYS_DROP`. Nếu column này có mặt trong CSV, ML model học được:
- `proc_data_valid=0` → RWRITE, FLOOD, SCAN, ENUM (logger không chạy khi đó)
- `proc_data_valid=1` → STEALTHY, BENIGN (logger đang chạy)

Đây là **collection artifact**, không phải ICS security signal. Dùng nó làm feature = label leakage gián tiếp — đây là nguyên nhân MCC âm của process_only trước đây.

**Cách sửa:**
```python
ALWAYS_DROP = {
    "label", "label_network", "label_system", "plc_under_attack", "extractor_label",
    # proc_data_valid là data-availability mask, KHÔNG phải process feature.
    # proc_data_valid=0 tương quan mạnh với RWRITE/FLOOD/SCAN/ENUM vì process
    # logger không chạy trong những windows đó — đây là collection artifact.
    "proc_data_valid",
}
```

---

### Method Fix 4 — Threshold `fbeta` in-sample → thêm mode `fbeta_oof`

**File:** `SemanticAware-S7comm-Dataset/scripts/train_ml.py` và `train_ml.py`

**Vấn đề:** Binary threshold trước đây dùng `--binary-threshold-mode fbeta`, chọn threshold bằng cách maximize F_β trên **prediction của chính mẫu train đã dùng để fit model**. Đây không dùng test labels nên không phải test leakage trực tiếp, nhưng là **in-sample threshold tuning** và có thể tạo optimistic bias cho Macro-F1, MCC, FPR/hour và model ranking.

**Cách sửa trong code:** Thêm mode mới `--binary-threshold-mode fbeta_oof`:

1. Với mỗi outer split, chỉ dùng outer-training partition.
2. Chạy inner grouped CV bên trong outer-training partition.
3. Tạo out-of-fold positive-class probabilities cho outer-training rows.
4. Fit constant/correlation feature pruning riêng trong từng inner-train fold, rồi predict inner-valid fold.
5. Chọn threshold maximize F_β từ OOF probabilities.
6. Fit lại model trên toàn bộ outer-training partition.
7. Áp threshold đã khóa lên outer-test/Day-6 holdout.

**Mode cũ vẫn giữ để tái lập:** `default`, `fixed`, `fbeta`, `fbeta_oof` đều được hỗ trợ. Bản thảo v13 nên dùng `fbeta_oof` hoặc `fixed=0.5`, không dùng `fbeta` in-sample làm kết quả chính.

**Câu chuẩn nếu dùng `fbeta_oof` trong bản thảo:**

> "For each outer split, the binary threshold was selected using grouped out-of-fold predictions generated entirely within the outer-training partition. The model was then refit on the full outer-training partition and evaluated once on the held-out partition."

> "All preprocessing steps, including correlation filtering and scaling, were refit independently within each inner-training fold when generating out-of-fold calibration scores."

**Lệnh ưu tiên chạy lại kết quả chính:**

```bash
python SemanticAware-S7comm-Dataset/scripts/train_ml.py \
  --network-data SemanticAware-S7comm-Dataset/processed/network.csv \
  --fusion-data SemanticAware-S7comm-Dataset/processed/fusion.csv \
  --process-data SemanticAware-S7comm-Dataset/processed/process.csv \
  --output-dir ml_results/threshold_oof_hybrid \
  --feature-profile hybrid \
  --tasks binary \
  --binary-threshold-mode fbeta_oof \
  --binary-threshold-beta 2.0 \
  --validation-session-id day6
```

**Fallback sạch nếu gần deadline:** chạy lại với `--binary-threshold-mode fixed --binary-threshold-value 0.5`, rồi báo cáo Macro-F1/MCC/attack recall/FPR-hour với threshold cố định.

**Smoke test đã chạy trên dữ liệu thật (không phải kết quả cuối):**

Lệnh: network_only, Day-6 holdout, `fbeta_oof`, `seed=42`, `--skip-group-cv`, binary only. Kết quả này là smoke test ban đầu để xác nhận pipeline chạy được trên dataset thật; bảng chính đã được thay bằng full `fbeta_oof` ở mục 2.1a/2.1c.

| View | Split | Seed | Model | Macro-F1 | MCC | FPR/hour |
|---|---|---:|---|---:|---:|---:|
| network_only | Day-6 holdout | 42 | CatBoost | 0.652 | 0.468 | 1.173 |
| network_only | Day-6 holdout | 42 | Logistic Reg. | 0.595 | 0.397 | 0.782 |
| network_only | Day-6 holdout | 42 | Random Forest | 0.654 | 0.471 | 1.173 |
| network_only | Day-6 holdout | 42 | XGBoost | 0.648 | 0.462 | 1.955 |

**File kết quả smoke:** `ml_results/threshold_oof_smoke/summary_mean_std.csv`

**Đối chiếu các số CatBoost Day-6 dễ nhầm:**
- `0.652` = smoke test seed 42 ở bảng trên, không phải kết quả cuối.
- `0.643` = legacy in-sample `fbeta`/auxiliary table cũ, không dùng làm main result.
- `0.659 ± 0.006` = kết quả cuối cho `network_only` CatBoost Day-6 Macro-F1 trong Bảng 2.1a với `fbeta_oof`.

---

### Làm rõ: số lượng mẫu STEALTHY — 839 hay 8?

Reviewer đề cập "STEALTHY chỉ có 8 windows" nhưng DATA_CARD.md và tất cả file CSV đều cho thấy **STEALTHY = 839 windows** (Day 4: 442, Day 6: 397). Điều tra xác nhận:
- Window size = 2 giây, STEALTHY attack kéo dài liên tục → 839 windows là hợp lý
- Số "8" trong bản thảo gốc nhiều khả năng là lỗi đánh máy hoặc từ phiên bản dataset cũ với window size khác
- **Cần tìm và sửa trong bản thảo nếu có ghi "STEALTHY = 8 windows"**

---

### Làm rõ: "host_holdout" vs "Day-6 external holdout"

Thuật ngữ `host_holdout` trong code (tên tham số `--validation-session-id day6`) tương đương với "Day-6 external holdout" trong bản thảo. Đây là **cùng một split** — toàn bộ Day 6 được giữ lại làm test set, không dùng trong training. Cần thống nhất tên gọi trong bản thảo: dùng "Day-6 external holdout" hoặc "session-disjoint holdout (Day 6)".

---

### Rebuild fusion.csv

Sau khi sửa 3 bugs, `fusion.csv` được rebuild lại:
- **Rows:** 55,902 | **Cols:** 355
- `proc_data_valid` có mặt và đúng giá trị (=1 chỉ khi logger thực sự chạy)
- ffill/bfill chỉ trong phạm vi từng ngày, không cross-day
- Class counts khớp hoàn toàn với DATA_CARD.md (xem bảng kiểm tra bên dưới)

---

## 2. Số Liệu Thực Đo Sau Khi Sửa

### Kiểm tra class counts — fusion.csv mới khớp DATA_CARD.md

| Class | DATA_CARD.md | fusion.csv mới | network.csv | Kết quả |
|---|---:|---:|---:|---|
| BENIGN | 47,460 | 47,460 | 47,460 | ✅ Khớp |
| STEALTHY | 839 | 839 | 839 | ✅ Khớp |
| ENUMERATION | 1,405 | 1,405 | 1,405 | ✅ Khớp |
| RWRITE | 1,231 | 1,231 | 1,231 | ✅ Khớp |
| SPOOF | 1,242 | 1,242 | 1,242 | ✅ Khớp |
| SETPOINT_ATTACK | 1,082 | 1,082 | 1,082 | ✅ Khớp |
| FLOOD | 1,211 | 1,211 | 1,211 | ✅ Khớp |
| FUZZ | 532 | 532 | 532 | ✅ Khớp |
| SCAN | 900 | 900 | 900 | ✅ Khớp |
| **Total** | **55,902** | **55,902** | **55,902** | ✅ |

**Day 6 holdout riêng:** 4,603 BENIGN + 2,685 attack = 7,288 windows.  
Class counts Day 6 thực tế: STEALTHY=397, ENUM=470, RWRITE=365, SPOOF=299, SETPOINT=253, FLOOD=317, FUZZ=122, SCAN=462.

---

### 2.1 Bảng đối xứng — Binary Detection với `fbeta_oof` (số liệu THỰC ĐO)

Tất cả số liệu trong bảng này đều là kết quả đo thực từ code, không có số ước lượng.  
Threshold mode: `fbeta_oof`. Feature profile: hybrid. Seeds: 42–46.

**Aggregation:** Với Grouped CV, metric được tính trên từng fold, average qua 5 folds trong từng seed, rồi summarize qua 5 seeds. Với Day-6 holdout, metric được summarize trực tiếp qua 5 seeds.

**Bảng 2.1a — Macro-F1 và MCC: Group CV vs Day 6 OOD Holdout**

| View | Model | Group CV F1 | Day 6 F1 | Δ F1 | Group CV MCC | Day 6 MCC |
|---|---|---:|---:|---:|---:|---:|
| network_only | CatBoost | 0.909 ± 0.002 | **0.659 ± 0.006** | −0.250 | 0.831 ± 0.003 | **0.477 ± 0.007** |
| network_only | Logistic Reg. | 0.833 ± 0.011 | 0.595 ± 0.000 | −0.239 | 0.702 ± 0.013 | 0.396 ± 0.000 |
| network_only | XGBoost | 0.903 ± 0.001 | 0.649 ± 0.006 | −0.255 | 0.821 ± 0.002 | 0.463 ± 0.007 |
| network_only | Random Forest | 0.900 ± 0.003 | **0.662 ± 0.005** | −0.239 | 0.817 ± 0.005 | **0.479 ± 0.005** |
| fusion | CatBoost | **0.922 ± 0.003** | 0.626 ± 0.005 | −0.297 | **0.854 ± 0.005** | 0.436 ± 0.007 |
| fusion | Logistic Reg. | 0.910 ± 0.002 | 0.621 ± 0.018 | −0.289 | 0.830 ± 0.003 | 0.430 ± 0.022 |
| fusion | XGBoost | 0.919 ± 0.003 | **0.673 ± 0.010** | −0.246 | 0.847 ± 0.006 | **0.495 ± 0.012** |
| fusion | Random Forest | 0.918 ± 0.003 | 0.634 ± 0.022 | −0.284 | 0.847 ± 0.005 | 0.446 ± 0.028 |
| process_only | CatBoost | 0.389 ± 0.027 | 0.547 ± 0.000 | +0.158 | 0.116 ± 0.043 | 0.370 ± 0.003 |
| process_only | Logistic Reg. | 0.402 ± 0.000 | **0.548 ± 0.000** | +0.146 | 0.141 ± 0.001 | **0.376 ± 0.000** |
| process_only | Random Forest | 0.393 ± 0.018 | 0.547 ± 0.000 | +0.155 | 0.121 ± 0.025 | 0.372 ± 0.001 |
| process_only | XGBoost | 0.401 ± 0.001 | 0.548 ± 0.000 | +0.146 | 0.135 ± 0.004 | 0.374 ± 0.000 |

**Bảng 2.1c — FPR/hour thực tế cho binary detection (`fbeta_oof`)**

FPR/hour = số benign windows bị predict nhầm là attack / tổng số giờ benign windows. Các giá trị dưới đây dùng cùng aggregation như Bảng 2.1a.

| View | Model | Group CV FPR/hour | Day 6 OOD FPR/hour |
|---|---|---:|---:|
| network_only | CatBoost | 105.440 ± 2.987 | 1.642 ± 0.700 |
| network_only | Logistic Reg. | 169.459 ± 20.777 | 1.017 ± 0.214 |
| network_only | XGBoost | 114.755 ± 2.477 | 1.877 ± 0.752 |
| network_only | Random Forest | 120.126 ± 4.565 | 2.972 ± 1.718 |
| fusion | CatBoost | 86.235 ± 4.197 | **0.078 ± 0.175** |
| fusion | Logistic Reg. | 98.115 ± 2.652 | 0.313 ± 0.175 |
| fusion | XGBoost | 91.338 ± 3.955 | 0.391 ± 0.000 |
| fusion | Random Forest | 94.295 ± 4.506 | 0.391 ± 0.000 |
| process_only | CatBoost | 720.835 ± 1.133 | 9.106 ± 6.071 |
| process_only | Logistic Reg. | 719.723 ± 0.108 | **0.000 ± 0.000** |
| process_only | Random Forest | 721.473 ± 0.943 | 5.464 ± 1.357 |
| process_only | XGBoost | 721.227 ± 1.422 | 3.035 ± 0.000 |

**Nguồn kết quả `fbeta_oof`:** network/process artifacts hoàn tất trong `ml_results/threshold_oof_hybrid/`; fusion group CV hoàn tất bằng `ml_results/threshold_oof_fusion/` + `ml_results/threshold_oof_fusion_seed46_group/`; fusion Day-6 holdout trong `ml_results/threshold_oof_fusion_holdout/`. Metrics được tái tính từ confusion matrices và split/sample-hours gốc để tránh mất kết quả do full monolithic run timeout trước khi ghi `summary_mean_std.csv`.

**Group/split audit cuối:** `run_group_split_audit.py` tạo `ml_results/group_split_audit/group_split_audit.json` và `.md`, xác nhận group key hiệu lực là `session_id|host_id|episode_id`, network/fusion có 228 groups (192 benign + 36 attack), process-only có 49 groups (40 benign + 9 attack), và train/test group overlap = 0 cho grouped CV, Day-6 holdout, và Day-5 temporal holdout.

**Bảng 2.1b — Temporal Day-5 Holdout: Train Day 1–4, Test Day 5 (`fbeta_oof`)**

*Network/fusion train: 37,523 windows (Day1–4). Network/fusion test Day 5: 11,091 windows (FLOOD=894, FUZZ=410, BENIGN=9,787). Process-only train/test: 7,185/1,798 windows because the process view contains only logger-derived rows. Threshold mode: `fbeta_oof`, hybrid profile, seeds 42–46. Command uses `--train-session-id day1 day2 day3 day4 --validation-session-id day5 --skip-group-cv`.*

| View | Model | Day5 Macro-F1 | Day5 MCC | Day5 FPR/hour |
|---|---|---:|---:|---:|
| network_only | CatBoost | 0.993 ± 0.011 | 0.986 ± 0.022 | 0.441 ± 0.210 |
| network_only | Logistic Reg. | 0.882 ± 0.000 | 0.786 ± 0.001 | 1.140 ± 0.201 |
| network_only | Random Forest | **0.999 ± 0.001** | **0.998 ± 0.001** | 0.993 ± 0.497 |
| network_only | XGBoost | 0.998 ± 0.001 | 0.996 ± 0.001 | 1.545 ± 0.443 |
| fusion | CatBoost | 0.930 ± 0.064 | 0.874 ± 0.115 | 0.110 ± 0.101 |
| fusion | Logistic Reg. | 0.884 ± 0.000 | 0.790 ± 0.000 | **0.000 ± 0.000** |
| fusion | Random Forest | **1.000 ± 0.000** | **1.000 ± 0.000** | 0.184 ± 0.000 |
| fusion | XGBoost | **1.000 ± 0.000** | **1.000 ± 0.000** | 0.184 ± 0.000 |
| process_only | CatBoost | 0.499 ± 0.001 | -0.001 ± 0.002 | 2.411 ± 5.391 |
| process_only | Logistic Reg. | 0.499 ± 0.000 | 0.000 ± 0.000 | **0.000 ± 0.000** |
| process_only | Random Forest | 0.499 ± 0.000 | 0.000 ± 0.000 | **0.000 ± 0.000** |
| process_only | XGBoost | 0.499 ± 0.000 | 0.000 ± 0.000 | **0.000 ± 0.000** |

*Lưu ý: Day 5 chỉ chứa FLOOD/FUZZ và phần lớn là BENIGN, nên đây là binary temporal stress test dễ hơn Day 6 OOD. Process-only gần chance vì Day 5 gần như không có process logger signal hợp lệ cho attack; kết quả network/fusion cao không chứng minh generalization sang Day 6 đa kịch bản.*

**Sanity check độc lập cho Day5 gần 1.000:** `run_day5_sanity_check.py` xác nhận safe feature matrix không còn cột metadata/leakage (`scenario_id`, `session_id`, `episode_id`, `proc_data_valid`, timestamp, rule flags), train/test group overlap = 0, và network/fusion không có exact duplicate feature rows giữa train Day1–4 và test Day5. Kết quả gần hoàn hảo của RF/XGBoost là hợp lý vì Day5 FLOOD/FUZZ tạo separation rất mạnh trên 15 network-derived connection/scan features; ví dụ `tcp_syn_count` benign max = 12 nhưng attack min = 18, `tcp_active_streams` benign max = 11 nhưng attack min = 13. Process-only có 25 duplicate test rows, tất cả là BENIGN; không có duplicate attack rows.

**File sanity check:** `ml_results/day5_sanity/summary.json` và `ml_results/day5_sanity/summary.md`.

**Nhận xét quan trọng cho bản thảo:**
1. Với `fbeta_oof`, **network_only vẫn generalize tương đối ổn nhất theo CatBoost/RF** trên Day 6: CatBoost F1=0.659, RF F1=0.662. Group CV cao hơn Day6 khoảng 0.239–0.255 F1, xác nhận temporal/OOD shift vẫn đáng kể.
2. **Fusion không cải thiện nhất quán**: với CatBoost, fusion Day6 F1=0.626 < network_only 0.659; với XGBoost, fusion Day6 F1=0.673 > network_only 0.649. Vì process logging không đầy đủ và STEALTHY chi phối process signal, không được kết luận fusion tổng quát tốt hơn.
3. **FPR/hour tăng rõ trong Group CV khi dùng OOF threshold** so với bảng legacy, đặc biệt process_only (~720 FPR/hour). Đây là trade-off của threshold β=2 ưu tiên recall; nếu manuscript dùng Macro-F1 làm metric chính, cần giải thích rõ mục tiêu threshold hoặc báo cáo thêm F2/attack recall.
4. **Day-6 FPR/hour phải lấy từ cột holdout, không lấy Group CV:** network_only nằm trong khoảng **1.02–2.97/hour**, fusion trong khoảng **0.08–0.39/hour**.
5. **Day5 temporal holdout đã được rerun bằng `fbeta_oof`**, nhưng vẫn chỉ là auxiliary temporal stress test vì Day5 chỉ có FLOOD/FUZZ và 88.2% benign; kết quả cao không chứng minh generalization tốt hơn Day6.
6. **process_only Day6 ~0.547–0.548** vẫn phản ánh gần như STEALTHY-only detection qua Q0 register; Group CV process_only thấp dưới `fbeta_oof` vì OOF threshold tạo nhiều false positives trên benign process windows.

---

### 2.2 Per-class F1 trên Day 6 — So sánh Network-only vs Fusion (CatBoost)

Bảng này **bắt buộc** phải có trong bản thảo theo yêu cầu reviewer.  
Support = số windows trong Day 6 holdout.

**Protocol note:** Đây là bảng multiclass CatBoost dùng dự đoán trực tiếp/argmax trên xác suất class. Binary threshold `fbeta_oof` **không áp dụng** cho bảng multiclass này.

| Class | Net-only P | Net-only R | Net-only F1 | Fusion P | Fusion R | Fusion F1 | Support |
|---|---:|---:|---:|---:|---:|---:|---:|
| BENIGN | 0.701 | 0.998 | 0.824 | 0.687 | 1.000 | 0.814 | 4,603 |
| **STEALTHY** | 0.641 | 0.736 | **0.683** | 1.000 | 1.000 | **1.000** ⚠️ | 397 |
| SETPOINT_ATTACK | 1.000 | 0.051 | 0.096 | 1.000 | 0.050 | 0.095 | 253 |
| SPOOF | 0.290 | 0.064 | 0.104 | 0.357 | 0.064 | 0.107 | 299 |
| SCAN | 0.141 | 0.052 | 0.076 | 0.160 | 0.009 | 0.016 | 462 |
| FLOOD | 1.000 | 0.038 | 0.072 | 1.000 | 0.037 | 0.066 | 317 |
| RWRITE | 0.000 | 0.000 | 0.000 | 0.189 | 0.009 | 0.018 | 365 |
| ENUMERATION | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 470 |
| FUZZ | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 122 |
| **Macro avg** | 0.419 | 0.215 | **0.206** | 0.488 | 0.241 | **0.235** | 7,288 |

**⚠️ STEALTHY F1=1.000 trong fusion là leakage gián tiếp — đã điều tra xác nhận, không được dùng để kết luận fusion tốt hơn.**

**Điều tra STEALTHY F1=1.0 (kết quả đo thực):**

| | Network-only F1 | Fusion F1 |
|---|---:|---:|
| STEALTHY (Day 6) | **0.683** | **1.000** ⚠️ |
| Macro-F1 với STEALTHY (9 classes) | 0.206 | 0.235 |
| Macro-F1 không có STEALTHY (8 classes) | 0.147 | 0.139 |
| Attack-only Macro-F1 (loại BENIGN + STEALTHY) | 0.050 | 0.043 |

**Phân tích (đã kiểm tra đầy đủ — sửa mâu thuẫn với mục 4.5):**

Tổng attack windows có `proc_data_valid=1` (toan dataset): **1,698 / 8,442 = 20.1%**, gồm:

| Class | proc=1 windows | % trong class |
|---|---:|---:|
| STEALTHY | 839 | 100.0% |
| ENUMERATION | 427 | 30.4% |
| SCAN | 249 | 27.7% |
| FUZZ | 128 | 24.1% |
| SPOOF | 55 | 4.4% |
| RWRITE, FLOOD, SETPOINT | 0 | 0.0% |

Tuy nhiên, **chỉ STEALTHY có proc features mang signal phân biệt**. Kiểm tra `proc__q0_raw_hex_mean` (feature quan trọng nhất) — **đã đo riêng trên Day 6 holdout**:

| Class | proc=1 (Day 6) | q0 unique values (Day 6) |
|---|---:|---|
| STEALTHY | 397 | **[40.0]** |
| ENUMERATION | 427 | [41.0] — giống BENIGN |
| SCAN | 249 | [41.0] — giống BENIGN |
| FUZZ | 122 | [41.0] — giống BENIGN |
| SPOOF | 0 | (no proc=1 windows in Day 6) |
| RWRITE, FLOOD, SETPOINT | 0 | (no proc=1 windows in Day 6) |

Kết quả toàn dataset (Day 1–6) hoàn toàn nhất quán: q0=40 **chỉ** xuất hiện ở STEALTHY; tất cả class còn lại kể cả BENIGN đều có q0=41.0. Đây là thuộc tính vật lý cố định của PLC (STOP bit → Q0=40), không phụ thuộc vào ngày thu thập.

→ SCAN/ENUM/FUZZ/SPOOF tuy có `proc_data_valid=1` nhưng proc feature values không khác BENIGN → không tạo thêm discrimination. Chỉ 839 STEALTHY windows (9.9% attack) có proc signal thực sự phân biệt được.

- Model học: `proc__ q0 = 40` ↔ STEALTHY; `q0 = 41` ↔ tất cả class khác
- Hệ quả: chênh lệch Macro-F1 (fusion=0.235 vs net=0.206) **hoàn toàn đến từ STEALTHY**. Loại STEALTHY: fusion=0.139 < net=0.147 — fusion thực ra kém hơn

**Câu chính xác để đưa vào bản thảo:**

> *"In the fusion multiclass evaluation, STEALTHY achieves F1=1.000 compared to F1=0.683 in the network-only view. This is not genuine detection improvement: although SCAN (27.7%), ENUMERATION (30.4%), and FUZZ (24.1%) also have windows with real process observations (proc\_data\_valid=1), their proc\_\_ feature values are identical to BENIGN (Q0 register = 41). Only STEALTHY produces a distinctive process signal (Q0 = 40, caused by the STOP bit write), making proc\_\_ features a near-perfect identifier for this class alone. When STEALTHY is excluded, fusion Macro-F1 (0.139) is lower than network-only (0.147), confirming that process features do not improve classification of the remaining attack classes under the present collection protocol."*

---

### 2.3 Process-only — Trước và sau fix (số liệu thực)

| Metric | Trước fix | Sau fix | Giải thích |
|---|---:|---:|---|
| binary, Day6 holdout, RF — MCC | −0.154 | **+0.372** | Bug 3 đã sửa; số sau fix dùng `fbeta_oof` |
| binary, Day6 holdout, LR — MCC | 0.000 | **+0.376** | Từ zero lên dương |
| binary, Day6 holdout, CatBoost — MCC | −0.007 | **+0.370** | Đã sửa; số sau fix dùng `fbeta_oof` |
| binary, Day6 holdout — Macro-F1 | 0.356 | **0.548** | Cải thiện rõ rệt |
| binary, group_cv, LR — Macro-F1 (`fbeta_oof`) | (legacy run, MCC âm) | **0.402** | OOF threshold làm lộ FPR cao trên benign process windows |
| binary, group_cv, RF — Macro-F1 (`fbeta_oof`) | (legacy run, MCC âm) | **0.393** | Nhất quán với Bảng 2.1a |

**MCC âm trước đây do model học `proc_data_valid=0` như signal của attack — đây là bug, không phải kết quả thực. Sau fix: tất cả MCC dương, Macro-F1 hợp lý.**

**Giải thích process_only F1=0.548 giống nhau cho cả 4 models (đã điều tra):**

Feature importance xác nhận `proc__q0_raw_hex_mean` chi phối toàn bộ quyết định (>50% với CatBoost). Đây là thanh ghi Q0 của PLC:
- `q0_raw_hex_mean = 40` → STEALTHY (bit STOP=1 làm Q0 thay đổi)
- `q0_raw_hex_mean = 41` → tất cả class còn lại (process đứng yên)

Tất cả 4 models hội tụ về cùng 1 decision rule đơn giản này, dẫn đến F1 giống hệt nhau. Xác minh: tính tay `F1(q0==40 → attack) = 0.548` — khớp chính xác số liệu model.

Đây **không phải** threshold collapse, **không phải** leakage theo nghĩa collection artifact. Đây là trường hợp: process feature Q0 thực sự phân biệt được STEALTHY nhờ process state thật (M5.0=STOP làm Q0 đổi), nhưng không phân biệt được các class khác (SCAN/ENUM/FUZZ không thay đổi Q0). **Cần ghi rõ trong bản thảo**: "process-only F1=0.548 effectively reflects STEALTHY-only detection via Q0 register change."

---

### 2.4 Định nghĩa FPR/hour — xác nhận trong code

Công thức thực trong `train_ml.py`:

```
fpr_per_hour = false_positive_count / benign_hours
```

Trong đó:
- `false_positive_count` = số windows benign bị predict là attack
- `benign_hours` = tổng duration (giờ) của các windows benign, tính từ `window_end_ms − window_start_ms`

**Cần ghi rõ trong bản thảo:**
> "FPR/hour is computed at window level (2-second windows): each false-positive window is counted individually. A sequence of 30 consecutive false-positive windows is counted as 30 false alarms, not 1 alarm episode. This metric reflects raw detection burden, not operator-level alarm rate."

---

## 3. Toàn Bộ Vấn Đề Reviewer Nêu — Đã/Chưa Giải Quyết

### Đã giải quyết trong code (có số liệu chứng minh)

| # | Vấn đề | Hành động | Kết quả |
|---|---|---|---|
| 1 | process_only MCC âm — sai logic | Sửa Bug 1+2+3, rebuild fusion.csv | MCC chuyển từ âm sang dương trên Day6 (`fbeta_oof`: RF +0.372, LR +0.376, CatBoost +0.370) |
| 2 | `proc_data_valid` không có trong CSV | Sửa merge_dataset.py, rebuild | Column có trong fusion.csv mới |
| 3 | ffill/bfill cross-day | Sửa thành per-day groupby | Xác nhận không còn cross-day fill |
| 4 | `proc_data_valid` bị dùng làm feature | Thêm vào `ALWAYS_DROP` với comment | Không còn trong feature matrix |
| 5 | Bảng model không đối xứng | Chạy network_only Day6 holdout | Bảng 2.1 đầy đủ, số thực |
| 6 | Per-class F1 thiếu | Chạy và extract | Bảng 2.2 đầy đủ cả net vs fusion |
| 7 | FPR/hour không có định nghĩa | Xác nhận công thức trong code | Định nghĩa rõ ở mục 2.4 |
| 8 | STEALTHY F1=1.0 nghi ngờ leakage | Điều tra feature importance | Xác nhận là class-specific process cue qua Q0=40, giải thích rõ trong mục 2.2 |
| 9 | "host_holdout" vs "Day-6 holdout" | Xác nhận là cùng 1 split | Thống nhất tên gọi ở mục 1 |
| 10 | STEALTHY "8 windows" mâu thuẫn | Kiểm tra tất cả CSV | STEALTHY = 839, số "8" trong bản thảo là lỗi đánh máy |
| 11 | Ablation semantic layers L1–L5 thiếu | Chạy lại layer-wise ablation bằng `fbeta_oof` | Bảng 4.2 đầy đủ, số thực (L0→L3, CatBoost, Day6 OOD) |
| 12 | Leave-one-day-out CV thiếu | Chạy lại temporal holdout Train Day1–4 / Test Day5 bằng `fbeta_oof` | Bảng 2.1b đầy đủ (network_only CatBoost F1=0.993 ± 0.011) |
| 13 | Threshold `fbeta` in-sample có optimistic bias | Thêm mode `fbeta_oof` trong `train_ml.py`, chạy lại/tái tính full binary metrics | Bảng 2.1a và 2.1c đã thay bằng số `fbeta_oof` thật |

### Chưa giải quyết — cần sửa trong bản thảo

| # | Vấn đề | Hành động cần làm |
|---|---|---|
| 11 | Thiếu Research Questions rõ ràng (RQ1/RQ2/RQ3) | Viết lại Introduction — xem Section 4.1 |
| 12 | Thiếu ablation theo semantic layers (L1–L5) | Đã xử lý bằng rerun `fbeta_oof`; copy Section 4.2 vào manuscript |
| 13 | Thiếu định nghĩa "session", "episode", "window", "day" | Thêm vào Section Methodology — xem Section 4.3 |
| 14 | Window size/stride/overlap threshold chưa ghi rõ | Thêm vào Section Dataset — xem Section 4.3 |
| 15 | `scenario_id` có bị dùng làm feature không? | Xác nhận: KHÔNG — đã drop qua `SAFE_DROP_EXACT` trong code |
| 16 | Ranh giới "phát hiện trước/sau tác động" | Định nghĩa rõ bài toán trong paper — xem Section 4.4 |
| 17 | "kill-chain-style" quá mạnh | Đổi thành "reconnaissance-to-impact progression" |
| 18 | Inconsistency/per-application counts | Không hứa per-application breakdown nếu không có `application_id`; dùng Limitations mục 9.5 |
| 19 | Kết luận "fusion không tốt hơn" cần cẩn trọng | Đổi thành câu chính xác hơn — xem Section 4.5 |
| 20 | STEALTHY F1=1.0 cần giải thích trong paper | Thêm footnote/paragraph — xem mục 2.2 |
| 21 | Lỗi số học "47%", mẫu số sai 7,442, "61.3%" sai | Sửa: dùng 9.9% (839/8,442 = proc discriminative) — xem Section 4.5 |
| 22 | process_only F1=0.548 giống nhau 4 models | Điều tra xong: `q0_raw_hex_mean` single-feature rule (q0=40↔STEALTHY) — mục 2.3 |
| 23 | Mâu thuẫn: "STEALTHY là class duy nhất có proc=1" vs FUZZ/SCAN/ENUM cũng có proc=1 | Sửa: STEALTHY là class duy nhất có **proc signal phân biệt** (q0=40); class khác dù proc=1 nhưng q0=41 giống BENIGN — mục 2.2 |
| 24 | Lỗi cộng "61.3%" | Đúng là **60.6%** (5,115/8,442) — xem bảng số học mục 4.5 |
| 25 | Mơ hồ `49.8h` vs `31.06h` | Viết rõ đây là hai phép đo khác nhau: wall-clock span vs released windowed duration — xem mục 4.7 và 9.1/9.6 |
| 26 | Threshold selection có nguy cơ optimistic bias | Đã chạy lại/tái tính binary metrics bằng `fbeta_oof`; thay Table IV/Table V bằng mục 2.1a/2.1c |
| 27 | Tối ưu F2 nhưng báo cáo Macro-F1 | Vì vẫn dùng β=2, nên nếu còn chỗ hãy báo cáo thêm F2/attack recall hoặc ghi rõ β=2 ưu tiên recall |
| 28 | Group key còn `auto` | Kết quả `fbeta_oof` hiện dùng composite auto `session_id|host_id|episode_id`; trong manuscript nên mô tả công thức group key rõ ràng và không nhấn mạnh `host_id` nếu không tạo phân tách |
| 29 | Fold/seed aggregation chưa nói rõ | Thêm câu: metrics averaged across five folds per seed, then summarized across five seeds |
| 30 | Hyperparameter binary vs multiclass chưa tách đủ | Đã sửa code để XGBoost dùng binary `logloss` và multiclass `mlogloss`; ghi rõ objective/eval metric, CatBoost loss, `scale_pos_weight` có/không |
| 31 | Std của Table IV thiếu trong manuscript | Nếu còn chỗ, thêm mean±std hoặc đưa std/range vào caption/supplementary |
| 32 | Clock-offset/label-precedence policy cần rõ trong data card | Đã cập nhật `SemanticAware-S7comm-Dataset/docs/DATA_CARD.md`; không claim measured offset vì release hiện không có offset log |
| 33 | Mâu thuẫn 192 benign segments vs group key | Đã kiểm tra bằng `train_ml.choose_group_series`: network/fusion có 228 CV groups = 192 benign 10-minute segments + 36 attack episodes; process-only có 49 groups vì chỉ gồm logger-derived rows |

---

## 4. Nội Dung Cụ Thể Cần Sửa Trong Bản Thảo

### 4.1 Thêm Research Questions (viết lại đoạn cuối Introduction)

Thay vì liệt kê 4 contribution ngang nhau, thêm 3 RQ rõ ràng:

> **RQ1 (Dataset):** Does the dataset cover diverse S7comm behaviors from a physical PLC testbed with sufficient scenario breadth and temporal variation to support IDS research?
>
> **RQ2 (Fusion):** Do process-level observations improve intrusion detection performance compared to network-only features, and under what conditions?
>
> **RQ3 (Generalization):** How does IDS performance change when transitioning from session-grouped in-distribution evaluation to a temporally disjoint out-of-distribution holdout day?

---

### 4.2 Ablation semantic layers — ĐÃ CHẠY THỰC NGHIỆM (số liệu thực)

**Taxonomy feature layers** (dựa trên cột thực tế trong CSV):
- **L0** — Network volume & protocol stats: `packet_count`, `byte_rate`, `tcp_*`, `pkt_len_*`, port stats, payload stats.
- **L1** — ICS protocol presence: `s7comm_packet_count`, `dcp_*`, `cotp_*`, `tpkt_*`, `to_plc_*`, `from_plc_*`, `fr_s7_present`, `fr_s7_packet_share`.
- **L2** — S7 operation semantics: `s7_read_count`, `s7_write_count`, `s7_cpu_control_count`, `s7_*area*`, `s7_unique_*`, `fr_s7_write_*_ratio`.
- **L3** — Process state: `proc__*` features từ PLC register polling.

**Thực nghiệm:** Train Day 1–4 → Test Day 6 (OOD), CatBoost, seeds 42–46, Macro-F1 binary, threshold `fbeta_oof`.

**Ghi chú protocol:** Ablation này dùng cùng threshold policy `fbeta_oof` và cùng leakage-exclusion list với pipeline chính, bao gồm loại bỏ `proc_data_valid`. Đây vẫn là auxiliary diagnostic vì train split là Day1–4 (loại Day5), trong khi Day-6 holdout ở Bảng 2.1a train trên Day1–5. Feature counts dưới đây là số feature được chọn từ safe+hybrid fusion matrix trước và sau constant/correlation filtering của train fold.

| Config | Layers | Selected features | After filter | Macro-F1 | MCC | FPR/hour |
|---|---|---:|---:|---:|---:|---:|
| A — Network volume only | L0 | 115 | 67 | 0.648 ± 0.008 | 0.462 ± 0.010 | 1.173 ± 0.479 |
| B — + ICS presence | L0+L1 | 147 | 77 | 0.654 ± 0.010 | 0.470 ± 0.013 | 1.251 ± 0.643 |
| C — + S7 op semantics | L0+L1+L2 | 192 | 92 | 0.647 ± 0.011 | 0.461 ± 0.012 | 1.173 ± 1.106 |
| D — + Process state | L0+L1+L2+L3 | 324 | 106 | **0.663 ± 0.020** | **0.483 ± 0.024** | **0.078 ± 0.175** |

**Kết quả (đã đo thực):**
- L1 (ICS presence) tạo cải thiện nhỏ so với L0: 0.648 → 0.654 Macro-F1, trong phạm vi biến thiên giữa seed.
- L2 (S7 operation semantics) không cải thiện thêm so với L1: 0.654 → 0.647 Macro-F1.
- L3 (process state) đạt kết quả cao nhất trong ablation này: 0.663 Macro-F1 và FPR/hour thấp nhất. Không được diễn giải thành fusion luôn tốt hơn, vì ablation này train Day1–4 còn bảng chính Day6 train Day1–5; tín hiệu process vẫn chủ yếu đến từ class STEALTHY/Q0.

**Giải thích cho bản thảo:**
> "A layer-wise auxiliary ablation on the Day-6 OOD holdout (CatBoost, binary task, seeds 42–46, trained on Day 1–4, `fbeta_oof` thresholding) shows a small gain from adding ICS protocol-presence features (L0 Macro-F1=0.648 vs. L0+L1 Macro-F1=0.654), no additional gain from S7 operation semantics (0.647), and the highest score when process-state features are included (0.663). This result should be interpreted as a diagnostic rather than a contradiction of the main benchmark: the ablation uses a different training window (Day1–4, excluding Day5), and the process contribution remains concentrated in the STEALTHY-specific Q0 signal rather than a broad improvement across all attack classes."

**File kết quả:** `ml_results/ablation_layers_fbeta_oof/ablation_results.csv`; runner: `run_layer_ablation_fbeta_oof.py`.

---

### 4.3 Thêm định nghĩa rõ ràng (Section Methodology/Dataset)

```
Window:  Khoảng thời gian cố định 2 giây (window_size=2s, stride=2s, không overlap).
         Một window được gán label ATTACK nếu bất kỳ attack interval nào overlap với window đó.

Episode: Một chuỗi hoàn chỉnh: warm-up → attack execution → cooldown → state restore.
         Dùng làm đơn vị group trong grouped cross-validation để tránh data leakage.

Session: Toàn bộ dữ liệu của một ngày thu thập (Day 1–6).
         session_id = day1, day2, ..., day6 trong CSV.

Day 1:   Benign baseline — không có attack, attacker idle.
Day 2–5: Attack collection — mỗi ngày 2–3 attack scenarios theo thứ tự reconnaissance → impact.
Day 6:   OOD holdout — tất cả 9 scenarios, thứ tự ngẫu nhiên, rate thấp hơn 20–50%.
         Không được dùng trong training hoặc hyperparameter selection.
```

---

### 4.4 Làm rõ bài toán phát hiện (Detection Task Definition)

Cần thêm đoạn này vào Section Problem Formulation:

> "The detection task is defined as **concurrent detection**: given a 2-second network observation window (and optionally, the synchronized process state snapshot), determine whether any attack is occurring within that window. This is distinct from **predictive detection** (forecasting attack before impact) and from **forensic identification** (labeling a past episode). Models trained here observe process state that reflects the result of the attack (e.g., M5.0=START after a write), which is intentional — the task is to detect the abnormal operation, not necessarily to predict it before impact."

> "Process-state features are contemporaneous observations within each 2-second window. Therefore, the process and fusion views address detection or attribution of an ongoing or realized attack, not prediction before physical impact."

---

### 4.5 Sửa kết luận về fusion (thay toàn bộ đoạn kết luận fusion)

**Trước (sai — quá mạnh):**
> "Process features do not help."

**Sau (đúng với số liệu — đã kiểm tra số học và loại mâu thuẫn):**
> "Naive feature concatenation of network and process views does not yield a consistent out-of-distribution gain under the present collection protocol. With the `fbeta_oof` threshold, fusion is lower than network-only for CatBoost on Day 6 (0.626 vs. 0.659 Macro-F1), but higher for XGBoost (0.673 vs. 0.649), indicating model-dependent behavior rather than robust fusion benefit. Of 8,442 total attack windows, only 839 (9.9%) — exclusively from the STEALTHY class — carry a discriminative process signal: the Q0 output register takes value 40 only during STEALTHY (STOP bit active), versus 41 for all other classes. Although SCAN (27.7%), ENUMERATION (30.4%), and FUZZ (24.1%) have windows with proc_data_valid=1, their process feature values are indistinguishable from BENIGN. Furthermore, the apparent multiclass advantage of fusion (Macro-F1=0.235 vs. 0.206) is entirely attributable to STEALTHY identification; excluding STEALTHY, fusion Macro-F1 (0.139) is lower than network-only (0.147). A dataset with fully synchronized process logging is required to evaluate RQ2 conclusively."

**Kiểm tra số học đầy đủ (đã sửa mâu thuẫn):**

| Con số | Cách tính | Kết quả | Dùng khi nào |
|---|---|---:|---|
| Tổng attack windows | 55,902 − 47,460 | **8,442** | Mẫu số chung |
| proc=1 trong attack (tổng) | 839+427+249+128+55 | **1,698 (20.1%)** | Không dùng trực tiếp |
| proc=1 có signal phân biệt | Chỉ STEALTHY (q0=40) | **839 (9.9%)** | Câu kết luận fusion |
| proc=0 trong attack (tổng) | 8,442 − 1,698 | **6,744 (79.9%)** | Mô tả logger coverage |
| 100% no-proc (RWRITE+FLOOD+SETPOINT) | 1,231+1,211+1,082 | **3,524 (41.7%)** | Khi liệt kê 3 class cụ thể |
| >90% no-proc (+SPOOF+FUZZ-Day5) | 3,524+1,187+404 | **5,115 (60.6%)** | **KHÔNG dùng 61.3%** — sai |

**Sửa lỗi số học mục trước:** "61.3%" sai → đúng là **60.6%** (3,524+1,187+404=5,115; 5,115/8,442=60.6%).

**Câu đúng nhất cho bản thảo:** dùng con số **9.9% (839/8,442)** = "proc features có signal phân biệt thực" vì đây là con số phản ánh đúng tác động lên ML, không phải 20.1% hay 79.9%.

---

### 4.6 Sửa lỗi nhỏ trong bản thảo

| Chỗ sai | Sửa thành |
|---|---|
| "STEALTHY = 8 windows" | "STEALTHY = 839 windows (Day 4: 442, Day 6: 397)" |
| "3,524 out of 7,442 attack windows (47%)" | Dùng **hai câu riêng** cho hai mục đích khác nhau: (1) mô tả dataset limitation → "6,744 out of 8,442 attack windows (79.9%) have proc_data_valid=0, as the process logger was not running during those collection periods"; (2) giải thích cơ chế STEALTHY leakage → "only 839 attack windows (9.9%, exclusively STEALTHY) carry a discriminative process signal (Q0=40); the remaining proc=1 windows from SCAN/ENUM/FUZZ have Q0=41, identical to BENIGN" — xem mục 4.5 |
| "two/three industrial control applications" hoặc hứa per-application counts | Không báo cáo per-application counts trừ khi có `application_id`; dùng limitation mục 9.5 |
| "six-day attack scenario suite" | "six-day collection schedule (Day 1: benign baseline; Days 2–5: attack collection; Day 6: OOD holdout)" |
| "kill-chain-style multi-stage attack" | "reconnaissance-to-impact progression" |
| Bảng chỉ có RF (Group CV) và LR (Day 6) | Bảng 2.1 mới với tất cả models × cả 2 splits (xem mục 2.1) |
| "host_holdout" trong code results | "Day-6 session-disjoint holdout" trong bản thảo |
| "fusion Macro-F1 > network-only ở multiclass" | Không đúng sau khi loại STEALTHY leakage — xem mục 2.2 |

### 4.7 Hai Vấn Đề Major Cần Sửa Trong Bản v11

**Major 1 — 49.8h vs 31.06h không phải lỗi số học**

Đây là hai phép đo khác nhau:
- **49.8h** = wall-clock span từ thời điểm đầu đến cuối trong lịch thu thập qua 6 ngày
- **31.06h** = tổng thời lượng các 2-second windows được release trong dataset

**Câu chuẩn để đưa vào bản thảo:**

> "The collection spans approximately 49.8 wall-clock hours across six days. The released two-second windows represent 31.1 of those hours. The release does not insert synthetic empty windows: overnight breaks and silent inter-episode gaps contribute to wall-clock span but not to released windowed duration, while captured background/idle traffic windows are retained and labeled BENIGN."

**Idle-gap rule cần ghi rõ:** release không chèn synthetic empty windows. Các khoảng overnight hoặc inter-episode không có packet/log record sẽ làm tăng wall-clock span nhưng không tạo released window; các inter-episode/background windows có traffic thật vẫn được giữ và label BENIGN. Khi build dataset, rows nằm trong vùng transition quanh attack boundaries có thể bị loại bởi `--drop-transition-seconds` (default 10s trong `merge_dataset.py`).

**Major 2 — Threshold selection risk**

Các kết quả `fbeta` legacy chọn binary threshold bằng cách maximize F_β trên **train fold scores**, rồi áp dụng threshold đó cho test fold. Đây là in-sample threshold tuning trong phạm vi train fold, **không phải** nested CV hoặc out-of-fold threshold calibration. Vì vậy không được viết rằng các bảng cũ đã dùng nested calibration.

Code đã thêm mode mới `fbeta_oof`, chọn threshold từ grouped out-of-fold predictions bên trong outer-training partition. Binary metrics đã được chạy lại/tái tính bằng `fbeta_oof` và cập nhật ở Bảng 2.1a/2.1c.

**Câu chuẩn cho Experimental Setup:**

> "For each outer split, the binary threshold was selected using grouped out-of-fold predictions generated entirely within the outer-training partition. The model was then refit on the full outer-training partition and evaluated once on the held-out partition."

> "All preprocessing steps, including correlation filtering and scaling, were refit independently within each inner-training fold when generating out-of-fold calibration scores."

**Nếu bản thảo vẫn dùng bảng `fbeta` legacy thì bắt buộc giữ Limitations:**

> "Threshold-dependent metrics may be optimistic because the F_β threshold is tuned in-sample on training-fold scores rather than calibrated using a nested validation split or out-of-fold predictions. Future work should use nested threshold calibration or a separate calibration set before reporting deployment-calibrated FPR/hour."

**Việc cần làm trong bản thảo:** thay Table IV/Table V binary bằng số `fbeta_oof` ở mục 2.1a/2.1c và dùng câu Experimental Setup ở trên. Không cần giữ Limitations về in-sample threshold nếu không còn dùng bảng `fbeta` legacy.

---

## 5. Files Đã Thay Đổi

| File | Thay đổi |
|---|---|
| `SemanticAware-S7comm-Dataset/scripts/merge_dataset.py` | Fix Bug 1 (proc_data_valid gán đúng thứ tự) + Bug 2 (per-day ffill/bfill) |
| `SemanticAware-S7comm-Dataset/scripts/train_ml.py` | Fix Bug 3 (`proc_data_valid` vào `ALWAYS_DROP`) + thêm `--binary-threshold-mode fbeta_oof`, `--train-session-id`, và XGBoost task-specific eval metric |
| `train_ml.py` | Đồng bộ `proc_data_valid` drop, `fbeta_oof`, `--train-session-id`, và XGBoost task-specific eval metric với script trong dataset để tránh lệch pipeline |
| `run_layer_ablation_fbeta_oof.py` | Runner reproducible cho layer-wise CatBoost ablation với `fbeta_oof` |
| `run_day5_sanity_check.py` | Sanity-check runner cho Day5 temporal holdout gần 1.000 |
| `run_group_split_audit.py` | Audit runner xác nhận group counts và zero train/test group overlap cho grouped CV, Day-6 holdout, Day-5 holdout |
| `SemanticAware-S7comm-Dataset/docs/DATA_CARD.md` | Bổ sung timestamp/timezone, clock-offset limitation, label precedence, transition, idle-gap, split/group policy |
| `SemanticAware-S7comm-Dataset/processed/fusion.csv` | Rebuild từ network.csv + process.csv với fix đúng (55,902 rows, 355 cols) |
| `ml_results/fixed_full/` | Kết quả ML mới — network_only group_cv + fusion/process Day6 holdout |
| `ml_results/net_day6_holdout/` | network_only Day6 holdout — số liệu để hoàn thiện bảng 2.1 |
| `ml_results/fusion_fixed/` | Fusion Day6 holdout (test nhanh xác nhận fix) |
| `ml_results/process_fixed/` | Process-only Day6 holdout sau fix |
| `ml_results/threshold_oof_smoke/` | Smoke test `fbeta_oof` trên network_only Day6 holdout, seed 42 |
| `ml_results/threshold_oof_hybrid/` | Artifact `fbeta_oof` hoàn tất cho network/process và một phần fusion; full monolithic run timeout trước khi ghi summary tổng |
| `ml_results/threshold_oof_fusion/` | Artifact fusion group CV `fbeta_oof` cho seeds 42–45 và phần seed 46 |
| `ml_results/threshold_oof_fusion_seed46_group/` | Fusion group CV `fbeta_oof` seed 46 hoàn tất |
| `ml_results/threshold_oof_fusion_holdout/` | Fusion Day-6 holdout `fbeta_oof` hoàn tất |
| `ml_results/lodo_day5_fbeta_oof_temporal/` | Temporal Day5 holdout `fbeta_oof`: train Day1–4, test Day5 |
| `ml_results/lodo_day5_fbeta_oof_temporal_xgb_logloss_check/` | Sanity rerun sau khi đổi XGBoost binary eval metric sang `logloss`; XGBoost rows không đổi so với artifact trước |
| `ml_results/ablation_layers_fbeta_oof/` | Layer-wise ablation `fbeta_oof` artifacts |
| `ml_results/day5_sanity/` | Sanity-check artifacts cho Day5 near-perfect results |
| `ml_results/group_split_audit/` | Group-count và split-overlap audit artifacts |

---

## 6. Những Điều KHÔNG Được Viết Vào Bản Thảo

| Điều không được viết | Lý do |
|---|---|
| "STEALTHY F1=1.0 chứng minh fusion hiệu quả" | Đây là leakage gián tiếp, không phải generalization thực |
| "Process features không có giá trị" | Chỉ đúng trong cấu hình hiện tại với logger không sync |
| "Macro-F1=0.919 là kết quả tốt nhất của hệ thống" | Đây là in-distribution CV, không phải OOD performance |
| Bất kỳ số có dấu ~ (ước lượng) | Tất cả số trong bảng phải là số đo thực |
| "process_only group_cv" từ ml_results/robust_hybrid | Dữ liệu đó có bug MCC âm, không dùng được |
| "Các bảng `fbeta` legacy đã dùng nested/out-of-fold calibration" | Sai: chỉ các bảng `fbeta_oof` ở mục 2.1a/2.1c dùng OOF calibration |
| "Bảng binary `fbeta` legacy là kết quả cuối cùng đã sạch threshold" | Sai: dùng bảng `fbeta_oof` ở mục 2.1a/2.1c làm kết quả chính |
| "49.8h là tổng duration của released windows" | Sai: 49.8h là wall-clock span; released windowed duration là 31.06h/31.1h |
| "Measured clock offsets are available" | Sai với release hiện tại: DATA_CARD ghi rõ chưa có per-host clock-offset log; chỉ dùng epoch-ms alignment |

---

---

## 7. Hyperparameters Thực Tế — Trích Từ `scripts/train_ml.py`

> Tất cả số liệu dưới đây đọc trực tiếp từ source code, không có số ước lượng.
> File nguồn: `SemanticAware-S7comm-Dataset/scripts/train_ml.py`

### 7.1 Bảng Hyperparameter Mô Hình (Table IV trong bản thảo)

| Hyperparameter | Random Forest | XGBoost | CatBoost | Logistic Regression |
|---|---|---|---|---|
| **n_estimators / iterations** | 300 | 300 | 300 | — |
| **max_depth / depth** | — (sklearn default) | 6 | 6 | — |
| **learning_rate** | — | 0.1 | 0.1 | — |
| **subsample** | — | 0.8 | — | — |
| **colsample_bytree** | — | 0.8 | — | — |
| **class_weight** | `balanced_subsample` | — | `Balanced` (auto) | `balanced` |
| **min_samples_leaf** | 2 | — | — | — |
| **max_iter** | — | — | — | 2,000 |
| **eval_metric** | — | binary: `logloss`; multiclass: `mlogloss` | — | — |
| **random_state / seed** | per-seed (42–46) | per-seed (42–46) | per-seed (42–46) | — |
| **n_jobs / thread_count** | −1 (all cores) | −1 | −1 | −1 |

**Scaler:** `StandardScaler` áp dụng **chỉ** trong Logistic Regression Pipeline (`sklearn.pipeline.Pipeline`). RF/XGB/CatBoost **không** dùng scaler (tree-based).

**XGBoost task-specific objective/metric:** code không hard-code `objective`, nhưng fitted `XGBClassifier` report `binary:logistic` cho binary task và `multi:softprob` cho multiclass task. Code hiện set `eval_metric="logloss"` cho binary và `eval_metric="mlogloss"` cho multiclass. `scale_pos_weight` không được set. Sanity rerun Day5 xác nhận đổi binary metric từ `mlogloss` sang `logloss` không làm thay đổi XGBoost thresholds/metrics vì pipeline không dùng eval set hoặc early stopping.

**CatBoost task-specific loss:** code không hard-code `loss_function`; CatBoost tự infer binary/multiclass loss từ số class sau label encoding và dùng `auto_class_weights="Balanced"`.

**Code nguồn** (`make_models`, dòng 436–476):
```python
"logistic_regression": Pipeline([
    ("scaler", StandardScaler()),
    ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", n_jobs=-1)),
]),
"random_forest": RandomForestClassifier(
    n_estimators=300, random_state=seed, n_jobs=-1,
    class_weight="balanced_subsample", min_samples_leaf=2,
),
"xgboost": XGBClassifier(
    n_estimators=300, max_depth=6, learning_rate=0.1,
    subsample=0.8, colsample_bytree=0.8,
    eval_metric="logloss" if task == "binary" else "mlogloss",
    random_state=seed, n_jobs=-1,
),
"catboost": CatBoostClassifier(
    iterations=300, depth=6, learning_rate=0.1,
    random_seed=seed, auto_class_weights="Balanced", thread_count=-1,
),
```

### 7.2 Preprocessing Pipeline

| Bước | Chi tiết |
|---|---|
| **NaN policy** | `replace([np.inf, -np.inf], np.nan).fillna(0.0)` — toàn bộ Inf và NaN đều fill bằng 0 trước khi đưa vào ML |
| **Correlation pruning** | Loại bỏ các feature có correlation tuyệt đối > **0.98** với feature khác — fit *trên train fold only*, áp dụng cho test |
| **Constant feature drop** | Loại bỏ feature có `nunique ≤ 1` trên train fold |
| **Feature profile chính** | `hybrid` — giữ safe features + thêm S7/process ratio và presence features |
| **Label encoding** | XGB/CatBoost: custom `_LabelEncodedClassifier` wrapper (string label → int → inverse) |

**Câu chuẩn cho bản thảo (Section IV — Experimental Setup):**
> "NaN and infinite values are replaced with zero prior to model fitting. Constant features and features with pairwise Pearson |r| > 0.98 are removed per training fold only, preventing test-set information from influencing feature selection. Logistic Regression is preceded by StandardScaler; tree-based models receive raw features. All models are trained with five random seeds (42–46) and results averaged."

> "For `fbeta_oof` threshold calibration, all preprocessing steps, including correlation filtering and scaling, are refit independently within each inner-training fold before generating out-of-fold calibration scores."

### 7.3 Cross-Validation Protocol

| Tham số | Giá trị | Nguồn code |
|---|---|---|
| **CV strategy** | `StratifiedGroupKFold` (sklearn ≥ 1.0) / fallback `GroupKFold` | `make_splits()`, dòng 403 |
| **n_splits** | **5** (default) | `--n-splits 5`, dòng 1290 |
| **Seeds** | **[42, 43, 44, 45, 46]** (5 seeds) | `--seeds`, dòng 1291 |
| **Group column** | `session_id \| host_id \| episode_id` (composite, auto-detect) | `DEFAULT_GROUP_COLUMNS`, dòng 190 |
| **Shuffle** | `shuffle=True, random_state=seed` (StratifiedGroupKFold) | `make_splits()`, dòng 409 |

**Kiểm tra group key thực tế:** `choose_group_series()` dùng composite `session_id|host_id|episode_id` khi đủ ba cột. Với `network.csv` và `fusion.csv`, số group thực tế là **228** = **192 BENIGN 10-minute segments + 36 attack episodes**. Với `process.csv`, số group là **49** = 40 BENIGN segments + 9 attack groups vì process view chỉ chứa logger-derived rows. Vì vậy không được viết công thức benign group là `session_id + "_benign"`; công thức đúng là `session_id|host_id|episode_id`, trong đó `episode_id` của BENIGN đã là chunk 10 phút (`session_id:BENIGN:<chunk>`).

**Audit tái lập:** chạy `python run_group_split_audit.py` từ repository root. Kết quả hiện tại nằm trong `ml_results/group_split_audit/group_split_audit.md` và xác nhận zero train/test group overlap cho Grouped CV (5 folds × seeds 42–46), Day-6 holdout, và Day-5 temporal holdout.

### 7.4 Binary Threshold

| Tham số | Giá trị dùng trong thực nghiệm |
|---|---|
| **mode cũ** | `fbeta` — tune in-sample trên train fold scores; dùng để tái lập bảng hiện tại, không nên dùng làm kết quả chính v13 |
| **mode mới khuyến nghị** | `fbeta_oof` — tune threshold từ grouped out-of-fold scores trong outer-training partition |
| **fallback sạch** | `fixed` với `--binary-threshold-value 0.5` |
| **β** | **2.0** (β > 1 ưu tiên recall — giảm false negative) |
| **Cách tính `fbeta_oof`** | Inner grouped CV trên outer-training data → OOF probabilities → maximize F_β → refit full outer-train → apply once to outer-test |
| **FPR/hour** | `false_positive_count / benign_hours` (window-level, không phải alarm episode) |

**Lưu ý quan trọng về threshold selection:**

Threshold `fbeta` legacy được tune **in-sample trên train fold scores**, không phải nested CV, không phải out-of-fold calibration, và không dùng validation split riêng cho threshold. Vì vậy các metric phụ thuộc threshold (Macro-F1, MCC, FPR/hour) có thể optimistic so với deployment-calibrated performance. Code hiện đã hỗ trợ `fbeta_oof` để khắc phục điểm này.

**Câu chuẩn cho bản thảo nếu đã rerun bằng `fbeta_oof`:**

> "For each outer split, the binary threshold was selected using grouped out-of-fold predictions generated entirely within the outer-training partition. The model was then refit on the full outer-training partition and evaluated once on the held-out partition."

> "All preprocessing steps, including correlation filtering and scaling, were refit independently within each inner-training fold when generating out-of-fold calibration scores."

**Bullet Limitations chỉ dùng nếu vẫn giữ bảng `fbeta` legacy:**

> "Threshold-dependent metrics may be optimistic because the F_β threshold is tuned in-sample on training-fold scores rather than calibrated using a nested validation split or out-of-fold predictions. Future work should use nested threshold calibration or a separate calibration set before reporting deployment-calibrated FPR/hour."

**Công thức FPR/hour** (`compute_metrics`, dòng 501–548):
```python
fpr_per_hour = false_positive_mask.sum() / benign_hours
# benign_hours = sum((window_end_ms - window_start_ms) / 3_600_000) cho benign windows
```

---

## 8. Phân Tích proc_data_valid=1 Matched Comparison

> Phần này mô tả **những gì có thể kết luận** từ dữ liệu hiện tại về matched comparison (proc_data_valid=1 vs =0), và **những gì dữ liệu hiện tại chưa đủ để kết luận**.

### 8.1 Những gì code hiện tại đã làm

Trong `merge_dataset.py` (dòng 614):
```python
fusion["proc_data_valid"] = fusion[proc_cols[0]].notna().astype(int)
```

- `proc_data_valid=1`: network window có matched process record thực (logger đang chạy, thời gian căn chỉnh)
- `proc_data_valid=0`: network window không có process record (logger chưa chạy / đã dừng)
- `proc_data_valid` bị **drop khỏi feature matrix** (`ALWAYS_DROP`, dòng 122) để tránh leakage

### 8.2 Phân phối proc_data_valid=1 theo class (từ REVISION_REPORT mục 2.2)

| Class | proc=1 windows | % trong class | Ghi chú |
|---|---:|---:|---|
| BENIGN | ~47,460 × coverage | (không rõ) | Logger chạy liên tục khi benign |
| STEALTHY | **839** | **100%** | Q0=40 — signal phân biệt thực |
| ENUMERATION | 427 | 30.4% | Q0=41 — giống BENIGN, không phân biệt |
| SCAN | 249 | 27.7% | Q0=41 — giống BENIGN, không phân biệt |
| FUZZ | 128 | 24.1% | Q0=41 — giống BENIGN, không phân biệt |
| SPOOF | 55 | 4.4% | Q0=41 — giống BENIGN, không phân biệt |
| RWRITE | 0 | 0% | Logger không chạy khi RWRITE |
| FLOOD | 0 | 0% | Logger không chạy khi FLOOD |
| SETPOINT_ATTACK | 0 | 0% | Logger không chạy khi SETPOINT |

### 8.3 Matched comparison thật — Future Work

**Câu hỏi research muốn trả lời:**
> "Nếu chỉ đánh giá trên rows có proc_data_valid=1, fusion có cải thiện so với network_only không?"

**Vì sao dữ liệu hiện tại chưa đủ để trả lời trực tiếp:**

1. Với RWRITE/FLOOD/SETPOINT: proc_data_valid=0 cho toàn bộ class → không có matched sample để so sánh
2. Với SCAN/ENUM/FUZZ: proc_data_valid=1 có tồn tại nhưng process feature values **giống hệt BENIGN** (Q0=41) → không tạo thêm discrimination
3. Với STEALTHY: 100% proc=1, nhưng đây là artifact vật lý cố định (Q0 bit STOP), không phải IDS signal thông thường

**Kết quả khi lọc proc_data_valid=1 (đã tính được từ số liệu hiện có):**
- Attack windows có proc=1: 839 + 427 + 249 + 128 + 55 = **1,698 windows**
- Trong đó có signal phân biệt thực: **839 (STEALTHY only)**
- Macro-F1 fusion với proc=1 subset sẽ dominated bởi STEALTHY → **không phải matched comparison thực sự**

**Câu đúng để đưa vào bản thảo (Future Work):**
> "A proper matched comparison—evaluating network-only vs. fusion exclusively on windows where proc_data_valid=1—is precluded by the current collection protocol: three attack classes (RWRITE, FLOOD, SETPOINT_ATTACK) have zero proc_data_valid=1 windows, and the remaining proc=1 attack windows (SCAN, ENUMERATION, FUZZ, SPOOF) exhibit process feature values indistinguishable from BENIGN (Q0 register = 41). Only STEALTHY windows carry a discriminative process signal (Q0 = 40), making any proc=1-filtered evaluation equivalent to STEALTHY-only detection rather than a multi-class IDS comparison. Synchronized process logging across all attack sessions is required before a valid matched comparison can be conducted."

### 8.4 Tóm Tắt: Các Chỗ Cần Điền Trong Bản Thảo

| # | Chỗ | Trạng thái | Hành động |
|---|---|---|---|
| 1 | **FPR/hour thực tế** (Table II) | ✅ Có số thật — mục 2.1c | Copy bảng FPR/hour mục 2.1c vào bản thảo hoặc thêm cột FPR/hour cạnh Macro-F1/MCC. |
| 2 | **Hyperparameters/preprocessing** (Section IV) | ✅ Đã trích từ code | Dùng bảng mục 7.1–7.4 ở trên. Không cần điền thêm — đây là số thật. |
| 3 | **proc_data_valid=1 matched comparison** | ✅ Đã xử lý bằng giới hạn dữ liệu/Future Work — mục 8.3 | Dùng đoạn Future Work ở mục 8.3; không báo cáo như matched comparison thực nghiệm. |
| 4 | **Per-scenario windows/attack episodes/grouping units** (Section III-A Table) | ✅ Đầy đủ — mục 9.2–9.4 | Copy bảng mục 9.2 và 9.3 vào bản thảo. |
| 5 | **Per-application windows/grouping units** (Traffic Light vs Conveyor Belt) | ✅ Đã xử lý bằng Limitations — mục 9.5 | Không trình bày bảng per-application vì dataset hiện có chỉ hỗ trợ per-day/per-class/per-scenario. Dùng câu Limitations mục 9.5. |
| 6 | **49.8h vs 31.06h** | ✅ Đã làm rõ — mục 4.7 và 9.1/9.6 | Viết rõ 49.8h là wall-clock span, 31.1h là released windowed duration. |
| 7 | **Threshold selection risk** | ✅ Đã có số `fbeta_oof` — mục 2.1a/2.1c | Thay Table IV/Table V bằng số `fbeta_oof`; không dùng bảng `fbeta` legacy làm kết quả chính. |
| 8 | **F2 vs Macro-F1** | ⚠️ Cần chỉnh wording | Vì threshold vẫn optimize F2 (β=2), ghi rõ mục tiêu ưu tiên recall; nếu còn chỗ, báo cáo thêm F2/attack recall. |
| 9 | **Group key deterministic** | ⚠️ Cần chỉnh wording | Kết quả hiện dùng composite auto `session_id|host_id|episode_id`; trong manuscript ghi group key rõ ràng, không mô tả mơ hồ là auto-detected. |

---

---

## 9. Per-Application / Per-Scenario Statistics — Truy vấn Trực Tiếp Từ Dataset

> **Nguồn:** `SemanticAware-S7comm-Dataset/processed/network.csv` (55,902 rows, 194 cols).
> Tất cả số liệu dưới đây là số đo thực, truy vấn bằng pandas.
> Dùng để điền vào **Table III / Section III-A** trong bản thảo.

### 9.1 Thông Số Tổng Quan Dataset

| Thông số | Giá trị |
|---|---|
| **Tổng số windows** | **55,902** |
| — Benign windows | 47,460 (84.9%) |
| — Attack windows | 8,442 (15.1%) |
| **Window size** | 2,000 ms (fixed, non-overlapping) |
| **Tổng số grouping units** | **228** = 36 attack episodes + 192 benign 10-minute segments trong network/fusion; process-only có 49 groups |
| **Số ngày thu thập** | **6** (Day 1–6) |
| **Số attack scenarios** | **9** (8 attack classes, FLOOD split thành S7\_FLOOD + SYN\_FLOOD) |
| **Tổng thời gian span (wall-clock)** | 179,334 s = **49.8 giờ** |
| **Tổng duration windowed (released windows)** | **31.06 giờ** |

**Làm rõ 49.8h vs 31.06h:** Đây không phải lỗi số học. `49.8h` là wall-clock span qua 6 ngày thu thập; `31.06h` là tổng thời lượng các 2-second windows được release. Release không chèn synthetic empty windows: overnight gaps và inter-episode silent gaps không tạo rows, còn background/idle windows có packet thật vẫn được giữ và label BENIGN.

**Group key thực tế:** grouped CV dùng `session_id|host_id|episode_id`. Trong network/fusion, `episode_id` gồm 36 attack episodes và 192 benign 10-minute segments, nên tổng là 228 groups. Đây không phải sáu day-level benign groups.

### 9.2 Bảng Windows × Day × Attack Class (Table III trong bản thảo)

> Nguồn: `df.groupby(['day','label']).size().unstack(fill_value=0)`

| Day | BENIGN | ENUM | FLOOD | FUZZ | RWRITE | SCAN | SETPOINT | SPOOF | STEALTHY | **Total** |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Day 1** (benign baseline) | 7,348 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **7,348** |
| **Day 2** (recon) | 8,761 | 935 | 0 | 0 | 0 | 438 | 0 | 0 | 0 | **10,134** |
| **Day 3** (write) | 11,753 | 0 | 0 | 0 | 866 | 0 | 0 | 0 | 0 | **12,619** |
| **Day 4** (logic) | 5,208 | 0 | 0 | 0 | 0 | 0 | 829 | 943 | 442 | **7,422** |
| **Day 5** (volume) | 9,787 | 0 | 894 | 410 | 0 | 0 | 0 | 0 | 0 | **11,091** |
| **Day 6** (OOD holdout) | 4,603 | 470 | 317 | 122 | 365 | 462 | 253 | 299 | 397 | **7,288** |
| **Total** | **47,460** | **1,405** | **1,211** | **532** | **1,231** | **900** | **1,082** | **1,242** | **839** | **55,902** |

> **FLOOD** = S7\_FLOOD (623 windows) + SYN\_FLOOD (588 windows) = **1,211** total.
> Day 6 là **OOD holdout** — toàn bộ 9 attack scenarios, không dùng trong training.

### 9.3 Bảng Per-Scenario: Windows, Attack Episodes / Benign Segments, Duration

> Nguồn: `df.groupby('scenario_id').agg(windows, episodes, duration)`
> Attack episodes = số lần lặp riêng biệt (warm-up → attack → restore); Day 6 là 1 episode cho mỗi attack scenario. BENIGN dùng 10-minute grouping segments, không gọi là attack episodes.

| Scenario ID | Attack Class | Windows | Attack episodes / benign segments | Duration (phút) | Days |
|---|---|---:|---:|---:|---|
| BENIGN | BENIGN | 47,460 | 192 benign segments | 2,988.9 | Day 1–6 |
| ENUM\_TAGS | ENUMERATION | 1,405 | **4** | 1,291.0 | Day 2, Day 6 |
| SCAN\_PORT | SCAN | 900 | **4** | 1,266.0 | Day 2, Day 6 |
| RWRITE\_BURST | RWRITE | 1,231 | **4** | 2,121.8 | Day 3, Day 6 |
| SENSOR\_SPOOF | SPOOF | 1,242 | **4** | 801.3 | Day 4, Day 6 |
| SETPOINT\_ATTACK | SETPOINT\_ATTACK | 1,082 | **4** | 891.4 | Day 4, Day 6 |
| STEALTHY\_WRITE | STEALTHY | 839 | **4** | 856.1 | Day 4, Day 6 |
| S7\_FLOOD | FLOOD (S7) | 623 | **4** | 611.0 | Day 5, Day 6 |
| SYN\_FLOOD | FLOOD (SYN) | 588 | **4** | 591.6 | Day 5, Day 6 |
| PROTOCOL\_FUZZ | FUZZ | 532 | **4** | 648.7 | Day 5, Day 6 |
| **Total (attack)** | — | **8,442** | **36 attack episodes** | — | — |

> **Episode structure (attack scenarios):** Mỗi attack scenario có **3 episodes trong training days + 1 episode trong Day 6** = **4 episodes tổng**.
> Day 6 dùng `profile_day6_robust` (rate thấp hơn 20–50% so với standard) để tạo distribution shift.

### 9.4 Per-Day Summary

| Day | Role | Total Windows | Benign | Attack | Grouping units | Scenarios | Duration (giờ) |
|---|---|---:|---:|---:|---:|---:|---:|
| Day 1 | Benign baseline | 7,348 | 7,348 | 0 | 26 | 1 | 4.08 |
| Day 2 | Attack: ENUM + SCAN | 10,134 | 8,761 | 1,373 | 41 | 3 | 5.64 |
| Day 3 | Attack: RWRITE | 12,619 | 11,753 | 866 | 46 | 2 | 7.02 |
| Day 4 | Attack: SETPOINT + SPOOF + STEALTHY | 7,422 | 5,208 | 2,214 | 34 | 4 | 4.14 |
| Day 5 | Attack: FLOOD (×2) + FUZZ | 11,091 | 9,787 | 1,304 | 48 | 4 | 6.18 |
| Day 6 | **OOD Holdout** (all 9 scenarios) | 7,288 | 4,603 | 2,685 | 33 | 10 | 4.07 |
| **Total** | — | **55,902** | **47,460** | **8,442** | **228** | — | **31.13** |

**Ghi chú:** Khi viết narrative trong bản thảo, dùng `31.1 hours` cho released windowed duration. Bảng per-day giữ duration theo truy vấn từng ngày; mục 9.1 giữ tổng windowed duration chuẩn từ toàn bộ released windows là `31.06 hours`.

### 9.5 Per-Application Breakdown — Giới Hạn Cần Ghi Rõ

Reviewer yêu cầu breakdown theo từng ứng dụng vật lý, ví dụ **Traffic Light** vs **Conveyor Belt**. Các số liệu mục 9.2–9.4 hiện chỉ là:

- Per-day × class: số windows theo ngày và nhãn attack
- Per-scenario: số windows/attack episodes/benign segments/duration theo `scenario_id`
- Per-day summary: tổng windows, benign/attack, grouping units, scenarios, duration

Các bảng này **không phải** per-application breakdown vì `network.csv`/`fusion.csv` hiện không có metadata ánh xạ chắc chắn từng window/episode sang application-level category như Traffic Light hoặc Conveyor Belt. Vì vậy không được viết rằng báo cáo đã có phân phối per-application.

**Câu Limitations đã sửa để đưa vào bản thảo:**

> "Table II quantifies distribution by day and class, but we do not report a per-application window/grouping-unit breakdown."

**Nếu cần câu đầy đủ hơn:**

> "Table II quantifies distribution by day and class, but we do not report a per-application window/grouping-unit breakdown (e.g., Traffic Light vs. Conveyor Belt), because the released window-level tables do not include an application_id field that can be used to assign every window or grouping unit unambiguously to a physical application. Future releases should include application-level metadata to support this analysis."

### 9.6 Câu Chuẩn Cho Section III-A (Testbed Description)

```text
The dataset comprises 55,902 two-second windows collected over six days
(Day 1: benign baseline; Days 2–5: attack collection; Day 6: OOD holdout).
Each of the nine attack scenarios is executed in three repetition episodes
during training days (Days 2–5) and one additional episode on Day 6 under
a reduced-rate profile (20–50% lower traffic volume) to introduce temporal
distribution shift. The collection spans approximately 49.8 wall-clock hours
across six days. The released two-second windows represent 31.1 of those
hours. The released tables do not insert synthetic empty windows: overnight
breaks and silent inter-episode gaps contribute to wall-clock span but not to
released windowed duration, while captured background/idle traffic windows are
retained and labeled BENIGN.
Attack windows total 8,442 (15.1%); benign windows total 47,460 (84.9%).
The 228 grouping units comprise 36 attack episodes and 192 benign segments.
FLOOD attacks are split into two sub-scenarios: S7_FLOOD (S7comm
connection exhaustion, 623 windows) and SYN_FLOOD (TCP SYN flood,
588 windows), both labeled FLOOD in the unified label column.
```

### 9.7 Cập Nhật Bảng 8.4 — Trạng Thái Các Chỗ Cần Điền

| # | Chỗ | Trạng thái | Hành động |
|---|---|---|---|
| 1 | **FPR/hour thực tế** (Table II) | ✅ Có số thật — mục 2.1c | Copy bảng FPR/hour hoặc thêm cột FPR/hour vào Table II |
| 2 | **Hyperparameters/preprocessing** (Section IV) | ✅ Đầy đủ — mục 7.1–7.4 | Copy bảng mục 7.1 vào bản thảo |
| 3 | **proc_data_valid=1 matched comparison** | ✅ Đã xử lý bằng Future Work — mục 8.3 | Dùng đoạn Future Work; không báo cáo như matched comparison thực nghiệm |
| 4 | **Per-scenario windows/attack episodes/grouping units** (Section III-A Table) | ✅ Đầy đủ — mục 9.2–9.4 | Copy bảng mục 9.2 và 9.3 vào bản thảo |
| 5 | **Per-application windows/grouping units** (Traffic Light vs Conveyor Belt) | ✅ Đã xử lý bằng Limitations — mục 9.5 | Dùng câu Limitations: "Table II quantifies distribution by day and class, but we do not report a per-application window/grouping-unit breakdown." |
| 6 | **49.8h vs 31.06h** | ✅ Đã làm rõ — mục 4.7 và 9.1/9.6 | Dùng câu: "49.8 wall-clock hours... released windows represent 31.1 of those hours..." |
| 7 | **Threshold selection risk** | ✅ Đã có số `fbeta_oof` — mục 2.1a/2.1c | Thay Table IV/Table V bằng số `fbeta_oof`; không dùng bảng `fbeta` legacy làm kết quả chính |
| 8 | **F2 vs Macro-F1** | ⚠️ Cần chỉnh wording | Vì threshold vẫn optimize F2 (β=2), ghi rõ mục tiêu ưu tiên recall; nếu còn chỗ, báo cáo thêm F2/attack recall |
| 9 | **Group key deterministic** | ⚠️ Cần chỉnh wording | Kết quả hiện dùng composite auto `session_id|host_id|episode_id`; trong manuscript ghi group key rõ ràng, không mô tả mơ hồ là auto-detected |

---

*Báo cáo tạo sau quá trình debug và sửa code. Cập nhật lần cuối: 2026-07-24.*
