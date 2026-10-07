# Bảng đối chiếu số liệu – artifact OPC UA

Trạng thái: các kết quả model/CSV cũ đã đối chiếu bằng
`tools/opcua_verify_artifacts.py` với 24/24 phép kiểm tra đạt; báo cáo máy đọc
được nằm tại `experiments/opcua_research_v2/scientific_verification.json`.
Kiểm toán packet-level mới được thực hiện riêng bằng
`tools/opcua_pcap_independent_audit.py`; không nhập các kiểm tra mới vào con số
24/24 nếu chưa cập nhật chính trình kiểm chứng cũ.

| Nội dung dự kiến dùng trong đồ án | Số liệu/khẳng định | Artifact trực tiếp | Mã nguồn tạo/kiểm tra | Kết luận được phép và lưu ý |
| --- | --- | --- | --- | --- |
| PCAP chuẩn dùng kiểm toán | 1.660.063 gói; 311.442.552 byte; SHA-256 `12abee34…c42e` | `label_audit/pcap_independent_audit/packet_audit_summary.json`; `PCAP_AUDIT_REPORT.md` | `tools/opcua_pcap_independent_audit.py`; `capinfos` | Là PCAP gộp duy nhất được đọc; không nạp thêm segment PCAP nên không đếm trùng giữa hai nguồn. Đây vẫn là cùng capture gốc, không phải nguồn thu độc lập. |
| Quy mô tập phát triển | 3.427 cửa sổ 5 giây | `label_audit/summary.json`; `label_audit/label_manifest.csv`; `label_audit/pcap_independent_audit/window_packet_evidence.csv` | `tools/opcua_label_manifest.py`; `tools/opcua_pcap_independent_audit.py`; `tools/opcua_verify_artifacts.py` | Đã xác minh số hàng và khóa cửa sổ duy nhất; toàn bộ cửa sổ có một dòng packet evidence. |
| Coverage cửa sổ từ PCAP | 3.425 cửa sổ full; 2 cửa sổ `partial_boundary`; 0 cửa sổ ngoài PCAP | `label_audit/pcap_independent_audit/window_packet_evidence.csv`; `audit_discrepancies.csv`; `packet_audit_summary.json` | `tools/opcua_pcap_independent_audit.py` | Hai cửa sổ biên là BENIGN và chỉ được bao phủ một phần; không dùng chúng để khẳng định vắng traffic trong toàn cửa sổ. |
| Phân bố trước activity-aware | 2.680 BENIGN, 747 attack | `label_audit/summary.json` | `tools/opcua_label_manifest.py:168-176` | Đây là checkpoint trước hiệu chỉnh, không phải tập cuối dùng cho model đã lưu. |
| Hiệu chỉnh nhãn | 29 cửa sổ: 24 SESSION_BURST, 4 SUBSCRIPTION_FLOOD, 1 PROTOCOL_FUZZ | `label_audit/changed_windows.csv`; `label_audit/summary.json` | `extract_opcua_features_ext.py:169-170,370-380`; `tools/opcua_label_manifest.py:112,171` | Manifest mô tả đầy đủ thay đổi trước–sau; bằng chứng packet nằm ở các hàng kế tiếp. |
| Tái kiểm 29 cửa sổ từ PCAP | 29/29 phù hợp rule; 0 bất nhất; 0 thiếu bằng chứng | `label_audit/pcap_independent_audit/changed_29_pcap_audit.csv`; `packet_audit_summary.json`; `PCAP_AUDIT_REPORT.md` | `tools/opcua_pcap_independent_audit.py` | Xác minh bằng cách trích xuất lại từ cùng PCAP gốc. Chỉ xác nhận consistency với rule, không xác nhận hành vi attack thành công. |
| Hai cửa sổ đổi nhãn có traffic ngoài rule | 1 gói không payload tại `04:54:00Z`; 7 gói, 3 payload/120 byte tại `06:05:45Z`; tất cả `.32 -> .31:7680`; 0 PLC/TCP-4840; 0 OPC UA decoded | `label_audit/pcap_independent_audit/changed_29_pcap_audit.csv`; `packet_audit_summary.json` | `tools/opcua_pcap_independent_audit.py` | Không được nói cả 29 cửa sổ hoàn toàn vắng hoạt động attacker. Traffic tới HMI nằm ngoài phạm vi rule đang kiểm toán và không tự động làm nhãn đảo lại. |
| Cửa sổ attack giữ lại | 718/718 có ít nhất một gói liên quan `.32` trong phạm vi PLC/TCP-4840 | `label_audit/pcap_independent_audit/window_packet_evidence.csv`; `packet_audit_summary.json` | `tools/opcua_pcap_independent_audit.py` | Xác nhận rule tái tạo được nhãn activity-aware; sự hiện diện gói không chứng minh attack thành công. |
| BENIGN có traffic liên quan attacker ngoài timeline | 118 cửa sổ có gói liên quan `.32` trong phạm vi PLC/TCP-4840; cả 118 có `timeline_overlap_ms=0` | `label_audit/pcap_independent_audit/window_packet_evidence.csv`; `packet_audit_summary.json` | `tools/opcua_pcap_independent_audit.py` | Không phải mismatch vì rule yêu cầu đồng thời overlap và traffic. Không đồng nhất BENIGN với vắng mặt tuyệt đối của máy kiểm thử. |
| Đối chiếu cửa sổ kề 29 thay đổi | 29/29 có ít nhất một láng giềng cùng episode; 25/29 có láng giềng chứa traffic thuộc rule | `label_audit/pcap_independent_audit/changed_29_pcap_audit.csv`; `packet_audit_summary.json` | `tools/opcua_pcap_independent_audit.py` | Hỗ trợ nhận định nhiều thay đổi nằm ở rìa hoạt động quan sát được; 4 trường hợp không có láng giềng dương tính nên không suy diễn quá mức. |
| Phân bố sau activity-aware | 2.709 BENIGN, 718 attack | `label_audit/summary.json` | `tools/opcua_verify_artifacts.py` | Tổng vẫn 3.427. |
| Không gian đặc trưng | 61 đầy đủ; 50 sau khi loại 11; 24 service-only | `feature_ablation/feature_groups.json` | `tools/opcua_feature_ablation.py:30-75,268-289` | 11 trường là aggregate cấu trúc nguồn, không phải IP thô. |
| Cấu hình model ablation | ExtraTrees, 400 cây, max_depth=10, seed 0, không class_weight | `feature_ablation/run_config.json` | `tools/opcua_feature_ablation.py:207-214,397-412` | Khớp recipe model gốc ở tham số cốt lõi. |
| Full-61 Group-CV mới | Macro-F1 0,961831 | `feature_ablation/ablation_results.csv`; `classification_all_61_train_group_cv.json` | `tools/opcua_feature_ablation.py:311-335` | So sánh nội bộ runtime 1.9.1; không thay thế metadata 1.8.0. |
| Metadata Group-CV model gốc | Macro-F1 0,959851 | `model_opcua/meta.json` | `train_opcua_eval.py:61-89` | Có thể trích dẫn như kết quả gốc; chưa tái lập bit-for-bit. |
| OOD2 full-61 | TP/FP/TN/FN = 124/23/457/1; attack precision 0,8435; recall 0,992; F1 0,9118; FPR 0,0479; multiclass Macro-F1 0,517804 | `feature_ablation/ablation_results.csv`; `warmup_ood/ood2_predictions.csv`; `eval_ood2_extratrees/ood_report.json` | `tools/opcua_export_predictions.py`; `tools/opcua_verify_artifacts.py:173-184,204-230` | Tái lập đúng inference legacy. OOD2 đã tham gia chọn ExtraTrees nên không phải final test độc lập. |
| Binary Macro-F1 OOD2 trong đồ án | 0,943 | `eval_ood2_extratrees/ood_report.json`; confusion 124/23/457/1 | `evaluate_opcua_ood.py` | Không mâu thuẫn với attack-class F1 0,9118; hai cách lấy trung bình khác nhau. |
| Warm-up OOD2 | 36 cửa sổ, 23 FP; 444 steady, 0 FP | `warmup_ood/error_summary.json`; `warmup_ood/ood2_predictions.csv` | `tools/opcua_warmup_error_analysis.py`; `tools/opcua_verify_artifacts.py` | Chỉ chứng minh lỗi tập trung ở warm-up của OOD2. |
| Episode OOD2 | 86 ID không trộn nhãn; 17 dương, 69 âm; TP/FP/TN/FN = 17/23/46/0 | `warmup_ood/ood2_episode_summary.json`; hai CSV episode | `tools/opcua_episode_eval.py:33,198-230`; `tools/opcua_verify_artifacts.py:233-290` | Recall 1,000 nhưng precision 0,425 và FPR episode 0,3333. |
| Episode theo pha | steady 0/37 FP; warm-up/cooldown 23/32 FP | `warmup_ood/ood2_episode_summary.json`; `warmup_ood/ood2_negative_episode_results.csv` | `tools/opcua_episode_eval.py` | FPR episode warm-up 0,71875; không được chỉ báo 17/17 mà bỏ precision. |
| Ablation bỏ 11 trường | CV Macro-F1 0,953913; OOD2 Macro-F1 0,408665; attack F1 0,627027; FPR 0,268750; testclean Macro-F1 0,940504 | `feature_ablation/ablation_results.csv` | `tools/opcua_feature_ablation.py` | Chứng minh feature dependence trong thiết kế hiện tại, không chứng minh leakage. |
| Service-only | CV Macro-F1 0,891816; OOD2 recall 0,440; attack F1 0,550; FPR 0,041667 | `feature_ablation/ablation_results.csv` | `tools/opcua_feature_ablation.py` | FPR thấp đi kèm bỏ sót 70/125 cửa sổ; không diễn giải thành cải thiện tổng thể. |
| Baseline ngưỡng | OOD2 recall 0,952; attack F1 0,670423; 111 FP; FPR 0,231250 | `feature_ablation/ablation_results.csv`; `simple_baseline_thresholds.json` | `tools/opcua_feature_ablation.py:217-249,367-390` | Model học máy không được giải thích chỉ bởi một luật ngưỡng đơn giản. |
| Testclean full-61 | TP/FP/TN/FN = 45/0/708/0; Macro-F1 0,949340 | `feature_ablation/ablation_results.csv`; `eval_testclean_extratrees/ood_report.json` | `tools/opcua_verify_artifacts.py:185-199` | Tái lập inference legacy; tập có ít attack và không có warm-up. |
| Vai trò OOD2 | Dùng trực tiếp để chấm nhiều thuật toán và chọn ExtraTrees | `scratch_try_improve_opcua_ood.py:34-36,42-91`; `train_opcua_eval.py:13-20` | Mã nguồn gốc | Phải gọi là development/cross-session validation, không gọi là untouched final test. |
| Phiên bản model | model lưu: sklearn 1.8.0; model ablation: 1.9.1 | marker trong hai file `classifier.joblib`; `scientific_verification.json` | `tools/opcua_verify_artifacts.py:293-303` | Tái lập được inference; chưa xác định duy nhất nguyên nhân lệch CV 0,001980. |
| Kiểm chứng artifact cũ | 24/24 phép kiểm tra pass | `scientific_verification.json` | `tools/opcua_verify_artifacts.py` | Chứng minh tính nhất quán nội bộ của artifact model/CSV cũ; không bao gồm kiểm toán PCAP mới và không tạo thêm tính độc lập thống kê. |

## Các số liệu chưa nên đưa vào như kết luận xác nhận

- Không mô tả kiểm toán PCAP là một nguồn thu thập độc lập; đây là phép trích
  xuất lại bằng mã mới từ cùng capture gốc.
- Không nói “29 cửa sổ không có traffic attacker”: hai cửa sổ có traffic
  `.32 -> .31:7680`, chỉ là không có traffic thuộc phạm vi PLC/TCP-4840 của rule.
- Không dùng vắng traffic trong phạm vi rule để kết luận vắng tuyệt đối mọi hoạt
  động của attacker hoặc hành vi attack không thành công.
- Không dùng sự hiện diện của gói, payload hay OPC UA decoded để kết luận một
  hành vi attack đã thực hiện thành công nếu không có tiêu chí tác động/log PLC.
- Không gọi 118 cửa sổ BENIGN có traffic liên quan `.32` là mislabeled chỉ từ
  packet evidence: cả 118 nằm ngoài khoảng attack trong timeline.
- Không gọi toàn bộ 3.427 cửa sổ được capture đầy đủ; hai cửa sổ biên chỉ có
  coverage một phần.
- Không gọi OOD2 là tập kiểm định cuối độc lập hoặc “unseen” đối với quyết định
  mô hình.
- Không khẳng định đã loại bỏ data leakage sau ablation 11 đặc trưng.
- Không dùng 17/17 episode mà không kèm 23 false-positive episode và precision
  0,425.
- Không gọi điểm Group-CV 0,961831 là tái lập chính xác metadata 0,959851.
- Không suy rộng 0 FP trên 444 cửa sổ steady thành FPR bằng 0 trong vận hành OPC
  UA nói chung.

## Bảng và hình đề xuất để tích hợp

| Vị trí | Bảng/hình đề xuất | Nội dung bắt buộc | Artifact nguồn |
| --- | --- | --- | --- |
| Mục 3.10 | Bảng phân bố nhãn trước–sau | 2.680/747 trước; 2.709/718 sau; breakdown 24/4/1 | `label_audit/summary.json`; `changed_windows.csv` |
| Mục 3.10 | Bảng kiểm toán packet-level | 3.425 full, 2 partial; 29/29 consistent; 0 mismatch; 718/718 retained attack có evidence | `pcap_independent_audit/packet_audit_summary.json`; `window_packet_evidence.csv` |
| Mục 3.10 | Hình timeline 29 cửa sổ và láng giềng | Mã hóa số gói thuộc rule; đánh dấu hai cửa sổ `.32 -> .31:7680` và biên PCAP | `changed_29_pcap_audit.csv`; `audit_discrepancies.csv` |
| Mục 5.10 | Bảng/hình ablation | CV Macro-F1, OOD2 attack F1 và FPR của 61/50/24 đặc trưng; ghi rõ OOD2 tham gia chọn model | `feature_ablation/ablation_results.csv` |
| Mục 5.10 | Bảng window–episode | 124/23/457/1 và 17/23/46/0; precision episode 0,425 | `warmup_ood/ood2_episode_summary.json`; hai CSV episode |
| Mục 5.10 | Bảng/hình warm-up | 23/36 warm-up FP, 0/444 steady FP; feature mean/p95 theo pha | `warmup_ood/error_summary.json`; `phase_feature_summary.csv` |
| Mục 5.10 | Sơ đồ vai trò OOD2 | Train/Group-CV → OOD2 model selection → phân tích lỗi; không vẽ như final test | `scratch_try_improve_opcua_ood.py`; `train_opcua_eval.py` |
| Mục 5.12 | Bảng ranh giới kết luận | Tách consistency, packet presence, model performance và attack success | `THESIS_ADDITION_DRAFT_VI.md`; toàn bộ artifact kiểm chứng |
