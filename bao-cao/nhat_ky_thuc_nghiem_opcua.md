# Nhật ký thực nghiệm OPC-UA (Day 8) — quá trình, sai, sửa, kết luận

> Tài liệu này ghi lại TOÀN BỘ quá trình thử nghiệm bề mặt tấn công OPC-UA
> trên testbed (PLC S7-1500 `192.168.210.211`, controller/HMI `.31`, attacker
> `.32`), kể cả các bước sai và cách sửa. Mục cuối ("Phần nào nên đưa vào luận
> văn") hướng dẫn chắt lọc lại cho báo cáo chính thức.
>
> Nguyên tắc xuyên suốt: **không bịa số** — mọi con số là kết quả chạy thật;
> MITRE ATT&CK for ICS đối chiếu trực tiếp ma trận chính thức.

---

## 0. Bối cảnh & mục tiêu

- Day 1–6: dataset S7comm (do thành viên khác làm) — tấn công ghi được vùng Merker.
- Day 7 (`attacks_ext/`): các đòn nâng cao (SMB recon, S7 replay, stealthy write,
  logic-aware, kill-chain, MITM S7).
- Day 8 (`tests/day8/`): **bề mặt OPC-UA** — đóng góp mới của khoá luận. Đây là
  nội dung tài liệu này.

Máy chủ OPC-UA của S7-1500 chạy ở chế độ **Anonymous / No-Security** — xác nhận
bằng thực nghiệm (xem §1), không phải giả định.

---

## 1. Day 8 — tấn công OPC-UA kết nối trực tiếp (kết quả chính)

Bộ `tests/day8/run_day8.py` mở kết nối OPC-UA ẩn danh và chạy từng kịch bản có
kiểm soát. Kết quả thật:

| Kịch bản | Trạng thái | Kết quả thật | MITRE ICS |
|---|---|---|---|
| OPCUA_ENDPOINT_DISCOVERY | EXECUTED | Lấy được endpoint + security policy | T0888 |
| OPCUA_NODE_BROWSE | EXECUTED | Liệt kê đủ 9 tag (BangTai, Nhap, HienThi, Vat 1–3, CD1–3) | T0861 |
| OPCUA_READ_SCRAPING | EXECUTED | Đọc toàn bộ giá trị thật, real-time (HienThi 13→14 khi quan sát) | T0802 |
| OPCUA_SESSION_BURST | EXECUTED_GATED | 5/5 session tạo được, không rate-limit | T0814 |
| OPCUA_SUBSCRIPTION_FLOOD | EXECUTED_GATED | 50 monitored item/1 session, không chặn | T0814 |
| OPCUA_WRITE_DENIED | EXECUTED_GATED | Bị từ chối `BadWriteNotSupported` | T1692.001 |
| OPCUA_INVALID_WRITE | EXECUTED_GATED | Bị từ chối (type mismatch) | T1692.001 |
| OPCUA_MALICIOUS_WRITE | EXECUTED_GATED | `baseline=24, attempt=27` → **BadWriteNotSupported**, không đổi PLC | T0836 |
| OPCUA_METHOD_CALL_ABUSE | EXECUTED_GATED | `method_nodes_found=0` — máy chủ không expose hàm | T0871 |
| OPCUA_PROTOCOL_FUZZ | EXECUTED_GATED | 5 khung dị dạng → server phản ứng có cấu trúc (ERR / close / timeout), **không crash** | T0814 |
| OPCUA_UNAUTHORIZED_SESSION | NOT_CONFIGURED | Không có user/password policy | — |
| OPCUA_CERTIFICATE_REJECTED | NOT_CONFIGURED | Không có certificate trust-list | — |

**Phát hiện cốt lõi:**
1. **Đọc/DoS ẩn danh: được** — không cần credential, chỉ cần kết nối cổng 4840.
2. **Ghi vào PLC: bị chặn** — mọi lệnh ghi trả `BadWriteNotSupported` do tag cấu
   hình read-only (AccessLevel), độc lập với việc xác thực yếu. Khác Day 1–6 (S7comm
   ghi được vùng Merker). → Anonymous **không** đồng nghĩa ghi được.
3. **Server chống fuzz cơ bản tốt** — không treo/crash trước gói dị dạng.
4. **Giới hạn session 30s**: mọi lần connect đều thấy log `Requested session
   timeout to be 3600000ms, got 30000ms instead` → cấu hình bảo mật thật của PLC.

---

## 2. Ba kịch bản bổ sung (thân thiện cho thu dataset)

Vì quyền ghi bị khoá, bổ sung 3 kịch bản đánh vào Bí mật/Sẵn sàng (không cần ghi),
đều **lặp lại được** → dùng thu dataset:

| Kịch bản | MITRE | Ý tưởng |
|---|---|---|
| OPCUA_BEHAVIORAL_PROFILING | T0801 Monitor Process State | Subscribe ẩn danh dài, log thay đổi theo thời gian (gián điệp hành vi) |
| OPCUA_SLOWLORIS | T0814 Denial of Service | Giữ nhiều session + keepalive → chiếm pool → client hợp lệ bị `BadTooManySessions` |
| OPCUA_RECURSIVE_BROWSE | T0814 Denial of Service | Browse đệ quy lặp lại (asymmetric load) |

**Đã sửa 2 lỗi MITRE trong đề xuất gốc:** Recursive Browse đề xuất `T0886 Resource
Hijacking` (sai — T0886 là Remote Services; Resource Hijacking không có trong ICS)
→ đúng là **T0814**. Behavioral Profiling đề xuất `T0802 Data from Information
Repository` (lẫn tên) → đúng là **T0801**.

**Trung thực về Recursive Browse:** namespace S7-1500 nhỏ (~9 tag), nên KHÔNG phải
"cây vài MB" — tải đến từ việc lặp lại, không phải kích thước cây (đã ghi rõ trong
code).

---

## 3. Câu chuyện MITM — quá trình SAI rồi SỬA (chi tiết kỹ thuật)

Mục tiêu ban đầu: tận dụng OPC-UA plaintext (No-Security) để MITM đọc + sửa nội
dung, đối lập với S7CommPlus (mã hoá). Đây là hành trình dài nhất, nhiều lần sai:

| # | Hiện tượng | Nguyên nhân thật | Cách xử lý |
|---|---|---|---|
| 1 | `intercepted=0`, luồng ARP crash `Interface '' not found` | `CAPTURE_IFACE` chưa cấu hình trong testbed.conf | Lấy interface đúng qua `conf.ifaces` (card Intel IP .32) |
| 2 | Chạy được: **127797 gói + WinCC treo** | ARP poison ăn (thời điểm đó) | Ghi nhận kết quả `010959`, `012127` |
| 3 | Spoof mode `intercepted=0` | Guard `Ether.dst==ATTACKER_MAC` mà `get_if_hwaddr` trả `00:00:00:00:00:00` | Đổi guard sang `Ether.src in (PLC_MAC,HMI_MAC)` |
| 4 | Vẫn 0, `has_ether=0` | Interface trả gói **không có lớp Ethernet** (Npcap) | Viết lại forward ở **tầng L3** (`send(IP)`), bỏ phụ thuộc L2 |
| 5 | Vẫn 0, `has_ip=0`, `raw_seen=80` | Filter `host X and host Y` **hút cả gói ARP** của chính mình (80 gói ARP, không có IP) | Đổi filter thành `tcp and host X and host Y` |
| 6 | Vẫn 0 dù web_scada đang poll | ARP poison **không chuyển hướng** được nữa | Thêm `resolve_attacker_mac()` (fix MAC=0) |
| 7 | MAC resolve đúng, nhưng disrupt **cũng** ra 0 và WinCC **không còn treo** | **Mạng chặn ARP spoof chuẩn** (DAI của switch Aruba). "127k lần trước" là **artifact do gói ARP MAC-rỗng gây flood**, không phải MITM thật | **Kết luận & dừng** |

### Các bug phụ đã sửa dọc đường (bài học kỹ thuật)
- **Mất evidence khi timeout:** nhiều hàm dùng `async with Client(timeout=5)` —
  khi asyncua ném lỗi lúc đóng session (thường `TimeoutError` rỗng), toàn bộ
  evidence bị mất, trạng thái báo `FAILED` dù đã đọc được dữ liệu. Sửa: (a) đặt
  timeout theo thời lượng thật của kịch bản; (b) bọc `try/except` quanh `async
  with` để **giữ lại evidence từng phần** + ghi rõ dòng `aborted_after_error`.
- **Bộ đếm chẩn đoán:** thêm `raw_seen / has_ip / victim_pair / forwarded` để
  định vị chính xác "gói chết ở tầng nào" thay vì đoán mò.

### Kết luận MITM
- **ARP MITM không phải vector khả thi/ổn định** trên mạng testbed: ARP spoof
  chuẩn bị switch chặn (DAI). → **Phát hiện phòng thủ tích cực**.
- Bản chất plaintext của OPC-UA vẫn là rủi ro **nếu** attacker chiếm được vị trí
  inline (TAP vật lý), nhưng không hiện thực hoá được bằng ARP poisoning ở đây.
- T0832 Manipulation of View (sửa hiển thị sạch): **không đạt** — cần (a) vị trí
  inline ổn định + (b) công cụ kernel (WinDivert/pydivert, NFQUEUE), scapy userland
  trên Windows không đủ. → Future work.

---

## 4. Quyết định phương pháp: MITM không dùng để thu dataset

**Vì sao:** dataset cần **ổn định, lặp lại, dán nhãn chuẩn**. ARP MITM lúc ăn lúc
không (§3) → không thu đều được. Ngược lại, các kịch bản **kết nối trực tiếp** (§1,
§2) chạy đi chạy lại ổn định → đây mới là nguồn dataset OPC-UA (y như S7comm là
nguồn Day 1–6).

**Góc nhìn Blue Team (điểm nhấn học thuật):** một hệ thống sinh ra hàng loạt log
`BadWriteNotSupported`, `BadTypeMismatch`, `BadTooManySessions` chính là **mỏ vàng
dữ liệu** — attacker thật luôn dò/thử/sai trước khi thọc sâu; mô hình học được các
mẫu-lỗi này sẽ cảnh báo sớm. → "Tấn công thất bại về vật lý" = "thành công về dataset".

---

## 5. Pipeline thu dataset OPC-UA (hiện trạng)

```
collect_opcua.py  (warmup → attack ngẫu nhiên → cooldown, ghi timeline epoch)
        │
        ├── gọi run_day8.py --scenario X --execute --allow-gated (subprocess, cô lập)
        │
        └── timeline_opcua_day8.csv  (start,end,label = tên kịch bản, multiclass)
                    │
   capture PCAP ở cổng mirror switch (trang của thầy) — thu thụ động, tin cậy
                    │
        extract_opcua_features.py --pcap ... --timeline ...  →  feature CSV có nhãn
                    │
                train_ml.py  →  Dataset & Model Stats
```

**Đã sửa 2 bug trong bản wrapper tham khảo:** `--target` không tồn tại trong
run_day8.py + thiếu `--execute --allow-gated` (không có thì chỉ dry-run); timestamp
chuỗi không tương thích → đổi sang **epoch giây** (đã verify extractor parse đúng).

**Đã kiểm thử offline:** wrapper chạy trọn vòng warmup/attack/cooldown, ghi timeline
đúng định dạng, `extract_opcua_features.py` đọc lại timeline thành interval chuẩn.
**Chưa chạy production** (cần PCAP thật từ cổng mirror).

---

## 6. Trạng thái hiện tại — chắc chắn vs. cần làm

**Chắc chắn (đã chạy thật):**
- 14 (nay 17) kịch bản OPC-UA trực tiếp có kết quả thật + MITRE đã verify.
- Phát hiện: đọc/DoS ẩn danh được; ghi bị chặn; server chống fuzz; session cap 30s.
- Phát hiện phòng thủ: mạng chặn ARP MITM.
- Pipeline thu dataset (wrapper + extractor) đã thông, test offline.

**Cần làm để hoàn tất:**
- Chạy `collect_opcua.py` production + capture ở cổng mirror → PCAP thật.
- Trích feature + train, cập nhật trang Dataset & Model Stats.
- (Tuỳ chọn, giá trị cao) Bật `Basic256Sha256` trên server → chạy lại → dùng
  Security Mode Comparator để chứng minh "bật security chặn được đọc/DoS ẩn danh"
  (biến khuyến nghị thành kết quả định lượng).

**Future work (thành thật ghi rõ):**
- T0832 spoof sạch cần TAP vật lý + WinDivert/NFQUEUE.

---

## 7. Phần nào NÊN đưa vào luận văn chính thức (chắt lọc)

**NÊN đưa (nội dung học thuật):**
- §1 kết quả Day 8 (bảng kịch bản + MITRE + phát hiện đọc/DoS được, ghi bị chặn).
- §2 ba kịch bản bổ sung.
- §3 **kết luận** MITM (mạng chặn ARP MITM — phát hiện phòng thủ) + giới hạn +
  future work. **Chỉ kết luận, không kể từng bug.**
- §4 quyết định phương pháp (vì sao MITM không vào pipeline thu) — đây là điểm
  thể hiện tư duy nghiên cứu, hội đồng đánh giá cao.
- Nghịch lý bảo mật: **mạng L2 có phòng thủ (chặn MITM), nhưng ứng dụng OPC-UA lại
  mở ẩn danh** → attacker không cần MITM vẫn đọc hết. Khuyến nghị bật OPC-UA
  security policy.

**KHÔNG nên đưa vào thân chính (để phụ lục hoặc bỏ):**
- Bảng 7 bước sai/sửa MITM ở §3 (bug MAC=0, filter ARP, timeout=5s...). Đây là
  nhật ký kỹ thuật — cùng lắm để **phụ lục** "quá trình hiệu chỉnh công cụ", không
  để thân bài.
- Chi tiết bug timeout/evidence, bộ đếm chẩn đoán.

**Nguyên tắc:** thân luận văn kể **cái gì phát hiện được và vì sao chọn hướng đó**;
phụ lục/nhật ký (file này) giữ **cách làm và các lần hiệu chỉnh**. Khi hội đồng hỏi
"sao biết mạng chặn MITM", bạn mở §3 ra dẫn chứng số liệu thật.
