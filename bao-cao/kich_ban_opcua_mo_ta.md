# Mô tả kịch bản tấn công OPC-UA (Day 8) cho báo cáo

> Toàn bộ số liệu dưới đây là kết quả thật đã chạy trên testbed
> (PLC S7-1500 `192.168.210.211`, controller/HMI `.31`, attacker `.32`),
> không phải giả định. MITRE ATT&CK for ICS được đối chiếu trực tiếp với
> ma trận chính thức (attack.mitre.org/matrices/ics), không suy đoán.

---

## Kịch bản 1 — Truy cập ẩn danh trực tiếp qua OPC-UA (kết quả chính)

**Mục tiêu.** Đánh giá bề mặt tấn công của máy chủ OPC-UA tích hợp trên PLC
S7-1500 khi được cấu hình ở chế độ Anonymous / No-Security, trong điều kiện
kẻ tấn công chỉ có kết nối mạng tới cổng TCP/4840, **không** có tài khoản,
**không** cần đứng giữa (MITM).

**Phương pháp.** Bộ kịch bản `tests/day8/run_day8.py` mở kết nối OPC-UA ẩn danh
tới máy chủ và thực thi từng nhóm hành động có kiểm soát (browse, read, session
burst, subscription flood, write, method call, fuzz), mỗi hành động có giới hạn
an toàn cứng và ghi lại bằng chứng thô.

**Kết quả thật quan sát được.**

| Nhóm | Kịch bản | Kết quả |
|---|---|---|
| Trinh sát | `OPCUA_ENDPOINT_DISCOVERY` | Lấy được danh sách endpoint + security policy của máy chủ |
| Trinh sát | `OPCUA_NODE_BROWSE` | Liệt kê đầy đủ 9 tag trong namespace (BangTai, Nhap, HienThi, Vat 1–3, CD1–3) |
| Đánh cắp dữ liệu | `OPCUA_READ_SCRAPING` | Đọc được toàn bộ giá trị quá trình thật, theo thời gian thực (ví dụ Nhap=24, HienThi thay đổi 13→14 trong lúc quan sát) |
| Sẵn sàng (DoS) | `OPCUA_SESSION_BURST` | Tạo được 5 phiên liên tiếp, máy chủ không giới hạn tốc độ |
| Sẵn sàng (DoS) | `OPCUA_SUBSCRIPTION_FLOOD` | Đăng ký được 50 monitored item trên một phiên, không bị chặn |
| Toàn vẹn | `OPCUA_WRITE_DENIED` / `OPCUA_INVALID_WRITE` / `OPCUA_MALICIOUS_WRITE` | Mọi lệnh ghi đều **bị máy chủ từ chối** với mã `BadWriteNotSupported` — không có thay đổi quá trình |
| Xác thực | `OPCUA_UNAUTHORIZED_SESSION`, `OPCUA_CERTIFICATE_REJECTED` | Testbed **không** cấu hình chính sách user/password và **không** có trust-list chứng thư → xác nhận máy chủ chạy Anonymous/No-Security |
| Thực thi | `OPCUA_METHOD_CALL_ABUSE` | Máy chủ **không** expose Method node nào → bề mặt "gọi hàm từ xa" không tồn tại |
| Giao thức | `OPCUA_PROTOCOL_FUZZ` | Gửi 5 khung UA-TCP dị dạng: máy chủ phản ứng có cấu trúc (đóng kết nối / chờ timeout / trả `ERR` đúng chuẩn), **không treo, không crash** |

**Ánh xạ MITRE ATT&CK for ICS.**
- T0846 Remote System Discovery / T0888 Remote System Information Discovery (endpoint discovery)
- T0861 Point & Tag Identification (node browse)
- T0802 Automated Collection / T0882 Theft of Operational Information (read scraping)
- T0814 Denial of Service (session burst, subscription flood, protocol fuzz)
- T1692.001 Unauthorized Message: Command Message (các lệnh ghi trái phép)

**Ý nghĩa bảo mật.** Kẻ tấn công chỉ cần khả năng kết nối mạng, **không cần
bất kỳ thông tin xác thực nào**, đã có thể: (i) lập bản đồ đầy đủ hệ thống,
(ii) đọc trộm toàn bộ dữ liệu vận hành theo thời gian thực, (iii) gây quá tải
tầng ứng dụng của máy chủ. Đây là vi phạm **tính bí mật** và **tính sẵn sàng**.

**Giới hạn (điểm phòng thủ còn hoạt động).** Khác với S7comm ở Day 1–6 (ghi
đè được vùng Merker), mọi lệnh **ghi** qua OPC-UA đều bị chặn ở tầng
AccessLevel (`writable=false` cho toàn bộ 9 tag), độc lập với việc xác thực
yếu. Nghĩa là: **xác thực yếu (Anonymous) không đồng nghĩa ghi được** — máy
chủ vẫn giữ một lớp kiểm soát ghi theo tag. Do đó bề mặt tấn công OPC-UA hiện
tại giới hạn ở đọc + DoS, chưa tới thao túng quá trình.

---

## Kịch bản 2 — Thử tấn công Man-in-the-Middle OPC-UA và phát hiện phòng thủ ARP của mạng

**Mục tiêu.** Kiểm tra khả năng chặn/đọc/sửa lưu lượng OPC-UA khi kẻ tấn công
đứng giữa controller (`.31`) và PLC (`.211`) bằng ARP poisoning — tận dụng việc
OPC-UA chạy plaintext (No-Security), khác với kênh S7CommPlus giữa WinCC và PLC
vốn được mã hóa.

**Phương pháp.** `tests/test_mitm_opcua_spoof.py`: ARP poison hai chiều để chèn
máy attacker vào giữa, sniff cổng 4840, có hai chế độ — `disrupt` (dựa vào IP
forwarding của OS) và `spoof` (attacker tự forward, sửa nội dung giữ nguyên độ
dài nhằm tới Manipulation of View).

**Kết quả thật quan sát được.**
- Lần chạy ban đầu (khi gói ARP poison mang MAC nguồn lỗi = `00:00:00:00:00:00`)
  bắt được ~127.000 gói OPC-UA và làm WinCC **treo hình tạm thời rồi tự hồi
  phục**. Phân tích sau cho thấy đây là **tác dụng phụ của gói poison dị dạng
  gây flooding tại switch**, không phải định vị MITM đúng nghĩa.
- Sau khi sửa để gói poison mang MAC nguồn **hợp lệ**
  (`f4:f1:9e:0d:a6:96`), tức là một ARP spoof "chuẩn", lưu lượng OPC-UA
  **không còn bị chuyển hướng** (0 gói bắt được) và WinCC **không còn bị gián
  đoạn**. Điều này cho thấy hạ tầng mạng (switch Aruba, và/hoặc anti-spoofing
  của S7-1500) **phát hiện và loại bỏ ARP spoofing hợp lệ**.

**Kết luận.** Trên phân đoạn mạng OT của testbed, **tấn công MITM dựa trên ARP
poisoning không phải một vector khả thi và ổn định**: một ARP spoof đúng chuẩn
bị chặn ở tầng 2. Đây là một **phát hiện phòng thủ tích cực** — mạng có khả
năng kháng ARP spoofing.

**Ánh xạ MITRE ATT&CK for ICS.**
- T0830 Adversary-in-the-Middle (kỹ thuật thử nghiệm)
- T0815 Denial of View (hiện tượng WinCC treo tạm thời quan sát được ở lần đầu)
- T0882 Theft of Operational Information (khả năng đọc plaintext khi ở vị trí giữa)
- T0832 Manipulation of View — **không đạt được**, ghi nhận là hướng phát triển.

**Giới hạn và hướng phát triển.**
- Bản chất plaintext của OPC-UA No-Security là rủi ro **nếu** kẻ tấn công chiếm
  được vị trí inline; nhưng trên mạng này lớp L2 chặn được ARP MITM nên rủi ro
  đó không hiện thực hóa được bằng ARP poisoning.
- Thao túng nội dung sạch (T0832 — làm HMI/dashboard hiển thị giá trị giả mà vẫn
  kết nối) về nguyên tắc khả thi (giao thức không mã hóa, không chữ ký toàn vẹn),
  nhưng đòi hỏi (a) một vị trí MITM ổn định (ví dụ network TAP vật lý thay vì ARP
  poisoning) và (b) công cụ chặn/sửa gói ở tầng kernel (WinDivert/pydivert trên
  Windows, hoặc NFQUEUE trên Linux) — userland forwarding bằng scapy trên Windows
  không đủ ổn định về tốc độ gói. Đây là hướng nghiên cứu tiếp theo.

---

## Nghịch lý bảo mật đáng nêu (điểm nhấn cho báo cáo)

Testbed cho thấy một tương phản hai tầng có giá trị: **tầng mạng L2 được bảo vệ
tốt** (chặn được ARP MITM), **nhưng tầng ứng dụng OPC-UA lại mở** (cho phép truy
cập ẩn danh đọc hết dữ liệu + DoS). Kẻ tấn công **không cần MITM** — chỉ cần kết
nối trực tiếp ẩn danh là đã đạt được mục tiêu đánh cắp dữ liệu và gây DoS. Bài
học: bảo mật mạng (network segmentation, ARP inspection) là cần thiết nhưng
**không đủ** nếu bản thân dịch vụ OPC-UA không bật security policy (xác thực +
mã hóa). Khuyến nghị: bật OPC-UA security policy (ví dụ Basic256Sha256 + user
authentication) để đóng bề mặt đọc/DoS ẩn danh này.
