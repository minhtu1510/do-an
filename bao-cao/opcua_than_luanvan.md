# Bề mặt tấn công OPC-UA (Day 8) — bản chắt lọc cho thân luận văn

> Bản này đã lược bỏ các chi tiết gỡ lỗi kỹ thuật (xem `nhat_ky_thuc_nghiem_opcua.md`
> nếu cần phụ lục). Chỉ giữ kết quả và các quyết định phương pháp có ý nghĩa khoa
> học, sẵn sàng ghép vào chương báo cáo. Mọi số liệu là kết quả chạy thật; MITRE
> ATT&CK for ICS đối chiếu ma trận chính thức.

---

## X.1. Bối cảnh và phạm vi

Ngoài bề mặt S7comm (Day 1–6), khoá luận mở rộng sang giao thức **OPC-UA** — cổng
TCP/4840 trên PLC Siemens S7-1500. Máy chủ OPC-UA tích hợp trên PLC được cấu hình
ở chế độ **Anonymous / No-Security** (không xác thực, không mã hoá) — điều này được
xác nhận bằng thực nghiệm chứ không giả định (Bảng X.1, hai dòng NOT_CONFIGURED).

Threat model: kẻ tấn công đã có kết nối mạng tới cổng 4840, **không** có tài khoản
hợp lệ và **không** cần chiếm vị trí trung gian (MITM).

## X.2. Các kịch bản tấn công OPC-UA và kết quả thực nghiệm

Toàn bộ kịch bản được thực thi có kiểm soát qua công cụ tự xây `run_day8.py`, với
giới hạn an toàn cứng cho mỗi kịch bản.

**Bảng X.1. Kịch bản tấn công OPC-UA và kết quả thật.**

| Nhóm | Kịch bản | Kết quả thực nghiệm | MITRE ICS |
|---|---|---|---|
| Trinh sát | OPCUA_ENDPOINT_DISCOVERY | Lấy được endpoint + security policy | T0888 |
| Trinh sát | OPCUA_NODE_BROWSE | Liệt kê đầy đủ 9 tag của dây chuyền | T0861 |
| Đánh cắp dữ liệu | OPCUA_READ_SCRAPING | Đọc toàn bộ giá trị quá trình theo thời gian thực | T0802 |
| Đánh cắp dữ liệu | OPCUA_BEHAVIORAL_PROFILING | Phiên ẩn danh dài, log thay đổi theo thời gian | T0801 |
| Từ chối dịch vụ | OPCUA_SESSION_BURST | Tạo nhiều phiên liên tiếp, không bị rate-limit | T0814 |
| Từ chối dịch vụ | OPCUA_SUBSCRIPTION_FLOOD | Đăng ký nhiều monitored item, không bị chặn | T0814 |
| Từ chối dịch vụ | OPCUA_SLOWLORIS | Giữ phiên để chiếm pool → BadTooManySessions | T0814 |
| Từ chối dịch vụ | OPCUA_RECURSIVE_BROWSE | Browse đệ quy lặp lại (asymmetric load) | T0814 |
| Giao thức | OPCUA_PROTOCOL_FUZZ | Server phản ứng có cấu trúc, không crash | T0814 |
| Toàn vẹn (ghi) | OPCUA_WRITE_DENIED / INVALID_WRITE / MALICIOUS_WRITE | Mọi lệnh ghi bị từ chối `BadWriteNotSupported` | T1692.001 / T0836 |
| Xác thực | OPCUA_UNAUTHORIZED_SESSION | Không có chính sách user/password (xác nhận Anonymous) | — |
| Xác thực | OPCUA_CERTIFICATE_REJECTED | Không có trust-list chứng thư (xác nhận No-Security) | — |
| Thực thi | OPCUA_METHOD_CALL_ABUSE | Server không expose Method node nào | T0871 |

## X.3. Phân tích: quyền truy cập ẩn danh cho phép gì?

Kết quả cho thấy một ranh giới rõ giữa ba tính chất an toàn:

- **Tính bí mật — bị phá.** Không cần xác thực, kẻ tấn công lập được bản đồ toàn bộ
  hệ thống (Browse), đọc trộm toàn bộ giá trị vận hành theo thời gian thực
  (Read/Subscribe), và có thể theo dõi hành vi quá trình trong thời gian dài
  (T0801, T0802) — tương đương gián điệp công nghiệp (T0882 Theft of Operational
  Information).
- **Tính sẵn sàng — bị phá.** Nhiều biến thể DoS tầng ứng dụng (session burst,
  subscription flood, Slowloris giữ phiên, recursive browse, protocol fuzz) đều
  thực hiện được không cần xác thực (T0814).
- **Tính toàn vẹn của quá trình — được bảo vệ.** Mọi lệnh **ghi** vào PLC đều bị
  từ chối với mã `BadWriteNotSupported`, do các tag được cấu hình chỉ-đọc ở tầng
  AccessLevel. Đây là điểm khác biệt quan trọng so với S7comm (Day 1–6, ghi được
  vùng Merker): **xác thực yếu không đồng nghĩa ghi được** — máy chủ vẫn duy trì
  một lớp kiểm soát ghi theo từng tag.

Ngoài ra, máy chủ thể hiện khả năng chống chịu tốt: không treo/crash trước gói
UA-TCP dị dạng, và áp giới hạn phiên (timeout tối đa ~30 giây quan sát được).

## X.4. Thử nghiệm Man-in-the-Middle và phát hiện phòng thủ tầng mạng

Do OPC-UA chạy plaintext, nhóm thử nghiệm tấn công MITM (ARP poisoning) để chặn/đọc/
sửa lưu lượng giữa controller và PLC, đối lập với kênh S7CommPlus (được mã hoá) giữa
WinCC và PLC.

**Kết quả:**
- Ở điều kiện cho phép, kẻ tấn công **đọc được lưu lượng OPC-UA dạng plaintext**
  và gây **gián đoạn hiển thị tạm thời** cho HMI (WinCC treo rồi tự hồi phục) — minh
  hoạ rủi ro của giao thức không mã hoá (T0830 Adversary-in-the-Middle, T0815 Denial
  of View).
- Tuy nhiên, khi thực hiện một phép ARP spoofing **đúng chuẩn**, lưu lượng
  **không còn bị chuyển hướng** và HMI không bị ảnh hưởng. Điều này cho thấy hạ tầng
  mạng (switch Aruba, và/hoặc cơ chế anti-spoofing của S7-1500) **phát hiện và loại
  bỏ ARP spoofing**.

**Kết luận:** trên phân đoạn mạng OT của testbed, **MITM dựa trên ARP poisoning
không phải một vector tấn công ổn định** — một phát hiện phòng thủ tích cực. Việc
thao túng hiển thị "sạch" (T0832 Manipulation of View) không đạt được và được ghi
nhận là hướng phát triển, đòi hỏi vị trí trung gian ổn định (ví dụ network TAP vật
lý) và công cụ chặn/sửa gói ở tầng nhân hệ điều hành.

## X.5. Quyết định phương pháp thu thập dữ liệu

Do MITM (ARP-based) không tái tạo ổn định, nhóm **loại nó khỏi pipeline thu thập
dataset tự động** và chỉ dùng các kịch bản **kết nối trực tiếp** (Bảng X.1) làm
nguồn dữ liệu OPC-UA — đảm bảo tính ổn định, lặp lại và dán nhãn chuẩn xác, tương
tự cách thu S7comm ở Day 1–6.

Đáng chú ý, việc PLC từ chối mọi lệnh ghi **không làm giảm** mà còn **tăng** giá trị
dataset dưới góc nhìn phòng thủ (Blue Team): lưu lượng chứa hàng loạt phản hồi lỗi
(`BadWriteNotSupported`, `BadTypeMismatch`, `BadTooManySessions`) phản ánh đúng
hành vi thực tế của kẻ tấn công (dò – thử – sai trước khi thọc sâu). Mô hình học
được các mẫu-lỗi này có khả năng cảnh báo sớm giai đoạn trinh sát/thử nghiệm của
một cuộc tấn công.

## X.6. Nghịch lý bảo mật và khuyến nghị

Testbed thể hiện một tương phản hai tầng đáng chú ý: **tầng mạng L2 được bảo vệ**
(chặn được ARP MITM), **nhưng tầng ứng dụng OPC-UA lại mở** (cho truy cập ẩn danh
đọc hết dữ liệu và gây DoS). Kẻ tấn công **không cần MITM** — chỉ cần kết nối trực
tiếp ẩn danh là đã đạt mục tiêu đánh cắp dữ liệu và làm quá tải dịch vụ.

Bài học: bảo mật mạng (phân đoạn, ARP inspection) là cần thiết nhưng **không đủ**
nếu bản thân dịch vụ OPC-UA không bật security policy. **Khuyến nghị:** kích hoạt
OPC-UA security policy (ví dụ `Basic256Sha256` kèm xác thực người dùng) để đóng bề
mặt đọc/DoS ẩn danh này.
