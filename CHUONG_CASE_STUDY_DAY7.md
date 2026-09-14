> **Ghi chú đặt bài (xoá khi ghép vào luận văn):** phần này viết ở dạng **một mục (section)**, không phải chương riêng. Vị trí khuyến nghị: **mục cuối của chương "Thu thập dữ liệu / Kịch bản tấn công"**, ngay sau phần mô tả Day 1–6 — để gom toàn bộ nội dung tấn công về một chỗ. Thay `[X]` bằng số mục thật (vd 4.5). Tuỳ chọn: chuyển mục [X].8 (thí nghiệm thất bại + nhật ký debug) xuống **Phụ lục** nếu chương chính cần gọn; nhắc lại luận điểm [X].7 ở **Kết luận**.

## [X]. Kịch bản tấn công nâng cao — Nghiên cứu tình huống và Phân tích an ninh (Day 7)

### [X].1 Giới thiệu và vai trò trong đồ án

Chương này trình bày bốn **nghiên cứu tình huống (case-study)** tấn công nâng cao trên
testbed. Khác với bộ dữ liệu Day 1–6 — vốn phục vụ **huấn luyện mô hình học máy** phát
hiện thao tác quá trình bằng phương pháp thống kê trên hàng chục nghìn mẫu — các
case-study ở đây phục vụ **hai mục tiêu bổ sung, cùng nằm trong phạm vi đề tài**:

1. **Chứng minh môi trường testbed đủ thực tế** để dựng và quan sát các tấn công đa
   giai đoạn, phối hợp — điều mà một bảng số độ chính xác không thể hiện được;
2. **Rút ra kết luận an ninh định lượng** về cấu hình hệ thống, có thể dùng làm khuyến
   nghị vận hành.

Nói cách khác: phần dữ liệu ML trả lời câu hỏi *"mô hình phát hiện được không?"*, còn
mục này trả lời *"tấn công thực sự xảy ra như thế nào, và nó cho biết điều gì về an
ninh của hệ thống?"*.

Bốn case-study được tổ chức thành **một chiến dịch tấn công liền mạch** theo đúng vòng
đời của một cuộc tấn công có chủ đích (APT), thay vì bốn thí nghiệm rời rạc:

| Pha | Case-study | Kỹ thuật MITRE ATT&CK for ICS |
|---|---|---|
| 1. Trinh sát (Recon) | SMB Reconnaissance | T0842 Network Share Discovery |
| 2. Chiếm quyền + Di chuyển ngang | Kill Chain | Initial Access + T0846 Remote System Discovery |
| 3. Phá hoại + Che giấu | Concealed Stop Attack | T0831 Manipulation of Control + T0856 Spoof Reporting Message |
| (Bằng chứng phòng thủ) | Program Upload Theft | T0845 Program Upload — **bị chặn** |

Mỗi case-study kết thúc bằng mục **"Đóng góp cho đồ án"** nêu rõ vai trò của nó, và
toàn mục khép lại bằng một luận điểm an ninh trung tâm được củng cố bởi nhiều bằng
chứng độc lập ([X].7).

> **Định vị rõ ràng để tránh hiểu nhầm:** các case-study trong mục này **KHÔNG** được
> tính là các lớp dữ liệu ML mới. Xương sống dữ liệu huấn luyện vẫn là Day 1–6; Day 6 là
> tập holdout đánh giá. Lý do và phân tích trùng lặp đặc trưng được trình bày ở [X].8.

---

### [X].2 Mô hình đe doạ và môi trường thực nghiệm

**Môi trường (testbed):**
- **PLC:** Siemens S7-1500 **phần cứng thật** (`192.168.210.211`), chạy chương trình
  điều khiển dây chuyền băng tải với các biến quá trình thật (cảm biến giai đoạn, timer
  CD1–CD3, cờ START/STOP trên vùng Merker M5).
- **HMI/Engineering:** máy WinCC Runtime (`192.168.210.31`), giao tiếp PLC qua giao thức
  **S7CommPlus (mã hoá + xác thực)**.
- **Kênh giám sát thứ hai:** Web-SCADA của đồ án, giao tiếp PLC qua **OPC UA** với cấu
  hình **Anonymous / No-Security**.
- **Bắt gói:** một Capture Host cắm vào cổng SPAN (port mirroring) của switch, thấy toàn
  bộ lưu lượng giữa mọi nút.

**Mô hình đe doạ:** kẻ tấn công đứng trong cùng mạng, xuất phát từ máy attacker riêng.
Kẻ tấn công **không sở hữu** thông tin xác thực OPC UA hợp lệ và **không có** quyền truy
cập vật lý trực tiếp vào PLC/HMI. Đây là mô hình sát thực tế: một kẻ xâm nhập đã vào được
mạng OT nhưng chưa có đặc quyền quản trị.

---

### [X].3 Case-study 1 — Trinh sát: SMB Reconnaissance (Pha Recon)

**Bối cảnh & động cơ.** Mọi cuộc tấn công có chủ đích đều bắt đầu bằng trinh sát. Sau khi
xâm nhập mạng OT, kẻ tấn công dò thăm các máy Windows (HMI/Engineering) để tìm chia sẻ
tệp, named pipe và dịch vụ — bàn đạp cho di chuyển ngang. Kỹ thuật: **T0842 Network Share
Discovery**.

**Mô hình đe doạ & thiết lập.** Attacker gửi các gói **SMB2 Negotiate** và thăm dò
share/RPC pipe tới máy HMI `192.168.210.31` (cổng 445), không cần đặc quyền.

**Thực nghiệm.**
```
$ python -m attacks_ext.smb_enum --target 192.168.210.31 --duration 15 \
    --session-id smoke --host-id attacker_host --label-file labels/smoke_test.csv
[15:58:05] label SMB_RECON_ENUM START
[*] SMB Recon -> 192.168.210.31
[15:58:26] label SMB_RECON_ENUM END
```
Mỗi chu kỳ gửi tổ hợp: 5 gói SMB2 Negotiate + thăm dò 15 tên share phổ biến (`C$`,
`ADMIN$`, `WinCC`, `SCADA`, `Engineering`…) + 8 RPC named pipe (`srvsvc`, `samr`,
`svcctl`…).

**Kết quả đo được.** Trong đợt thu thập đã kiểm chứng (session `day7_final`), phiên thăm
dò gửi **140 probe** trong 30 giây (`probes=140` trong nhật ký nhãn). Đối chiếu với pcap
thu qua cổng SPAN của switch trong đúng cửa sổ thời gian này, xác nhận **65 gói SMB2**
gửi tới HMI `.31` — chữ ký enumeration hiện diện thật trên dây, không chỉ là log phía
attacker.

**Phân tích.** Đây là chữ ký **enumeration ở tầng giao thức SMB2** (bắt tay Negotiate,
thăm dò share/pipe) — khác biệt về giao thức và đích so với các kịch bản trinh sát của
Day 1–6 (SCAN_PORT/ENUM_TAGS nhắm S7comm trên PLC).

**★ Đóng góp cho đồ án.** Bổ sung chiều **Discovery** vào phân loại tấn công của bộ dữ
liệu, với một chữ ký giao thức (SMB2 trên HMI) mà Day 1–6 không có. Về mặt tường thuật,
đây là nước đi mở màn hợp lý của chiến dịch — chứng minh môi trường có cả thành phần IT
(HMI Windows) để trinh sát, không chỉ có PLC.

---

### [X].4 Case-study 2 — Kill Chain: Foothold S7 + Di chuyển ngang

**Bối cảnh & động cơ.** Sau trinh sát, kẻ tấn công thiết lập chỗ đứng (foothold) rồi
dùng chính chỗ đứng đó làm bàn đạp tấn công máy khác — **di chuyển ngang (lateral
movement)**. Điểm nhấn của case-study này là **tính liên tục trong một phiên**: chiếm
PLC qua S7 rồi lập tức pivot sang HMI, thể hiện đúng mạch truyện APT thay vì các bước rời
rạc. Kỹ thuật: Initial Access (S7) → **T0846 Remote System Discovery**.

**Mô hình đe doạ & thiết lập.** Attacker kết nối S7 (snap7) tới PLC `.211`, đọc thông
tin thiết bị, rồi dò cổng máy HMI `.31` từ vị trí đã chiếm.

**Thực nghiệm.**
```
$ python -m attacks_ext.kill_chain --target 192.168.210.211 --rack 0 --slot 1 \
    --hmi-target 192.168.210.31 --session-id smoke --host-id attacker_host ...

[STAGE 1] INITIAL_ACCESS_ROGUE_EWS
  [+] Kết nối S7 thành công từ IP attacker
  [INFO] PLC Module:            <-- rỗng
  [INFO] Serial:                <-- rỗng
  [*] Rogue session thiết lập thành công

[STAGE 2] LATERAL_MOVEMENT_PIVOT_HMI
  [PIVOT] 192.168.210.31:102   (S7comm)              -> OPEN
  [PIVOT] 192.168.210.31:135   (MSRPC Endpoint Mapper) -> OPEN
  [PIVOT] 192.168.210.31:139   (NetBIOS Session)      -> OPEN
  [PIVOT] 192.168.210.31:445   (SMB)                  -> OPEN
  [PIVOT] 192.168.210.31:1433  (MSSQL WinCC DB)       -> closed
  [PIVOT] 192.168.210.31:3389  (RDP)                  -> OPEN
  [*] Lateral movement xong: 5/8 port mở trên 192.168.210.31
```

**Kết quả đo được.** Foothold S7 thiết lập thành công; pivot phát hiện **5/8 cổng mở**
trên HMI: 102 (S7comm cục bộ), 135 (MSRPC), 139 (NetBIOS), 445 (SMB), 3389 (RDP) — đúng
các bề mặt tấn công tiếp theo của một máy Engineering Windows. Pcap thu qua cổng SPAN
trong cửa sổ này xác nhận **15 gói TCP SYN** quét cổng tới HMI `.31` (chữ ký port-scan)
và **5 gói S7comm** tới PLC `.211` (phiên foothold) — khớp với hành vi hai bước
foothold→pivot của kịch bản.

**Phân tích.** Một quan sát phụ đáng chú ý: ở Stage 1, `get_cpu_info()` trả về **Module
và Serial rỗng**. Trên S7-1500 thật, đây là biểu hiện của việc firmware **hạn chế các
dịch vụ chẩn đoán S7comm cổ điển** — cùng cơ chế bảo mật sẽ xuất hiện lại ở [X].6. Về
nhãn MITRE: phần pivot là port-scan thuần (TCP connect) từ vị trí đã chiếm, đúng bản chất
T0846 Remote System Discovery trong ngữ cảnh lateral movement.

**★ Đóng góp cho đồ án.** Chứng minh **testbed đủ thực tế để dựng tấn công đa giai đoạn
liên tục** — không phải môi trường đồ chơi. Đây là bằng chứng trực tiếp cho nửa "xây dựng
môi trường" của đề tài. (Phần chữ ký port-scan có thể trùng một phần với SCAN_PORT của
Day 1–6; do đó case-study này không được tính là lớp ML mới — xem [X].8.)

---

### [X].5 Case-study 3 — Concealed Stop Attack: Phá hoại phối hợp có che giấu

Đây là case-study **trung tâm** của mục, đóng góp bằng chứng định lượng chính cho kết
luận an ninh ở [X].7.

**Bối cảnh & động cơ.** Dựa trên Urbina et al., *"Limiting the Impact of Stealthy
Attacks on Industrial Control Systems"* (ACM CCS 2016): một tấn công tinh vi không chỉ
tác động lên actuator, mà **đồng thời giả mạo phản hồi cảm biến** để che giấu hiệu ứng
khỏi người vận hành và hệ thống giám sát. Đây là **tấn công đa điểm phối hợp có điều
kiện** (Adepu & Mathur, COMPSAC 2016), khác về bản chất với một thao tác đơn lẻ. Kỹ
thuật: **T0831 Manipulation of Control** phối hợp **T0856 Spoof Reporting Message**.

**Mô hình đe doạ & thiết lập.** Attacker có foothold S7 vào PLC `.211` (điều khiển thật)
và một kênh OPC UA Anonymous (giả mạo hiển thị). Mục tiêu: dừng băng tải thật **nhưng làm
Web-SCADA vẫn hiển thị RUNNING**.

**Thực nghiệm.** Vòng lặp giám sát timer `CD1`; khi phát hiện đúng lúc "vật đang vận
chuyển" (`0 < CD1 < 30000ms`): (1) bật che giấu — 5 luồng OPC UA song song liên tục ghi
`BangTai = True`; (2) ghi `STOP = True / START = False` thật lên M5 của PLC qua S7; (3)
giữ 6 giây; (4) khôi phục.
```
[16:00:43] label CONCEALED_STOP_ATTACK START
[+] Probe: BangTai chấp nhận ghi (giá trị hiện tại=True)
[+] S7 foothold connected -- monitoring CD1 for transport window...
[+] OPC UA concealment channel connected (5 writer song song)
  [1] STOP thật (CD1=1133ms) + concealment ON (đang ghi lại BangTai=True qua OPC UA)
  [1] Restart thật -- concealment OFF
[*] Restored START=False STOP=False
```

**Kết quả đo được.** Băng tải **dừng thật** — cả WinCC lẫn Web-SCADA phản ánh trạng thái
dừng (đúng sự thật). Trong đợt thu thập đã kiểm chứng (session `day7_final`, 180 giây,
**9 chu kỳ STOP**), phần che giấu (làm Web-SCADA hiển thị RUNNING giả) chỉ thành công
một phần:

| Chỉ số (session day7_final) | Giá trị |
|---|---|
| Số chu kỳ STOP thật | 9 |
| Số lần ghi giả gửi đi (`conceal_attempts`) | 13.604 (0 lỗi) |
| Giá trị giả **giữ được** khi đọc lại (`readback_still_true`) | 183 |
| Giá trị giả **bị PLC ghi đè** (`readback_reverted`) | 843 |
| **Tỷ lệ che giấu "dính"** | **183 / 1026 = 17.8%** |

Con số 17.8% này (trên 1026 lần đọc) **tái xác nhận** kết quả ~17–18% của các lần chạy
trước với số mẫu lớn hơn — cho thấy đây là một hằng số ổn định, không phải kết quả ngẫu
nhiên một lần.

**Bằng chứng trên dây (pcap thu qua cổng SPAN):** trong đúng cửa sổ tấn công, mirror bắt
được **16.680 gói OPC UA** đổ tới PLC `.211` (burst ghi che giấu) và **162 gói S7comm**
(lệnh STOP thật) — đồng thời **3.702 gói TLS/S7CommPlus** của kênh WinCC hợp lệ vẫn chạy
nền. Đây là **ảnh chụp hai kênh trong cùng một capture**: attacker đổ hàng chục nghìn gói
vào kênh OPC UA không xác thực, trong khi kênh WinCC mã hoá vẫn hoạt động bình thường,
không bị đụng tới.

**Phát hiện định lượng quan trọng:** tỷ lệ che giấu ổn định ~17–18% bất kể số lần ghi
(13.604 lần ghi chỉ "dính" 183). Nút thắt cổ chai nằm ở **khả năng xử lý bên trong
PLC/OPC UA server** — PLC tính lại giá trị thật mỗi chu kỳ scan và ghi đè giá trị giả gần
như ngay lập tức — chứ không phải tốc độ gửi của attacker. Đây là **trần cứng** của mô
hình "client bên ngoài đua thời gian với chu kỳ scan của PLC".

Đối chứng trên kênh WinCC/S7CommPlus (mã hoá + xác thực): **0% — không thể can thiệp**.

**Phân tích & neo lý thuyết.** Kết quả xác nhận đúng luận điểm của Urbina et al.: che
giấu **đáng tin** đòi hỏi kẻ tấn công **kiểm soát được đường truyền hoặc cảm biến**, chứ
không thể chỉ ghi đè giá trị từ một client bên ngoài. (Nhóm đã thử hướng MITM/ARP để kiểm
soát đường truyền và **thất bại** — xem [X].7, thí nghiệm 4 — càng củng cố luận điểm
này.) Mặt khác, chính sự yếu này là **bằng chứng cho hướng phòng thủ**: các tag khác trên
Web-SCADA (`Stage timer = 0ms`, giai đoạn không tiến triển) **không được che giấu** →
người vận hành quan sát kỹ toàn bộ dashboard vẫn phát hiện tấn công qua **mâu thuẫn giữa
các tín hiệu** — đúng nguyên lý "physical invariants / cross-signal consistency" mà
Urbina et al. đề xuất làm cơ chế phòng thủ.

**Quan sát bổ trợ độc lập.** Cùng cơ chế ghi-đè-theo-chu-kỳ-scan còn được quan sát trong
một bối cảnh hoàn toàn khác — tính năng điều khiển của Web-SCADA. Khi ghi giá trị mới cho
tag `nhap` (số lượng sản phẩm mục tiêu) qua OPC UA, giá trị bị **hoàn nguyên trong vòng
một chu kỳ scan** (0% giữ được, so với ~17% của `BangTai`). Nguyên nhân: `nhap` là biến
được **nạp trực tiếp trong chương trình PLC**, nên PLC tính lại và ghi đè mọi giá trị đến
từ bên ngoài. Đây **không phải một biện pháp bảo mật có chủ đích** mà là hệ quả của việc
chương trình PLC "sở hữu" biến đó — nhưng nó xác nhận rằng **trần che giấu là thuộc tính
của việc ghi từ ngoài vào tag do PLC điều khiển, không riêng gì `BangTai`**. (Đây cũng là
lý do Web-SCADA đánh dấu `nhap` là `writable: false` — nhất quán với quan sát này.)

**★ Đóng góp cho đồ án.** Cung cấp **bằng chứng định lượng** (~17–18%, đo được, ổn định)
cho kết luận an ninh trung tâm: trên cùng một PLC, kênh có xác thực miễn nhiễm, chỉ kênh
OPC UA Anonymous bị khai thác một phần → **lỗ hổng nằm ở cấu hình, không phải ở giao
thức**. Đồng thời chứng minh testbed cho phép nghiên cứu **cả tấn công lẫn cơ chế phát
hiện phòng thủ** trên một môi trường thật.

---

### [X].6 Case-study 4 (bổ sung) — Program Upload Theft: Tấn công bị S7-1500 chặn

**Bối cảnh & động cơ.** Đánh cắp logic điều khiển (upload toàn bộ khối chương trình
OB/FB/FC/DB) là bước tiền đề cho tấn công có nhận thức về logic. Kỹ thuật: **T0845 Program
Upload**. Case-study này ghi lại một **kết quả âm có giá trị** — tấn công bị chặn.

**Thực nghiệm & kết quả.**
```
$ python -m attacks_ext.program_upload --target 192.168.210.211 --rack 0 --slot 1 ...
USERDATA response error 0x8104: This service is not implemented on the module
[*] PROGRAM_UPLOAD_THEFT -> 192.168.210.211  (list_blocks_err=S7ProtocolError)
  [cycle 1] uploaded=0 blk (0B), denied=0
```
Kết nối S7 thành công, nhưng mọi lệnh `list_blocks`/`full_upload` bị trả `0x8104 =
service not implemented`. Kết quả: **0 khối** đánh cắp được.

**Phân tích.** Trên S7-1500 phần cứng thật, Siemens **cố tình gỡ/chặn** các lệnh S7comm
cổ điển thao tác khối chương trình (chuyển sang S7CommPlus có xác thực). Bằng chứng bổ
sung cho cùng cơ chế: `get_cpu_info()` trả về rỗng ở [X].4, và `plc_hot_start()` bị từ
chối ở Day 3 (khiến CPU kẹt STOP). Ba hiện tượng cùng một nguyên nhân: **hardening của
firmware S7-1500 đối với giao thức cổ điển/không xác thực**.

**★ Đóng góp cho đồ án.** Bằng chứng phòng thủ thật: kênh S7comm cổ điển **bị PLC chặn ở
tầng giao thức**. Cùng với [X].5, tạo thành cặp đối xứng — kênh có xác thực an toàn, kênh
Anonymous hở.

---

### [X].7 Tổng hợp: Luận điểm an ninh trung tâm

**Luận điểm (một câu):** trên **cùng một PLC S7-1500 phần cứng thật**, mọi kênh dùng giao
thức có xác thực hoặc S7comm cổ điển đều **chống được** tấn công; lỗ hổng duy nhất khai
thác được nằm ở **cấu hình OPC UA Anonymous / No-Security** của testbed — tức là **lỗ
hổng cấu hình, không phải lỗ hổng giao thức hay phần cứng**.

Luận điểm này được củng cố bởi **bốn thí nghiệm độc lập cùng hội tụ**:

| # | Thí nghiệm | Kênh / kỹ thuật | Kết quả | Ý nghĩa |
|---|---|---|---|---|
| 1a | Che giấu STOP | **OPC UA Anonymous** ghi `BangTai` | Giả được 17.8% (183/1026, nhấp nháy) | Kênh không xác thực: khai thác được nhưng **yếu** |
| 1b | (cùng thí nghiệm) | **WinCC / S7CommPlus** | **0%** | Kênh có xác thực: **miễn nhiễm** |
| 2 | Program Upload (T0845) | S7comm cổ điển — upload khối | `0x8104` not implemented | S7-1500 **chặn** |
| 3 | CPU Stop (Day 3) | S7comm — `plc_hot_start` | Bị từ chối | S7-1500 **chặn** |
| 4 | MITM / ARP poison | Sửa gói OPC UA trên dây | `intercepted=0` (3/3 lần) | Stack mạng CN **chặn** ARP giả mạo |

**Neo vào lý thuyết:** thí nghiệm 1a (~17%) và thí nghiệm 4 (MITM thất bại) là bằng chứng
thực nghiệm cho luận điểm Urbina et al. rằng che giấu đáng tin đòi hỏi kiểm soát đường
truyền/cảm biến. Cơ chế phát hiện phòng thủ tương ứng là kiểm tra nhất quán chéo giữa các
tín hiệu vật lý.

**Kết luận phòng thủ (khuyến nghị vận hành, có bằng chứng):** khoá kênh OPC UA — bật
`SecurityPolicy: Basic256Sha256` kèm xác thực người dùng. Khi đó kết nối tấn công ẩn danh
bị từ chối ngay ở bước bắt tay, vô hiệu hoá vector 1a. Đây là khuyến nghị **cụ thể, đo
được**, không phải lời khuyên chung chung.

> *(Nếu đã thực hiện so sánh A/B: chèn bảng kết quả cùng một tấn công chạy dưới hai chế độ
> — Anonymous (~17%) vs Basic256Sha256 (0% — kết nối bị từ chối) — làm bằng chứng đóng.)*

---

### [X].8 Thí nghiệm thất bại và bài học kỹ thuật

Một môi trường nghiên cứu trung thực phải ghi lại **cả những gì không hoạt động**. Phần
này tài liệu hoá các thí nghiệm thất bại và lỗi kỹ thuật đã gặp — vì hai lý do: (1) **kết
quả âm cũng là kết quả** — một tấn công bị chặn là bằng chứng về sức mạnh phòng thủ; (2)
**nhật ký debug là bài học** giúp người sau không lặp lại sai lầm, đồng thời thể hiện quá
trình nghiên cứu thực chất thay vì chỉ trình bày các kết quả đã chọn lọc.

#### [X].8.1 Thí nghiệm thất bại là bằng chứng phòng thủ (kết quả âm có giá trị)

**a) MITM / ARP poisoning để chặn-sửa gói OPC UA — thất bại do hardening mạng.**
Hướng ban đầu của Concealed Stop Attack ([X].5) là **kiểm soát đường truyền** bằng MITM:
ARP poison giữa PLC và HMI, rồi sửa trực tiếp gói OPC UA trên dây (kiểm soát 100%, thay
vì đua ghi đè ~17%).
- *Lỗi 1 (đã sửa):* `get_if_hwaddr()` trên Npcap trả về **MAC rỗng** → gói ARP poison
  không hợp lệ. Đã vá.
- *Sau khi vá — vẫn thất bại:* xác nhận qua `diag_arp_redirect.py` rằng attacker gửi
  được **44 gói ARP poison với MAC hợp lệ**, nhưng `intercepted=0` **ở cả 3 lần chạy**.
- *Kết luận:* PLC/HMI **không chấp nhận gratuitous ARP** (ARP reply không được yêu cầu) —
  rất có thể là **hardening có chủ đích của stack mạng công nghiệp**. Không sửa được bằng
  code, không chẩn đoán sâu hơn được vì không có quyền truy cập trực tiếp PLC/HMI để kiểm
  tra bảng ARP.
- *Quyết định:* **bỏ hoàn toàn hướng MITM/ARP**, chuyển sang ghi giá trị giả trực tiếp
  qua OPC UA. Chính thất bại này là **thí nghiệm 4** trong bảng hội tụ [X].7 — bằng chứng
  cho luận điểm Urbina: kẻ tấn công ngoài không dễ kiểm soát đường truyền trong mạng OT
  được làm cứng.

**b) Program Upload Theft — bị S7-1500 chặn (`0x8104`).** Đã trình bày chi tiết ở [X].6:
tấn công chạy được nhưng target từ chối ở tầng giao thức (0 khối đánh cắp). Kết quả âm =
bằng chứng hardening.

**c) CPU Stop (Day 3) — `plc_hot_start` bị từ chối.** `plc_stop()` thực thi được nhưng
S7-1500 **từ chối `plc_hot_start()`**, khiến CPU kẹt ở trạng thái STOP, phải khởi động
lại thủ công qua TIA Portal. Đây là lý do CPU_STOP **bị tắt mặc định** và không được đưa
lại vào Day 7 — vừa trùng nhãn với Day 3, vừa dính đúng lỗi đã biết.

**d) Profinet DCP Abuse — không thực thi được trong môi trường ảo.** Kịch bản cần raw
socket tầng 2 (DCP dùng EtherType `0x8892`, không có lớp IP) và quyền root. Máy attacker
(WSL2) vô hiệu hoá `sudo`, và interface ảo không nhìn thấy segment Profinet vật lý. Đây
là **giới hạn môi trường phía attacker**, KHÔNG phải kết luận bảo mật về target — được
ghi nhận trung thực và loại khỏi lịch.

#### [X].8.2 Nhật ký lỗi kỹ thuật đã sửa (bài học triển khai)

| Lỗi gặp phải | Nguyên nhân gốc | Cách sửa |
|---|---|---|
| `BadWriteNotSupported` khi ghi OPC UA | `asyncua` tự gắn `SourceTimestamp`; S7-1500 từ chối gói ghi kèm timestamp | Tự dựng `ua.DataValue(ua.Variant(value))` tối giản, không timestamp |
| `TypeError`/`FrozenInstanceError` khi set `StatusCode` | Khác biệt phiên bản `asyncua` giữa các máy | Chỉ dùng constructor 1 tham số vị trí, tương thích mọi bản |
| Mọi probe SMB2 bị drop (SMB_RECON không có tác dụng) | Độ dài NBSS hard-code lệch với payload thật → frame dị dạng, bị bỏ âm thầm | Tính độ dài từ payload thật (xem `tests/test_smb_enum.py`) |
| Tấn công có nhãn nhưng **0 gói** trong capture | `CAPTURE_FILTER="host $TARGET_IP"` chỉ bắt PLC, bỏ traffic đánh HMI | Sửa filter: `host $TARGET_IP or host $HMI_IP` |
| Frame DCP tầng 2 bị drop sạch | Filter `host …` chỉ bắt gói có lớp IP; DCP là layer-2 | Thêm `or ether proto 0x8892` vào filter |
| Mỗi tấn công có **2×START + 2×END** (timeline chồng lấn) | Cả tầng shell lẫn module đều ghi nhãn vào cùng file | Bỏ nhãn ở tầng shell; module là **nguồn nhãn duy nhất** |

**★ Đóng góp cho đồ án.** Các lỗi capture (filter bỏ HMI, bỏ DCP; trùng nhãn) đặc biệt
quan trọng: nếu không phát hiện, dataset sẽ có **nhãn tấn công nhưng không có gói tin** —
lỗi âm thầm phá hoại chất lượng dữ liệu mà không báo lỗi rõ ràng. Việc tài liệu hoá chúng
thể hiện đúng tinh thần "thu thập dữ liệu **chất lượng**", không chỉ "thu cho có".

---

### [X].9 Định vị đóng góp và ranh giới với dữ liệu ML

Để bảo đảm tính trung thực và khả năng chống phản biện, mục này nêu rõ ranh giới:

- **Day 7 KHÔNG đóng góp lớp thao tác-quá-trình mới cho học máy.** Phần ghi S7 của
  Concealed Stop Attack ghi vào vùng M5 **trùng vùng/offset với RWRITE_BURST** (Day 3/6)
  ở tầng đặc trưng; phần port-scan của Kill Chain trùng một phần với SCAN_PORT. Do đó
  chúng **không** được dùng làm lớp huấn luyện riêng — nếu làm sẽ gây trùng nhãn (label
  collision), hạ trần hiệu năng phân loại đa lớp.
- **Sự trùng này không ảnh hưởng mô hình đã huấn luyện**, vì: xương sống huấn luyện là
  Day 1–5; Day 6 là tập holdout đánh giá; Day 7 là case-study đứng ngoài quy trình ML.
  Ba vai trò tách biệt, không "đấu" nhau trong bất kỳ phép huấn luyện/đánh giá nào.
- **Đóng góp dữ liệu thật, khiêm tốn:** chữ ký enumeration SMB2 trên HMI (Case-study 1) —
  giao thức/đích mà Day 1–6 không có.
- **Đóng góp chính là định tính:** minh chứng môi trường thực tế (đa giai đoạn, đa giao
  thức, đa host) và phân tích an ninh định lượng ([X].7).

**Kết luận mục.** Day 1–6 là xương sống dữ liệu cho mô hình AI phát hiện thao tác quá
trình; mục case-study này là **tầng phân tích an ninh và minh chứng môi trường** —
chứng minh testbed đủ thực tế để dựng một chiến dịch tấn công APT hoàn chỉnh, và rút ra
kết luận phòng thủ định lượng có giá trị vận hành. Hai phần bổ trợ nhau, đúng theo hai
nửa của tên đề tài: *xây dựng môi trường* và *thu thập dữ liệu truyền thông công nghiệp*.
