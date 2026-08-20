# BÁO CÁO KỸ THUẬT: TESTBED & XÂY DỰNG DATASET ICS/IIoT IDS

---

## PHẦN 1 — MÔ HÌNH HỆ THỐNG TESTBED

### 1.1 Kiến trúc tổng quan testbed

Hệ thống testbed được xây dựng với mục tiêu tái tạo môi trường điều khiển công nghiệp thực tế, bao gồm ba thành phần chính:

```
┌─────────────────────────────────────────────────────┐
│                 Mạng công nghiệp 192.168.1.0/24      │
│                  (Layer-2 switch, span port)          │
│                                                       │
│  ┌──────────────┐    ┌──────────────┐                │
│  │ Engineering  │    │ Controller   │                │
│  │ Station      │    │ Host         │                │
│  │ (TIA Portal) │    │ (HMI/SCADA)  │                │
│  └──────┬───────┘    └──────┬───────┘                │
│         │                   │  Snap7 S7comm           │
│         └──────────┬────────┘                        │
│                    │                                  │
│             ┌──────┴──────┐                          │
│             │  PLC TARGET  │                         │
│             │ S7-1500/1200 │  <── thiết bị THẬT      │
│             │ 192.168.1.10 │       hoặc PLCSIM        │
│             └─────────────┘                          │
│                                                       │
│  ┌──────────────┐                                    │
│  │ Attacker Host│  (192.168.1.100)                   │
│  │ tshark+snap7 │──── capture eth0                   │
│  └──────────────┘                                    │
└─────────────────────────────────────────────────────┘
```

> 📌 **[HÌNH 1]** Sơ đồ topology testbed đầy đủ: PLC thật + Engineering station + Controller host + Attacker host, thể hiện luồng S7comm và điểm capture tại NIC của từng host.

---

### 1.2 Điểm khác biệt then chốt: Kết hợp PLC thật và PLCSIM

Đây là điểm **quan trọng nhất** phân biệt hệ thống với các nghiên cứu trước. Hầu hết dataset ICS công khai (BATADAL, SWaT) chỉ dùng thiết bị thật nhưng không công bố protocol trace ở lớp S7; các nghiên cứu học thuật khác chỉ dùng PLCSIM để tránh rủi ro phần cứng. Hệ thống này **chủ động kết hợp cả hai** trong cùng một quy trình thu thập:

| Tiêu chí | PLCSIM | PLC thật (S7-1500/S7-1200) |
|---|---|---|
| Timing TCP thực tế | Mô phỏng, lý tưởng hóa | Có: jitter phần cứng thật, RTT thật |
| Phản hồi CPU state (RUN/STOP) | Không phản hồi lệnh STOP thật | TCP session drop khi CPU STOP, trạng thái thật |
| Giới hạn PUT/GET | Không giới hạn | S7-1500 block PUT/GET nếu không bật trong TIA Portal |
| Profinet DCP discovery | Không có | Có: station name thật, vendor ID thật (Siemens 002a) |
| Side-effect vật lý | Không | Có: actuator thật dừng, cảm biến thật thay đổi trạng thái |
| Giới hạn session đồng thời | Không | Có: S7-1500 giới hạn số kết nối → S7_FLOOD có tác động thật |

**Ý nghĩa với AI/ML:** Traffic từ PLC thật tạo ra các đặc trưng timing (IAT, TCP RTT, window size jitter) phản ánh giới hạn phần cứng thật — không bị "lý tưởng hóa" như PLCSIM. Mô hình học trên dữ liệu này có khả năng generalize tốt hơn khi triển khai thực tế. Đồng thời, việc có PLCSIM cho phép tái tạo nhanh các kịch bản không an toàn (CPU STOP) mà không rủi ro hệ thống sản xuất.

> 📌 **[HÌNH 2]** So sánh waveform timing S7comm: PLCSIM vs PLC thật — biểu đồ phân bố RTT (round-trip time) và TCP retransmit rate giữa hai môi trường.

---

### 1.3 Bài toán điều khiển được triển khai — Hệ thống Băng Truyền (Conveyor Belt)

Bài toán **Băng Truyền** được chọn vì nó là mô hình thu nhỏ đại diện cho một **lớp rộng các hệ thống công nghiệp phân tán**: điều khiển đèn giao thông đô thị (vòng lặp timing theo pha), hệ thống thủy lợi (van mở/đóng theo cảm biến mực nước), dây chuyền sản xuất tự động. Tất cả đều có cấu trúc chung:

```
sensor input (I area) → PLC logic (M area Merker) → actuator output (Q area)
                              ↑
                        timer/counter (MD/MW area)
```

**Bảng tag TIA Portal — mapping đầy đủ** (từ `log_tags_bangtruyen.py`):

```
I area (Physical Input — đầu vào vật lý):
  I0.0 = Start_1         — Nút khởi động vật lý tại máy
  I0.1 = Stop_1          — Nút dừng khẩn cấp vật lý
  I0.2 = Cam_bien        — Cảm biến quang phát hiện thùng/vật thể

Q area (Physical Output — đầu ra điều khiển actuator):
  Q0.0 = BangTai         — Động cơ băng tải: CHẠY (1) / DỪNG (0)
  Q0.6 = Aux output      — Tín hiệu phụ trợ

M area (Merker — biến nội bộ logic PLC):
  M5.0 = START           — Lệnh khởi động từ HMI/SCADA (remote)
  M5.1 = STOP            — Lệnh dừng từ HMI/SCADA (remote)
  M5.2 = Tag_1           — Cờ nội bộ
  M5.3 = Tag_2           — Cờ nội bộ
  M5.4 = Vat_1           — Vật thể 1 đang trên băng
  M5.5 = Tag_5           — Cờ nội bộ
  M5.6 = Vat_2           — Vật thể 2 đang trên băng
  M5.7 = Tag_6           — Cờ nội bộ
  M6.0 = Vat_3           — Vật thể 3 đang trên băng
  M6.1 = S1              — Cờ trạng thái sensor 1
  M6.2 = Tag_8           — Cờ nội bộ

MD area (Double Integer — timer/counter, đơn vị ms):
  MD50 = Times_1         — Bộ đếm thời gian tổng chu kỳ
  MD54 = CD1             — Countdown timer xử lý vật thể 1
  MD58 = CD2             — Countdown timer xử lý vật thể 2
  MD62 = CD3             — Countdown timer xử lý vật thể 3

MW area (Word Integer — đếm):
  MW70 = Nhap            — Đếm số thùng vào
  MW74 = HienThi         — Giá trị hiển thị HMI
```

**Tương đồng với bài toán công nghiệp diện rộng:**

| Hệ thống | Tương đương trong Băng Truyền | S7comm traffic pattern |
|---|---|---|
| Đèn giao thông đô thị | M5.0/M5.1 = lệnh chuyển pha; CD1/CD2/CD3 = timer xanh/vàng/đỏ; Q0.x = đèn | Giống hệt: Job(Write M) → Ack theo chu kỳ |
| Hệ thống thủy lợi | Vat_1/2/3 = mực nước van cống; Times_1 = chu kỳ tưới; START/STOP = lệnh điều phối trung tâm | Giống hệt: Read M/I → Write M theo ngưỡng |
| Dây chuyền sản xuất | Vat_x = trạng thái trạm gia công; CD_x = thời gian gia công; BangTai = băng chuyền liên trạm | Giống hệt: đọc cảm biến → ghi lệnh actuator |

Cả ba loại hệ thống này đều tạo ra **cùng một pattern S7comm**: Job(Read/Write) → Ack_Data lặp lại, với Merker area là trung gian điều khiển — đây là lý do dataset trên Băng Truyền có thể đại diện cho nhóm bài toán rộng hơn.

> 📌 **[HÌNH 3]** Sơ đồ chức năng hệ thống Băng Truyền: luồng I→PLC logic (Merker)→Q, các timer CD1/CD2/CD3 điều phối 3 vật thể song song.
> 📌 **[HÌNH 4]** Bảng tag TIA Portal — screenshot từ phần mềm TIA Portal V17: thể hiện mapping địa chỉ thực tế.

---

### 1.4 Thu thập dữ liệu — hai host song song, capture đồng thời

Script `run_day_bangtruyen.sh` điều phối hai host hoạt động **độc lập và đồng thời**, mỗi host có TShark capture riêng:

**Controller host** — mô phỏng đầy đủ hoạt động vận hành bình thường:

| Thành phần | Cơ chế | Loại traffic tạo ra |
|---|---|---|
| HMI poll (`start_hmi`) | Snap7 đọc M[0..80] + Q[0] + I[0], interval random 1–2s | S7comm: Job(Read MK/PA/PE) → Ack_Data |
| Tag logger (`log_tags_bangtruyen.py`) | Poll 0.5s, ghi tất cả tag ra CSV | S7comm session riêng, song song với HMI |
| TIA Portal online | Kỹ sư bật "Go Online", monitor watch table | S7comm UserData (ROSCTR=0x07) — khác HMI |
| Chế độ idle | Không poll, không logger | Chỉ TCP keepalive, ARP broadcast |

**Attacker host:**
- Day 1: idle hoàn toàn, chỉ TShark capture → baseline thuần túy không có tấn công
- Day 2–6: thực thi từng kịch bản tấn công, TShark capture độc lập với controller

**Timeline labeling thời gian thực** — ghi ngay khi chạy, không post-hoc:
```
label() ghi ra file CSV mỗi khi episode bắt đầu/kết thúc:
  attacker_timestamp_ms | scenario_label | action | session_id | host_id | episode_id | day | note
```

> 📌 **[HÌNH 5]** Timeline 6 ngày thu thập: trục thời gian thể hiện các pha benign (Day 1), reconnaissance (Day 2), integrity attacks (Day 3–4), availability attacks (Day 5), OOD test (Day 6) với nhãn kịch bản.

---

## PHẦN 2 — XÂY DỰNG DATASET CHO HUẤN LUYỆN AI

### 2.1 Pipeline tổng quan

```
┌──────────────────┐   ┌────────────────────┐   ┌─────────────────┐
│  captures/       │   │  labels/            │   │  logs/          │
│  day1/           │   │  *_timeline.csv     │   │  *_tags.csv     │
│  *.pcapng        │   │  *_attack_events.csv│   │  (PLC tag log)  │
└────────┬─────────┘   └──────────┬──────────┘   └────────┬────────┘
         │                        │                        │
         ▼                        │                        │
extract_s7_features.py ───────────┘ (timeline optional)   │
  TShark DPI toàn stack S7comm                             │
  → 1 dòng / 1 cửa sổ 5 giây                              │
         │                                                 │
         ▼                                                 ▼
features/*_features.csv ──────── merge_dataset.py ← tags.csv
                                        │
                          ┌─────────────┼─────────────────┐
                          ▼             ▼                  ▼
                 dataset_network  dataset_process   dataset_fusion
                 (PCAP features)  (PLC tag view)   (Network+Process)
                          │
                          ▼
                     train_ml.py
              GroupKFold | RF + LR | metrics đầy đủ
```

> 📌 **[HÌNH 6]** Sơ đồ pipeline end-to-end: từ raw PCAP + timeline + tag log đến 3 dataset views và model evaluation.

---

### 2.2 Tính mới — Khai thác ngữ nghĩa sâu traffic công nghiệp (Industrial DPI)

**Đây là đóng góp kỹ thuật trọng tâm nhất của nghiên cứu.**

Các dataset ICS trước đây (CIC-IDS2017 phiên bản ICS, TON_IoT, UNSW-NB15) dừng ở đặc trưng **L3/L4**: số gói, byte count, TCP flag count, IAT — hoàn toàn bỏ qua lớp ứng dụng công nghiệp. Hệ thống này thực hiện **Deep Packet Inspection toàn bộ stack S7comm** — đi từ L2 đến L7 ứng dụng PLC.

#### 2.2.1 Phân tầng đặc trưng theo stack giao thức

```
L2  Ethernet    → src/dst MAC, eth.type
                   Profinet DCP (eth.type=0x8892):
                     service_id (Identify/Set/Get/Hello)
                     service_type (Request/Response)
                     vendor_id, device_id, station_name, ip_addr

L3  IP          → src/dst IP, protocol

L4  TCP         → port 102 (S7comm), TCP flags (SYN/ACK/RST/FIN/URG/CWE/ECE)
                   stream ID, IAT per direction (fwd/bwd), window size

L5  TPKT        → transport header (RFC 1006): length field
                   tpkt_count per window

L6  COTP        → Connection Request (CR): mở session
                   Connection Confirm (CC): server chấp nhận
                   Data Transfer (DT): chứa S7 command thực tế
                   Disconnect Request (DR): đóng session
                   → cotp_cr_count, cotp_cc_count, cotp_dt_count, cotp_dr_count

L7  S7comm      → ROSCTR: Job(0x01) / Ack(0x02) / Ack_Data(0x03) / UserData(0x07)
                   param.func: Read(0x04) / Write(0x05) / Setup(0xF0) / CPU Control
                   param.item.area: MK(Merker) / PA(Output) / PE(Input) / DB(DataBlock)
                   param.item.db: số DataBlock
                   param.item.address: byte offset trong vùng nhớ
                   param.item.transport_size: kích thước dữ liệu
                   resp.error_class / error_code: phản hồi lỗi

    S7comm-plus → opcode, function:
                   GetMultiVariables (đọc nhiều tag)
                   SetMultiVariables (ghi nhiều tag)
                   CreateObject / DeleteObject (quản lý session)
```

#### 2.2.2 Các đặc trưng ngữ nghĩa không có trong bất kỳ dataset ICS công khai nào

**`s7_write_read_ratio`** — tỷ lệ lệnh Write / Read trong cùng window 5 giây:
- Hoạt động bình thường HMI: chủ yếu đọc trạng thái → ratio << 1 (< 0.1)
- RWRITE_BURST: attacker ghi liên tục START/STOP → ratio >> 1 (> 5)
- SETPOINT_ATTACK: ghi timer → ratio tăng, nhưng target là MD offset (khác RWRITE)

**`s7_sequential_offset_score`** — độ tuần tự của địa chỉ byte offset trong window:
- Bình thường: HMI đọc cùng vài địa chỉ cố định (M5, M6, MD54...) → score ≈ 0
- ENUM_TAGS: đọc toàn bộ M[0..80] với offset tăng dần → score ≈ 1.0
- Công thức: tỷ lệ các diff(offset) ∈ {1, 2, 4, 8} (bước đi đặc trưng của enumeration)

**`s7_merker_area_count` vs `s7_output_write_count` vs `s7_input_write_count`** — phân biệt vùng nhớ bị tấn công:
- Ghi vào Merker (M): tác động gián tiếp qua logic PLC → nguy hiểm mức vừa
- Ghi vào Output (Q): bypass logic PLC, điều khiển trực tiếp actuator → nguy hiểm cao nhất
- Ghi vào Input (I): giả mạo trạng thái cảm biến → SENSOR_SPOOF

**`cotp_cr_count` cao + `s7comm_packet_count` thấp** → S7_FLOOD signature:
- Session bình thường: 1 CR → nhiều DT (nhiều S7 command)
- S7_FLOOD: nhiều CR nhưng không có DT theo sau (connect rồi ngắt ngay)

**`s7_negotiation_only_ratio`** — tỷ lệ packet chỉ có COTP/TPKT nhưng không có S7 command:
- Normal: ratio thấp (kết nối được dùng thực sự)
- S7_FLOOD / SYN_FLOOD: ratio ≈ 1.0

**`payload_entropy_mean` + `payload_hash_unique_ratio`**:
- Normal S7 command: payload có cấu trúc cố định → entropy thấp, hash lặp lại nhiều
- PROTOCOL_FUZZ: payload ngẫu nhiên → entropy cao (≈ 8 bit/byte), hash unique ≈ 1.0
- REPLAY attack: payload lặp lại giống hệt → hash unique ≈ 0, entropy thấp

**`dcp_identify_request_count` + `dcp_discover_ip_count`** — Profinet DCP recon:
- Normal: không có hoặc rất ít DCP request
- Recon scan: burst DCP Identify Request → enumerate tất cả thiết bị Profinet trên mạng

> 📌 **[HÌNH 7]** Bảng so sánh đặc trưng: dataset này vs CIC-IDS2017-ICS vs TON_IoT — thể hiện rõ các tầng L5 (TPKT), L6 (COTP), L7 (S7comm semantic) chỉ có trong nghiên cứu này.
>
> 📌 **[HÌNH 8]** Box plot / violin plot của 6 đặc trưng ngữ nghĩa S7 phân theo nhãn tấn công:
> - `s7_write_count` (RWRITE >> BENIGN)
> - `s7_sequential_offset_score` (ENUM_TAGS >> BENIGN)
> - `cotp_cr_count` (S7_FLOOD >> BENIGN)
> - `payload_entropy_mean` (FUZZ >> BENIGN)
> - `s7_merker_area_count` (tất cả integrity attacks)
> - `s7_negotiation_only_ratio` (FLOOD attacks)

#### 2.2.3 Decode level — kiểm soát chất lượng giải mã

Mỗi window được gán `decode_level` theo chất lượng giải mã đạt được:

| decode_level | Ý nghĩa | Đặc trưng có thể dùng |
|---|---|---|
| `network_only` | Chỉ L3/L4 | packet count, byte, TCP flags, IAT |
| `cotp_tpkt` | L5/L6 nhận dạng được | Thêm tpkt_count, cotp_cr/cc/dt/dr |
| `s7_partial` | S7comm nhận dạng được ROSCTR | Thêm read/write/setup count |
| `s7_full` | S7comm đầy đủ area + offset | Toàn bộ semantic features |

Chỉ window với `decode_level = s7_full` mới có đủ đặc trưng ngữ nghĩa — đây là điều kiện để sử dụng trong train/test ML.

---

### 2.3 Xây dựng dữ liệu hoạt động bình thường (Benign Traffic)

**Điểm thường bị bỏ qua trong các nghiên cứu:** benign traffic phải đủ **đa dạng** để mô hình không overfit vào một kiểu traffic duy nhất. Hệ thống tạo benign traffic qua **4 chế độ hoạt động** phản ánh thực tế vận hành:

| Profile segment | Thời lượng mặc định | Cơ chế | S7comm traffic đặc trưng |
|---|---|---|---|
| `normal_hmi` | 90 phút | Snap7 poll 1–2s random + tag logger 0.5s | Đều đặn: Job(Read M+Q+I) → Ack_Data lặp lại, 2 TCP stream song song |
| `sparse_hmi` | 60 phút | Snap7 poll 5–20s random + tag logger 2s | Traffic thưa, IAT lớn, nhiều gap im lặng trong window |
| `tia_portal_only` | 60 phút | Chỉ TIA Portal online (kỹ sư theo dõi) | UserData (ROSCTR=0x07) — diagnostic packet, khác hẳn Read/Write |
| `idle_quiet` | 30 phút | Không poll, không logger | Chỉ TCP keepalive, ARP broadcast định kỳ |

**Tính thực tế của benign traffic:**
- Poll interval là `random.uniform(min, max)` → IAT không phải hằng số, phân bố đúng hoạt động thực
- Tag logger tạo một Snap7 session riêng biệt → trong cùng một window có 2 TCP stream S7comm đồng thời (giống thực tế: HMI + SCADA cùng kết nối PLC)
- TIA Portal tạo S7comm UserData (ROSCTR=0x07) — loại traffic đặc trưng của công cụ lập trình, không có trong script HMI đơn giản
- Benign có thể có `s7_write_count` > 0 do HMI thỉnh thoảng gửi START pulse hợp lệ (prob = 2%) → tránh mô hình học "write = attack"

> 📌 **[HÌNH 9]** Time-series plot của tag log Day 1 (benign baseline): M5.0 (START), M5.1 (STOP), Q0.0 (BangTai), CD1 — thể hiện quá trình hoạt động bình thường ổn định của băng tải.
>
> 📌 **[HÌNH 10]** Phân bố IAT (inter-arrival time) của benign traffic: 4 profile segment có phân bố rõ ràng khác nhau — normal_hmi (1–2s), sparse_hmi (5–20s), tia_portal (không đều), idle (rất thưa).

---

### 2.4 Xây dựng dữ liệu tấn công — 9 kịch bản, 6 ngày, theo MITRE ATT&CK for ICS

Các kịch bản được thiết kế có **kịch bản thực tế rõ ràng** (không chỉ là tool chạy ngẫu nhiên), phân theo 3 nhóm tấn công:

---

#### Nhóm A — Reconnaissance / Tình báo mạng (Ngày 2)

**A1. SCAN_PORT** — `T0846 Remote System Discovery`

**Kịch bản thực tế:** Attacker đã xâm nhập vào mạng nội bộ nhà máy (qua VPN bị compromise hoặc insider). Bước đầu tiên: xác nhận PLC còn hoạt động và cổng S7comm (TCP 102) có thể kết nối. Quét liên tục với interval ngẫu nhiên 0.4–1.5s để không kích hoạt rate-limit đơn giản.

**Cơ chế kỹ thuật:** `socket.create_connection((target, 102), timeout=1.0)` trong vòng lặp vô tận. Không cần credential, không cần Snap7 — chỉ TCP connection probe.

**Traffic signature:**
- `tcp_102_probe_count` tăng đột biến (nhiều TCP SYN đến port 102)
- `tcp_syn_count` cao, `tcp_rst_count` cao (PLC reset connection không hoàn chỉnh)
- `cotp_cr_count` = 0 (không đủ để lên được tầng COTP)
- `s7comm_packet_count` = 0 (hoàn toàn không có S7 data)

---

**A2. ENUM_TAGS** — `T0861 Point & Tag Identification`

**Kịch bản thực tế:** Sau khi biết PLC còn sống, attacker lập bản đồ toàn bộ vùng nhớ PLC để hiểu cấu trúc chương trình. Đọc quét M[0..80] (80 byte Merker), Q[0] (output byte), I[0] (input byte), lấy giá trị timer MD54/58/62. Thông tin này được dùng để lên kế hoạch tấn công integrity sau.

**Cơ chế kỹ thuật:**
```python
c.read_area(Areas.MK, 0, 0, 80)   # Đọc toàn bộ 80 byte Merker
c.read_area(Areas.PA, 0, 0, 1)    # Đọc Output byte 0
c.read_area(Areas.PE, 0, 0, 1)    # Đọc Input byte 0
```

**Traffic signature:**
- `s7_read_count` rất cao (> 100/window)
- `s7_sequential_offset_score` ≈ 1.0 (offset tăng 0→80 theo bước 1)
- `s7_unique_offset_count` > 40 (nhiều địa chỉ khác nhau trong 5 giây)
- `s7_merker_area_count` chiếm > 90% tổng area count
- `s7_write_count` = 0 (chỉ đọc, chưa ghi)

> 📌 **[HÌNH 11]** Wireshark screenshot: so sánh packet S7comm ENUM_TAGS (offset 0, 1, 2... tăng đều) vs benign HMI (chỉ đọc offset cố định 5, 6, 50, 54).

---

#### Nhóm B — Integrity Attacks / Tấn công tính toàn vẹn quá trình (Ngày 3–4)

**B1. RWRITE_BURST** — `T0836 Modify Parameter`

**Kịch bản thực tế:** Attacker đã biết địa chỉ bit START (M5.0) và STOP (M5.1) từ bước ENUM_TAGS. Ghi liên tục toggle START/STOP để băng tải liên tục dừng/khởi lại — không crash PLC nhưng phá hoàn toàn năng suất sản xuất. Mỗi lần ghi đọc giá trị hiện tại rồi mới ghi để không gây xung đột với logic PLC.

**Cơ chế kỹ thuật:**
```python
m5 = c.read_area(Areas.MK, 0, 5, 1)   # Đọc byte M5 hiện tại
set_bool(m5, 0, 1, True)               # Bật STOP (M5.1)
set_bool(m5, 0, 0, False)              # Tắt START (M5.0)
c.write_area(Areas.MK, 0, 5, m5)      # Ghi lại
# Chu kỳ: toggle giữa STOP và START, interval 0.15–0.45s
```

**Ghi lại ground truth:** mỗi lần ghi thay đổi giá trị được log vào `attack_events.csv`:
```
signal=M5.1_STOP, old_value=0, new_value=1, episode_id=bt_s1:d3:RWRITE_BURST:r1:1
```

**Traffic signature:**
- `s7_write_count` cao (> 50/window)
- `s7_write_read_ratio` >> 1 (ghi nhiều hơn đọc)
- `s7_merker_area_count` cao (toàn bộ ghi vào Merker)
- `s7_output_write_count` = 0 (không ghi trực tiếp vào Q area)

---

**B2. SETPOINT_ATTACK** — `T0836 Modify Parameter`

**Kịch bản thực tế:** Tấn công tinh vi hơn — không dừng băng tải trực tiếp mà thay đổi các tham số timing (CD1/CD2/CD3) về giá trị bất thường. Băng tải vẫn chạy, nhưng nhịp đếm bị sai hoàn toàn: vật thể không được xử lý đúng thời gian, có thể va chạm hoặc bị bỏ sót. Rất khó phát hiện bằng mắt thường vì băng tải "trông có vẻ đang chạy bình thường".

**Cơ chế kỹ thuật:**
```python
values = [100, 250, 45000, 60000, 90000]  # ms — bất thường so với default 5000ms
cd1 = random.choice(values)
write_dint(c, 54, cd1, "CD1_MS")  # MD54 = CD1 timer
write_dint(c, 58, cd2, "CD2_MS")  # MD58 = CD2 timer
write_dint(c, 62, cd3, "CD3_MS")  # MD62 = CD3 timer
write_dint(c, 50, random.choice([0, 120000, 180000]), "Times_1_MS")
```

**Traffic signature:**
- `s7_write_count` vừa phải (< 30/window — không burst như RWRITE)
- Target offset: 50, 54, 58, 62 (MD area) — khác với M5 offset của RWRITE
- `s7_merker_area_count` tăng, nhưng `s7_write_payload_bytes_mean` cao hơn (DInt = 4 bytes)
- Trong tag log: `proc__CD1__std` và `proc__CD1__max` tăng đột biến (timer bị đổi về giá trị cực đoan)

---

**B3. SENSOR_SPOOF** — `T0836 Spoof Reporting Message`

**Kịch bản thực tế:** Attacker giả mạo trạng thái cảm biến vật thể (Vat_1/Vat_2/Vat_3) trong Merker. PLC "thấy" có vật thể trên băng → kích hoạt timer countdown → nhưng thực tế không có vật thể nào → gây nhầm lẫn toàn bộ logic điều phối. Hệ quả: timer chạy ảo, cơ cấu phân loại hoạt động sai, báo cáo sản lượng bị sai lệch.

**Cơ chế kỹ thuật:**
```python
patterns = [(1,1,1), (1,0,1), (0,1,1)]  # Vat_1, Vat_2, Vat_3
v1, v2, v3 = random.choice(patterns)
set_bool(m5, 0, 4, bool(v1))  # M5.4 = Vat_1
set_bool(m5, 0, 6, bool(v2))  # M5.6 = Vat_2
set_bool(m6, 0, 0, bool(v3))  # M6.0 = Vat_3
```

**Traffic signature:**
- `s7_write_count` vừa phải, interval 0.4–1.5s
- Ghi vào 2 byte khác nhau (M5 và M6) trong cùng một episode
- Trong tag log: `proc__Vat_1__std` tăng bất thường (bit trạng thái vật thể dao động)

---

**B4. STEALTHY_WRITE** — `T0836 Low-rate evasion`

**Kịch bản thực tế:** Tấn công tinh vi nhất trong nhóm integrity. Chỉ ghi STOP bit với tần số cực thấp (20–60 giây/lần trong Day 6). Băng tải dừng đột ngột mỗi vài chục giây — operator thấy bất thường nhưng không rõ nguyên nhân (tưởng sensor lỗi). Traffic quá thưa thớt để kích hoạt bất kỳ threshold-based IDS nào. Đây là thách thức chính cho AI.

**Cơ chế kỹ thuật:**
```python
# Chỉ ghi STOP, không ghi START → băng tải dừng và không tự khởi lại
set_bool(m5, 0, 1, True)   # STOP = True
set_bool(m5, 0, 0, False)  # START = False
# Interval: random.uniform(20.0, 60.0) giây (Day 6 robust profile)
```

**Traffic signature:**
- `s7_write_count` rất thấp (< 5/window 5 giây, thường = 0 hoặc 1)
- Không có burst, không có pattern tuần tự
- **Chỉ phân biệt được với benign write nhờ context:** benign write luôn đi kèm Read trước đó, STEALTHY_WRITE chỉ ghi không đọc context
- Trong tag log: `proc__M5_STOP__max` = 1 xuất hiện bất thường trong window

> 📌 **[HÌNH 12]** So sánh tag log 3 loại integrity attack: RWRITE_BURST (M5.0/M5.1 thay đổi liên tục ≈ 2–3 lần/giây), SETPOINT_ATTACK (CD1/CD2/CD3 nhảy về giá trị bất thường), STEALTHY_WRITE (STOP=1 xuất hiện lẻ tẻ).
>
> 📌 **[HÌNH 13]** attack_events.csv mẫu: 5 dòng đầu cho mỗi kịch bản — thể hiện signal name, old_value, new_value, timestamp.

---

#### Nhóm C — Availability / Protocol Attacks (Ngày 5)

**C1. S7_FLOOD** — `T0814 Denial of Service`

**Kịch bản thực tế:** S7-1500 giới hạn số session S7comm đồng thời (thường 4–8 session). Attacker tung 6 thread song song liên tục mở kết nối Snap7 và giữ trong thời gian ngắn. Toàn bộ slot session bị chiếm → TIA Portal không thể kết nối, HMI mất kết nối, operator mù hoàn toàn.

**Cơ chế kỹ thuật:**
```python
# 6 thread đồng thời, mỗi thread: connect → sleep(0.03–0.2s) → disconnect → lặp lại
def worker():
    c = snap7.client.Client()
    c.connect(target, rack, slot)
    time.sleep(random.uniform(0.03, 0.2))
    c.disconnect()
```

**Traffic signature:**
- `cotp_cr_count` rất cao (nhiều Connection Request)
- `cotp_cc_count` tăng (server chấp nhận đến khi hết slot)
- `s7comm_packet_count` thấp tương đối (session bị ngắt sớm, ít S7 command)
- `s7_negotiation_only_ratio` cao (phần lớn session chỉ có COTP setup, không có S7 data)
- `tcp_active_streams` tăng đột biến

---

**C2. SYN_FLOOD** — `T0814 Denial of Service`

**Kịch bản thực tế:** Tấn công ở tầng TCP thấp hơn S7_FLOOD. 20 thread gửi TCP SYN liên tục đến port 102, không hoàn thành 3-way handshake. TCP connection table của PLC bị cạn kiệt → ngay cả TCP connection hợp lệ cũng không thể được thiết lập.

**Cơ chế kỹ thuật:**
```python
# 20 thread, mỗi thread: tạo socket → connect (timeout 0.08s) → close → lặp
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.08)
s.connect((target, 102))  # SYN gửi đi, không chờ hoàn chỉnh
```

**Traffic signature:**
- `tcp_syn_count` cực cao (>> 100/window)
- `tcp_ack_count` thấp (không hoàn thành handshake)
- `tcp_syn_ack_ratio` >> 1 (nhiều SYN không có ACK tương ứng)
- `tcp_102_packet_count` tăng đột biến
- `cotp_cr_count` = 0 (không lên được tầng COTP)

---

**C3. PROTOCOL_FUZZ** — `T0819 Exploitation of Remote Services`

**Kịch bản thực tế:** Attacker gửi các packet có định dạng TPKT header hợp lệ (3 byte đúng chuẩn RFC 1006) nhưng payload hoàn toàn ngẫu nhiên. PLC phải cố parse và reject từng packet → tăng tải CPU parser, có thể gây lỗi firmware chưa được vá, hoặc crash trong một số phiên bản firmware cũ.

**Cơ chế kỹ thuật:**
```python
payload = os.urandom(random.randint(12, 80))  # Random bytes
pkt = b"\x03\x00" + (len(payload) + 4).to_bytes(2, "big") + payload
# \x03\x00 = TPKT version + reserved; length = đúng; payload = rác
s.connect((target, 102))
s.sendall(pkt)
```

**Traffic signature:**
- `malformed_packet_count` tăng (TShark phát hiện malformed S7/COTP)
- `payload_entropy_mean` cao ≈ 7.5–8.0 bit/byte (random bytes)
- `payload_hash_unique_ratio` ≈ 1.0 (mỗi packet payload khác nhau)
- `s7_error_count` tăng (PLC trả về error response)
- `raw_payload_len_std` cao (length ngẫu nhiên 12–80 byte)

> 📌 **[HÌNH 14]** Heatmap đặc trưng phân theo kịch bản tấn công: trục X = các đặc trưng ngữ nghĩa S7 chính, trục Y = 9 kịch bản + BENIGN. Màu = giá trị trung bình chuẩn hóa. Thể hiện rõ pattern đặc trưng của từng kịch bản.

---

#### Ngày 6 — OOD Robustness Test (Out-of-Distribution)

Toàn bộ 9 kịch bản chạy lại với các thay đổi có chủ đích:

| Thay đổi | Giá trị Day 2–5 (standard) | Giá trị Day 6 (robust) |
|---|---|---|
| Thứ tự kịch bản | Cố định theo ngày | Shuffle ngẫu nhiên |
| Sleep interval giữa các packet | 0.15–1.5s | 2–60s (tùy loại) |
| S7_FLOOD threads | 6 | Tối đa 2 |
| SYN_FLOOD threads | 20 | Tối đa 3 |
| Gap giữa các episode | 5 phút cố định | 2–15 phút ngẫu nhiên |
| FUZZ payload size | 12–80 bytes | Giữ nguyên |

**Mục đích:** kiểm tra xem mô hình AI có thực sự học **ngữ nghĩa** (loại lệnh S7, vùng nhớ bị tác động) hay chỉ học **timing/intensity** (số packet/giây). Nếu model chỉ học timing thì Day 6 sẽ có F1 thấp hơn đáng kể so với Day 2–5.

---

### 2.5 Cơ chế gán nhãn — thời gian thực, không post-hoc, không ambiguity

**Vấn đề với post-hoc labeling** (cách thông thường): gán nhãn sau khi thu thập dựa trên log file → dễ bị lệch thời gian, bỏ sót các window chuyển tiếp, không xác định được chính xác khoảnh khắc START/END của tấn công.

**Hệ thống này dùng event-based timeline** — ghi nhãn ngay tại thời điểm thực thi:

```
Thời điểm chạy lệnh tấn công:
  label("RWRITE_BURST", "START", episode_id, note) → ghi timestamp_ms ngay lập tức

Thời điểm dừng lệnh tấn công:
  label("RWRITE_BURST", "END", episode_id, note) → ghi timestamp_ms ngay lập tức
```

**Window overlap labeling** (`merge_dataset.py:label_for_window`):
```python
# Cửa sổ [w_start, w_start+5000ms] được gán nhãn attack nếu có overlap > 0ms
overlap = max(0, min(window_end_ms, item.end_ms) - max(window_start_ms, item.start_ms))
# Khi có nhiều attack interval cùng overlap → lấy nhãn của interval có overlap lớn nhất
if overlap > best_overlap:
    best = item
```

**Transition window dropping:** các window tại biên ±N giây quanh START/END attack bị loại khỏi training set → tránh label noise tại khoảnh khắc chuyển trạng thái.

**`attack_events.csv`** — ground truth ở mức tín hiệu quá trình, không chỉ ở mức packet:
```
signal      | area | byte_offset | bit_offset | data_type | old_value | new_value | episode_id
M5.1_STOP   | MK   | 5           | 1          | bool      | 0         | 1         | bt_s1:d3:RWRITE_BURST:r1:1
CD1_MS      | MK   | 54          |            | dint      | 5000      | 90000     | bt_s1:d4:SETPOINT_ATTACK:r1:1
```

File này cho phép đối chiếu: khi network IDS phát hiện anomaly, có thể tra cứu xem tín hiệu nào bị thay đổi trong khoảng thời gian đó.

> 📌 **[HÌNH 15]** Sơ đồ cơ chế window overlap labeling: timeline START/END events, các cửa sổ 5 giây, thể hiện cách gán nhãn khi window nằm trọn trong attack, nằm trên biên, và nằm ngoài attack interval.

---

### 2.6 Ba góc nhìn dataset — tách bạch khoa học rõ ràng

`merge_dataset.py` xuất 3 views độc lập phục vụ 3 câu hỏi nghiên cứu khác nhau:

**View 1: `dataset_network.csv`** — IDS thuần mạng
- Chỉ dùng đặc trưng từ PCAP window (extract_s7_features.py)
- Drop toàn bộ process context (tag log, timer value)
- Câu hỏi: "Chỉ nhìn vào traffic mạng, AI có phát hiện tấn công không?"

**View 2: `dataset_process.csv`** — Process anomaly detection
- Chỉ dùng PLC tag log, aggregated theo window 5 giây
- Mỗi tag được tính mean/std/min/max trong window: `proc__CD1__mean`, `proc__CD1__std`...
- Câu hỏi: "Chỉ nhìn vào trạng thái quá trình (không cần network), AI có phát hiện không?"

**View 3: `dataset_fusion.csv`** — Sensor fusion
- Kết hợp cả network features + process features (join theo `window_start_ms`)
- Câu hỏi: "Kết hợp hai nguồn có cải thiện detection rate và giảm false positive không?"

**View 4: `dataset_leakage_ablation.csv`** — Ablation study
- Giữ lại các cột identity (IP, MAC, session) và rule flag
- Mục đích: đo lường "information leakage inflation" — F1 score tăng bao nhiêu nếu không làm leakage control

> 📌 **[HÌNH 16]** Sơ đồ 3 dataset views: nguồn đặc trưng, câu hỏi nghiên cứu, và cách join theo window_start_ms.

---

### 2.7 Chống data leakage — thiết kế hướng publication

`train_ml.py` áp dụng chính sách leakage control nghiêm ngặt trước khi đưa vào ML:

**Các cột bị loại hoàn toàn trước khi train:**

| Nhóm | Ví dụ cột | Lý do loại |
|---|---|---|
| Identity endpoint | `src_ip`, `dst_ip`, `src_mac`, `top_src_ip` | Model nhận dạng IP của attacker thay vì hành vi |
| Timestamp | `window_start_ms`, `window_end_ms` | Model nhớ thứ tự thời gian của ngày thu thập |
| Session metadata | `session_id`, `episode_id`, `host_id` | Leakage qua group identity |
| Rule flags | `scan_detected_rule`, `timer_out_of_range` | Hand-crafted rules không phải ML features |
| Score columns | `port_scan_score`, `arp_scan_score` | Derived từ rules, là target leakage |
| Process context | `tag_*` (trong network view) | Cross-modal leakage |

**GroupKFold theo session:**
```python
# Dữ liệu từ cùng session_id không xuất hiện ở cả train lẫn test
# Ngăn model học "fingerprint" của một buổi thu thập cụ thể
splitter = StratifiedGroupKFold(n_splits=5, shuffle=True)
splits = splitter.split(X, y, groups=df["session_id"])
```

**Day 6 = OOD held-out test set:**
- Không tham gia cross-validation
- Chỉ dùng để đánh giá khả năng generalize ra ngoài phân bố train
- Nếu F1 trên Day 6 thấp hơn đáng kể → model đang học timing thay vì ngữ nghĩa

**Ablation leakage measurement:**
- Train lại với toàn bộ cột (bao gồm IP, rule flag, score)
- So sánh F1: `F1_leakage_ablation - F1_safe_ml` = mức độ "inflate" do leakage
- Con số này được báo cáo tường minh trong paper như một cảnh báo phương pháp

> 📌 **[HÌNH 17]** Sơ đồ GroupKFold: 5 fold, mỗi fold thể hiện các session nào vào train và test — không có session nào xuất hiện ở cả hai.
>
> 📌 **[HÌNH 18]** Bảng kết quả ablation: F1/Balanced Accuracy với safe ML features vs với leakage columns — định lượng bias nếu không làm leakage control.

---

### 2.8 Tóm tắt tính mới — so sánh với các dataset ICS công khai hiện có

| Tiêu chí so sánh | SWaT (2016) | BATADAL (2018) | ICSX (2021) | CIC-ICS2024 | **Dataset này** |
|---|---|---|---|---|---|
| Thiết bị PLC thật | Có | Mô phỏng | Một phần | Có | **Có (S7-1500)** |
| PLCSIM kết hợp | Không | Không | Không | Không | **Có** |
| S7comm DPI (L7) | Không | Không | Không | Một phần | **Đầy đủ** |
| Đặc trưng ngữ nghĩa S7 (write/read/area/offset) | Không | Không | Không | Không | **Có (17 features)** |
| Profinet DCP features | Không | Không | Không | Không | **Có** |
| COTP session features | Không | Không | Không | Không | **Có** |
| Process + Network tách biệt | Không | Không | Không | Không | **3 views độc lập** |
| Leakage control + GroupKFold | Không | Không | Không | Không | **Có, tường minh** |
| Timeline gán nhãn thời gian thực | Không | Không | Một phần | Một phần | **Có, millisecond** |
| Attack event log (signal level) | Không | Không | Không | Không | **Có (attack_events.csv)** |
| Stealthy low-rate attack | Không | Một phần | Không | Không | **STEALTHY_WRITE** |
| OOD robustness test day | Không | Không | Không | Không | **Day 6** |
| Số kịch bản tấn công | 36 | 11 | 7 | 8 | **9 + OOD** |
| MITRE ATT&CK for ICS mapping | Không | Không | Một phần | Có | **Có (đầy đủ)** |

---

## PHỤ LỤC — Danh sách hình cần vẽ

| Số hình | Nội dung | Gợi ý công cụ |
|---|---|---|
| HÌNH 1 | Topology testbed: PLC thật + Engineering station + 2 host + switch + capture point | Draw.io / Visio |
| HÌNH 2 | So sánh RTT distribution: PLCSIM vs PLC thật | Matplotlib histogram |
| HÌNH 3 | Sơ đồ chức năng Băng Truyền: I→M(logic+timer)→Q | Draw.io |
| HÌNH 4 | Screenshot bảng tag TIA Portal | TIA Portal V17 |
| HÌNH 5 | Timeline 6 ngày: trục thời gian với pha benign/attack | Matplotlib Gantt-style |
| HÌNH 6 | Pipeline end-to-end: PCAP → features → dataset → model | Draw.io flowchart |
| HÌNH 7 | Bảng so sánh đặc trưng: dataset này vs SWaT vs CIC-ICS2024 | LaTeX table / Excel |
| HÌNH 8 | Box plot 6 đặc trưng ngữ nghĩa S7 phân theo 9 nhãn + BENIGN | Matplotlib / Seaborn |
| HÌNH 9 | Time-series tag log Day 1 benign: M5.0, Q0.0, CD1 | Matplotlib time series |
| HÌNH 10 | Phân bố IAT benign: 4 profile segment | Matplotlib KDE / histogram |
| HÌNH 11 | Wireshark screenshot: ENUM_TAGS vs benign HMI (offset sequence) | Wireshark |
| HÌNH 12 | Tag log so sánh 3 integrity attack: RWRITE / SETPOINT / STEALTHY | Matplotlib subplots |
| HÌNH 13 | attack_events.csv mẫu (5 dòng/kịch bản) | LaTeX table |
| HÌNH 14 | Heatmap đặc trưng ngữ nghĩa phân theo kịch bản | Seaborn heatmap |
| HÌNH 15 | Sơ đồ window overlap labeling | Draw.io |
| HÌNH 16 | Sơ đồ 3 dataset views (network / process / fusion) | Draw.io |
| HÌNH 17 | Sơ đồ GroupKFold 5-fold theo session | Draw.io / Matplotlib |
| HÌNH 18 | Bảng ablation: F1 safe ML vs F1 với leakage columns | LaTeX table / bar chart |
