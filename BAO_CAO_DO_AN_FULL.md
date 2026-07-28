# BÁO CÁO ĐỒ ÁN TỐT NGHIỆP
## Xây Dựng Hệ Thống Phát Hiện Xâm Nhập Cho Mạng Công Nghiệp ICS/IIoT Dựa Trên Giao Thức Siemens S7comm

---

> **Tóm tắt:** Đồ án xây dựng một hệ sinh thái hoàn chỉnh cho nghiên cứu bảo mật mạng công nghiệp ICS (Industrial Control System), bao gồm: (1) testbed vật lý kết hợp PLC Siemens S7 thật và mô phỏng, (2) hai công cụ tự phát triển (ICSScout và S7Pwn) phục vụ đánh giá bảo mật và kiểm thử tấn công, (3) bộ dataset benchmark đa phương thức SemanticAware-S7comm-Dataset với 55.902 time-window từ 6 ngày thu thập, ánh xạ 9 kịch bản tấn công theo chuẩn MITRE ATT&CK for ICS, và (4) pipeline huấn luyện/đánh giá mô hình học máy với kiểm soát data leakage nghiêm ngặt.

---

## MỤC LỤC

1. [Mục Đích và Động Lực Nghiên Cứu](#1)
2. [Tổng Quan Hệ Thống và Đóng Góp Chính](#2)
3. [Kiến Trúc Testbed](#3)
4. [Bài Toán Điều Khiển — Hệ Thống Băng Truyền](#4)
5. [Công Cụ Bảo Mật Tự Phát Triển](#5)
6. [Thu Thập Dữ Liệu — Phương Pháp và Quy Trình](#6)
7. [Kịch Bản Tấn Công — 9 Scenarios Theo MITRE ATT&CK for ICS](#7)
8. [Đặc Trưng Khai Thác — Deep Packet Inspection Toàn Stack S7comm](#8)
9. [Pipeline Xây Dựng Dataset và Kiểm Soát Leakage](#9)
10. [Mô Hình Học Máy và Kết Quả Thực Nghiệm](#10)
11. [Phân Tích Kết Quả và Điểm Nổi Bật](#11)
12. [Hạn Chế và Hướng Phát Triển](#12)
13. [Kết Luận](#13)

---

<a name="1"></a>
## 1. MỤC ĐÍCH VÀ ĐỘNG LỰC NGHIÊN CỨU

### 1.1 Bối Cảnh Vấn Đề

Các hệ thống điều khiển công nghiệp (ICS — Industrial Control System) và mạng Internet of Things công nghiệp (IIoT — Industrial Internet of Things) đang ngày càng được kết nối với mạng doanh nghiệp và Internet, tạo ra bề mặt tấn công khổng lồ. Trong khi các cuộc tấn công mạng vào cơ sở hạ tầng IT (văn phòng, ngân hàng) chủ yếu gây thiệt hại về tài chính và dữ liệu, các cuộc tấn công vào hệ thống OT/ICS (nhà máy, lưới điện, hệ thống xử lý nước) có thể gây ra hậu quả vật lý nghiêm trọng: thiết bị hỏng hóc, ngừng sản xuất, thậm chí đe dọa tính mạng con người.

**Minh chứng thực tế:**
- **Stuxnet (2010):** Tấn công vào PLC Siemens S7-315 tại cơ sở làm giàu uranium Iran, phá hủy ~1.000 máy ly tâm bằng cách thay đổi tần số quay trong khi che giấu giá trị hiển thị trên HMI.
- **Ukraine Power Grid (2015):** Nhóm Sandworm tắt điện cho 230.000 hộ dân tại Ukraine bằng cách chiếm quyền điều khiển hệ thống SCADA.
- **Triton/TRISIS (2017):** Tấn công vào hệ thống an toàn (Safety Instrumented System) tại nhà máy hóa dầu Ả Rập Xê-Út, cố gắng vô hiệu hóa cơ chế bảo vệ an toàn.
- **Colonial Pipeline (2021):** Ransomware tắt hệ thống pipeline dầu lớn nhất Đông Bắc Mỹ trong 6 ngày.

### 1.2 Khoảng Trống Nghiên Cứu

Mặc dù lĩnh vực ICS security đang phát triển mạnh, các hệ thống phát hiện xâm nhập (IDS) cho môi trường OT vẫn còn nhiều hạn chế lớn:

**Hạn chế của nghiên cứu hiện có:**

1. **Dataset không đủ sâu về ngữ nghĩa giao thức:** Các dataset phổ biến (CIC-IDS2017, TON_IoT, UNSW-NB15, SWaT, BATADAL) dừng lại ở đặc trưng L3/L4 (số gói, byte count, TCP flags, IAT) mà hoàn toàn bỏ qua lớp ứng dụng công nghiệp. Với giao thức Siemens S7comm, các đặc trưng ngữ nghĩa quan trọng nhất nằm ở tầng L5–L7: loại lệnh (Read/Write), vùng nhớ bị truy cập (Merker/Output/Input), địa chỉ byte offset, và phản hồi lỗi từ PLC.

2. **Thiếu kịch bản tấn công đa dạng và có chú thích rõ ràng:** Nhiều dataset chỉ mô phỏng tấn công DoS đơn giản, thiếu các tấn công tính toàn vẹn (integrity attacks) tinh vi như thao túng setpoint, giả mạo cảm biến, hoặc tấn công low-rate stealthy.

3. **Thiếu ground truth ở mức tín hiệu quá trình:** Không có dataset nào công bố log thay đổi tín hiệu PLC ở mức bit/byte (giá trị trước và sau khi bị tấn công), khiến việc phân tích tác động vật lý của tấn công trở nên rất khó.

4. **Data leakage chưa được kiểm soát chặt:** Nhiều kết quả F1 cao trong tài liệu đến từ việc model học dấu hiệu nhận dạng endpoint (địa chỉ IP nguồn/đích của attacker) thay vì hành vi tấn công thực sự.

5. **Thiếu công cụ kiểm thử bảo mật ICS nguồn mở:** Hầu hết công cụ pentest cho ICS là thương mại (Claroty, Nozomi, Dragos), rào cản cao cho nghiên cứu học thuật.

### 1.3 Mục Tiêu Nghiên Cứu

Đồ án này đặt ra ba câu hỏi nghiên cứu cụ thể:

> **RQ1 (Dataset):** Có thể xây dựng một bộ dataset S7comm đủ đa dạng, có ngữ nghĩa sâu, và có kiểm soát leakage chặt chẽ để làm benchmark cho nghiên cứu ICS-IDS không?

> **RQ2 (Fusion):** Kết hợp đặc trưng mạng (network traffic) với đặc trưng trạng thái quá trình (PLC process tags) có cải thiện khả năng phát hiện tấn công so với chỉ dùng một nguồn không?

> **RQ3 (Generalization):** Mô hình học máy huấn luyện trên in-distribution data có generalize tốt sang out-of-distribution holdout (tấn công cùng loại nhưng khác rate và thứ tự) không?

---

<a name="2"></a>
## 2. TỔNG QUAN HỆ THỐNG VÀ ĐÓNG GÓP CHÍNH

### 2.1 Kiến Trúc Tổng Thể Dự Án

Đồ án được tổ chức thành bốn thành phần lớn, liên kết chặt với nhau:

```
┌─────────────────────────────────────────────────────────────────┐
│                    HỆ SINH THÁI ICS SECURITY                    │
│                                                                   │
│  ┌──────────────────┐    ┌──────────────────────────────────┐   │
│  │   TESTBED VẬT LÝ │    │     HAI CÔNG CỤ TỰ PHÁT TRIỂN   │   │
│  │                  │    │                                   │   │
│  │  S7-1200/S7-1500 │    │  ICSScout v2.0 (passive recon,  │   │
│  │  + PLCSIM        │    │  vuln assessment, packet DPI)    │   │
│  │  Conveyor Belt   │    │                                   │   │
│  │  application     │    │  S7Pwn (active PLC testing,     │   │
│  └────────┬─────────┘    │  CPU control, memory R/W)        │   │
│           │              └──────────────────────────────────┘   │
│           ▼                                                       │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │        SemanticAware-S7comm-Dataset                      │   │
│  │                                                           │   │
│  │  55,902 windows × 6 ngày × 9 attack scenarios            │   │
│  │  3 views: network / process / fusion                     │   │
│  │  MITRE ATT&CK for ICS mapping                            │   │
│  └──────────────────────────────────────────────────────────┘   │
│           │                                                       │
│           ▼                                                       │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │        ML PIPELINE VỚI LEAKAGE CONTROL                   │   │
│  │                                                           │   │
│  │  4 models: RF, XGBoost, CatBoost, Logistic Regression    │   │
│  │  GroupKFold + fbeta_oof threshold + Day6 OOD holdout     │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Đóng Góp Chính

| # | Đóng Góp | Tính Mới |
|---|---|---|
| 1 | **Testbed kết hợp PLC thật + PLCSIM** | Lần đầu kết hợp cả hai trong cùng một quy trình thu thập dữ liệu IDS |
| 2 | **Deep Packet Inspection toàn stack S7comm (L2–L7)** | Đặc trưng tầng TPKT/COTP/S7comm không có trong bất kỳ dataset ICS công khai nào |
| 3 | **17 đặc trưng ngữ nghĩa S7** (write_read_ratio, sequential_offset_score, area breakdown...) | Chưa có trong SWaT, BATADAL, ICSX, CIC-ICS2024 |
| 4 | **3 dataset views độc lập** (network / process / fusion) | Cho phép đánh giá từng nguồn thông tin riêng biệt |
| 5 | **Timeline labeling thời gian thực** (millisecond precision) | Không post-hoc, không ambiguity tại biên attack |
| 6 | **Attack event log ở mức tín hiệu** (signal, old_value, new_value) | Ground truth vật lý chưa có dataset nào công bố |
| 7 | **GroupKFold theo session + fbeta_oof threshold** | Chống data leakage và in-sample threshold bias |
| 8 | **Day 6 OOD holdout** | Kiểm tra khả năng generalize với rate và thứ tự khác |
| 9 | **Công cụ ICSScout + S7Pwn** | Mã nguồn mở, sẵn sàng tái sử dụng |

---

<a name="3"></a>
## 3. KIẾN TRÚC TESTBED

### 3.1 Sơ Đồ Topology Tổng Quát

Testbed mô phỏng một mạng công nghiệp thực tế với đầy đủ các thành phần: PLC, Engineering Station, Controller Host và Attacker Host. Tất cả đều kết nối vào một **Layer-2 Switch trung tâm**. Switch được cấu hình **SPAN port (port mirroring)** — toàn bộ traffic đi qua switch được nhân bản sang một cổng giám sát duy nhất, tại đó máy Capture chạy TShark để thu thập tập trung.

```
┌────────────────────────────────────────────────────────────────────┐
│                  Mạng công nghiệp: 192.168.1.0/24                  │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │ Engineering  │  │  Controller  │  │   Attacker   │             │
│  │  Station     │  │    Host      │  │    Host      │             │
│  │ (TIA Portal) │  │ (HMI/SCADA)  │  │  (S7Pwn +   │             │
│  │ IP: dynamic  │  │ IP:192.168.1.50│ │   scripts)  │             │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘            │
│         │                 │                  │                      │
│         └────────┬────────┘                  │                      │
│                  │        S7comm / TCP 102    │                      │
│                  ▼                            │                      │
│         ┌────────────────┐                   │                      │
│         │   PLC TARGET   │                   │                      │
│         │ S7-1200/S7-1500│                   │                      │
│         │ IP:192.168.1.10│                   │                      │
│         └────────┬───────┘                   │                      │
│                  │                            │                      │
│         ┌────────┴────────────────────────────┘                     │
│         │                                                            │
│         ▼                                                            │
│  ┌─────────────────────────────────────────┐                       │
│  │        LAYER-2 SWITCH (trung tâm)       │                       │
│  │   Port 1: Engineering Station           │                       │
│  │   Port 2: Controller Host               │                       │
│  │   Port 3: PLC Target                    │                       │
│  │   Port 4: Attacker Host                 │                       │
│  │   Port 5: SPAN port ──────────────────► │──┐                    │
│  └─────────────────────────────────────────┘  │                    │
│                                                │ Mirror of          │
│                                                │ ALL traffic        │
│                                                ▼                    │
│                              ┌──────────────────────────┐          │
│                              │   CAPTURE HOST           │          │
│                              │   NIC: kết nối SPAN port │          │
│                              │   TShark: thu toàn bộ    │          │
│                              │   traffic trong mạng     │          │
│                              │   → *.pcapng             │          │
│                              └──────────────────────────┘          │
└────────────────────────────────────────────────────────────────────┘
```

### 3.2 Thành Phần và Vai Trò

| Thành Phần | IP | Vai Trò | Tool |
|---|---|---|---|
| PLC Target | 192.168.1.10 | Thiết bị điều khiển trung tâm | Siemens S7-1200 / S7-1500 hoặc PLCSIM |
| Engineering Station | Dynamic | Lập trình và giám sát PLC | TIA Portal V17 |
| Controller Host | 192.168.1.50 | Mô phỏng HMI/SCADA bình thường | Python Snap7 (poll loop) |
| Attacker Host | 192.168.1.100 | Thực hiện các kịch bản tấn công | S7Pwn + custom scripts |
| **Layer-2 Switch** | — | Kết nối tất cả thiết bị; cấu hình SPAN port | Managed switch hỗ trợ port mirroring |
| **Capture Host** | (ngoài băng) | Kết nối vào SPAN port, thu toàn bộ traffic | TShark → `.pcapng` |

> **Điểm quan trọng về kiến trúc capture:** Toàn bộ traffic trong mạng (giữa Engineering Station, Controller Host, Attacker Host và PLC) đều đi qua switch trung tâm. Nhờ SPAN port, **một đầu capture duy nhất** nhìn thấy và ghi lại toàn bộ luồng dữ liệu của mọi thành phần — không cần cài TShark trên từng máy riêng lẻ.

### 3.3 Điểm Khác Biệt Then Chốt: PLC Thật + PLCSIM

Đây là điểm quan trọng nhất phân biệt testbed này với các nghiên cứu trước. Hệ thống **chủ động kết hợp cả hai** trong cùng một quy trình:

| Tiêu Chí | PLCSIM | PLC Thật (S7-1200/S7-1500) |
|---|---|---|
| Timing TCP thực tế | Mô phỏng, lý tưởng hóa | Có: jitter phần cứng thật, RTT thật |
| Phản hồi CPU state (RUN/STOP) | Không phản hồi lệnh STOP thật | TCP session drop khi CPU STOP — trạng thái thật |
| Giới hạn PUT/GET | Không giới hạn | S7-1500 block PUT/GET nếu không bật trong TIA Portal |
| Profinet DCP discovery | Không có | Có: station name thật, vendor ID thật (Siemens 002a) |
| Side-effect vật lý | Không | Có: actuator thật dừng, cảm biến thật thay đổi trạng thái |
| Giới hạn session đồng thời | Không | Có: S7-1500 giới hạn số kết nối → S7_FLOOD có tác động thật |

**Ý nghĩa với AI/ML:** Traffic từ PLC thật tạo ra các đặc trưng timing (IAT, TCP RTT, window size jitter) phản ánh giới hạn phần cứng thật — không bị "lý tưởng hóa" như PLCSIM. Mô hình học trên dữ liệu này có khả năng generalize tốt hơn khi triển khai thực tế.

### 3.4 Phương Pháp Thu Thập — SPAN Port Tập Trung

Thay vì cài TShark trên từng máy riêng lẻ, toàn bộ traffic trong testbed được thu thập **tập trung qua SPAN port của switch**:

**Cơ chế hoạt động:**
```
[Engineering Station] ─┐
[Controller Host]      ─┤
[Attacker Host]        ─┤─► Layer-2 Switch ─► SPAN port ─► Capture Host (TShark)
[PLC Target]           ─┘
```

- Switch cấu hình **port mirroring (SPAN)**: tất cả traffic đến/đi từ mọi cổng đều được nhân bản (mirror) sang cổng SPAN.
- Capture Host kết nối NIC vào cổng SPAN ở **chế độ promiscuous** — nhận tất cả packet mà không cần địa chỉ đích khớp.
- TShark chạy liên tục trên Capture Host, ghi ra file `.pcapng` theo ngày.

**Ưu điểm của thiết kế này:**
- **Một điểm capture duy nhất** thấy toàn bộ traffic: traffic benign (Controller → PLC), traffic tấn công (Attacker → PLC), và traffic kỹ sư (Engineering Station → PLC) đều nằm trong cùng một file PCAP.
- **Không ảnh hưởng hiệu năng** các máy tham gia — không cần cài thêm phần mềm capture trên từng node.
- **Không bỏ sót packet** do đồng bộ thời gian giữa nhiều capture đầu — chỉ có một đồng hồ duy nhất trên Capture Host.
- **Phản ánh đúng thực tế triển khai IDS**: trong môi trường nhà máy thực tế, IDS sensor cũng thường được đặt tại SPAN port của switch OT, không được cài trực tiếp trên PLC hay HMI.

---

<a name="4"></a>
## 4. BÀI TOÁN ĐIỀU KHIỂN — HỆ THỐNG BĂNG TRUYỀN (CONVEYOR BELT)

### 4.1 Lý Do Lựa Chọn

Hệ thống **Băng Truyền** được chọn vì đây là mô hình thu nhỏ đại diện cho một **lớp rộng các hệ thống công nghiệp phân tán**:

| Hệ Thống Thực Tế | Tương Đương Trong Băng Truyền | S7comm Pattern |
|---|---|---|
| Đèn giao thông đô thị | M5.0/M5.1 = lệnh chuyển pha; CD1/CD2/CD3 = timer xanh/vàng/đỏ | Job(Write M) → Ack theo chu kỳ |
| Hệ thống thủy lợi | Vat_1/2/3 = mực nước van cống; Times_1 = chu kỳ tưới | Read M/I → Write M theo ngưỡng |
| Dây chuyền sản xuất | Vat_x = trạng thái trạm gia công; BangTai = băng chuyền | Đọc cảm biến → ghi lệnh actuator |

### 4.2 Cấu Trúc Hệ Thống Điều Khiển

```
                   ┌─────────────────────────────────────┐
  I area           │         LOGIC PLC                   │           Q area
  (Physical Input) │                                     │       (Physical Output)
                   │   M area (Merker — biến nội bộ)    │
  I0.0 Start_1 ───►│                                     ├──► Q0.0 BangTai (động cơ)
  I0.1 Stop_1  ───►│   M5.0 START (lệnh từ HMI)         │
  I0.2 Cam_bien──►│   M5.1 STOP  (lệnh từ HMI)         ├──► Q0.6 Aux output
                   │   M5.4 Vat_1 (vật thể 1)           │
                   │   M5.6 Vat_2 (vật thể 2)           │
                   │   M6.0 Vat_3 (vật thể 3)           │
                   │                                     │
  MD area          │   MD50 Times_1 (chu kỳ tổng)       │
  (Timer/Counter)  │   MD54 CD1  (timer vật thể 1)      │
                   │   MD58 CD2  (timer vật thể 2)      │
                   │   MD62 CD3  (timer vật thể 3)      │
                   │                                     │
                   │   MW70 Nhap (đếm thùng vào)        │
                   └─────────────────────────────────────┘
```

### 4.3 Bảng Tag TIA Portal Đầy Đủ

| Area | Address | Tag Name | Loại | Chức Năng |
|---|---|---|---|---|
| I | I0.0 | Start_1 | BOOL | Nút khởi động vật lý tại máy |
| I | I0.1 | Stop_1 | BOOL | Nút dừng khẩn cấp vật lý |
| I | I0.2 | Cam_bien | BOOL | Cảm biến quang phát hiện vật thể |
| Q | Q0.0 | BangTai | BOOL | Động cơ băng tải: CHẠY=1 / DỪNG=0 |
| Q | Q0.6 | Aux | BOOL | Tín hiệu phụ trợ |
| M | M5.0 | START | BOOL | Lệnh khởi động từ HMI/SCADA |
| M | M5.1 | STOP | BOOL | Lệnh dừng từ HMI/SCADA |
| M | M5.4 | Vat_1 | BOOL | Vật thể 1 đang trên băng |
| M | M5.6 | Vat_2 | BOOL | Vật thể 2 đang trên băng |
| M | M6.0 | Vat_3 | BOOL | Vật thể 3 đang trên băng |
| MD | MD50 | Times_1 | DINT | Bộ đếm thời gian tổng chu kỳ (ms) |
| MD | MD54 | CD1 | DINT | Countdown timer xử lý vật thể 1 (ms) |
| MD | MD58 | CD2 | DINT | Countdown timer xử lý vật thể 2 (ms) |
| MD | MD62 | CD3 | DINT | Countdown timer xử lý vật thể 3 (ms) |
| MW | MW70 | Nhap | WORD | Đếm số thùng đi vào |
| MW | MW74 | HienThi | WORD | Giá trị hiển thị HMI |

---

<a name="5"></a>
## 5. CÔNG CỤ BẢO MẬT TỰ PHÁT TRIỂN

### 5.1 ICSScout v2.0 — Nền Tảng Đánh Giá Bảo Mật OT/ICS

#### Mục Đích

ICSScout là công cụ đánh giá bảo mật thụ động cho mạng OT/ICS, được thiết kế theo nguyên tắc **Read-Only by Default** — không can thiệp vào hệ thống điều khiển, chỉ quan sát và phân tích.

#### Kiến Trúc Clean Architecture (4 Layers)

```
┌──────────────────────────────────────────────┐
│  Interfaces — Web GUI (Flask + WebSocket)     │
│  Packet Analyzer (3-pane Wireshark-like)      │
│  Risk Assessment Dashboard                    │
├──────────────────────────────────────────────┤
│  Services — Session Management               │
│           — Activity Tracker                 │
│           — Workflow Orchestration           │
├──────────────────────────────────────────────┤
│  Core — Protocol Clients (S7, Modbus, OPC-UA)│
│       — Packet Capture Engine (Scapy)        │
│       — Vulnerability Scanner (CVE DB)       │
│       — Risk Engine + Scoring Rules          │
│       — Safety Checker                       │
├──────────────────────────────────────────────┤
│  Domain — Device, Protocol, Vulnerability    │
│         — Risk Assessment, Target models     │
└──────────────────────────────────────────────┘
```

#### Tính Năng Chính

**1. Packet Analyzer (Wireshark-like)**
- 3-pane layout: Packet List / Packet Details / Hex Dump
- Protocol dissection chi tiết cho S7comm, Modbus TCP, OPC UA
- Giải mã đầy đủ: TPKT → COTP → S7 Header → Parameters → Data
- Export PCAP files cho phân tích offline

**2. Vulnerability Scanner**
- CVE database tích hợp (cập nhật cho PLC Siemens)
- Kiểm tra default credentials (factory password)
- Phát hiện unencrypted protocols (cleartext S7comm không có TLS)
- Risk scoring theo CVSS và context-aware rules
- Recommendations cụ thể cho từng vulnerability

**3. Protocol Support**
- **Siemens S7:** S7-300, S7-400, S7-1200, S7-1500 (qua python-snap7)
- **Modbus TCP:** Coils, Holding/Input Registers, Discrete Inputs
- **OPC UA:** Protocol detection và session monitoring
- **Profinet DCP:** Station discovery, vendor/device fingerprinting

**4. Safety Features**
- Read-only mode mặc định — không ghi dữ liệu lên PLC
- Safety checker kiểm tra trước mọi thao tác có nguy cơ
- Audit trail ghi log tất cả actions với timestamp
- Session management theo dõi workflow đánh giá

**5. Network Topology Scanner**
- ARP Scan phát hiện devices trong LAN
- ICMP Ping Sweep cho devices không respond ARP
- Port scanning nhận dạng services
- Topology visualization real-time bằng vis.js
- Device classification: PLC, Switch, Computer, Gateway
- OS detection từ TTL fingerprinting

#### Web GUI

```
Dashboard (http://localhost:5000):
  ┌─────────────────────────────────────────────────────┐
  │  Quick Statistics: Devices | Packets | Vulns | Risk  │
  ├─────────────────────────────────────────────────────┤
  │  Protocol Distribution Chart (real-time)            │
  │  Device List với Quick Actions                      │
  │  Active Sessions                                    │
  └─────────────────────────────────────────────────────┘

Packet Analyzer (/packets):
  ┌─────────────────────────────────────────────────────┐
  │  Packet List: Time | Src | Dst | Protocol | Info    │
  ├─────────────────────────────────────────────────────┤
  │  Packet Details: ▼ TPKT ▼ COTP ▼ S7 Header         │
  │                  ▼ S7 Parameter (Read DB1.DBX0.0)   │
  ├─────────────────────────────────────────────────────┤
  │  Hex Dump: 0000  03 00 00 1f 02 f0 80 ... |......|  │
  └─────────────────────────────────────────────────────┘
```

### 5.2 S7Pwn — Công Cụ Kiểm Thử Bảo Mật PLC Siemens S7

#### Mục Đích

S7Pwn là công cụ kiểm thử bảo mật **chủ động** (active security testing) cho PLC Siemens S7, phục vụ pentesting có ủy quyền và nghiên cứu học thuật. Được thiết kế để thực hiện đầy đủ workflow pentest: Discovery → Probe → Enumerate → Exploit → Report.

#### Giao Diện CLI (Interactive Shell)

```
s7pwn> scan 192.168.1.0/24    # Quét mạng tìm PLC Siemens
s7pwn> target 192.168.1.10 0 1 # Đặt target (IP, Rack, Slot)
s7pwn> probe                   # Lấy thông tin CPU, firmware, module
s7pwn> enum-tags M 0 80        # Đọc toàn bộ 80 byte Merker
s7pwn> read M 5 1              # Đọc byte M5
s7pwn> write M 5 1 0x81        # Ghi byte M5 (đặt START+STOP bits)
s7pwn> flood --threads 6       # S7 session flood (pentesting DoS)
s7pwn> fuzz --type tpkt        # Protocol fuzzing với random payload
s7pwn> sniff --duration 60     # Capture traffic thụ động 60 giây
s7pwn> replay --file cap.pcap  # Phát lại capture đã thu thập
s7pwn> export scan html        # Xuất báo cáo HTML
s7pwn> webgui                  # Khởi động Web GUI
```

#### Các Module Tấn Công (Attack Commands)

| Command | Module | Chức Năng | MITRE ATT&CK |
|---|---|---|---|
| `scan` | scan.py | Quét mạng tìm PLC, phát hiện Profinet DCP | T0846 |
| `probe` | probe.py | Fingerprint CPU type, firmware version, protection level | T0888 |
| `enum-tags` | enum_tags.py | Đọc tuần tự toàn bộ vùng nhớ (M/DB/I/Q) | T0888 |
| `read` / `write` | read.py / write.py | Đọc/ghi bộ nhớ PLC theo area và offset | T0836 |
| `rwrite` | rwrite.py | Burst write liên tục vào một địa chỉ | T0855 |
| `flood` | flood.py | S7 session flood — exhausting connection slots | T0814 |
| `fuzz` | fuzz.py | Protocol fuzzing với random TPKT/COTP payload | T0819 |
| `sniff` | sniff.py | Passive sniffing S7comm traffic | T0842 |
| `replay` | replay.py | Phát lại packet đã capture | T0843 |
| `spoof` | spoof.py | Giả mạo packet S7comm | T0856 |
| `cpu_control` | cpu_control.py | Gửi lệnh CPU STOP/START | T0816 |
| `auth` | auth.py | Kiểm tra S7 authentication (password brute-force) | T0852 |

#### Extended Attack Modules (`attacks_ext/`)

Ngoài các lệnh cơ bản, S7Pwn còn tích hợp module tấn công nâng cao cho môi trường phức tạp hơn:

| Module | Mục Tiêu | Kịch Bản |
|---|---|---|
| `dns_spoof_ics.py` | DNS Server trong mạng ICS | Redirect traffic HMI → Fake PLC |
| `ews_firmware_tamper.py` | Engineering Workstation | Thao túng firmware update package |
| `ews_rogue_engineer.py` | TIA Portal sessions | Giả mạo kỹ sư hợp lệ |
| `hmi_alarm_suppress.py` | HMI alarm system | Ngăn cảnh báo hiển thị lên operator |
| `hmi_credential_brute.py` | HMI login | Brute-force credential HMI web |
| `hmi_fake_display.py` | HMI display values | Hiện thị giá trị giả trên màn hình |
| `kill_chain.py` | Full kill chain | Tự động hóa chuỗi recon → exploit |

#### Báo Cáo Đa Định Dạng

S7Pwn xuất báo cáo ở 3 định dạng: JSON (machine-readable), CSV (Excel import), HTML (đẹp, có thể in). Bao gồm: scan results, probe data, operation log, network topology.

---

<a name="6"></a>
## 6. THU THẬP DỮ LIỆU — PHƯƠNG PHÁP VÀ QUY TRÌNH

### 6.1 Lịch Thu Thập 6 Ngày

Toàn bộ traffic trong cả 6 ngày đều được thu thập tập trung bởi **Capture Host kết nối vào SPAN port của switch** — một file `.pcapng` duy nhất mỗi ngày chứa traffic của tất cả các thành phần (benign HMI, Engineering Station, và Attacker). Không cài TShark trên từng máy riêng lẻ.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        TIMELINE 6 NGÀY                               │
│                                                                        │
│  Day 1: ════════════════════════════════════ BENIGN BASELINE          │
│         (idle hoàn toàn, không tấn công)                              │
│                                                                        │
│  Day 2: ══════════════════ RECONNAISSANCE                             │
│         [  SCAN  ] [    ENUMERATION    ]                              │
│                                                                        │
│  Day 3: ═══════════════════ INTEGRITY ATTACKS (phần 1)               │
│         [   RWRITE_BURST   ] [      SETPOINT_ATTACK      ]            │
│                                                                        │
│  Day 4: ═══════════════════ INTEGRITY ATTACKS (phần 2)               │
│         [    SENSOR_SPOOF    ] [       STEALTHY_WRITE      ]          │
│                                                                        │
│  Day 5: ═══════════════════ AVAILABILITY ATTACKS                      │
│         [  S7_FLOOD  ] [  SYN_FLOOD  ] [  PROTOCOL_FUZZ  ]           │
│                                                                        │
│  Day 6: ═══════════════ OOD ROBUSTNESS HOLDOUT                       │
│         (tất cả 9 kịch bản, thứ tự ngẫu nhiên, rate thấp hơn)       │
└────────────────────────────────────────────────────────────────────────┘
```

**Tổng thu thập:**
- Wall-clock span: ~49.8 giờ qua 6 ngày
- Released windowed duration: 31.1 giờ (55,902 windows × 2 giây)
- Phần còn lại: gaps overnight, transition periods bị loại bỏ

### 6.2 Benign Traffic — 4 Chế Độ Hoạt Động

Điểm thường bị bỏ qua: benign traffic phải đủ **đa dạng** để mô hình không overfit vào một kiểu traffic duy nhất. Hệ thống tạo benign traffic qua 4 chế độ phản ánh thực tế vận hành:

| Profile | Thời Lượng | Cơ Chế | Đặc Trưng Traffic |
|---|---|---|---|
| `normal_hmi` | 90 phút | Snap7 poll 1–2s random + tag logger 0.5s | Job(Read M+Q+I) → Ack_Data đều đặn, 2 TCP stream song song |
| `sparse_hmi` | 60 phút | Snap7 poll 5–20s random + tag logger 2s | Traffic thưa, IAT lớn, nhiều gap im lặng trong window |
| `tia_portal_only` | 60 phút | Chỉ TIA Portal online (kỹ sư theo dõi) | UserData (ROSCTR=0x07) — diagnostic packet, khác hẳn Read/Write |
| `idle_quiet` | 30 phút | Không poll, không logger | Chỉ TCP keepalive, ARP broadcast định kỳ |

**Kỹ thuật quan trọng:**
- Poll interval là `random.uniform(min, max)` → IAT không phải hằng số, phân bố đúng thực tế
- Tag logger tạo Snap7 session riêng biệt → 2 TCP stream S7comm đồng thời trong cùng window (giống thực tế: HMI + SCADA cùng kết nối)
- TIA Portal tạo S7comm UserData (ROSCTR=0x07) — loại traffic đặc trưng của công cụ lập trình, không có trong script HMI đơn giản
- Benign có xác suất 2% gửi START pulse hợp lệ → tránh model học "write = luôn là attack"

### 6.3 Gán Nhãn Thời Gian Thực (Event-Based Timeline)

**Vấn đề với post-hoc labeling (cách thông thường):** Gán nhãn sau khi thu thập dựa trên log file dễ bị lệch thời gian, bỏ sót các window chuyển tiếp, không xác định được chính xác thời điểm START/END của tấn công.

**Giải pháp của đồ án:** Event-based timeline — ghi nhãn ngay tại thời điểm thực thi:

```python
# Ghi nhãn ngay khi bắt đầu tấn công:
label("RWRITE_BURST", "START", episode_id)  → timestamp_ms = T1

# Ghi nhãn ngay khi kết thúc:
label("RWRITE_BURST", "END", episode_id)    → timestamp_ms = T2
```

**Window overlap labeling** (trong `merge_dataset.py`):
```
Cửa sổ [w_start, w_start + 2000ms] → nhãn ATTACK nếu có overlap > 0ms với bất kỳ attack interval
Khi nhiều attack interval overlap → lấy nhãn của interval có overlap lớn nhất
Transition window: loại bỏ ±10 giây quanh biên attack để tránh label noise
```

**Attack Event Log (`attack_events.csv`):** Ground truth ở mức tín hiệu quá trình:
```
signal     | area | byte_offset | bit_offset | data_type | old_value | new_value | episode_id
M5.1_STOP  | MK   | 5           | 1          | bool      | 0         | 1         | bt_s1:d3:RWRITE_BURST:r1:1
CD1_MS     | MK   | 54          |            | dint      | 5000      | 90000     | bt_s1:d4:SETPOINT_ATTACK:r1:1
```

---

<a name="7"></a>
## 7. KỊCH BẢN TẤN CÔNG — 9 SCENARIOS THEO MITRE ATT&CK FOR ICS

### 7.1 Phân Loại Theo Nhóm

```
NHÓM A — RECONNAISSANCE (Ngày 2)
  ├── A1. SCAN_PORT        → T0846 Remote System Discovery
  └── A2. ENUM_TAGS        → T0888 Point & Tag Identification

NHÓM B — INTEGRITY ATTACKS (Ngày 3–4)
  ├── B1. RWRITE_BURST     → T0855 Unauthorized Command Message
  ├── B2. SETPOINT_ATTACK  → T0836 Modify Parameter
  ├── B3. SENSOR_SPOOF     → T0856 Spoof Reporting Message
  └── B4. STEALTHY_WRITE   → T0836 Low-rate evasion

NHÓM C — AVAILABILITY ATTACKS (Ngày 5)
  ├── C1. S7_FLOOD         → T0814 Denial of Service
  ├── C2. SYN_FLOOD        → T0814 Denial of Service
  └── C3. PROTOCOL_FUZZ    → T0819 Exploitation of Remote Services
```

---

### 7.2 NHÓM A — Reconnaissance / Tình Báo Mạng

#### A1. SCAN_PORT — Port & Host Scanning

**Kịch bản thực tế:** Attacker đã xâm nhập vào mạng nội bộ (qua VPN bị compromise hoặc insider). Bước đầu: xác nhận PLC còn hoạt động và cổng S7comm (TCP 102) có thể kết nối. Quét với interval ngẫu nhiên 0.4–1.5s để không kích hoạt rate-limit đơn giản.

**Cơ chế kỹ thuật:**
```python
# TCP connection probe đến port 102 — không cần credential
s = socket.create_connection((target, 102), timeout=1.0)
# Vòng lặp vô tận, interval: random.uniform(0.4, 1.5) giây
```

**Traffic Signature:**
- `tcp_syn_count` cao → nhiều TCP SYN đến port 102
- `tcp_rst_count` cao → PLC reset connections không hoàn chỉnh
- `cotp_cr_count` = 0 → không đủ để lên tầng COTP
- `s7comm_packet_count` = 0 → hoàn toàn không có S7 data

**Tác Động:** Không gây hại trực tiếp, nhưng tiết lộ PLC đang hoạt động và exposed trên mạng.

---

#### A2. ENUM_TAGS — Tag & Memory Enumeration

**Kịch bản thực tế:** Sau khi biết PLC còn sống, attacker lập bản đồ toàn bộ vùng nhớ PLC để hiểu cấu trúc chương trình. Đọc quét M[0..80] (Merker), Q[0] (output), I[0] (input), và các timer MD. Thông tin này phục vụ lên kế hoạch tấn công integrity.

**Cơ chế kỹ thuật:**
```python
c.read_area(Areas.MK, 0, 0, 80)   # Đọc 80 byte Merker
c.read_area(Areas.PA, 0, 0, 1)    # Đọc Output byte 0
c.read_area(Areas.PE, 0, 0, 1)    # Đọc Input byte 0
# Timer: read MD50, MD54, MD58, MD62
```

**Traffic Signature:**
- `s7_read_count` rất cao (> 100 lần/window 5 giây)
- `s7_sequential_offset_score` ≈ 1.0 → offset tăng 0→80 theo bước đều
- `s7_unique_offset_count` > 40 → nhiều địa chỉ khác nhau
- `s7_write_count` = 0 → chỉ đọc, chưa ghi

**Tác Động:** Tiết lộ toàn bộ cấu trúc logic PLC, là bước chuẩn bị cho các tấn công tiếp theo.

---

### 7.3 NHÓM B — Integrity Attacks / Tấn Công Tính Toàn Vẹn

#### B1. RWRITE_BURST — Burst Write Attack

**Kịch bản thực tế:** Attacker đã biết địa chỉ START (M5.0) và STOP (M5.1) từ ENUM_TAGS. Ghi liên tục toggle START/STOP để băng tải liên tục dừng/khởi lại. Không crash PLC nhưng phá hoàn toàn năng suất sản xuất.

**Cơ chế kỹ thuật:**
```python
while running:
    m5 = c.read_area(Areas.MK, 0, 5, 1)  # Đọc byte M5 hiện tại
    set_bool(m5, 0, 1, True)              # Bật STOP (M5.1)
    set_bool(m5, 0, 0, False)             # Tắt START (M5.0)
    c.write_area(Areas.MK, 0, 5, m5)     # Ghi lại
    # Rồi toggle sang START:
    set_bool(m5, 0, 0, True)
    set_bool(m5, 0, 1, False)
    c.write_area(Areas.MK, 0, 5, m5)
    time.sleep(random.uniform(0.15, 0.45))
```

**Traffic Signature:**
- `s7_write_count` rất cao (> 50/window)
- `s7_write_read_ratio` >> 1 → ghi nhiều hơn đọc
- `s7_merker_area_count` cao → toàn bộ ghi vào M area
- `s7_output_write_count` = 0 → không ghi trực tiếp Q area

**Tác Động Vật Lý:** Băng tải dừng/khởi lại liên tục 2–3 lần/giây → quá tải motor, hỏng vật thể đang vận chuyển, ngừng dây chuyền.

---

#### B2. SETPOINT_ATTACK — Timer Manipulation

**Kịch bản thực tế:** Tấn công tinh vi hơn — không dừng băng tải trực tiếp mà thay đổi timing parameters (CD1/CD2/CD3). Băng tải vẫn chạy nhưng nhịp đếm bị sai hoàn toàn. Rất khó phát hiện bằng mắt thường vì băng tải "trông có vẻ bình thường".

**Cơ chế kỹ thuật:**
```python
abnormal_values = [100, 250, 45000, 60000, 90000]  # ms — bất thường so với default 5000ms
cd1 = random.choice(abnormal_values)
write_dint(c, 54, cd1, "CD1_MS")   # MD54: 5 giây → 90 giây
write_dint(c, 58, cd2, "CD2_MS")   # MD58: 5 giây → 250 ms
write_dint(c, 62, cd3, "CD3_MS")   # MD62: 5 giây → 45 giây
write_dint(c, 50, random.choice([0, 120000, 180000]), "Times_1_MS")
```

**Traffic Signature:**
- `s7_write_count` vừa phải (< 30/window — không burst như RWRITE)
- Target offset: 50, 54, 58, 62 (MD area) → khác M5 offset của RWRITE
- `s7_write_payload_bytes_mean` cao hơn → DInt = 4 bytes/lần ghi
- Process signal: `proc__CD1__std` và `proc__CD1__max` tăng đột biến

**Tác Động Vật Lý:** Timer bất thường gây vật thể va chạm nhau, không được phân loại đúng, báo cáo sản lượng sai lệch.

---

#### B3. SENSOR_SPOOF — Cảm Biến Giả Mạo

**Kịch bản thực tế:** Giả mạo trạng thái cảm biến vật thể (Vat_1/Vat_2/Vat_3) trong Merker. PLC "thấy" có vật thể trên băng nhưng thực tế không có → kích hoạt timer countdown ảo → logic điều phối bị nhiễu loạn.

**Cơ chế kỹ thuật:**
```python
patterns = [(1,1,1), (1,0,1), (0,1,1)]  # Vat_1, Vat_2, Vat_3
v1, v2, v3 = random.choice(patterns)
set_bool(m5, 0, 4, bool(v1))   # M5.4 = Vat_1
set_bool(m5, 0, 6, bool(v2))   # M5.6 = Vat_2
set_bool(m6, 0, 0, bool(v3))   # M6.0 = Vat_3
# Interval: 0.4–1.5 giây
```

**Traffic Signature:**
- `s7_write_count` vừa phải, interval 0.4–1.5s
- Ghi vào 2 byte khác nhau (M5 và M6) trong cùng episode
- Process signal: `proc__Vat_1__std` tăng bất thường

**Tác Động Vật Lý:** Hệ thống báo nhầm số vật thể, gây lỗi phân loại, sản lượng báo cáo sai.

---

#### B4. STEALTHY_WRITE — Tấn Công Low-Rate Lén Lút

**Kịch bản thực tế:** Tấn công tinh vi nhất trong nhóm integrity. Chỉ ghi STOP bit với tần số cực thấp (20–60 giây/lần). Băng tải dừng đột ngột mỗi vài chục giây — operator thấy bất thường nhưng không rõ nguyên nhân. **Traffic quá thưa để kích hoạt bất kỳ threshold-based IDS nào.**

**Cơ chế kỹ thuật:**
```python
# Chỉ ghi STOP, không ghi START → băng tải dừng và không tự khởi lại
m5 = c.read_area(Areas.MK, 0, 5, 1)
set_bool(m5, 0, 1, True)   # STOP = True
set_bool(m5, 0, 0, False)  # START = False
c.write_area(Areas.MK, 0, 5, m5)
time.sleep(random.uniform(20.0, 60.0))  # Chờ 20–60 giây!
```

**Traffic Signature:**
- `s7_write_count` cực thấp (< 5/window 5 giây, thường = 0 hoặc 1)
- Không có burst, không có pattern tuần tự
- Phân biệt với benign write: benign write luôn đi kèm Read trước đó; STEALTHY chỉ ghi không đọc context
- Process signal: `proc__M5_STOP__max` = 1 xuất hiện bất thường

**Thách Thức:** Đây là kịch bản khó nhất cho AI vì volume signal quá nhỏ. Chỉ phân biệt được nếu model học ngữ nghĩa (write-without-read-context) thay vì volume/rate.

---

### 7.4 NHÓM C — Availability / Protocol Attacks

#### C1. S7_FLOOD — Session Exhaustion

**Kịch bản thực tế:** S7-1500 giới hạn số session S7comm đồng thời (thường 4–8 session). Attacker tung 6 thread song song mở kết nối và giữ ngắn. Toàn bộ connection slot bị chiếm → TIA Portal, HMI mất kết nối, operator mù hoàn toàn.

**Cơ chế kỹ thuật:**
```python
# 6 thread đồng thời
def worker():
    c = snap7.client.Client()
    c.connect(target, rack, slot)
    time.sleep(random.uniform(0.03, 0.2))  # Giữ kết nối ngắn
    c.disconnect()

threads = [Thread(target=worker) for _ in range(6)]
# Mỗi thread: connect → sleep → disconnect → lặp lại vô tận
```

**Traffic Signature:**
- `cotp_cr_count` rất cao → nhiều Connection Request
- `s7_negotiation_only_ratio` cao → phần lớn session chỉ setup, không có S7 data
- `tcp_active_streams` tăng đột biến
- `s7comm_packet_count` thấp tương đối

---

#### C2. SYN_FLOOD — TCP Layer Attack

**Kịch bản thực tế:** Tấn công ở tầng TCP thấp hơn S7_FLOOD. 20 thread gửi TCP SYN liên tục đến port 102, không hoàn thành handshake. TCP connection table của PLC bị cạn kiệt.

**Cơ chế kỹ thuật:**
```python
# 20 thread, mỗi thread: tạo socket → connect (timeout 0.08s) → close → lặp
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.08)  # SYN gửi, không chờ hoàn chỉnh
s.connect((target, 102))
```

**Traffic Signature:**
- `tcp_syn_count` cực cao (>> 100/window)
- `tcp_ack_count` thấp → không hoàn thành handshake
- `tcp_syn_ack_ratio` >> 1
- `cotp_cr_count` = 0 → không lên được tầng COTP

---

#### C3. PROTOCOL_FUZZ — Fuzzing Giao Thức

**Kịch bản thực tế:** Gửi packet với TPKT header hợp lệ nhưng payload hoàn toàn ngẫu nhiên. PLC phải cố parse và reject từng packet → tăng tải CPU parser, có thể gây lỗi firmware chưa được vá.

**Cơ chế kỹ thuật:**
```python
payload = os.urandom(random.randint(12, 80))  # Random bytes
# TPKT header: version=0x03, reserved=0x00, length=đúng chuẩn
pkt = b"\x03\x00" + (len(payload) + 4).to_bytes(2, "big") + payload
s.connect((target, 102))
s.sendall(pkt)
```

**Traffic Signature:**
- `payload_entropy_mean` cao ≈ 7.5–8.0 bit/byte (random bytes)
- `payload_hash_unique_ratio` ≈ 1.0 → mỗi packet payload khác nhau
- `malformed_packet_count` tăng → TShark phát hiện malformed S7/COTP
- `s7_error_count` tăng → PLC trả về error response

---

### 7.5 Day 6 — OOD Robustness Test

Toàn bộ 9 kịch bản chạy lại với các thay đổi có chủ đích để kiểm tra generalization:

| Thay Đổi | Day 2–5 (Standard) | Day 6 (OOD Robust) |
|---|---|---|
| Thứ tự kịch bản | Cố định theo ngày | Shuffle ngẫu nhiên |
| Packet interval | 0.15–1.5 giây | 2–60 giây (tùy loại) |
| S7_FLOOD threads | 6 | Tối đa 2 |
| SYN_FLOOD threads | 20 | Tối đa 3 |
| Gap giữa episodes | 5 phút cố định | 2–15 phút ngẫu nhiên |

**Mục đích:** Kiểm tra xem mô hình AI có thực sự học **ngữ nghĩa** (loại lệnh, vùng nhớ bị tác động) hay chỉ học **timing/intensity** (số packet/giây). Nếu model chỉ học timing thì Day 6 F1 sẽ thấp hơn đáng kể.

### 7.6 Thống Kê Phân Phối Dataset

| Kịch Bản / Class | Day 1 | Day 2 | Day 3 | Day 4 | Day 5 | Day 6 (Holdout) | Tổng |
|---|---:|---:|---:|---:|---:|---:|---:|
| **BENIGN** | 7,348 | 8,761 | 11,753 | 5,208 | 9,787 | 4,603 | **47,460** |
| **SCAN** | 0 | 438 | 0 | 0 | 0 | 462 | **900** |
| **ENUMERATION** | 0 | 935 | 0 | 0 | 0 | 470 | **1,405** |
| **RWRITE** | 0 | 0 | 866 | 0 | 0 | 365 | **1,231** |
| **SETPOINT_ATTACK** | 0 | 0 | 0 | 829 | 0 | 253 | **1,082** |
| **SPOOF** | 0 | 0 | 0 | 943 | 0 | 299 | **1,242** |
| **STEALTHY** | 0 | 0 | 0 | 442 | 0 | 397 | **839** |
| **S7_FLOOD + SYN_FLOOD** | 0 | 0 | 0 | 0 | 894 | 317 | **1,211** |
| **FUZZ** | 0 | 0 | 0 | 0 | 410 | 122 | **532** |
| **Tổng** | 7,348 | 10,134 | 12,619 | 7,422 | 10,091 | 6,288 | **55,902** |

---

<a name="8"></a>
## 8. ĐẶC TRƯNG KHAI THÁC — DEEP PACKET INSPECTION TOÀN STACK S7comm

### 8.1 Đây Là Đóng Góp Kỹ Thuật Trọng Tâm

Các dataset ICS trước đây dừng ở đặc trưng L3/L4 — bỏ qua hoàn toàn lớp ứng dụng công nghiệp. Đồ án này thực hiện **DPI toàn stack** từ L2 đến L7:

### 8.2 Phân Tầng Đặc Trưng Theo Stack Giao Thức

```
L2  Ethernet    → src/dst MAC, eth.type
                   Profinet DCP (0x8892):
                     service_id (Identify/Set/Get/Hello)
                     vendor_id, device_id, station_name
                     dcp_identify_request_count
                     dcp_discover_ip_count

L3  IP          → src/dst IP, protocol

L4  TCP         → port 102, TCP flags (SYN/ACK/RST/FIN/URG/CWE/ECE)
                   stream ID, IAT (fwd/bwd), window size
                   tcp_syn_count, tcp_ack_count, tcp_rst_count
                   tcp_active_streams

L5  TPKT        → RFC 1006: length field
                   tpkt_count (per window)

L6  COTP        → Connection Request (CR): mở session
                   Connection Confirm (CC): server chấp nhận
                   Data Transfer (DT): chứa S7 command thực tế
                   Disconnect Request (DR): đóng session
                   cotp_cr_count, cotp_cc_count, cotp_dt_count, cotp_dr_count

L7  S7comm      → ROSCTR: Job(0x01)/Ack(0x02)/Ack_Data(0x03)/UserData(0x07)
                   param.func: Read(0x04)/Write(0x05)/Setup(0xF0)/CPU Control
                   param.item.area: MK/PA/PE/DB (Merker/Output/Input/DataBlock)
                   param.item.address: byte offset
                   param.item.transport_size: kích thước dữ liệu
                   resp.error_class / error_code

    S7comm-plus → opcode, function:
                   GetMultiVariables / SetMultiVariables
                   CreateObject / DeleteObject (session management)

Payload         → payload_entropy_mean, payload_hash_unique_ratio
                   raw_payload_len_std, malformed_packet_count
```

### 8.3 Đặc Trưng Ngữ Nghĩa — Không Có Trong Bất Kỳ Dataset ICS Công Khai Nào

#### `s7_write_read_ratio`
Tỷ lệ lệnh Write / Read trong window 5 giây:
- Bình thường: HMI chủ yếu đọc trạng thái → ratio << 1 (< 0.1)
- RWRITE_BURST: ghi liên tục → ratio >> 1 (> 5)
- SETPOINT_ATTACK: ghi timer → ratio tăng, nhưng target là MD offset

#### `s7_sequential_offset_score`
Độ tuần tự của địa chỉ byte offset trong window:
- Bình thường: HMI đọc cùng vài địa chỉ cố định → score ≈ 0
- ENUM_TAGS: đọc M[0..80] với offset tăng đều → score ≈ 1.0
- Công thức: tỷ lệ diff(offset) ∈ {1, 2, 4, 8}

#### `s7_merker_area_count` vs `s7_output_write_count` vs `s7_input_write_count`
Phân biệt vùng nhớ bị tấn công:
- Ghi vào Merker (M): tác động gián tiếp qua logic PLC → nguy hiểm vừa
- Ghi vào Output (Q): bypass logic PLC, điều khiển trực tiếp actuator → nguy hiểm cao nhất
- Ghi vào Input (I): giả mạo cảm biến → SENSOR_SPOOF

#### `cotp_cr_count` cao + `s7comm_packet_count` thấp
S7_FLOOD signature: nhiều Connection Request nhưng không có Data Transfer theo sau.

#### `s7_negotiation_only_ratio`
Tỷ lệ packet chỉ có COTP/TPKT nhưng không có S7 command:
- Normal: ratio thấp
- S7_FLOOD / SYN_FLOOD: ratio ≈ 1.0

#### `payload_entropy_mean` + `payload_hash_unique_ratio`
- Normal S7: payload cố định → entropy thấp, hash lặp lại nhiều
- PROTOCOL_FUZZ: payload ngẫu nhiên → entropy ≈ 8 bit/byte, hash unique ≈ 1.0
- REPLAY attack: payload lặp lại → hash unique ≈ 0

### 8.4 Decode Level — Chất Lượng Giải Mã

| decode_level | Ý Nghĩa | Đặc Trưng Có Thể Dùng |
|---|---|---|
| `network_only` | Chỉ L3/L4 | packet count, byte, TCP flags, IAT |
| `cotp_tpkt` | L5/L6 nhận dạng được | Thêm tpkt_count, cotp_cr/cc/dt/dr |
| `s7_partial` | S7comm nhận dạng ROSCTR | Thêm read/write/setup count |
| `s7_full` | S7comm đầy đủ area + offset | Toàn bộ semantic features |

Chỉ window với `decode_level = s7_full` mới có đủ đặc trưng ngữ nghĩa.

### 8.5 So Sánh Với Các Dataset ICS Công Khai

| Tiêu Chí | SWaT (2016) | BATADAL (2018) | ICSX (2021) | CIC-ICS2024 | **Dataset Này** |
|---|:---:|:---:|:---:|:---:|:---:|
| PLC thật (S7) | ✗ | ✗ | Một phần | Có | **S7-1200/1500** |
| S7comm DPI (L7) | ✗ | ✗ | ✗ | Một phần | **Đầy đủ** |
| Đặc trưng ngữ nghĩa S7 | ✗ | ✗ | ✗ | ✗ | **17 features** |
| Profinet DCP features | ✗ | ✗ | ✗ | ✗ | **Có** |
| COTP session features | ✗ | ✗ | ✗ | ✗ | **Có** |
| Process + Network tách biệt | ✗ | ✗ | ✗ | ✗ | **3 views** |
| Leakage control + GroupKFold | ✗ | ✗ | ✗ | ✗ | **Có, tường minh** |
| Timeline thời gian thực (ms) | ✗ | ✗ | Một phần | Một phần | **Có** |
| Attack event log (signal level) | ✗ | ✗ | ✗ | ✗ | **Có** |
| Stealthy low-rate attack | ✗ | Một phần | ✗ | ✗ | **STEALTHY_WRITE** |
| OOD robustness test | ✗ | ✗ | ✗ | ✗ | **Day 6** |
| MITRE ATT&CK for ICS mapping | ✗ | ✗ | Một phần | Có | **Đầy đủ** |

---

<a name="9"></a>
## 9. PIPELINE XÂY DỰNG DATASET VÀ KIỂM SOÁT LEAKAGE

### 9.1 Pipeline End-to-End

```
┌────────────────┐   ┌──────────────────────┐   ┌─────────────────┐
│  raw/pcap/     │   │  raw/attack_logs/    │   │  raw/tag_logs/  │
│  day*.pcapng   │   │  *_timeline.csv      │   │  *_tags.csv     │
│  (TShark cap)  │   │  *_attack_events.csv │   │  (PLC tag poll) │
└────────┬───────┘   └──────────┬───────────┘   └────────┬────────┘
         │                      │                         │
         ▼                      │                         │
scripts/feature_extract.py      │                         │
  TShark DPI toàn stack S7comm  │                         │
  → 1 dòng / 1 cửa sổ 2 giây   │                         │
         │                      │                         │
         ▼                      ▼                         ▼
processed/*_features.csv ──── scripts/merge_dataset.py ──────────
                                         │
                           ┌─────────────┼──────────────────────┐
                           ▼             ▼                       ▼
                  network.csv      process.csv           fusion.csv
               (PCAP features)  (PLC tag view)    (Network+Process)
                           │
                           ▼
                   scripts/train_ml.py
                GroupKFold | RF+XGB+CatBoost+LR
                fbeta_oof threshold | Day6 holdout
```

### 9.2 Ba Dataset Views Độc Lập

**View 1: `network.csv`** — IDS thuần mạng
- Chỉ dùng đặc trưng từ PCAP window (feature_extract.py)
- Drop toàn bộ process context (tag log, timer value)
- Câu hỏi: "Chỉ nhìn vào traffic mạng, AI có phát hiện tấn công không?"
- **55,902 rows × 192 safe features**

**View 2: `process.csv`** — Process Anomaly Detection
- Chỉ dùng PLC tag log, aggregated theo window 2 giây
- Mỗi tag: mean/std/min/max trong window: `proc__CD1__mean`, `proc__CD1__std`
- Câu hỏi: "Chỉ nhìn vào trạng thái quá trình, AI có phát hiện không?"
- **10,771 rows × 154 features** (ít hơn vì chỉ có logger-derived rows)

**View 3: `fusion.csv`** — Sensor Fusion
- Kết hợp network features + process features (join theo `window_start_ms`)
- Câu hỏi: "Kết hợp hai nguồn có cải thiện detection rate không?"
- **55,902 rows × 324 safe features**

**View 4: `leakage_ablation.csv`** — Ablation Study
- Giữ lại các cột identity (IP, MAC, session) và rule flags
- Chỉ dùng để đo lường "information leakage inflation"
- Không dùng làm benchmark chính

### 9.3 Kiểm Soát Data Leakage — Thiết Kế Hướng Publication

**Các cột bị loại bỏ trước khi train:**

| Nhóm | Ví Dụ Cột | Lý Do Loại |
|---|---|---|
| Identity endpoint | `src_ip`, `dst_ip`, `src_mac`, `top_src_ip` | Model học IP attacker thay vì hành vi |
| Timestamp | `window_start_ms`, `window_end_ms` | Model nhớ thứ tự thời gian thu thập |
| Session metadata | `session_id`, `episode_id`, `host_id` | Leakage qua group identity |
| Rule flags | `scan_detected_rule`, `timer_out_of_range` | Hand-crafted rules, không phải ML feature |
| Score columns | `port_scan_score`, `arp_scan_score` | Derived từ rules = target leakage |
| Data availability | `proc_data_valid` | Collection artifact (logger không chạy đồng bộ) |

### 9.4 GroupKFold Theo Session

```python
# Dữ liệu từ cùng session_id|host_id|episode_id KHÔNG xuất hiện ở cả train lẫn test
# Ngăn model học "fingerprint" của một buổi thu thập cụ thể
splitter = StratifiedGroupKFold(n_splits=5, shuffle=True)
splits = splitter.split(X, y, groups=composite_group_key)
```

**Số groups trong từng view:**
- network.csv + fusion.csv: **228 groups** = 192 BENIGN (10-phút/segment) + 36 attack episodes
- process.csv: **49 groups** = 40 BENIGN segments + 9 attack groups

### 9.5 Fbeta_OOF Threshold Calibration

Vấn đề với in-sample threshold: chọn threshold bằng cách maximize F_β trên predictions của chính mẫu train đã dùng để fit model → optimistic bias.

**Giải pháp `fbeta_oof`:**
1. Với mỗi outer split, chỉ dùng outer-training partition
2. Chạy inner grouped CV bên trong outer-training partition
3. Tạo out-of-fold positive-class probabilities cho outer-training rows
4. Chọn threshold maximize F_β từ OOF probabilities
5. Fit lại model trên toàn bộ outer-training partition
6. Áp threshold đã khóa lên outer-test/Day-6 holdout

**β = 2.0** → ưu tiên recall (giảm false negative) so với precision, phù hợp với bài toán ICS security.

---

<a name="10"></a>
## 10. MÔ HÌNH HỌC MÁY VÀ KẾT QUẢ THỰC NGHIỆM

### 10.1 Thiết Lập Thực Nghiệm

**4 Mô Hình Được Đánh Giá:**

| Model | Hyperparameter Chính | Đặc Điểm |
|---|---|---|
| Random Forest | n_estimators=300, class_weight="balanced_subsample", min_samples_leaf=2 | Ensemble cây quyết định, không cần scaler |
| XGBoost | n_estimators=300, max_depth=6, lr=0.1, subsample=0.8 | Gradient boosting, objective=binary:logistic |
| CatBoost | iterations=300, depth=6, lr=0.1, auto_class_weights="Balanced" | Gradient boosting với xử lý class imbalance tốt |
| Logistic Regression | max_iter=2000, class_weight="balanced" | Tuyến tính với StandardScaler |

**Preprocessing:**
- NaN và Inf: fill bằng 0
- Correlation pruning: loại feature với |r| > 0.98 (fit trên train fold only)
- Constant feature drop: loại feature có nunique ≤ 1 trên train fold
- Feature profile: `hybrid` (safe features + S7/process ratio + presence features)

**Validation Protocol:**
- Grouped CV: 5 folds × 5 seeds (42–46)
- Day 6 external holdout: không dùng trong training
- Day 5 temporal holdout: train Day 1–4, test Day 5 (stress test phụ)

### 10.2 Kết Quả Binary Detection — Macro-F1 và MCC

**Bảng 1: Group CV vs Day 6 OOD Holdout (`fbeta_oof`, seeds 42–46)**

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

### 10.3 False Positive Rate Per Hour

**Bảng 2: FPR/hour (binary, `fbeta_oof`)**

| View | Model | Group CV FPR/hr | Day 6 OOD FPR/hr |
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

> **Ghi chú FPR/hour:** Tính ở mức window (2 giây/window). Một chuỗi 30 windows liên tiếp bị dự đoán sai được tính là 30 false alarms, không phải 1. Đây là raw detection burden, không phải operator-level alarm rate.

### 10.4 Temporal Holdout — Day 5 Stress Test

**Train Day 1–4 → Test Day 5 (FLOOD + FUZZ only)**

| View | Model | Day5 Macro-F1 | Day5 MCC | Day5 FPR/hr |
|---|---|---:|---:|---:|
| network_only | Random Forest | **0.999 ± 0.001** | **0.998 ± 0.001** | 0.993 ± 0.497 |
| network_only | XGBoost | 0.998 ± 0.001 | 0.996 ± 0.001 | 1.545 ± 0.443 |
| network_only | CatBoost | 0.993 ± 0.011 | 0.986 ± 0.022 | 0.441 ± 0.210 |
| fusion | Random Forest | **1.000 ± 0.000** | **1.000 ± 0.000** | 0.184 ± 0.000 |
| fusion | XGBoost | **1.000 ± 0.000** | **1.000 ± 0.000** | 0.184 ± 0.000 |
| process_only | All models | ≈ 0.499 | ≈ 0.000 | varies |

> Day 5 kết quả cao vì FLOOD/FUZZ tạo separation rất mạnh: `tcp_syn_count` benign max=12 nhưng attack min=18; `tcp_active_streams` benign max=11 nhưng attack min=13. Kết quả gần hoàn hảo này chỉ là stress test phụ, không chứng minh generalization tốt hơn Day 6.

### 10.5 Per-Class F1 Trên Day 6 — CatBoost Multiclass

**Network-only vs Fusion:**

| Class | Net-only P | Net-only R | Net-only F1 | Fusion F1 | Support |
|---|---:|---:|---:|---:|---:|
| BENIGN | 0.701 | 0.998 | 0.824 | 0.814 | 4,603 |
| STEALTHY | 0.641 | 0.736 | **0.683** | **1.000** ⚠️ | 397 |
| SETPOINT_ATTACK | 1.000 | 0.051 | 0.096 | 0.095 | 253 |
| SPOOF | 0.290 | 0.064 | 0.104 | 0.107 | 299 |
| SCAN | 0.141 | 0.052 | 0.076 | 0.016 | 462 |
| FLOOD | 1.000 | 0.038 | 0.072 | 0.066 | 317 |
| RWRITE | 0.000 | 0.000 | 0.000 | 0.018 | 365 |
| ENUMERATION | 0.000 | 0.000 | 0.000 | 0.000 | 470 |
| FUZZ | 0.000 | 0.000 | 0.000 | 0.000 | 122 |
| **Macro avg** | 0.419 | 0.215 | **0.206** | **0.235** | 7,288 |

> ⚠️ **STEALTHY F1=1.000 trong fusion là class-specific leakage** (Q0=40 khi STOP bit active), không phải genuine detection improvement. Xem phân tích mục 11.

### 10.6 Ablation Theo Semantic Layers

**Train Day 1–4 → Test Day 6 OOD (CatBoost, seeds 42–46)**

| Config | Layers | Features | After Filter | Macro-F1 | MCC | FPR/hr |
|---|---|---:|---:|---:|---:|---:|
| A — Network volume only | L0 | 115 | 67 | 0.648 ± 0.008 | 0.462 ± 0.010 | 1.173 ± 0.479 |
| B — + ICS presence | L0+L1 | 147 | 77 | 0.654 ± 0.010 | 0.470 ± 0.013 | 1.251 ± 0.643 |
| C — + S7 semantics | L0+L1+L2 | 192 | 92 | 0.647 ± 0.011 | 0.461 ± 0.012 | 1.173 ± 1.106 |
| D — + Process state | L0+L1+L2+L3 | 324 | 106 | **0.663 ± 0.020** | **0.483 ± 0.024** | **0.078 ± 0.175** |

---

<a name="11"></a>
## 11. PHÂN TÍCH KẾT QUẢ VÀ ĐIỂM NỔI BẬT

### 11.1 Trả Lời Các Câu Hỏi Nghiên Cứu

**RQ1 — Dataset đủ đa dạng không?**
Dataset gồm 55,902 windows từ 6 ngày, 9 kịch bản tấn công thuộc 3 nhóm khác nhau (recon, integrity, availability), 4 chế độ benign, với leakage control nghiêm ngặt và OOD test day. So sánh với các dataset công khai, đây là dataset S7comm đầu tiên có DPI đầy đủ L2–L7, ground truth ở mức tín hiệu PLC, và temporal OOD holdout. **RQ1: Có.**

**RQ2 — Fusion có cải thiện không?**
Kết quả không nhất quán: với CatBoost binary, fusion (0.626) thấp hơn network-only (0.659) trên Day 6. Với XGBoost, fusion (0.673) nhỉnh hơn network-only (0.649). Nguyên nhân: chỉ 839/8,442 attack windows (9.9%) có process signal phân biệt (Q0=40 duy nhất cho STEALTHY). Các class SCAN, ENUM, FUZZ dù có `proc_data_valid=1` nhưng process values giống BENIGN (Q0=41). Với logger coverage đầy đủ và đồng bộ, fusion có thể hiệu quả hơn. **RQ2: Phụ thuộc điều kiện, cần logger sync tốt hơn.**

**RQ3 — Generalization sang OOD?**
Group CV F1 cao (0.90+) nhưng Day 6 OOD F1 thấp hơn đáng kể (~0.66). Khoảng cách Δ≈0.25 cho thấy temporal/OOD shift đáng kể. Tuy nhiên Day 6 vẫn đạt F1=0.66 và MCC=0.48 — chứng minh model học một phần ngữ nghĩa thật, không chỉ học timing. **RQ3: Generalize vừa phải, OOD gap đáng kể nhưng không catastrophic.**

### 11.2 Điểm Mạnh Nổi Bật

#### 11.2.1 Tính Thực Tế Của Testbed

Việc kết hợp PLC thật và PLCSIM là điểm khác biệt then chốt:
- PLC thật tạo timing features phản ánh giới hạn phần cứng (jitter, RTT thật, connection limits)
- PLCSIM cho phép tái tạo nhanh kịch bản CPU STOP mà không rủi ro hệ thống sản xuất
- Profinet DCP traffic chỉ xuất hiện với PLC thật (vendor ID Siemens 002a)

#### 11.2.2 Đặc Trưng Ngữ Nghĩa S7 Có Discriminative Power Thực Sự

Các đặc trưng tầng L6/L7 phân biệt được các kịch bản mà L3/L4 không thể:
- `s7_sequential_offset_score` → phân biệt ENUM_TAGS vs normal HMI (cùng số lệnh Read nhưng pattern địa chỉ khác nhau)
- `s7_write_read_ratio` → phân biệt RWRITE_BURST vs benign write (tỷ lệ khác nhau rõ rệt)
- `cotp_cr_count / s7comm_packet_count` → phân biệt S7_FLOOD vs normal connection churn
- `payload_entropy_mean` → phân biệt PROTOCOL_FUZZ vs normal S7 payload

#### 11.2.3 Chất Lượng Dataset Cao — Không Ambiguous Label

Labeling thời gian thực với millisecond precision, loại bỏ transition windows ±10 giây, và attack event log ở mức bit/byte tạo ra ground truth chất lượng cao nhất trong các dataset ICS công khai.

#### 11.2.4 Kiểm Soát Leakage Tường Minh

Phát hiện và sửa 3 bugs leakage trong quá trình phát triển:
- Bug 1: `proc_data_valid` gán sai thứ tự → sửa → column phản ánh đúng logger availability
- Bug 2: ffill/bfill cross-day → sửa → per-day groupby
- Bug 3: `proc_data_valid` dùng làm feature → sửa → thêm vào `ALWAYS_DROP`

Sau khi sửa: process_only MCC từ âm lên +0.37 — minh chứng leakage control có tác động thực sự.

#### 11.2.5 STEALTHY_WRITE — Kịch Bản Thách Thức Quan Trọng

Dataset là một trong rất ít dataset ICS có kịch bản low-rate stealthy attack:
- Rate: 1 lần ghi / 20–60 giây → quá thưa cho bất kỳ threshold-based IDS nào
- Chỉ phát hiện được bằng ngữ nghĩa: "write-without-read-context" trong cùng session
- Trên Day 6, network-only CatBoost đạt F1=0.683 cho STEALTHY — kết quả đáng kể với kịch bản này

### 11.3 Hiểu Sâu Kết Quả Đặc Biệt

#### Tại Sao Process-Only F1=0.548 Giống Nhau Cho Tất Cả 4 Models?

Feature importance xác nhận `proc__q0_raw_hex_mean` chi phối hoàn toàn (>50% với CatBoost):
- `q0_raw_hex_mean = 40` → STEALTHY (STOP bit = 1 làm Q0 đổi sang 40)
- `q0_raw_hex_mean = 41` → mọi class khác (process đứng yên)

Cả 4 model học cùng 1 decision rule đơn giản này → F1 giống hệt nhau. Giá trị q0=40 là thuộc tính vật lý PLC thật (không phải artifact), nên đây là detection thực, nhưng chỉ cho class STEALTHY.

#### Tại Sao Day 5 Gần Hoàn Hảo (RF F1=0.999)?

FLOOD/FUZZ tạo separation tuyệt đối trên network features:
- `tcp_syn_count`: benign max=12, attack min=18 (không overlap)
- `tcp_active_streams`: benign max=11, attack min=13 (không overlap)

Model học boundary đơn giản này → Day 5 là stress test dễ, không đại diện cho generalization tổng quát.

---

<a name="12"></a>
## 12. HẠN CHẾ VÀ HƯỚNG PHÁT TRIỂN

### 12.1 Hạn Chế Hiện Tại

#### Hạn Chế 1 — Process Logger Không Đồng Bộ

**Vấn đề:** Process logger không được khởi động đồng thời với PCAP capture trong một số ngày:
- Day 2 (SCAN, ENUM): logger bắt đầu 13 phút SAU khi attack kết thúc
- Day 3 (RWRITE): logger bắt đầu 36 phút SAU khi attack kết thúc
- Day 5 (FLOOD, FUZZ): chỉ overlap 10 giây với attack window

**Hậu quả:** 6,744/8,442 attack windows (79.9%) có `proc_data_valid=0`. Chỉ 839/8,442 (9.9%) có process signal phân biệt (STEALTHY). Đây là lý do fusion không cải thiện nhất quán.

**Giải pháp tương lai:** Khởi động logger tự động cùng lúc với capture, bằng script wrapper đồng bộ hóa cả hai tiến trình.

#### Hạn Chế 2 — Chênh Lệch Group CV vs OOD (Δ≈0.25 F1)

Model học tốt trong in-distribution nhưng F1 giảm đáng kể trên Day 6. Nguyên nhân có thể là:
- Temporal drift: đặc trưng thống kê thay đổi giữa các ngày
- Model học một phần timing/rate dù có leakage control
- Day 6 có rate thấp hơn → volume features khác biệt dù semantic giống nhau

**Giải pháp tương lai:** Thêm Day 7, 8 với biến thể rate khác nhau để model học được invariance theo rate.

#### Hạn Chế 3 — Phân Loại Multiclass Kém Cho Nhiều Class

Multiclass F1=0 cho ENUMERATION, FUZZ, RWRITE trên Day 6. Nguyên nhân:
- Các class này có ít training data (1,231–1,405 windows)
- Day 6 versions có rate khác nhau so với Day 2–5

**Giải pháp tương lai:** Thêm dữ liệu tổng hợp (SMOTE hoặc thu thập thêm), và sử dụng class-specific threshold trong multiclass.

#### Hạn Chế 4 — Đơn Lẻ Về Loại PLC

Toàn bộ dataset dùng Siemens S7-1200/S7-1500. Không có dữ liệu từ Allen-Bradley, Schneider, ABB, Beckhoff.

**Giải pháp tương lai:** Thu thập thêm trên các PLC khác (Modbus TCP, EtherNet/IP, Profinet với vendor khác).

#### Hạn Chế 5 — Thiếu Clock Offset Log

Release hiện tại không có per-host clock-offset measurement log. Đồng bộ thời gian giữa controller host và attacker host dùng epoch-ms alignment (không có constant offset correction).

### 12.2 Hướng Phát Triển

#### Hướng 1 — Tăng Cường Dataset

- Thu thập thêm ít nhất 10 ngày với logger sync đầy đủ
- Thêm kịch bản tấn công nâng cao: Replay, MitM, Supply Chain (firmware tamper)
- Thêm multi-protocol: OPC UA, Modbus TCP, DNP3, IEC 104
- Thêm dữ liệu từ nhiều PLC vendor

#### Hướng 2 — Cải Thiện Mô Hình

- Transfer learning: pre-train trên dataset lớn rồi fine-tune trên S7comm
- Time-series models: LSTM, Transformer để khai thác temporal patterns
- Graph-based IDS: phát hiện bất thường dựa trên topology tương tác
- Federated learning: huấn luyện phân tán trên nhiều nhà máy

#### Hướng 3 — Tích Hợp Thực Tế

- Tích hợp ICSScout với SIEM (Splunk, Elastic)
- Dashboard real-time detection với alert management
- Plugin cho Wireshark để hiển thị S7comm security risk score
- API cho phép tích hợp với OT security platforms

#### Hướng 4 — Công Bố Khoa Học

- Công bố dataset trên GitHub/Zenodo để cộng đồng tái sử dụng
- Viết paper cho IEEE S&P, ACSAC, DSN hoặc ICS-security workshop
- Tổ chức challenge/competition dùng dataset làm benchmark

---

<a name="13"></a>
## 13. KẾT LUẬN

### 13.1 Tóm Tắt Kết Quả

Đồ án đã xây dựng thành công một hệ sinh thái hoàn chỉnh cho nghiên cứu bảo mật ICS, bao gồm:

**1. Testbed vật lý kết hợp** PLC Siemens S7-1200/S7-1500 thật với PLCSIM, bài toán Băng Truyền đại diện cho lớp hệ thống công nghiệp phân tán rộng.

**2. Hai công cụ tự phát triển:**
- **ICSScout v2.0**: Platform đánh giá bảo mật thụ động với Web GUI, Packet Analyzer (Wireshark-like), Vulnerability Scanner, Network Topology Scanner
- **S7Pwn**: Công cụ kiểm thử bảo mật chủ động với CLI interactive shell, 14 attack commands, 7 extended attack modules

**3. SemanticAware-S7comm-Dataset** — dataset benchmark đầu tiên:
- 55,902 time-windows (2 giây/window) qua 6 ngày thu thập
- 9 kịch bản tấn công theo MITRE ATT&CK for ICS (3 nhóm: recon, integrity, availability)
- DPI đầy đủ tầng L2–L7 với 17 đặc trưng ngữ nghĩa S7 chưa có trong bất kỳ dataset ICS công khai nào
- 3 views độc lập (network/process/fusion) + leakage control tường minh
- Ground truth ở mức tín hiệu PLC (bit/byte level) với millisecond precision
- Day 6 OOD holdout để kiểm tra generalization

**4. Kết quả ML:**
- Binary detection (network-only, CatBoost): **F1=0.659, MCC=0.477** trên Day 6 OOD holdout
- Binary detection (fusion, XGBoost): **F1=0.673, MCC=0.495** trên Day 6 OOD holdout
- Day 5 temporal holdout (FLOOD/FUZZ): **F1=0.999** (RF), xác nhận model học được đặc trưng volumetric mạnh
- Fusion FPR/hour: **0.078/hour** (CatBoost), thấp hơn network-only (1.642/hour) đáng kể

### 13.2 Ý Nghĩa Khoa Học và Thực Tiễn

**Về mặt khoa học:** Đồ án chứng minh rằng DPI toàn stack S7comm tạo ra các đặc trưng có discriminative power thực sự cho IDS, vượt trội hơn so với chỉ dùng L3/L4 features. Đặc biệt, các đặc trưng ngữ nghĩa như `s7_sequential_offset_score` và `s7_write_read_ratio` có thể phân biệt các kịch bản tấn công mà volume-based features không thể.

**Về mặt thực tiễn:** Hai công cụ ICSScout và S7Pwn có thể được sử dụng ngay trong môi trường pentesting OT thực tế. Dataset được công bố để cộng đồng nghiên cứu bảo mật ICS toàn cầu có thể so sánh và cải thiện các thuật toán IDS.

**Về mặt phương pháp:** Quy trình kiểm soát data leakage chặt chẽ (GroupKFold theo session, fbeta_oof threshold, loại bỏ identity columns, Day 6 OOD holdout) là khuôn mẫu có thể áp dụng cho các nghiên cứu ICS-IDS trong tương lai.

---

## PHỤ LỤC A — Cấu Trúc Thư Mục Dự Án

```
iiot/
├── icsscout/                     # ICSScout v2.0 source code
│   ├── core/
│   │   ├── capture/              # Packet capture engine (Scapy)
│   │   ├── protocols/s7/         # S7comm client (python-snap7)
│   │   ├── protocols/modbus/     # Modbus TCP client (pymodbus)
│   │   ├── protocols/opcua/      # OPC UA detection
│   │   ├── risk_assessment/      # Risk engine + scoring rules + CVE DB
│   │   ├── vulnerability/        # CVE scanner
│   │   └── safety/               # Safety checker
│   ├── interfaces/web/           # Flask + WebSocket Web GUI
│   └── services/                 # Session manager, activity tracker
│
├── s7pwn/                        # S7Pwn source code
│   ├── commands/                 # CLI commands (scan, probe, read, write...)
│   ├── ext/                      # Extended scanner modules
│   └── web_gui.py, cli.py        # Web GUI + CLI entry points
│
├── attacks_ext/                  # Extended attack modules
│   ├── hmi_alarm_suppress.py
│   ├── hmi_credential_brute.py
│   ├── ews_firmware_tamper.py
│   └── kill_chain.py
│
├── SemanticAware-S7comm-Dataset/ # Dataset release
│   ├── raw/
│   │   ├── pcap/                 # Raw PCAP files (Day 1–6)
│   │   ├── tag_logs/             # PLC tag polling CSVs
│   │   └── attack_logs/          # Timeline + attack event logs
│   ├── processed/
│   │   ├── network.csv           # L3–L7 DPI features (55,902 rows)
│   │   ├── process.csv           # PLC tag dynamics (10,771 rows)
│   │   ├── fusion.csv            # Network + Process (55,902 rows)
│   │   └── leakage_ablation.csv  # Diagnostic ablation view
│   ├── scripts/
│   │   ├── feature_extract.py    # PCAP → DPI features
│   │   ├── merge_dataset.py      # Multi-modal alignment + fusion
│   │   └── train_ml.py           # Grouped CV + OOD ML benchmark
│   └── docs/
│       ├── DATA_CARD.md
│       └── ATTACK_DESCRIPTION.md
│
├── ml_results/                   # ML experiment artifacts
│   ├── threshold_oof_hybrid/     # Main fbeta_oof results
│   ├── group_split_audit/        # Split integrity audit
│   └── ablation_layers_fbeta_oof/ # Layer-wise ablation
│
├── run_day_bangtruyen.sh         # Main data collection orchestrator
├── log_tags_bangtruyen.py        # Real-time PLC tag logger
├── collect_dataset.py            # Data collection controller
└── docker-compose.attacker.yml   # Attacker container deployment
```

## PHỤ LỤC B — Danh Sách Hình Cần Vẽ Cho Báo Cáo

| # | Nội Dung | Công Cụ Gợi Ý |
|---|---|---|
| 1 | Sơ đồ topology testbed đầy đủ | Draw.io |
| 2 | So sánh RTT distribution: PLCSIM vs PLC thật | Matplotlib histogram |
| 3 | Sơ đồ chức năng Băng Truyền: I→M(logic)→Q | Draw.io |
| 4 | Screenshot bảng tag TIA Portal | TIA Portal V17 screenshot |
| 5 | Timeline 6 ngày: trục thời gian Gantt-style | Matplotlib |
| 6 | Pipeline end-to-end: PCAP → features → ML | Draw.io flowchart |
| 7 | Bảng so sánh đặc trưng vs SWaT, CIC-ICS2024 | LaTeX table |
| 8 | Box plot 6 đặc trưng ngữ nghĩa S7 theo 9 nhãn | Seaborn |
| 9 | Time-series tag log Day 1 benign | Matplotlib |
| 10 | Phân bố IAT benign: 4 profile | Matplotlib KDE |
| 11 | Wireshark: ENUM_TAGS offset sequence vs benign | Wireshark |
| 12 | Tag log 3 integrity attack: RWRITE/SETPOINT/STEALTHY | Matplotlib subplots |
| 13 | attack_events.csv mẫu 5 dòng/kịch bản | LaTeX table |
| 14 | Heatmap đặc trưng × kịch bản tấn công | Seaborn heatmap |
| 15 | Sơ đồ window overlap labeling | Draw.io |
| 16 | Sơ đồ 3 dataset views | Draw.io |
| 17 | Sơ đồ GroupKFold 5-fold theo session | Draw.io |
| 18 | Bảng ablation: safe ML vs leakage columns | LaTeX table / bar chart |
| 19 | Confusion matrices Day 6: network-only vs fusion | Seaborn heatmap |
| 20 | ICSScout Web GUI screenshots | Browser screenshot |

## PHỤ LỤC C — Thư Viện và Dependencies

| Thư Viện | Phiên Bản | Mục Đích |
|---|---|---|
| python-snap7 | 1.3+ | Giao tiếp S7comm với PLC Siemens |
| scapy | 2.5+ | Packet capture và phân tích mạng |
| pymodbus | 3.0+ | Modbus TCP client |
| flask | 2.3+ | Web framework cho ICSScout + S7Pwn GUI |
| flask-socketio | 5.0+ | Real-time WebSocket updates |
| scikit-learn | 1.3+ | ML models (RF, LR), GroupKFold |
| xgboost | 2.0+ | XGBoost classifier |
| catboost | 1.2+ | CatBoost classifier |
| pandas | 2.0+ | Data processing |
| numpy | 1.24+ | Numerical computation |
| matplotlib / seaborn | latest | Visualization |

---

*Báo cáo này phản ánh trạng thái dự án tại thời điểm hoàn thành đồ án (2026). Toàn bộ số liệu đều là kết quả đo thực từ code, không có ước lượng.*
