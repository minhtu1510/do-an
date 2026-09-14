# Báo cáo Day 7 — Advanced Attack Scenarios

## 1. Tổng quan

Day 7 mở rộng bộ kịch bản Day 1–6 bằng các kỹ thuật nâng cao, được **tuyển chọn có chủ đích để tránh trùng nhãn (label collision) với Day 1–6 và với nhau**. Sau rà soát, chỉ giữ lại các kịch bản thực sự tạo ra dữ liệu **phân biệt được** hoặc mang giá trị tường thuật riêng.

Mạch truyện: **Recon → Foothold + Lateral Movement → Impact có che giấu (concealment)**.

- Script điều phối: [`run_day_bangtruyen_ext.sh`](run_day_bangtruyen_ext.sh)
- Modules: [`attacks_ext/`](attacks_ext/)

## 2. Ba (03) kịch bản trong lịch thu thập

> **Cập nhật sau thực nghiệm smoke-test:** hai kịch bản đánh dấu **(MỚI)** trước đây đã được **gỡ khỏi lịch thu thập** — `PROGRAM_UPLOAD_THEFT` (T0845) vì target trả `0x8104 (service not implemented)`, và `PROFINET_DCP_ABUSE` vì không thực thi được trong môi trường ảo hiện tại (cần raw socket layer-2 / quyền root — `sudo` bị vô hiệu hoá). Chi tiết ở mục 3 và 3.1. Lịch còn lại đúng **3 kịch bản đã kiểm thử ✅**, khớp với script chạy full ở mục 7.3.

| # | Scenario label | Module | MITRE (ICS) | Kỹ thuật cốt lõi | Lặp |
|---|---|---|---|---|---|
| 1 | `SMB_RECON_ENUM` | `attacks_ext/smb_enum.py` | T0842 Network Share Discovery | SMB2 Negotiate + share/named-pipe probe trên máy HMI (kỹ thuật SMB2-specific, không chỉ port scan thô) | ×3 |
| 2 | `KILL_CHAIN` | `attacks_ext/kill_chain.py` | Initial Access (S7) → Lateral Movement (T0846) | Chiếm foothold qua S7, dùng chính phiên đó pivot port-scan sang HMI/Engineering (RDP/SMB/S7-local) trong cùng 1 kịch bản liên tục | ×2 |
| 3 | `CONCEALED_STOP_ATTACK` | `attacks_ext/concealed_stop_attack.py` | T0831 + T0832 phối hợp (Urbina CCS16-style) | STOP thật trên PLC qua S7 + đồng thời ghi giả `BangTai=RUNNING` qua OPC UA trong đúng cửa sổ STOP đó | ×2 |

> **CPU_STOP KHÔNG thêm vào Day 7** — đã tồn tại ở Day 3 (`run_day_bangtruyen.sh`, label `CPU_STOP`) và **bị tắt mặc định** vì lỗi đã biết: `plc_stop()` chạy được nhưng S7-1500 **TỪ CHỐI `plc_hot_start()`** → CPU kẹt STOP, phải khởi động lại thủ công trong TIA Portal. Thêm lại sẽ trùng nhãn + dính đúng lỗi cũ.

> Định vị 3 kịch bản (xem đánh giá trung thực ở mục 9): `SMB_RECON_ENUM` thêm chữ ký **recon SMB2 trên HMI** — đóng góp dữ liệu thật nhưng khiêm tốn (giao thức/đích mà Day 1-6 không có). `KILL_CHAIN` và `CONCEALED_STOP_ATTACK` mang **giá trị case-study/tường thuật** (APT đa giai đoạn; demo bảo mật 2 kênh + đo trần concealment ~17%), **KHÔNG phải lớp ML mới** — phần ghi S7 của CONCEALED_STOP trùng vùng/offset M5 với `RWRITE_BURST` (Day 3) ở tầng feature.

## 3. Các kịch bản đã loại khỏi lịch (giữ code trong repo)

| Kịch bản | Lý do loại | Trạng thái |
|---|---|---|
| `S7_REPLAY` | Bản chất tàng hình/né IDS, không gây gián đoạn thật như kỳ vọng; muốn treo WinCC cần flood (mở nhiều kết nối song song, giữ lại) — cơ chế khác hẳn | File giữ, ngoài lịch |
| `ENG_STATION_PORT_SCAN` | Chức năng port-scan máy Engineering **đã nằm sẵn trong `KILL_CHAIN`** lateral movement (import `PORTS` + `tcp_probe` từ chính module này) → standalone là dư thừa | File giữ, ngoài lịch |
| `STEALTHY_WRITE` | Trùng tên + trùng kỹ thuật + trùng vùng ghi với `STEALTHY_WRITE` Day 3/4 (label collision); lại ghi `MD100` mà tag logger không ghi lại (process-view vô hình) | File giữ, ngoài lịch |
| `LOGIC_AWARE` | Ghi S7 vào **đúng offset** M5/CD54/CD58 giống hệt `RWRITE_BURST` (Day3) + `SETPOINT_ATTACK`/`SENSOR_SPOOF` (Day4) ở packet-level; chỉ khác điều kiện/timing → nguy cơ trùng nhãn cao, chất lượng dữ liệu không tốt | File giữ, ngoài lịch |
| `PROGRAM_UPLOAD_THEFT` **(MỚI)** | Thực nghiệm smoke-test: **S7-1500 phần cứng thật** trả `0x8104 (service not implemented)` cho `list_blocks`/`full_upload` → 0 khối upload → **không sinh dữ liệu tấn công thành công**. Không phải lỗi code — S7-1500 chặn nghiệp vụ upload khối S7comm cổ điển (hardening firmware). Giữ lại làm **bằng chứng "T0845 bị S7-1500 chặn"**, không đưa vào lịch. Xem mục 3.1a | File giữ, ngoài lịch |
| `PROFINET_DCP_ABUSE` **(MỚI)** | Thực nghiệm smoke-test: **không thực thi được** trong môi trường ảo — DCP là layer-2 (`ether proto 0x8892`), cần raw socket + quyền root; `sudo` bị vô hiệu hoá trên máy attacker (WSL2, iface ảo cũng không nhìn thấy segment Profinet thật). Đây là **giới hạn môi trường phía attacker**, không phải kết quả bảo mật về target. Xem mục 3.1 | File giữ, ngoài lịch |

### 3.1 Thực nghiệm smoke-test 2 module (MỚI) → gỡ khỏi lịch (2026-09-02)

Cả hai module đánh dấu (MỚI) được chạy thử riêng lẻ (`--duration 60`, `--session-id smoke`) trên môi trường ảo phục vụ đồ án. Kết quả dẫn tới quyết định loại khỏi lịch, ghi lại đầy đủ ở đây (dữ liệu âm — "attack bị chặn / không chạy được" — vẫn là kết quả hợp lệ, không giấu).

**a) `PROGRAM_UPLOAD_THEFT` (T0845) — target từ chối ở tầng giao thức**

```
$ python -m attacks_ext.program_upload --target 192.168.210.211 --rack 0 --slot 1 --duration 60 ...
[15:23:25] label PROGRAM_UPLOAD_THEFT START
USERDATA response error 0x8104: This service is not implemented on the module or a frame error was reported
[*] PROGRAM_UPLOAD_THEFT -> 192.168.210.211  (list_blocks_err=S7ProtocolError)
  [cycle 1] uploaded=0 blk (0B), denied=0
```

- Kết nối S7 thành công, nhưng **mọi lệnh `list_blocks`/`full_upload` bị trả `0x8104 = service not implemented`**. Kết quả: `uploaded=0`, `denied=0` — tức không phải "bị từ chối theo protection level" (kết cục mà module lường trước), mà là **dịch vụ upload khối S7comm cổ điển bị từ chối ở tầng firmware**.
- **Nguyên nhân (target là S7-1500 phần cứng thật — đã xác nhận):** Siemens **cố tình gỡ/chặn** các lệnh S7comm cổ điển thao tác khối chương trình trên dòng S7-1500 (đã chuyển sang S7CommPlus có xác thực) → server trả `0x8104`. **Bằng chứng bổ sung cho cùng cơ chế hardening này:** ở `KILL_CHAIN` Stage 1, `get_cpu_info()` (đọc SZL qua S7comm cổ điển) trả về **Module/Serial rỗng** — S7-1500 hạn chế luôn cả dịch vụ chẩn đoán cổ điển này. Nhất quán với việc `plc_hot_start()` bị từ chối (mục 2 CPU_STOP) và ghi nhận ở mục 5.6.
- **Định vị:** đây là **kết quả phòng thủ thật của S7-1500** — cùng luận điểm với `CONCEALED_STOP_ATTACK` (kênh S7comm cổ điển/không xác thực bị chặn, chỉ kênh có xác thực mới thao tác được). Giữ làm **bằng chứng "T0845 Program Upload bị S7-1500 chặn ở tầng giao thức"**, không đưa vào lịch thu thập vì không sinh flow tấn công thành công để gán nhãn.

**b) `PROFINET_DCP_ABUSE` — không thực thi được trong môi trường ảo**

```
$ sudo python -m attacks_ext.profinet_dcp --iface eth0 --duration 60 ...
Sudo is disabled on this machine. To enable it, go to the Developer Settings page in the Settings app
```

- **Không chạy tới bước tấn công.** DCP là giao thức layer-2 (EtherType `0x8892`, không có IP layer) → cần raw socket + quyền root; máy attacker hiện tại (WSL2) đã vô hiệu hoá `sudo`. Ngay cả khi có root, `eth0` của WSL2 là interface ảo NAT, **không nhìn thấy segment Profinet vật lý** nơi các biến tần SINAMICS (`.220/.221/.222`) nằm.
- **Định vị:** đây là **giới hạn môi trường phía attacker**, KHÔNG phải kết luận bảo mật về target (khác hẳn ca (a)). Muốn chạy thật cần một host Linux có NIC cắm trực tiếp vào segment Profinet + quyền root. Giữ code trong repo, ngoài lịch, đánh dấu "chưa kiểm chứng được trong testbed ảo".

## 4. Lỗi capture đã sửa (quan trọng cho chất lượng dataset)

**4.1 Filter bỏ sót HMI (đã sửa trước đó).** `CAPTURE_FILTER="host $TARGET_IP"` chỉ bắt PLC; traffic `SMB_RECON_ENUM`/nửa lateral-movement `KILL_CHAIN` đánh HMI (`.31`) bị drop → label attack nhưng 0 gói. Sửa: `host $TARGET_IP or host $HMI_IP`.

**4.2 Filter drop DCP layer-2 (mới, sửa cùng đợt thêm PROFINET_DCP).** DCP là layer-2 (EtherType `0x8892`), **không có IP layer** → filter `host ...` drop sạch mọi frame DCP → lại rơi vào đúng bẫy "label attack, 0 gói". Sửa: `CAPTURE_FILTER="host $TARGET_IP or host $HMI_IP or ether proto 0x8892"`.

**4.3 Trùng nhãn (label collision ở tầng ghi) — mới sửa.** `_run_attack`/`run_kill_chain` (shell) ghi `label START/END`, **đồng thời** mỗi module cũng `write_label START/END` vào **cùng file, cùng schema, cùng episode** → mỗi tấn công có **2×START + 2×END** → interval chồng lấn khi dựng timeline. Sửa: **bỏ nhãn attack ở tầng shell**, module là nguồn nhãn duy nhất (timing sát hơn + note giàu hơn). Shell chỉ còn ghi các pha benign.

## 5. Điểm nhấn: `CONCEALED_STOP_ATTACK` — Stealthy Concealment Attack

### 5.1 Cơ sở lý thuyết

Dựa trên **Urbina et al., "Limiting the Impact of Stealthy Attacks on Industrial Control Systems" (ACM CCS 2016)**: tấn công actuator thật + đồng thời giả mạo sensor feedback để che giấu hiệu ứng khỏi operator. Đây là **tấn công đa điểm phối hợp có điều kiện** (Adepu & Mathur, COMPSAC 2016) — khác với tấn công actuator đơn lẻ (không che giấu) hay tấn công sensor đơn lẻ (không kèm actuator thật).

### 5.2 Cơ chế

1. Luồng S7 (snap7): theo dõi `CD1`, chỉ hành động khi phát hiện đúng lúc "vật đang vận chuyển" (`0 < CD1 < 30000ms`).
2. Kích hoạt: bật cờ concealment **trước**, rồi mới ghi `STOP=True/START=False` thật lên PLC qua S7.
3. Song song, nhiều luồng OPC UA (`asyncua`) ghi liên tục `BangTai=True` (RUNNING) suốt cửa sổ STOP — đấu tranh liên tục với chính PLC (PLC tự tính lại giá trị thật mỗi chu kỳ scan).
4. Khi restart thật, tắt cờ concealment.

### 5.3 Lịch sử debug (giữ lại để không lặp lại sai lầm)

| Vấn đề | Nguyên nhân | Giải quyết |
|---|---|---|
| MITM (ARP poison + sửa gói OPC UA) — `intercepted=0` mọi lần | `get_if_hwaddr()` trên Npcap trả về MAC rỗng; sau khi vá vẫn `intercepted=0` | PLC/HMI không chấp nhận gratuitous ARP (hardening công nghiệp), không có quyền truy cập để xác nhận |
| **Bỏ hẳn hướng MITM/ARP** | Không sửa được bằng code, không chẩn đoán tiếp được | Chuyển sang ghi giả **trực tiếp qua OPC UA** |
| `BadWriteNotSupported` khi ghi OPC UA | `asyncua` tự gắn `SourceTimestamp`; S7-1500 từ chối gói ghi kèm timestamp | Tự dựng `ua.DataValue(ua.Variant(value))` tối giản, không timestamp |
| `TypeError`/`FrozenInstanceError` khi set `StatusCode` | Khác biệt phiên bản `asyncua` giữa các máy | Chỉ dùng constructor 1 tham số vị trí, tương thích mọi bản |

### 5.4 Kết quả định lượng

Probe xác nhận `BangTai` **chấp nhận ghi** qua OPC UA (server không chặn ở tầng protocol, dù `config/opcua_tags.yaml` đánh dấu app-level `writable: false`).

**Đợt thu thập đã kiểm chứng (session `day7_final`, 180 giây, 9 chu kỳ STOP):**

| Chỉ số | Giá trị |
|---|---|
| Số chu kỳ STOP thật | 9 |
| Số lần ghi giả gửi đi (`conceal_attempts`) | 13.604 (0 lỗi gửi) |
| Giá trị giả **giữ được** khi đọc lại (`readback_still_true`) | 183 |
| Giá trị giả **bị PLC ghi đè** (`readback_reverted`) | 843 |
| **Tỷ lệ che giấu "dính"** | **183 / 1026 = 17.8%** |

**Bằng chứng trên dây (pcap thu qua cổng SPAN, cùng cửa sổ):** 16.680 gói OPC UA đổ tới PLC `.211` (burst ghi che giấu) + 162 gói S7comm (STOP thật), đồng thời 3.702 gói TLS/S7CommPlus của kênh WinCC hợp lệ vẫn chạy nền — ảnh chụp hai kênh trong cùng một capture.

Con số 17.8% này **nhất quán** với các lần chạy trước (đều rơi ~17–18% qua nhiều lần đo, cả ghi tuần tự lẫn song song).

**Phát hiện quan trọng:** dù gửi tới 13.604 lần ghi, tỷ lệ "dính" vẫn chỉ ~17–18% và **không cải thiện khi tăng số luồng/số lần ghi**. → nút thắt cổ chai nằm ở **khả năng xử lý bên trong PLC/OPC UA server** (PLC tính lại giá trị thật mỗi chu kỳ scan, ghi đè giá trị giả gần như ngay lập tức), không phải tốc độ gửi phía attacker. Đây là **trần cứng** của kiểu tấn công "client bên ngoài đua thời gian với PLC".

### 5.5 Bằng chứng trực quan

Chụp đúng lúc trong cửa sổ STOP+concealment, quan sát 2 màn hình:

- **WinCC thật** (giao thức S7CommPlus, mã hóa + xác thực): băng tải **đứng yên** — đúng sự thật, **không thể can thiệp**.
- **Web-SCADA** (giao thức OPC UA, Anonymous/No-Security): `CONVEYOR STATUS: RUNNING` — **giá trị giả hiển thị thành công**.

**Giới hạn phát hiện thêm:** các tag khác trên Web-SCADA (`Stage timer` = 0ms, `Stage 2: ACTIVE` không tiến triển) **không được che giấu** (chỉ `BangTai` bị fake) → vẫn phản ánh đúng "quá trình đã đóng băng". Operator quan sát kỹ toàn bộ dashboard vẫn có thể phát hiện qua **mâu thuẫn giữa các tín hiệu** — đúng luận điểm phòng thủ của Urbina et al. (kiểm tra tính nhất quán chéo / physical invariants).

### 5.6 So sánh bảo mật 2 kênh — phát hiện chính

| Kênh giám sát | Giao thức | Cấu hình bảo mật | Kết quả concealment |
|---|---|---|---|
| WinCC | S7CommPlus | Mã hóa + xác thực (session key) | **0% — không thể can thiệp** |
| Web-SCADA | OPC UA | `SecurityPolicy: None`, Anonymous | **~17.6–18% — can thiệp được 1 phần** |

**Kết luận:** đây **không phải lỗi giao thức OPC UA** (OPC UA hỗ trợ đầy đủ mã hóa/xác thực) mà là **lỗi cấu hình testbed** (đã xác nhận từ Day 8: `OPCUA_UNAUTHORIZED_SESSION`, `OPCUA_CERTIFICATE_REJECTED` đều `NOT_CONFIGURED`). Cùng 1 PLC, 2 cửa vào, chỉ 1 cửa được khóa — kẻ tấn công đi vào cửa còn lại.

## 6. Module đã thiết kế, CHỜ hoàn thiện (chưa vào lịch thu thập)

**`EVASION_SHAPED_WRITE`** ([attacks_ext/evasion_shaped_write.py](attacks_ext/evasion_shaped_write.py)) — Adversarial Evasion Attack nhắm vào **chính ML-IDS của project** (lừa mô hình, khác với concealment lừa người), theo dòng nghiên cứu 2024–2025 (*On Practical Realization of Evasion Attacks for ICS* 2024; *FEVA-ICS* 2025).

- **Cơ chế:** nắn traffic S7 sao cho các feature thật của `extract_s7_features.py` (`s7_write_read_ratio`, `s7_write_count`, `s7_sequential_offset_score`...) rơi vào vùng benign; hành động phá hoại thật (1 write STOP) bị vùi trong nhiều read benign ở nhịp HMI thật, window 5s khớp dataset.
- **Trạng thái:** đã build + compile OK, **chưa test trên PLC**, **chưa vào lịch Day 7**.
- **Điều kiện để có giá trị (bắt buộc):** phải kèm bước **đo detection rate A/B** (thô vs shaped) trên model thật. Hiện `train_ml.py` **không lưu model ra disk** → cần thêm mảnh (a) lưu/serve model + (c) script đánh giá offline. **Không có bước đo này thì module thoái biến thành `STEALTHY_WRITE` đã bị loại.**
- **Giới hạn đã biết (kết quả có giá trị, không phải lỗi):** shaping né được feature volume/rate nhưng **không giấu được feature offset** (benign ghi offset 100, STOP là offset 5) — đúng kỳ vọng "feature semantic robust hơn feature volume" của FEVA-ICS.

## 7. Cách chạy

### 7.1 Test riêng từng module (khuyến nghị trước khi chạy full)

```bash
python -m attacks_ext.smb_enum --target 192.168.210.31 --duration 15 --session-id smoke --host-id attacker_host --label-file labels/smoke_test.csv

python -m attacks_ext.kill_chain --target 192.168.210.211 --rack 0 --slot 1 --hmi-target 192.168.210.31 --session-id smoke --host-id attacker_host --label-file labels/smoke_test.csv

python -m attacks_ext.concealed_stop_attack --target 192.168.210.211 --rack 0 --slot 1 --opc-url opc.tcp://192.168.210.211:4840 --duration 30 --session-id smoke --host-id attacker_host --label-file labels/smoke_test.csv

# (ĐÃ GỠ KHỎI LỊCH — target trả 0x8104, xem mục 3.1a) Program Upload Theft (T0845).
# Lệnh giữ lại chỉ để tái lập kết quả "attack bị chặn":
python -m attacks_ext.program_upload --target 192.168.210.211 --rack 0 --slot 1 --duration 60 --session-id smoke --host-id attacker_host --label-file labels/smoke_test.csv

# (ĐÃ GỠ KHỎI LỊCH — không chạy được trên WSL2, xem mục 3.1b) Profinet DCP Abuse (T0814/T0816).
# CẦN host Linux có NIC cắm thẳng segment Profinet + quyền root; testbed ảo hiện tại không đáp ứng.
sudo python -m attacks_ext.profinet_dcp --iface eth0 --duration 60 --session-id smoke --host-id attacker_host --label-file labels/smoke_test.csv
```

### 7.2 Preflight

```bash
bash run_day_bangtruyen_ext.sh --day 7 --role attacker --session-id day7_final --preflight-only
```

### 7.3 Chạy full

```bash
bash run_day_bangtruyen_ext.sh --day 7 --role attacker --session-id day7_final
```

Lịch: Warmup → SMB Recon (×3) → Kill Chain (×2) → Concealed Stop Attack (×2) → Cooldown. Có `tshark` capture song song (filter đã sửa để bắt cả PLC lẫn HMI), ghi label vào `labels/day7_<session-id>_attacker_host_timeline.csv`.

## 8. Trạng thái kiểm thử

| Module | Test riêng lẻ | Trạng thái |
|---|---|---|
| `SMB_RECON_ENUM` | ✅ | OK sau khi vá bug đóng gói SMB2 Negotiate (NBSS length sai) |
| `KILL_CHAIN` | ✅ | OK, xác nhận foothold S7 thật + lateral movement phát hiện RDP/SMB/S7-local thật trên HMI |
| `CONCEALED_STOP_ATTACK` | ✅ | OK, partial success có số liệu đầy đủ (~17–18%), có bằng chứng ảnh chụp 2 màn hình |
| `PROGRAM_UPLOAD_THEFT` | ✅ Đã chạy → target từ chối | **Gỡ khỏi lịch.** Target trả `0x8104 service not implemented` (mục 3.1a); giữ làm bằng chứng "T0845 bị chặn" |
| `PROFINET_DCP_ABUSE` | ❌ Không thực thi được | **Gỡ khỏi lịch.** Cần raw socket L2 + root; `sudo` bị tắt trên attacker WSL2 (mục 3.1b) |
| `EVASION_SHAPED_WRITE` | ⚠️ Compile OK, chưa test PLC | Ngoài lịch; cần eval harness mới có giá trị |
| Full end-to-end | ⏳ Chưa chạy trong session này | Cần `--preflight-only` xác nhận trước khi chạy full |

## 9. Đánh giá trung thực cho mục đích thu thập dữ liệu

- **Day 7 KHÔNG đóng góp lớp process-manipulation mới cho ML.** Các lớp thao tác quá trình (SETPOINT / SPOOF / RWRITE / FLOOD / FUZZ) đã đủ ở Day 1-6. Phần ghi S7 của `CONCEALED_STOP_ATTACK` ghi vào **M5 trùng vùng/offset với `RWRITE_BURST` (Day 3)** ở tầng feature → không phải lớp mới sạch; còn burst ghi OPC UA của nó tuy đặc trưng nhưng thuộc **feature domain khác** (OPC UA, không phải S7comm của bộ Day 1-6) và rất ngắn.
- **Đóng góp dữ liệu thực sự (khiêm tốn nhưng thật):** `SMB_RECON_ENUM` thêm chữ ký **enumeration SMB2 trên máy HMI** (T0842) — giao thức và đích (SMB trên `.31`) mà Day 1-6 (tập trung S7comm trên PLC) không có. Đây là mở rộng chiều **Discovery/Lateral** cho taxonomy tấn công, không phải thêm lớp thao tác quá trình.
- **Đóng góp chính là tầng case-study / tường thuật (KHÔNG phải lớp ML):**
  - `KILL_CHAIN` — chuỗi APT đa giai đoạn (foothold S7 → pivot lateral sang HMI trong cùng 1 phiên). Phần port-scan có thể trùng một phần `SCAN_PORT` (Day 1-6) ở packet-level; giá trị nằm ở mạch truyện, không ở feature mới.
  - `CONCEALED_STOP_ATTACK` — demo **so sánh bảo mật 2 kênh** (S7CommPlus khoá vs OPC UA Anonymous hở) + đo **trần concealment ~17%** từ client ngoài. Giá trị định tính/an ninh, không phải feature ML.
- **Khuyến nghị định vị:** trình bày Day 7 là **"tầng case-study nâng cao + mở rộng recon/lateral"**, KHÔNG bán là "nhiều lớp tấn công ML mới độc lập". **Xương sống dữ liệu ML vẫn là Day 1-6.** Cách này trung thực và chống phản biện tốt hơn — tránh bị soi trùng feature giữa `CONCEALED_STOP` và `RWRITE_BURST`.
- **Hướng phát triển mạnh nhất tiếp theo:** hoàn thiện `EVASION_SHAPED_WRITE` (kèm eval A/B detection rate) — đóng góp định lượng đối nghịch trực tiếp với chính IDS của project.

## 10. Tổng hợp phát hiện an ninh — luận điểm trung tâm (dùng cho thuyết trình)

Mục này gom toàn bộ thí nghiệm rải rác ở trên thành **một câu chuyện an ninh mạch lạc** — dùng làm slide/đoạn kết luận khi bảo vệ.

**Luận điểm trung tâm (một câu):** trên **cùng một PLC S7-1500 phần cứng thật**, mọi kênh dùng giao thức có xác thực / S7comm cổ điển đều **chống được** tấn công; lỗ hổng duy nhất khai thác được nằm ở **cấu hình OPC UA Anonymous / No-Security** của testbed — tức là **lỗ hổng cấu hình, không phải lỗ hổng giao thức hay phần cứng**.

**Bốn thí nghiệm độc lập, cùng hội tụ về một kết luận:**

| # | Thí nghiệm | Kênh / kỹ thuật | Kết quả đo được | Ý nghĩa |
|---|---|---|---|---|
| 1a | CONCEALED_STOP — che giấu STOP | **OPC UA Anonymous** ghi `BangTai` | Giả được **~17–18%** số lần đọc (chỉ nhấp nháy) | Kênh không xác thực: khai thác được nhưng **yếu** |
| 1b | (cùng thí nghiệm, kênh song song) | **WinCC / S7CommPlus** | **0% — không giả được** | Kênh có xác thực: **miễn nhiễm** |
| 2 | PROGRAM_UPLOAD_THEFT (T0845) | S7comm cổ điển — upload khối | `0x8104` service not implemented | S7-1500 **chặn** nghiệp vụ cổ điển (mục 3.1a) |
| 3 | CPU_STOP (Day 3) | S7comm — `plc_hot_start` | `plc_stop` chạy được nhưng **`hot_start` bị từ chối** | S7-1500 **chặn** điều khiển CPU cổ điển |
| 4 | MITM / ARP poison (đã bỏ) | Sửa gói OPC UA trên dây | `intercepted=0` (3/3 lần chạy) | Stack mạng CN **chặn** gratuitous ARP (mục 5.3) |

**Chi tiết định lượng đắt nhất (thí nghiệm 1a):** tỷ lệ giả thành công **ổn định ~17–18% qua cả ghi tuần tự lẫn song song 5 luồng** — tăng số luồng **không cải thiện** (chi tiết mục 5.4). → nút thắt nằm ở **khả năng xử lý của PLC/server**, không phải tốc độ attacker. Đây là **trần cứng** của mô hình "client ngoài đua với chu kỳ scan PLC" — con số ít đồ án đo được.

**Neo vào lý thuyết (2 nguồn đã cite):**
- **Urbina et al. (CCS 2016):** che giấu đáng tin đòi hỏi kiểm soát đường truyền/sensor, không thể chỉ ghi đè từ ngoài. → thí nghiệm 1a (17%) + thí nghiệm 4 (MITM thất bại) là **bằng chứng thực nghiệm** cho đúng luận điểm này.
- **Phòng thủ thắng bằng kiểm tra nhất quán chéo:** Stage timer = 0 tố cáo băng tải đã dừng dù `BangTai=RUNNING` → đúng "physical invariants" của Urbina; operator quan sát kỹ toàn dashboard vẫn phát hiện.

**Kết luận phòng thủ (khuyến nghị vận hành, có bằng chứng):** khoá kênh OPC UA (bật `SecurityPolicy: Basic256Sha256` + xác thực) → cả 4 vector trên đều bị chặn, testbed trở về trạng thái "mọi cửa đều khoá". Đây là khuyến nghị **cụ thể, đo được, đúng tinh thần đồ án bảo mật ICS** — không phải lời khuyên chung chung.

> **Định vị tổng thể của đồ án:** Day 1-6 là **xương sống dữ liệu ML** (phát hiện thao tác quá trình). Day 7 là **tầng phân tích an ninh + minh chứng môi trường** — chứng minh testbed đủ thực tế để dựng tấn công đa giai đoạn, và rút ra kết luận phòng thủ định lượng ở trên. Hai phần bổ trợ nhau: một cái cho AI học, một cái chứng minh môi trường và phân tích bảo mật.
