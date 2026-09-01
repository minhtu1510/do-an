# Báo cáo Day 7 — Advanced Attack Scenarios

## 1. Tổng quan

Day 7 mở rộng bộ kịch bản Day 1–6 bằng các kỹ thuật nâng cao, được **tuyển chọn có chủ đích để tránh trùng nhãn (label collision) với Day 1–6 và với nhau**. Sau rà soát, chỉ giữ lại các kịch bản thực sự tạo ra dữ liệu **phân biệt được** hoặc mang giá trị tường thuật riêng.

Mạch truyện: **Recon → Foothold + Lateral Movement → Impact có che giấu (concealment)**.

- Script điều phối: [`run_day_bangtruyen_ext.sh`](run_day_bangtruyen_ext.sh)
- Modules: [`attacks_ext/`](attacks_ext/)

## 2. Ba (03) kịch bản trong lịch thu thập

| # | Scenario label | Module | MITRE (ICS) | Kỹ thuật cốt lõi | Lặp |
|---|---|---|---|---|---|
| 1 | `SMB_RECON_ENUM` | `attacks_ext/smb_enum.py` | T0842 Network Share Discovery | SMB2 Negotiate + share/named-pipe probe trên máy HMI (kỹ thuật SMB2-specific, không chỉ port scan thô) | ×3 |
| 2 | `PROGRAM_UPLOAD_THEFT` **(MỚI)** | `attacks_ext/program_upload.py` | **T0845 Program Upload** | `list_blocks` + `full_upload` hút toàn bộ khối logic OB/FB/FC/DB qua S7 — đánh cắp mã điều khiển (IP theft). Khác hẳn read/write_area (chỉ ô nhớ) | ×2 |
| 3 | `PROFINET_DCP_ABUSE` **(MỚI)** | `attacks_ext/profinet_dcp.py` | **T0814 DoS / T0816 / T0842** | Tấn công **layer-2 Profinet DCP**: Identify-All flood (recon + tải bất đối xứng); tùy chọn Set-NameOfStation (chiếm danh tính). Bề mặt giao thức mới, `extract_dcp_features.py` đã hỗ trợ | ×2 |
| 4 | `KILL_CHAIN` | `attacks_ext/kill_chain.py` | Initial Access (S7) → Lateral Movement (T0846) | Chiếm foothold qua S7, dùng chính phiên đó pivot port-scan sang HMI/Engineering (RDP/SMB/S7-local) trong cùng 1 kịch bản liên tục | ×2 |
| 5 | `CONCEALED_STOP_ATTACK` | `attacks_ext/concealed_stop_attack.py` | T0831 + T0832 phối hợp (Urbina CCS16-style) | STOP thật trên PLC qua S7 + đồng thời ghi giả `BangTai=RUNNING` qua OPC UA trong đúng cửa sổ STOP đó | ×2 |

> **CPU_STOP KHÔNG thêm vào Day 7** — đã tồn tại ở Day 3 (`run_day_bangtruyen.sh`, label `CPU_STOP`) và **bị tắt mặc định** vì lỗi đã biết: `plc_stop()` chạy được nhưng S7-1500 **TỪ CHỐI `plc_hot_start()`** → CPU kẹt STOP, phải khởi động lại thủ công trong TIA Portal. Thêm lại sẽ trùng nhãn + dính đúng lỗi cũ.

> Trong 3 kịch bản, `CONCEALED_STOP_ATTACK` là đóng góp **mới và phân biệt rõ nhất** (signature burst ghi OPC UA Boolean — không tồn tại ở đâu trong Day 1–6). `KILL_CHAIN` mang giá trị tường thuật APT đa giai đoạn. `SMB_RECON_ENUM` là recon SMB2-specific.

## 3. Các kịch bản đã loại khỏi lịch (giữ code trong repo)

| Kịch bản | Lý do loại | Trạng thái |
|---|---|---|
| `S7_REPLAY` | Bản chất tàng hình/né IDS, không gây gián đoạn thật như kỳ vọng; muốn treo WinCC cần flood (mở nhiều kết nối song song, giữ lại) — cơ chế khác hẳn | File giữ, ngoài lịch |
| `ENG_STATION_PORT_SCAN` | Chức năng port-scan máy Engineering **đã nằm sẵn trong `KILL_CHAIN`** lateral movement (import `PORTS` + `tcp_probe` từ chính module này) → standalone là dư thừa | File giữ, ngoài lịch |
| `STEALTHY_WRITE` | Trùng tên + trùng kỹ thuật + trùng vùng ghi với `STEALTHY_WRITE` Day 3/4 (label collision); lại ghi `MD100` mà tag logger không ghi lại (process-view vô hình) | File giữ, ngoài lịch |
| `LOGIC_AWARE` | Ghi S7 vào **đúng offset** M5/CD54/CD58 giống hệt `RWRITE_BURST` (Day3) + `SETPOINT_ATTACK`/`SENSOR_SPOOF` (Day4) ở packet-level; chỉ khác điều kiện/timing → nguy cơ trùng nhãn cao, chất lượng dữ liệu không tốt | File giữ, ngoài lịch |

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

| Cấu hình | Kết quả | Tỷ lệ "dính" |
|---|---|---|
| Ghi tuần tự (1 luồng) | `readback_still_true=149 / 847` | ~17.6% |
| Ghi song song (5 luồng), lần 1 | `76 / 432` | ~17.6% |
| Ghi song song (5 luồng), lần 2 | `41 / 227` | ~18.1% |

**Phát hiện quan trọng:** tăng 5 lần số luồng ghi song song (432 → 3018 attempts) nhưng **tỷ lệ thành công không đổi** (~17–18%). → nút thắt cổ chai nằm ở **khả năng xử lý bên trong PLC/OPC UA server**, không phải tốc độ gửi phía attacker. Đây là **trần cứng** của kiểu tấn công "client bên ngoài đua thời gian với PLC".

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

# MỚI — Program Upload Theft (T0845)
python -m attacks_ext.program_upload --target 192.168.210.211 --rack 0 --slot 1 --duration 60 --session-id smoke --host-id attacker_host --label-file labels/smoke_test.csv

# MỚI — Profinet DCP Abuse (T0814/T0816). CẦN root + đúng --iface (cùng segment Profinet).
# Mặc định recon/identify-flood (an toàn). Thêm --enable-set-name --victim-mac <MAC> để bật mức phá hoại.
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
| `EVASION_SHAPED_WRITE` | ⚠️ Compile OK, chưa test PLC | Ngoài lịch; cần eval harness mới có giá trị |
| Full end-to-end | ⏳ Chưa chạy trong session này | Cần `--preflight-only` xác nhận trước khi chạy full |

## 9. Đánh giá trung thực cho mục đích thu thập dữ liệu

- **Lớp mới thực sự phân biệt được cho ML:** 1 (`CONCEALED_STOP_ATTACK`).
- **Giá trị tường thuật (case-study, không phải lớp ML mới):** `KILL_CHAIN` (APT đa giai đoạn), `SMB_RECON_ENUM` (recon).
- **Khuyến nghị định vị:** Day 7 nên được trình bày là **"1 đóng góp concealment attack mới + tầng case-study nâng cao"**, KHÔNG bán là "nhiều lớp tấn công mới độc lập" — cách này trung thực và chống phản biện tốt hơn.
- **Hướng phát triển mạnh nhất tiếp theo:** hoàn thiện `EVASION_SHAPED_WRITE` (kèm eval A/B detection rate) — đây sẽ là đóng góp định lượng đối nghịch trực tiếp với chính IDS của project.
