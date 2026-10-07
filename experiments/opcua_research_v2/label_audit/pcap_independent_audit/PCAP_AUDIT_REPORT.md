# Báo cáo kiểm toán độc lập 29 cửa sổ OPC UA từ PCAP gốc

## Phạm vi và nguồn dữ liệu

Kiểm toán này đọc lại **một nguồn duy nhất** là PCAP gộp Day 8. Các PCAP segment không được nạp cùng PCAP gộp, vì vậy một bản ghi không thể bị đếm hai lần do xuất hiện ở cả hai loại nguồn. Tổng cộng kiểm tra 3427 cửa sổ 5 giây theo khoảng nửa kín `[window_start, window_end)`, trong đó có 29 cửa sổ đã đổi từ nhãn tấn công sang `benign`.

- `data_opc/day8_out/harvest_ot1786331948_merged.pcap` — 311442552 bytes — SHA-256 `12abee34d688678cbbc4479b067462dc7c25d73b739b72e1cea7c6b44ac3c42e`
- `test_results/day8/timeline_harvest.csv` — 27825 bytes — SHA-256 `f8f6e83cc1594a93e26ab7dec2211d92e0c5d3b8e7cda46de7b67aa90c4bda84`
- `data_opc/day8_out/opcua_harvest_ext.csv` — 1063732 bytes — SHA-256 `10723f3e4d01f10bd758a5bb22d927a8a1d04e7a7af3fe87d5be69c7a07343d7`
- `data_opc/day8_out/opcua_harvest_ext_aa.csv` — 1063070 bytes — SHA-256 `45cccda0b5bee1f47f0337bac6043349283d427146b71c04d0abf13e3d5f196b`
- `experiments/opcua_research_v2/label_audit/label_manifest.csv` — 736518 bytes — SHA-256 `bc5fcabd7c76486e3a46608befc9a1322e884f61b211c593c36e74b747230d79`
- `experiments/opcua_research_v2/label_audit/changed_windows.csv` — 8455 bytes — SHA-256 `04839a27a1f1499316deff30853eb373945e7af9a3b3cde72511bf6cb586a2ea`
- `extract_opcua_features_ext.py` — 18748 bytes — SHA-256 `2f0d30cad673b91c014effbb5b53fdca274d4383bf692fb70b7119c0b3879f39`
- `tests/day8/collect_opcua.py` — 8471 bytes — SHA-256 `72319899a15b6637a5905509ea9beeffcb6a2c68a295885ec7cd17d84b8b4984`
- `testbed.conf` — 2848 bytes — SHA-256 `c260ce7133ada08a2d1cbba1fb2b75bd56cb207ffde50c75d804a2339d6b72f3`
- `tests/day8/scenarios.yaml` — 10521 bytes — SHA-256 `9fa5ad490bb79a20c07f0300e361e57b91afb476e5d4f1c8c112ae894a09837d`

PCAP có 1660063 gói, từ epoch `1786331949.039861` đến `1786349077.786115`. `capinfos` báo `Strict time order=False`; việc gán cửa sổ dựa trực tiếp trên `frame.time_epoch`, không dựa vào thứ tự dòng.

## Phương pháp

- Máy kiểm thử: `192.168.210.32`; HMI/Web-SCADA: `192.168.210.31`; PLC: `192.168.210.211`.
- Epoch trong timeline được đổi sang mili giây bằng phép cắt phần lẻ giống pipeline gốc. Chuỗi `start_human/end_human` UTC+7 chỉ dùng để trình bày, không tham gia phép ghép.
- “Gói từ attacker” là gói IPv4 có `ip.src` bằng IP máy kiểm thử. “Phản hồi PLC” là gói có `ip.src=PLC` và `ip.dst=attacker`; hai chiều không bị cộng lẫn.
- Quy tắc activity-aware được tái áp dụng đúng phạm vi extractor gốc: `tcp.port==4840 && ip.addr==PLC`, sau đó coi có hoạt động attacker nếu **nguồn hoặc đích** là IP attacker.
- Dấu hiệu OPC UA giải mã dùng các trường transport type, service NodeId, status hoặc transport error của TShark. Đồng thời báo cáo riêng TCP/4840 để không coi lỗi/giới hạn dissector là vắng lưu lượng.
- Lệnh trích xuất thực tế: `tshark -r /home/sus/do-an/data_opc/day8_out/harvest_ot1786331948_merged.pcap -o tcp.desegment_tcp_streams:TRUE -Y ip.addr == 192.168.210.32 -T fields -e frame.time_epoch -e frame.number -e frame.len -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.len -e tcp.stream -e tcp.seq -e tcp.ack -e opcua.transport.type -e opcua.servicenodeid.numeric -e opcua.StatusCode -e opcua.ServiceResult -e opcua.transport.error -E separator=	 -E quote=n -E occurrence=a`.

## Kết quả 29 cửa sổ đổi nhãn

| Kết quả | Số cửa sổ |
|---|---:|
| Phù hợp quy tắc activity-aware | 29 |
| Không nhất quán | 0 |
| Chưa đủ bằng chứng | 0 |

Có 2 cửa sổ trong nhóm 29 vẫn chứa gói IPv4 **phát từ** máy `.32`; 1 cửa sổ có TCP payload, nhưng 0 cửa sổ có lưu lượng thuộc phạm vi activity-aware gốc và 0 cửa sổ có OPC UA phát từ attacker được TShark giải mã. Do đó, các gói ngoài phạm vi PLC/TCP-4840 không phải bằng chứng để tự động đổi nhãn ngược lại:

| Bắt đầu UTC | Episode gốc | Gói từ attacker | TCP payload | IP đích | Cổng TCP đích | Gói thuộc phạm vi rule |
|---|---|---:|---:|---|---|---:|
| 2026-08-10T04:54:00+00:00 | `OPCUA_SESSION_BURST#c79` | 1 | 0 (0 B) | `{"192.168.210.31":1}` | `{"7680":1}` | 0 |
| 2026-08-10T06:05:45+00:00 | `OPCUA_SESSION_BURST#c139` | 7 | 3 (120 B) | `{"192.168.210.31":7}` | `{"7680":7}` | 0 |

Có 29/29 cửa sổ có ít nhất một cửa sổ kề cùng episode để đối chiếu; 25 cửa sổ đổi nhãn có cửa sổ kề cùng episode chứa lưu lượng attacker trong phạm vi pipeline. Chi tiết từng cửa sổ và hai láng giềng nằm trong `changed_29_pcap_audit.csv`.

## Đối chiếu toàn bộ 3.427 cửa sổ

| Chỉ báo | Số cửa sổ |
|---|---:|
| Được PCAP bao phủ đầy đủ | 3425 |
| Nằm ở biên PCAP, chỉ được bao phủ một phần | 2 |
| Ngoài PCAP | 0 |
| Timeline tái tính không khớp raw manifest | 0 |
| Quy tắc activity-aware tái tính không khớp manifest | 0 |
| Có gói IPv4 phát từ attacker | 1253 |
| Có TCP payload phát từ attacker | 1031 |
| Có OPC UA do TShark giải mã phát từ attacker | 655 |
| Cửa sổ benign vẫn có lưu lượng attacker trong phạm vi pipeline | 118 |

Toàn bộ 118 cửa sổ ở dòng cuối có `timeline_overlap_ms=0`: traffic `.32` xuất hiện ngoài khoảng attack do timeline công bố (thí dụ warm-up/cooldown), nên điều này không tạo bất nhất với quy tắc vốn yêu cầu đồng thời có timeline overlap và traffic attacker.

`window_packet_evidence.csv` lưu các trường đếm và dấu hiệu dịch vụ cho toàn bộ cửa sổ. Các bất nhất/biên dữ liệu được tách vào `audit_discrepancies.csv`:

- `incomplete_capture_coverage`: 2

## Kết luận khoa học

1. **Tính nhất quán manifest** chỉ cho biết nhãn lưu trữ có tái tạo được từ timeline và quy tắc đã công bố hay không.
2. **Bằng chứng gói tin** ở đây là một phép trích xuất lại độc lập về mã nguồn từ **cùng PCAP đã thu**, không phải một nguồn thu thập độc lập hoàn toàn.
3. **Sự hiện diện của lưu lượng attacker** là quan sát packet-level gắn với IP đã xác minh. Phản hồi của PLC được tách khỏi gói do attacker phát.
4. **Thực hiện thành công hành vi tấn công** không thể suy ra chỉ từ sự hiện diện gói tin, TCP payload hay việc TShark giải mã được OPC UA. Cần log phía ứng dụng/PLC hoặc tiêu chí tác động riêng cho kết luận đó.

## Giới hạn

- Vắng gói trong PCAP chỉ có nghĩa là không có gói phù hợp được capture trong phạm vi và thời gian đang xét; không chứng minh không có hành động ngoài điểm quan sát.
- Các cửa sổ biên PCAP được đánh dấu thiếu bao phủ đầy đủ, không tự động gán giá trị “đã xác minh vắng mặt”.
- Bộ đếm OPC UA phụ thuộc phiên bản TShark TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3). và khả năng reassembly/dissector. Vì vậy artifact giữ đồng thời số gói IP, TCP payload, TCP/4840 và OPC UA đã giải mã.
- `Strict time order=False` phản ánh PCAP gộp không hoàn toàn theo thứ tự timestamp; phép gán theo timestamp từng frame vẫn bảo toàn ranh giới cửa sổ.

## Tái lập

Từ thư mục gốc repository:

```bash
python3 tools/opcua_pcap_independent_audit.py
```

Câu lệnh đầy đủ được lưu trong `reproduce_command.txt`; cấu hình và hash đầu vào nằm trong `packet_audit_summary.json`.
