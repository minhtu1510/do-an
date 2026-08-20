# BÁO CÁO GIẢI TRÌNH VÀ CẬP NHẬT PHƯƠNG PHÁP TRÍCH XUẤT ĐẶC TRƯNG CHO IDS CÔNG NGHIỆP

**Người thực hiện:** Nhóm phát triển Đồ án IDS
**Nội dung:** Báo cáo giải trình và đề xuất phương án khắc phục dựa trên góp ý của Giảng viên hướng dẫn về hạn chế của công cụ CICFlowMeter trong mạng Truyền thông Công nghiệp.

---

## 1. TIẾP THU NHẬN XÉT CỦA GIẢNG VIÊN

Nhóm xin tiếp thu hoàn toàn nhận xét mang tính quyết định của Giảng viên: *"Dùng CICFlowMeter về cơ bản không lấy được thông tin gì cả vì chỉ nhìn header TCP/UDP/IP (L3/L4) mà bỏ qua hoàn toàn Payload (L7)."*

Trong mạng CNTT (IT) thông thường, phân tích lưu lượng dựa trên header (Flow-based) là đủ để phát hiện DDoS hay Port Scan. Tuy nhiên, trong mạng OT/ICS, các tấn công nguy hiểm nhất lại lợi dụng chính các luồng TCP hợp lệ để gửi đi các **lệnh điều khiển sai lệch**. Việc CICFlowMeter bỏ qua các thông số cốt lõi như Function Code (Modbus), PDU Type hay DB Number (S7comm) khiến mô hình AI hoàn toàn "mù" trước các biến động của quy trình vật lý.

Từ góp ý này, nhóm đã tái cấu trúc toàn bộ quy trình sinh dữ liệu (Testbed) và trích xuất đặc trưng.

---

## 2. PHƯƠNG ÁN KHẮC PHỤC: KIỂM TRA GÓI TIN SÂU (DEEP PACKET INSPECTION - DPI)

Để mô hình AI thực sự "hiểu" được truyền thông công nghiệp, nhóm đã loại bỏ sự phụ thuộc độc lập vào CICFlowMeter. Thay vào đó, nhóm phát triển tích hợp một module **Deep Packet Inspection (DPI)** bằng thư viện Scapy (Python) trực tiếp vào mã nguồn `collect_dataset.py`.

Phương pháp mới sử dụng cách tiếp cận **Hybrid (Lai)**: Giữ lại một số đặc trưng lưu lượng cần thiết ở tầng Network, đồng thời **bóc tách sâu vào tầng Application (Layer 7)** để lấy các đặc trưng ngữ nghĩa của gói tin điều khiển.

### Đặc trưng mới được trích xuất (Tập trung vào giao thức S7comm hiện có trên Testbed):
Đáp ứng trực tiếp yêu cầu của cô giáo, hệ thống mới đã bóc tách được các trường thông tin:
1. **PDU Type (ROSCTR) & Function:** Nhận diện chính xác gói tin đang làm gì (Ví dụ: `0x04` Read Var, `0x05` Write Var, `0x29` Setup Comm/STOP CPU).
2. **Vùng nhớ truy cập (Memory Area):** Phân biệt được lệnh đang tác động vào vùng nhớ `0x84` (Data Block - DB) hay `0x83` (Merker - M).
3. **Số lượng biến bị truy xuất (Item Count):** Đếm số lượng thẻ (tags) được yêu cầu đọc/ghi trong một gói tin.
4. **Kích thước Dữ liệu Ghi (Write Payload Size):** Bóc tách chính xác dung lượng (bytes) của giá trị điều khiển đang bị ghi đè vào PLC.

---

## 3. PHÂN TÍCH ĐẶC TRƯNG TẤN CÔNG Ở TẦNG APPLICATION VÀ NETWORK

Khi áp dụng phương pháp trích xuất Payload mới vào hệ thống vật lý (Ví dụ: Hệ thống Băng chuyền), các cuộc tấn công bộc lộ rõ ràng đặc trưng ở cả tầng Mạng và tầng Ứng dụng như sau:

### 3.1. Tấn công Ghi đè tham số điều khiển (False Data Injection / RWRITE)
Mục tiêu của hacker là ghi đè trạng thái cảm biến (ví dụ: đánh lừa PLC rằng không có vật cản để băng chuyền chạy đâm vào nhau).
* **Đặc trưng tầng Network (L3/L4):** Rất mờ nhạt. Kích thước luồng mạng tương đương với một lệnh Write đổi tốc độ hợp lệ của Kỹ sư.
* **Đặc trưng tầng Application (L7):** 
  Do hacker phải nã liên tục dữ liệu để ép PLC nhận giá trị sai, module DPI sẽ ghi nhận thông số **`s7_write_payload_bytes`** (Khối lượng byte ghi đè) và **`s7_m_area_count`** (Số lần truy cập vùng nhớ nội bộ) tăng đột biến so với mức cơ sở (baseline) của HMI bình thường. Đây là dấu hiệu quyết định giúp AI phát hiện tấn công.

### 3.2. Tấn công Dò quét cấu trúc (Tag Enumeration / Reconnaissance)
Mục tiêu của hacker là quét toàn bộ bộ nhớ PLC để tìm ra vị trí biến điều khiển Động cơ.
* **Đặc trưng tầng Network (L3/L4):** Chỉ là các luồng Request-Response liên tục, dễ bị nhầm lẫn với chu kỳ lấy mẫu (Polling) tự động của hệ thống SCADA.
* **Đặc trưng tầng Application (L7):**
  Lệnh đọc của HMI thông thường được cấu hình cố định, thông số **`Item Count`** (số lượng biến cần đọc) chỉ dao động từ 1-5 biến. Trong khi đó, công cụ quét của hacker sẽ bộc lộ điểm yếu khi đóng gói một Payload yêu cầu quét hàng loạt, làm cho đặc trưng **`s7_max_item_count`** tăng vọt bất thường. Đặc trưng này bóc trần hoàn toàn ý đồ do thám.

### 3.3. Tấn công Can thiệp trạng thái (Command Injection / CPU STOP)
Mục tiêu của hacker là làm ngừng trệ sản xuất bằng lệnh dừng CPU của PLC.
* **Đặc trưng tầng Network (L3/L4):** Gói tin tấn công chỉ có kích thước khoảng 65 bytes, hoàn toàn biến mất trong thống kê dung lượng mạng và không thể bị phát hiện bởi CICFlowMeter.
* **Đặc trưng tầng Application (L7):**
  Module DPI trực tiếp soi vào Function Code. Lệnh đổi trạng thái hệ thống mang mã đặc thù (VD: `0x29` trong S7comm). Khi mã này xuất hiện, biến **`s7_stop_count`** sẽ mang giá trị lớn hơn 0. IDS không cần suy đoán theo xác suất mà có thể khẳng định chắc chắn 100% sự hiện diện của một hành vi can thiệp trái phép vào vòng đời thiết bị.

---

## 4. KẾT LUẬN

Nhờ sự chỉ đạo sát sao của Giảng viên, nhóm đã khắc phục được sai lầm căn bản khi áp dụng tư duy mạng IT vào mạng OT. Việc chuyển đổi sang phương pháp phân tích sâu Payload (DPI) đảm bảo rằng bộ dữ liệu (Dataset) được sinh ra mang đầy đủ **"chữ ký"** của các gói tin điều khiển công nghiệp thực thụ. ## 5. SƠ ĐỒ KIẾN TRÚC TESTBED ĐỀ XUẤT

Dưới đây là sơ đồ kiến trúc Testbed Băng chuyền được sử dụng để thu thập dữ liệu và trích xuất đặc trưng DPI. Sơ đồ này mô phỏng chân thực quy trình giao tiếp mạng công nghiệp:

![Sơ đồ Kiến trúc Testbed IIoT](/home/mtu/.gemini/antigravity/brain/ac218e91-2ee8-415e-9820-9e79a364f9a2/iiot_testbed_conveyor_1777449130136.png)
