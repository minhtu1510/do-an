# Chương 4. PHÂN TÍCH GIAO THỨC VÀ TRIỂN KHAI MODULE MÔ PHỎNG TẤN CÔNG

Chương 3 đã trình bày testbed và lịch trình chín kịch bản tấn công dùng để thu thập dữ liệu. Chương này giải thích cơ sở kỹ thuật đứng sau các kịch bản đó: lỗ hổng nào trong giao thức Profinet và S7comm bị khai thác, và mỗi module trong công cụ tấn công khai thác lỗ hổng đó bằng cơ chế cụ thể ra sao. Nội dung được tổ chức thành hai phần nối tiếp nhau — trước hết phân tích các điểm yếu cố hữu của giao thức mục tiêu, sau đó mô tả chi tiết từng module đã triển khai để khai thác các điểm yếu ấy trong quá trình thu thập dữ liệu tại Chương 3.

Đồ án tập trung vào giao thức Profinet và các bộ điều khiển PLC của Siemens do vị thế thống trị của chúng trong ngành tự động hóa, biến chúng thành nền tảng thực nghiệm phù hợp và có tính đại diện cao. Siemens là công ty có lịch sử lâu đời trong tự động hóa công nghiệp, hiện giữ vị trí hàng đầu trong thị trường PLC toàn cầu, đặc biệt tại châu Âu và châu Á. Profinet — giao thức Ethernet công nghiệp do Siemens phát triển — được dùng mặc định trong các CPU tiêu chuẩn, bộ điều khiển phân tán, biến tần và HMI dòng mới của hãng, khiến nó trở thành một trong những giao thức phổ biến nhất trong các dây chuyền sản xuất thực tế.

**Hình 4.1. Thị phần các nhà cung cấp PLC phổ biến**

Về mặt kỹ thuật, các module được triển khai bằng Python, dùng Scapy để dựng và phân tích gói tin ở tầng thấp, và Snap7 để giao tiếp với PLC qua S7comm. Mỗi module được viết độc lập, tương ứng với từng kịch bản trong Bảng 3.4 (Chương 3), giúp việc bật/tắt từng loại tấn công theo đúng lịch trình thu thập dễ dàng và nhất quán.

## 4.1. Công cụ trinh sát ban đầu và module tạo nhãn SCAN

Trước khi đi vào chín module tương ứng chín kịch bản của Chương 3, cần phân biệt rõ hai công cụ dễ bị nhầm lẫn với nhau vì cùng phục vụ mục đích trinh sát nhưng hoạt động ở hai tầng hoàn toàn khác nhau: công cụ khảo sát thiết bị Profinet dùng khi thiết lập testbed, và module `SCAN_PORT` thực sự tạo ra nhãn SCAN trong bộ dữ liệu Ngày 2.

### 4.1.1. Công cụ khảo sát thiết bị Profinet (dựa trên DCP)

Trước khi cấu hình testbed, một công cụ riêng được dùng để khảo sát các thiết bị Profinet có mặt trong mạng, dựa trên Discovery and Configuration Protocol (DCP) — giao thức hoạt động ở Tầng 2 (Data Link Layer), cho phép các thiết bị Profinet tự nhận diện lẫn nhau mà không cần địa chỉ IP.

Công cụ xây dựng một gói tin Ethernet có EtherType `0x8892` (dành riêng cho Profinet), gửi đến địa chỉ MAC đa hướng `01:0e:cf:00:00:00` — địa chỉ mà mọi thiết bị Profinet đều lắng nghe — mang theo yêu cầu DCP "Identify Request". Các thiết bị nhận được sẽ phản hồi bằng một gói DCP Identify Response chứa tên trạm (NameOfStation), địa chỉ IP và MAC, Vendor ID (`002a` cho Siemens), Device ID và vai trò thiết bị. Dựa vào Device ID, công cụ tra cứu một bảng dữ liệu xây dựng sẵn để xác định model cụ thể — ví dụ mã `010e` tương ứng dòng S7-1500 — từ đó xác định luôn cặp rack/slot mặc định cần thiết cho các kết nối S7comm ở bước sau.

**Hình 4.2. Truy xuất DeviceID trong file GSD**

Điểm yếu bị khai thác ở đây là DCP hoàn toàn không có cơ chế xác thực: bất kỳ ai có quyền truy cập vào mạng Lớp 2 đều có thể thực hiện quy trình khám phá này, và vì giao tiếp không đi qua tầng IP, nó không để lại dấu vết trên các hệ thống giám sát an ninh dựa trên địa chỉ IP như tường lửa hay IDS thông thường.

Công cụ này chỉ được dùng một lần trong giai đoạn khảo sát và thiết lập testbed, để xác nhận PLC mục tiêu và lấy các thông số cấu hình ban đầu (IP, rack, slot). Nó không phải một kịch bản lặp lại theo lịch trình Ngày 1-6, và không tạo ra nhãn nào trong Bảng 3.4/3.9 của Chương 3.

### 4.1.2. Module SCAN_PORT — cơ chế thật của nhãn SCAN

Khác hẳn công cụ DCP ở trên, `SCAN_PORT` — module thực sự chạy trong Ngày 2 để sinh dữ liệu có nhãn SCAN — có cơ chế đơn giản hơn nhiều: một vòng lặp kết nối TCP thuần tới cổng 102 của PLC, không dùng DCP, không thiết lập phiên COTP, không gửi bất kỳ lệnh S7comm nào. Mỗi lần lặp, module mở kết nối, xác nhận PLC phản hồi, rồi đóng kết nối và chờ một khoảng ngẫu nhiên 0,4-1,5 giây trước khi lặp lại. Mục đích duy nhất là xác nhận cổng 102 đang mở — bước tối thiểu nhất trong chuỗi trinh sát, tạo ra lưu lượng TCP SYN/ACK lặp lại mà không để lộ bất kỳ ý định cụ thể nào qua nội dung gói tin, vì đơn giản là không có nội dung ở tầng ứng dụng để phân tích. Trình tự trao đổi gói tin của module này đã được minh họa ở Hình 3.4 (Chương 3).

## 4.2. Nguyên lý hoạt động của các module

Các module còn lại được sắp xếp theo một trình tự logic, phản ánh các giai đoạn của một chuỗi tấn công thực tế: sau khi đã xác nhận mục tiêu qua SCAN_PORT, kẻ tấn công tiến hành liệt kê cấu trúc vùng nhớ, sau đó thực hiện các thao tác can thiệp có kiểm soát, và cuối cùng là các kịch bản tấn công trực diện vào tính toàn vẹn hoặc tính sẵn sàng của hệ thống.

### 4.2.1. Module Liệt kê vùng nhớ (ENUM_TAGS)

Sau khi xác định PLC còn hoạt động, bước tiếp theo là liệt kê nội dung vùng nhớ để hiểu cấu trúc dữ liệu và suy luận logic điều khiển đang chạy trên thiết bị — giai đoạn trinh sát chủ động, khai thác trực tiếp điểm yếu thiếu xác thực của S7comm.

Module dùng Snap7 để thiết lập kết nối và đọc liên tục ba vùng nhớ: MK (Marker), PA (Process Output, tương ứng vùng Q) và PE (Process Input, tương ứng vùng I), đồng thời truy vấn thông tin CPU (tên module, trạng thái RUN/STOP) ngay khi kết nối thành công. Bằng cách quan sát sự thay đổi của các byte trong vùng nhớ theo thời gian, có thể suy luận ra địa chỉ của các biến quan trọng mà không cần truy cập vào mã nguồn chương trình PLC.

Module vận hành ở hai chế độ tốc độ, phản ánh hai giai đoạn trinh sát khác nhau trong thực tế. Chế độ chậm (khoảng 2 giây/lần đọc) nằm dưới ngưỡng phát hiện của phần lớn IDS dựa trên tần suất, khiến lưu lượng gần như không phân biệt được với hoạt động polling định kỳ của HMI hợp lệ — phù hợp cho giai đoạn đầu khi chưa nắm rõ cấu trúc mạng và cần tránh bị phát hiện. Chế độ nhanh (0,05-0,5 giây/lần) tạo lưu lượng S7comm dày đặc, dễ bị phát hiện hơn nhưng cho phép thu thập bức tranh đầy đủ về trạng thái vùng nhớ trong thời gian ngắn.

Kết quả thu được từ module này — đặc biệt là sự thay đổi có chu kỳ của các byte M5, M6 trong kịch bản băng truyền — chính là cơ sở để xác định địa chỉ các biến điều khiển quan trọng, phục vụ trực tiếp cho các module thao túng logic trình bày ở mục 4.2.4.

### 4.2.2. Module Đọc ghi biến trên PLC S7-1500 (read.py, write.py)

Điểm yếu cơ bản mà nhóm module này khai thác là sự thiếu vắng cơ chế phân quyền chi tiết trong nhiều cấu hình S7comm: giao thức không phân biệt giữa một client chỉ muốn đọc dữ liệu và một client muốn ghi dữ liệu, miễn kết nối được thiết lập thì cả hai thao tác đều thực hiện được. Đây là công cụ chẩn đoán nền tảng, dùng để xác minh lỗ hổng có thực sự tồn tại trên cấu hình PLC đang thử nghiệm hay không, trước khi xây dựng các module tấn công có chủ đích hơn.

Trong các hệ thống mạng công nghiệp vừa và nhỏ, cấu hình bảo mật thường không được chú trọng để việc lập trình và vận hành được thuận tiện. Khi thêm PLC vào một dự án TIA Portal với cấu hình mặc định, tính năng bảo vệ dữ liệu cấu hình được bật, nhưng chế độ giao tiếp cũ (Legacy and secure PG/PC communication) thường vẫn được cho phép để tương thích với HMI cũ hoặc thiết bị khác hãng — đây chính là điểm yếu dẫn đến việc ghi đè biến bằng công cụ tạo gói tin giả có thể khai thác được. Mức kiểm soát truy cập mặc định là Full Access nếu người cấu hình chỉ nhấn Next/Finish khi thiết lập dự án, và tùy chọn cho phép giao tiếp PUT/GET từ xa thường được bật để PLC có thể giao tiếp với SCADA hoặc các thiết bị IoT khác.

**Hình 4.3. Cấu hình không mật khẩu là mặc định cho PLC**

**Hình 4.4. Legacy communication thường được cho phép khi cấu hình**

**Hình 4.5. Mức kiểm soát truy cập mặc định là Full Access**

**Hình 4.6. PLC thường cho phép truy cập từ SCADA hoặc PLC khác**

Với cấu hình như trên, PLC S7-1500 trong testbed cũng xử lý giao thức S7comm để giao tiếp với các thiết bị ngoài TIA Portal. Thử nghiệm bằng Snap7 để gửi lần lượt lệnh dừng CPU, đọc biến và ghi biến cho thấy một điểm đáng chú ý: chức năng dừng CPU bị PLC từ chối thực hiện, trong khi các thao tác đọc và ghi biến vẫn thực hiện được bình thường.

**Hình 4.7. Kiểm tra thấy module có thể lợi dụng lỗ hổng cho đọc biến**

Phát hiện này giải thích trực tiếp lý do bộ dữ liệu Ngày 1-6 không có nhãn CPU_CONTROL: ngoài việc PLC tự chặn lệnh dừng CPU ở mức cấu hình bảo mật đang áp dụng, công cụ tấn công cũng chủ động khóa module `CPU_STOP` bằng một cờ cấu hình riêng trong `testbed.conf` (mặc định tắt), như một lớp an toàn bổ sung trong suốt quá trình thu thập dữ liệu tự động. Hai lý do này không mâu thuẫn mà bổ sung cho nhau: dù cấu hình PLC ở một thử nghiệm khác có được nới lỏng, module vẫn không được kích hoạt trong lịch trình thu thập, nên `CPU_STOP` là một năng lực đã được cài đặt và kiểm chứng nhưng chủ động không đưa vào bộ dữ liệu chính thức, đúng như đã nêu ở mục 3.5.1.

### 4.2.3. Module Giám sát thay đổi vùng nhớ (monitor.py)

Module này được xây dựng dựa trên module đọc vùng nhớ, nhưng thay vì đọc một lần, nó liên tục đọc và so sánh các vùng nhớ quan trọng của PLC với trạng thái trước đó để phát hiện bất kỳ sự thay đổi nào. Bằng cách quan sát sự thay đổi của các bit Đầu ra (Q) và Marker (M) khi có sự thay đổi ở các bit Đầu vào (I), có thể suy luận ra một phần logic điều khiển của chương trình đang chạy trên PLC mà không cần truy cập mã nguồn.

Quy trình hoạt động: module thiết lập kết nối S7comm, sau đó vào một vòng lặp đọc lần lượt các khối dữ liệu từ vùng Inputs, Outputs và Markers. Dữ liệu đọc về được so sánh với lần đọc trước; nếu có thay đổi, module duyệt qua từng bit trong khối dữ liệu để xác định chính xác bit nào vừa chuyển trạng thái, ghi lại sự kiện đó kèm thời điểm. Khi dừng module, một bản tóm tắt toàn bộ chuỗi thay đổi của từng bit được hiển thị.

Việc hiểu được logic điều khiển thông qua module này là tiền đề trực tiếp để thực hiện các kịch bản thao túng logic trình bày ở mục tiếp theo — đây là bước cầu nối giữa giai đoạn trinh sát (mục 4.2.1) và giai đoạn tấn công có chủ đích (mục 4.2.4).

### 4.2.4. Module Thao túng logic điều khiển

Đây là nhóm module có mức độ nguy hiểm cao nhất trong bộ công cụ, tác động trực tiếp vào trạng thái vận hành của hệ thống vật lý thông qua việc ghi đè vùng nhớ PLC. Điểm yếu cốt lõi vẫn là sự thiếu vắng cơ chế phân quyền chi tiết của S7comm đã nêu ở mục 4.2.2, nhưng bốn module trong nhóm này khai thác điểm yếu đó theo bốn chiến thuật khác nhau về tốc độ và mức độ, nhằm tái hiện đầy đủ các kỹ thuật thao túng logic thường gặp trong các sự cố ICS thực tế.

**Module ghi đè biến liên tục (rwrite.py → RWRITE_BURST).** Module lợi dụng việc PLC không so sánh lệnh ghi đến với logic chương trình đang chạy. Quy trình lặp ở tần suất cao gồm ba bước: đọc giá trị hiện tại của biến mục tiêu, so sánh với giá trị muốn áp đặt, và nếu khác nhau thì ghi đè để buộc biến trở về trạng thái mong muốn — lặp lại với chu kỳ 0,1-0,5 giây. Cách làm này cho phép vượt qua lớp logic ứng dụng và tác động trực tiếp đến trạng thái hệ thống vật lý. Hậu quả có thể rất nghiêm trọng: liên tục cấp điện cho một lò nung bất chấp nhiệt độ, buộc một máy bơm luôn chạy gây tràn bể chứa, hoặc "ghim" các bit cờ cảnh báo ở trạng thái an toàn khiến người vận hành không nhận biết sự cố cho đến khi hậu quả vật lý đã xảy ra.

**Module ghi đè tần suất thấp (STEALTHY_WRITE).** Nếu `RWRITE_BURST` tấn công ở tần suất cao và có thể bị phát hiện qua lưu lượng bất thường, `STEALTHY_WRITE` áp dụng chiến thuật đối lập: ghi với tần suất thấp, cố tình duy trì lưu lượng gần với mức bình thường để tránh các cơ chế phát hiện dựa trên ngưỡng. Module ghi trực tiếp vào cặp bit START/STOP (M5.0/M5.1, Bảng 3.15) — cùng hai biến mà người vận hành hợp lệ dùng để khởi động và dừng hệ thống — đồng thời xóa bit START tương ứng để ngăn PLC tự khởi động lại, với chu kỳ ngẫu nhiên 1,5-3,0 giây — tương đương tần suất của một lần polling HMI thông thường. Trước mỗi lần ghi, module đọc trạng thái hiện tại và chỉ ghi khi giá trị chưa đúng với mục tiêu, giảm thêm số lượng gói tin phát sinh. Hậu quả thực tế là hệ thống bị dừng lặp đi lặp lại dai dẳng, trong khi lưu lượng mạng nhìn bề ngoài không có gì bất thường — sự tồn tại của nhãn này trong bộ dữ liệu đòi hỏi mô hình phát hiện xâm nhập phải học cách phân tích ngữ nghĩa của từng gói tin S7comm, thay vì chỉ dựa vào khối lượng lưu lượng.

**Module thao túng thông số vận hành (SETPOINT_ATTACK).** Khác với hai module trên vốn can thiệp trực tiếp vào bit điều khiển bật/tắt, `SETPOINT_ATTACK` nhắm vào các thông số thời gian chi phối nhịp vận hành của hệ thống — chính là các biến CD1, CD2, CD3 đã mô tả ở Bảng 3.15 (mục 3.2.3) — một dạng tấn công tinh vi hơn vì không có thiết bị nào dừng đột ngột, hệ thống vẫn chạy bình thường về mặt hình thức, nhưng nhịp vận hành đã bị phá vỡ hoàn toàn. Module chọn một giá trị bất thường cho mỗi biến — ví dụ đổi từ 5.000ms mặc định sang các giá trị như 100, 250, 45.000, 60.000 hoặc 90.000ms — rồi ghi từng biến **đúng một lần**, không lặp lại như `RWRITE_BURST`. Vì vậy, lưu lượng tấn công chỉ xuất hiện trong một khoảng thời gian rất ngắn — vài gói Write Request liên tiếp rồi im lặng hoàn toàn — nhưng hậu quả tiếp diễn cho đến khi có người phát hiện và khôi phục thủ công giá trị mặc định. Kỹ thuật thao túng thông số vận hành từng được ghi nhận trong các sự cố ICS nghiêm trọng, điển hình là Stuxnet — mã độc đã thay đổi tốc độ quay của máy ly tâm uranium trong khi báo cáo giá trị bình thường về hệ thống giám sát, gây hư hỏng thiết bị mà người vận hành không hay biết trong nhiều tháng.

**Module giả mạo tín hiệu cảm biến (SENSOR_SPOOF).** Đây là hình thức tấn công tinh vi nhất trong nhóm: thay vì can thiệp vào đầu ra hay thông số điều khiển, module tác động vào chính dữ liệu đầu vào — tín hiệu cảm biến mà PLC dùng để ra quyết định. Điểm yếu bị khai thác là tín hiệu cảm biến trong chương trình PLC được lưu ở vùng nhớ Marker thay vì vùng Process Input thực, và vùng Marker có thể bị ghi đè tự do qua S7comm mà không có cơ chế bảo vệ riêng. Mục tiêu chính là ba bit Vat_1, Vat_2, Vat_3 (Bảng 3.15, mục 3.2.3) — cảm biến phát hiện vật thể tại ba trạm của chương trình băng truyền; module ghi đè các bit này bằng tổ hợp giá trị giả với chu kỳ 0,4-1,5 giây. Khi thông tin đầu vào đã bị làm sai lệch, logic điều khiển dù được lập trình đúng đắn đến đâu cũng đưa ra quyết định sai — băng truyền có thể dừng nhầm chỗ, bỏ sót vật thể hoặc gây va chạm, trong khi bản thân chương trình điều khiển không hề có lỗi. Đây là thách thức phân loại đặc biệt cho IDS: các gói tin sinh ra hoàn toàn hợp lệ về cú pháp, chỉ khác ở nội dung giá trị và tần suất ghi, đòi hỏi mô hình phải học được ngữ nghĩa của các giá trị cảm biến hợp lệ trong từng trạng thái vận hành.

### 4.2.5. Module Tấn công từ chối dịch vụ

Ba module trong nhóm này chia sẻ cùng mục tiêu — làm gián đoạn khả năng giao tiếp của PLC — nhưng tấn công ở ba tầng khác nhau của ngăn xếp giao thức, đòi hỏi hiểu rõ cấu trúc của S7comm trước khi trình bày cơ chế cụ thể.

**Cấu trúc giao thức S7comm.** S7comm hoạt động ở tầng ứng dụng, dùng TCP/IP (thường qua cổng 102) để kết nối PLC với HMI, SCADA hoặc phần mềm lập trình. S7comm không chạy trực tiếp trên TCP mà qua một lớp đệm ISO-on-TCP (RFC 1006), gồm hai thành phần TPKT và COTP.

**Bảng 4.1. Các giao thức lớp dưới của giao thức S7comm**

| OSI Layer | Giao thức |
|---|---|
| 7 — Application | S7 communication |
| 6 — Presentation | S7 communication |
| 5 — Session | S7 communication |
| 4 — Transport | ISO-on-TCP |
| 3 — Network | IP |
| 2 — Data Link | Ethernet |
| 1 — Physical | Ethernet |

TPKT là lớp vỏ bọc ngoài cùng, có chức năng duy nhất là định rõ ranh giới các gói tin: trong giao tiếp TCP thông thường, dữ liệu truyền dưới dạng luồng liên tục không có khái niệm "gói tin" ở tầng ứng dụng, nên TPKT thêm một tiêu đề 4 byte (phiên bản, dự trữ, độ dài) trước mỗi gói COTP để thiết bị nhận biết chính xác cần đọc bao nhiêu byte để tái tạo một thông điệp hoàn chỉnh.

COTP (theo chuẩn ISO 8073) quản lý phiên cho S7comm, với các loại PDU chính: Connection Request (CR, gói đầu tiên client gửi để khởi tạo phiên, chứa TSAP nguồn/đích để xác định CPU mục tiêu qua rack/slot), Connection Confirm (CC, PLC xác nhận kết nối), Data Transfer (DT, đóng gói mọi thông điệp S7comm — đọc/ghi biến, tải chương trình, đổi trạng thái RUN/STOP), và Disconnect Request (DR, đóng phiên có trật tự).

S7comm không có cơ chế mã hóa, có thể bị phân tích bằng Wireshark để thực hiện tấn công Replay hoặc Packet Crafting — điểm yếu này từng bị Stuxnet khai thác để giao tiếp với PLC. Do đó, các dòng PLC mới như S7-1200 và S7-1500 chuyển sang dùng S7comm-plus, có cơ chế chống phân tích nội dung khiến Wireshark chỉ thấy được các gói COTP mà không ghép và giải mã được lệnh cụ thể PLC được yêu cầu thực hiện.

**Hình 4.8. Phân tích đường truyền giao thức S7comm bằng Wireshark**

**Hình 4.9. Phân tích đường truyền giao thức S7CommPlus bằng Wireshark**

Dù S7comm-plus khó bị đọc trộm nội dung, giao thức vẫn tồn tại một điểm yếu ở tầng thiết lập phiên: nếu không phát lại toàn bộ phiên mà chỉ dừng lại ở bước tạo kết nối (không trao đổi COTP DT), PLC vẫn duy trì kết nối miễn thiết bị giữ phiên bằng TCP Keepalive. Số lượng kết nối PLC có thể duy trì đồng thời là có hạn (thường 8-256 tùy model) do giới hạn phần cứng và cấu hình firmware; khi vượt quá giới hạn, PLC từ chối mọi kết nối mới. Vì bước xác thực của PLC nằm sau bước tạo kết nối, tấn công loại này khai thác được kể cả khi PLC đã thiết lập mật khẩu. Đáng chú ý, thông báo lỗi hiển thị trên phần mềm cấu hình trong tình huống này giống hệt lỗi đường truyền do switch hoặc PLC mất nguồn, khiến việc phát hiện tấn công qua quan sát thông thường trở nên khó khăn.

**Module Tấn công S7-Flood (flood.py → S7_FLOOD).** Module giả mạo thiết bị yêu cầu kết nối đến PLC, trao đổi COTP Connection Request/Connection Confirm nhưng không thực hiện xác thực hay trao đổi COTP DT, chỉ duy trì bằng TCP Keepalive. Dùng thư viện threading để mở đồng thời **6 luồng**, mỗi luồng chiếm một slot kết nối, cho đến khi đạt giới hạn của PLC — khi đó HMI của người vận hành hoặc máy tính kỹ thuật không thể kết nối để giám sát hay điều khiển được nữa.

**Hình 4.10. Các bước tấn công phân tích bằng Wireshark**

**Hình 4.11. PLC báo lỗi kết nối khi số kết nối đạt giới hạn**

**Module Tấn công SYN Flood (SYN_FLOOD).** Trong khi S7_FLOOD khai thác giới hạn kết nối ở tầng ứng dụng COTP, SYN_FLOOD tấn công ở tầng thấp hơn — tầng giao vận TCP — nhằm làm cạn kiệt tài nguyên xử lý kết nối trước khi bất kỳ giao tiếp S7comm nào diễn ra. Module tạo 20 luồng song song, mỗi luồng liên tục thực hiện bắt tay TCP ba bước đến cổng 102 rồi đóng kết nối ngay lập tức mà không gửi gói COTP nào, nhằm làm cạn hàng đợi kết nối TCP (SYN backlog) của PLC. Khác với S7_FLOOD đòi hỏi hoàn thành bắt tay COTP mới chiếm được một slot, SYN_FLOOD tạo được số lượng yêu cầu lớn hơn nhiều trong cùng thời gian do không cần chờ phản hồi từ tầng ứng dụng — đặc trưng lưu lượng là mật độ gói TCP SYN rất cao mà hoàn toàn không có gói COTP CR theo sau, phân biệt rõ với cả lưu lượng S7comm hợp lệ lẫn S7_FLOOD.

**Module tấn công làm mờ giao thức (PROTOCOL_FUZZ).** Khác với hai module DoS trên vốn khai thác giới hạn tài nguyên kết nối, PROTOCOL_FUZZ gửi các gói tin dị thường về nội dung để kiểm tra khả năng xử lý lỗi của PLC. Mỗi gói tin gồm hai phần: tiêu đề TPKT hợp lệ theo đúng chuẩn RFC 1006 (hai byte phiên bản/dự trữ, hai byte độ dài), theo sau là payload hoàn toàn ngẫu nhiên dài 12-80 byte sinh bằng hàm `os.urandom`. Kết quả là PLC nhận được một gói tin trông hợp lệ ở tầng TPKT nhưng không thể phân tích được ở tầng COTP hay S7comm bên trong, vì nội dung không tuân theo bất kỳ cấu trúc PDU nào đã biết. Mỗi gói tin được gửi qua một kết nối TCP riêng đến cổng 102, với chu kỳ 0,05-0,25 giây. Đây là một lớp mẫu lưu lượng đặc trưng mà IDS cần học cách nhận diện: gói tin có TPKT header hợp lệ nhưng payload không khớp với bất kỳ PDU đã biết nào — một dấu hiệu không thể phát hiện chỉ bằng kiểm tra header, mà đòi hỏi phân tích sâu vào nội dung payload.

## 4.3. Tiểu kết chương 4

Chương 4 đã trình bày cơ chế của các giao thức mục tiêu — từ điểm yếu thiếu xác thực của DCP đến cấu trúc TPKT/COTP/S7comm và giới hạn kết nối bị S7_FLOOD khai thác — làm nền tảng lý luận cho các module tấn công. Trên cơ sở đó, chín module tương ứng chín kịch bản của Chương 3 đã được mô tả chi tiết về cơ chế hoạt động: SCAN_PORT và ENUM_TAGS cho giai đoạn trinh sát, RWRITE_BURST cho can thiệp điều khiển liên tục, ba module SETPOINT_ATTACK/SENSOR_SPOOF/STEALTHY_WRITE cho thao túng logic với ba chiến thuật khác nhau, và S7_FLOOD/SYN_FLOOD/PROTOCOL_FUZZ cho ba dạng tấn công từ chối dịch vụ ở ba tầng giao thức khác nhau. Công cụ trinh sát DCP và module CPU_STOP được trình bày riêng biệt vì cả hai không tạo ra dữ liệu có nhãn trong bộ dữ liệu chính thức — công cụ DCP chỉ phục vụ khảo sát ban đầu, còn CPU_STOP tồn tại trong công cụ nhưng bị khóa an toàn trong suốt quá trình thu thập.

Sự đa dạng về chiến thuật giữa các module — từ ghi đè tần suất cao, ghi đè tần suất thấp né phát hiện, thao túng thông số vận hành một lần, giả mạo tín hiệu cảm biến, đến ba dạng tấn công tầng mạng — đảm bảo bộ dữ liệu phản ánh đầy đủ phổ kỹ thuật tấn công trong thực tế, từ hành vi dễ phát hiện đến hành vi tinh vi đòi hỏi phân tích ngữ nghĩa sâu. Đây là nền tảng kỹ thuật trực tiếp cho quá trình thực thi và đánh giá được trình bày ở các chương tiếp theo.
