# XÂY DỰNG MÔI TRƯỜNG THỬ NGHIỆM VÀ THU THẬP DỮ LIỆU

Hai chương trước đã trình bày nền tảng về hệ thống điều khiển công nghiệp và các vấn đề an toàn thông tin trong môi trường OT. Trên cơ sở đó, chương này mô tả phần thực nghiệm của đề tài: xây dựng một môi trường có PLC Siemens thật, tổ chức các kịch bản tấn công trong điều kiện kiểm soát và thu thập dữ liệu để phục vụ bài toán phát hiện xâm nhập.

Nội dung chương được trình bày theo trình tự xây dựng môi trường, tổ chức kịch bản, thu thập dữ liệu, gán nhãn và kiểm tra bộ dữ liệu trước khi đưa vào huấn luyện mô hình.

## 3.1. Tổng quan kiến trúc testbed

### 3.1.1. Mục tiêu thiết kế

Testbed được xây dựng để thu thập dữ liệu từ một hệ thống điều khiển công nghiệp có PLC thật. Thành phần trung tâm là PLC Siemens S7-1500. PLC được nối qua switch Ethernet với Engineering Station và Attacker Machine. Engineering Station là máy tính cài TIA Portal V18 và WinCC Runtime để cấu hình, giám sát và vận hành PLC; Attacker Machine là máy tính riêng dùng để chạy các kịch bản kiểm thử. Toàn bộ thiết bị được triển khai trong một mạng cục bộ riêng dành cho quá trình thử nghiệm. Mạng này giúp giới hạn phạm vi trao đổi dữ liệu giữa các thiết bị trong testbed và tránh ảnh hưởng đến các hệ thống mạng khác.

Phần mềm mô phỏng vẫn có thể thực thi chương trình điều khiển và tạo một phần lưu lượng giao tiếp. Tuy nhiên, thời gian phản hồi và tài nguyên của mô phỏng phụ thuộc vào máy tính chạy mô phỏng, nên không phải lúc nào cũng phản ánh đúng độ trễ, giới hạn số phiên kết nối, quá trình thiết lập phiên hoặc phản ứng của PLC vật lý khi vùng nhớ bị ghi thay đổi. Vì vậy, PLC thật được sử dụng để ghi nhận các hành vi này trong điều kiện có kiểm soát.

Bên cạnh tính thực tế, testbed còn phải đáp ứng hai yêu cầu. Thứ nhất, mỗi kịch bản phải có thể chạy lại với cùng cấu hình để kết quả có thể kiểm chứng. Thứ hai, mọi thao tác phải nằm trong phạm vi an toàn, có bước khôi phục trạng thái sau tấn công và không gây hư hỏng thiết bị.

### 3.1.2. Nguyên tắc thiết kế

Kiến trúc testbed được xây dựng theo ba nguyên tắc chính.

1. Bám sát cấu trúc của một mạng OT tầng điều khiển. PLC là thiết bị điều khiển; Engineering Station là máy vận hành; Attacker Machine được đặt trong cùng mạng thí nghiệm để mô phỏng giai đoạn kẻ tấn công đã có khả năng truy cập mạng OT và bắt đầu tương tác với PLC. Đồ án không mô phỏng giai đoạn xâm nhập từ Internet vào mạng nhà máy.
2. Tách rõ lưu lượng vận hành và lưu lượng tấn công. Mỗi kịch bản có thời điểm bắt đầu, kết thúc và mã lần chạy (episode_id) riêng. Các mốc này được lưu trong nhật ký thời gian sự kiện để gán nhãn sau thu thập.
3. Ghi lại đầy đủ cấu hình để có thể tái lập. Địa chỉ IP, phiên bản phần mềm, tham số kịch bản, thời lượng chạy và khoảng nghỉ đều được quản lý bằng tệp cấu hình và mã nguồn của đồ án.

### 3.1.3. Các thành phần chính

Các thành phần được tách theo vai trò vận hành, kiểm thử và quan sát dữ liệu. Quan hệ giữa các thành phần được minh họa trong Hình 3.1.

**Hình 3.1. Kiến trúc kết nối các thành phần trong testbed**

**Bảng 3.1. Thành phần chính của testbed**

| Thành phần | Địa chỉ/Cấu hình chính | Vai trò trong thí nghiệm |
|---|---|---|
| PLC Siemens S7-1500 | CPU 1516-3 PN/DP, 192.168.210.211 | Tham gia trong toàn bộ Ngày 1 đến Ngày 6: vận hành bình thường ở Ngày 1 và tiếp nhận các kịch bản kiểm thử từ Ngày 2 đến Ngày 6. |
| Engineering Station | 192.168.210.31, TIA Portal V18, WinCC Runtime | Lập trình, giám sát PLC và tạo lưu lượng vận hành bình thường. |
| Attacker Machine | 192.168.210.32, Python, Snap7, Scapy | Thực thi các kịch bản kiểm thử theo nhật ký thời gian sự kiện. |
| Switch Ethernet | TP-Link TL-SG108E | Kết nối các thiết bị và sao chép lưu lượng từ các cổng cần quan sát sang cổng mirror. |
| Capture Machine | TShark/Npcap | Kết nối với cổng mirror của switch và ghi lưu lượng mạng vào PCAP/PCAPNG. |

### 3.1.4. Phạm vi và giới hạn của testbed

Testbed tập trung vào một PLC Siemens S7-1500, một Engineering Station, một Attacker Machine, switch có port mirroring và một Capture Machine. Các chương trình trên PLC mô tả những bài toán điều khiển có cảm biến, bit điều khiển, bộ đếm thời gian và đầu ra. Giá trị quá trình được đọc từ vùng nhớ PLC; đây không phải là số đo từ một dây chuyền cơ điện hoàn chỉnh hoặc từ hệ cảm biến độc lập.

Mạng thử nghiệm có cấu trúc phẳng và chưa triển khai VLAN, tường lửa công nghiệp, vùng DMZ, Safety PLC hoặc nhiều PLC hoạt động đồng thời. Vì vậy, kết quả phản ánh môi trường thí nghiệm có kiểm soát, chưa đại diện cho toàn bộ độ phức tạp của một mạng sản xuất thực tế.

Khả năng quan sát giao thức không đồng đều giữa các loại lưu lượng trong testbed. Lưu lượng vận hành giữa Engineering Station và PLC, do TIA Portal hoặc WinCC Runtime tạo ra, có thể sử dụng S7comm-plus. Khi nội dung tầng ứng dụng được bảo vệ hoặc chưa được bộ phân tích hỗ trợ đầy đủ, tệp PCAP vẫn ghi được gói tin nhưng chỉ cung cấp chắc chắn các thông tin như địa chỉ, cổng, hướng truyền, kích thước gói, thời gian và trạng thái phiên TCP.

Giới hạn này không áp dụng cho toàn bộ lưu lượng trao đổi với PLC. Các kịch bản do Attacker Machine thực hiện bằng python-snap7 sử dụng S7comm cổ điển qua COTP/TCP/102; với các gói tin hợp lệ, Wireshark và quy trình xử lý dữ liệu có thể nhận diện thao tác đọc/ghi, vùng nhớ và địa chỉ truy cập. Các kịch bản ở tầng TCP hoặc sử dụng payload bất thường có thể không chứa cấu trúc S7comm hoàn chỉnh để giải mã.

## 3.2. Thành phần phần cứng và phần mềm

### 3.2.1. Phần cứng

PLC Siemens S7-1500 CPU 1516-3 PN/DP là thiết bị điều khiển trung tâm. PLC sử dụng địa chỉ IP tĩnh 192.168.210.211 và giao tiếp với Engineering Station qua cổng TCP/102. Trên PLC được nạp các chương trình điều khiển đèn giao thông, bơm nước và băng truyền. Các chương trình này tạo ra các biến có ý nghĩa vận hành, như bit START/STOP, trạng thái cảm biến và thời gian dừng tại từng trạm. Đây cũng là các biến được chọn để xây dựng kịch bản thao túng logic.

Engineering Station và Attacker Machine là hai máy tính độc lập. Engineering Station chạy phần mềm Siemens để tạo lưu lượng vận hành hợp lệ. Attacker Machine chạy công cụ tấn công do nhóm phát triển. Việc tách hai vai trò giúp xác định rõ nguồn phát sinh của từng luồng lưu lượng và thuận lợi cho việc kiểm tra nhãn.

PLC, Engineering Station và Attacker Machine được nối qua switch TL-SG108E. Trong đợt thu chính, switch được cấu hình port mirroring: lưu lượng tại các cổng cần quan sát được sao chép sang một cổng riêng nối với Capture Machine. TShark chạy trên Capture Machine và ghi dữ liệu tập trung vào PCAP/PCAPNG.

### 3.2.2. Phần mềm và công cụ

**Bảng 3.2. Phần mềm và công cụ sử dụng trong testbed**

| Nhóm | Công cụ | Mục đích sử dụng |
|---|---|---|
| Vận hành PLC | TIA Portal V18 | Cấu hình phần cứng, nạp chương trình và theo dõi PLC ở chế độ trực tuyến (online). |
| HMI | WinCC Runtime | Đọc dữ liệu định kỳ từ PLC và tạo lưu lượng vận hành BENIGN. |
| Giao tiếp S7 | python-snap7 | Kết nối PLC, đọc/ghi vùng nhớ và tạo các kịch bản ở tầng S7. |
| Tạo gói tầng thấp | Scapy | Tạo TCP SYN và payload bất thường cho SYN_FLOOD, PROTOCOL_FUZZ. |
| Bắt gói | TShark/Npcap | Chạy trên Capture Machine để ghi lưu lượng nhận từ cổng mirror của switch vào PCAPNG. |
| Kiểm tra gói tin | Wireshark | Xem lại phiên TCP, COTP, S7comm và các dấu hiệu bất thường sau thu thập. |
| Xử lý dữ liệu | Python, pandas, numpy, pyshark | Chuẩn hóa thời gian, trích xuất đặc trưng, gán nhãn và tạo các bảng dữ liệu phục vụ đánh giá. |

Các kịch bản Ngày 1 đến Ngày 6 không sử dụng Nmap hoặc Metasploit. Toàn bộ hành vi tấn công vào PLC được tạo bằng chương trình Python của nhóm. Cách làm này cho phép điều chỉnh chính xác tần suất gửi, địa chỉ vùng nhớ và thời lượng của từng lần chạy, đồng thời ghi nhật ký thời gian sự kiện ngay trong quá trình chạy.

## 3.3. Kiến trúc mạng và cơ chế quan sát

### 3.3.1. Sơ đồ kết nối mạng

Các thiết bị hoạt động trong mạng 192.168.210.0/24 và kết nối qua switch Layer 2. PLC, Engineering Station và Attacker Machine trao đổi dữ liệu qua các cổng thông thường; một cổng riêng trên switch được dùng để gửi bản sao lưu lượng sang Capture Machine.

**Hình 3.2. Sơ đồ kết nối mạng và vị trí thu thập dữ liệu**

WinCC trên Engineering Station định kỳ gửi yêu cầu đọc các giá trị trong PLC để cập nhật màn hình. Khoảng thời gian giữa hai lần đọc được gọi là chu kỳ truy vấn (polling). Trong cấu hình thu thập, chu kỳ này được thay đổi trong một khoảng xác định để lưu lượng vận hành không lặp lại hoàn toàn theo một nhịp cố định. Attacker Machine có thể đồng thời tạo các kết nối hoặc gói tin kiểm thử tới PLC theo nhật ký thời gian sự kiện của từng ngày.

### 3.3.2. Cơ chế thu thập qua cổng mirror

Switch TL-SG108E được cấu hình port mirroring, còn gọi là SPAN. Gói tin đi qua các cổng kết nối PLC, Engineering Station và Attacker Machine được sao chép sang cổng nối với Capture Machine. Capture Machine chỉ nhận bản sao gói tin và không gửi lệnh điều khiển xuống PLC.

**Bảng 3.3. Điểm thu thập lưu lượng mạng**

| Điểm thu | Kết nối | Lưu lượng quan sát được | Dữ liệu tạo ra |
|---|---|---|---|
| Capture Machine | Cổng mirror trên switch TL-SG108E | Lưu lượng trao đổi giữa PLC, Engineering Station và Attacker Machine trên các cổng được cấu hình mirror. | Một tệp PCAP/PCAPNG theo phiên hoặc theo ngày thu thập. |

Cách thu tập trung giúp các luồng vận hành và kiểm thử xuất hiện trong cùng một mốc thời gian, đồng thời tránh phải chạy phần mềm bắt gói trên các máy đang thực hiện điều khiển hoặc tấn công. Chất lượng PCAP vẫn phụ thuộc vào cấu hình mirror và khả năng xử lý của Capture Machine, vì vậy số lượng gói và thời gian capture được kiểm tra sau mỗi phiên.

### 3.3.3. Giới hạn khi phân tích giao thức

Khả năng phân tích tầng ứng dụng phụ thuộc vào nguồn tạo lưu lượng và giao thức được sử dụng. Đối với lưu lượng vận hành giữa Engineering Station và PLC, TIA Portal hoặc WinCC Runtime có thể sử dụng S7comm-plus. Khi nội dung phiên được bảo vệ hoặc chưa được bộ phân tích hỗ trợ đầy đủ, quy trình xử lý dữ liệu chỉ sử dụng các trường quan sát chắc chắn ở tầng mạng và tầng phiên, gồm địa chỉ IP, cổng, hướng truyền, kích thước gói, thời gian và trạng thái TCP.

Đối với các kịch bản do Attacker Machine thực hiện bằng python-snap7, lưu lượng trao đổi với PLC sử dụng S7comm cổ điển qua COTP/TCP/102. Khi gói tin có cấu trúc hợp lệ, Wireshark và quy trình xử lý dữ liệu có thể giải mã quá trình thiết lập phiên, thao tác đọc/ghi, vùng nhớ và địa chỉ truy cập. Do đó, các trường ngữ nghĩa S7 được sử dụng cho nhóm lưu lượng này khi giải mã thành công.

Riêng SCAN_PORT và SYN_FLOOD chỉ tạo hành vi ở tầng TCP nên không có trường S7comm. PROTOCOL_FUZZ gửi payload bất thường nên có thể không được nhận diện là một bản tin COTP hoặc S7comm hợp lệ. Việc không có trường S7 trong các trường hợp này xuất phát từ cơ chế của kịch bản, không phải từ giới hạn giải mã S7comm-plus.

Nguyên tắc này giúp tránh suy diễn từ phần nội dung chưa được giải mã. Nhật ký sự kiện tấn công được dùng làm căn cứ xác định nhãn và đối chiếu lại thao tác đã thực hiện, nhưng không được đưa vào ma trận đặc trưng của mô hình.

## 3.4. Vai trò của Engineering Station

### 3.4.1. Vai trò vận hành

Engineering Station là máy trạm kỹ thuật dùng để cấu hình, giám sát và bảo trì PLC. Trong testbed, máy này cài TIA Portal V18 và WinCC Runtime. TIA Portal được dùng khi cần nạp chương trình, kiểm tra biến hoặc khôi phục trạng thái. WinCC Runtime hoạt động trong thời gian thu thập để đọc dữ liệu từ PLC và hiển thị trạng thái quá trình.

Lưu lượng do Engineering Station tạo ra là phần quan trọng của lớp BENIGN. Nó giúp bộ dữ liệu không chỉ có các khoảng tấn công tách biệt, mà còn có hoạt động vận hành chạy song song. Nhờ đó, mô hình sau này phải phân biệt giữa thao tác hợp lệ từ máy vận hành và hành vi bất thường từ máy tấn công, thay vì chỉ nhận biết sự xuất hiện của cổng TCP/102.

### 3.4.2. Vai trò trong thu thập dữ liệu

Engineering Station là nơi chạy bộ ghi trạng thái PLC. Chương trình này đọc định kỳ một nhóm biến đã chọn, chẳng hạn bit START/STOP, trạng thái cảm biến, bộ đếm thời gian và đầu ra. Mỗi dòng trong tệp CSV lưu thời điểm đọc cùng giá trị của các biến tại thời điểm đó.

Các bản ghi được gom theo cùng cửa sổ 2 giây với dữ liệu mạng. Từ đó, quy trình xử lý dữ liệu tạo một bảng chỉ chứa trạng thái PLC (process.csv). Khi các cột trạng thái PLC được ghép với đặc trưng mạng ở cùng mốc thời gian, quy trình xử lý dữ liệu tạo bảng kết hợp hai nguồn (fusion.csv).

## 3.5. Thiết kế và tổ chức các kịch bản tấn công

Một bộ dữ liệu chỉ có ý nghĩa khi các kịch bản được chọn có mục tiêu rõ ràng và tạo ra những dạng hành vi khác nhau. Trong đề tài, các kịch bản được sắp theo quá trình tăng dần mức độ tác động: từ dò tìm dịch vụ, đọc cấu trúc vùng nhớ, ghi thay đổi trạng thái, thao túng logic cho đến gây quá tải kết nối. Cách sắp xếp này giúp bộ dữ liệu bao phủ cả hành vi dễ phát hiện bằng lưu lượng và hành vi ít gói nhưng có ảnh hưởng lớn tới quá trình điều khiển.

### 3.5.1. Nguyên tắc lựa chọn

1. Kịch bản phải thực hiện được trên PLC thật và có thể lặp lại bằng cùng một cấu hình.
2. Hành vi phải quan sát được trong PCAP, nhật ký trạng thái PLC hoặc nhật ký sự kiện tấn công để có cơ sở gán nhãn.
3. Tập kịch bản cần có nhiều mức tần suất: từ ghi thưa, ghi một lần cho đến hành vi gây quá tải với tốc độ cao.
4. Mọi thao tác phải có giới hạn an toàn và bước khôi phục. Kịch bản CPU_STOP được cài đặt trong công cụ nhưng tắt mặc định, vì vậy không có nhãn CPU_CONTROL trong bộ dữ liệu cuối cùng.

### 3.5.2. Danh sách kịch bản

**Bảng 3.4. Kịch bản tấn công trong phạm vi ngày 1 đến ngày 6**

| Nhóm | Mã kịch bản | Nhãn | Cơ chế chính | Ngày |
|---|---|---|---|---|
| Trinh sát | SCAN_PORT | SCAN | Lặp kết nối TCP tới cổng 102, chu kỳ 0,4-1,5 s. | Ngày 2 |
| Trinh sát | ENUM_TAGS | ENUMERATION | Đọc liên tục vùng MK/PA/PE qua Snap7 ở chế độ chậm và nhanh. | Ngày 2 |
| Can thiệp ghi | RWRITE_BURST | RWRITE | Đọc, so sánh và ghi đè địa chỉ mục tiêu theo chu kỳ 0,1-0,5 s. | Ngày 3 |
| Thao túng logic | SETPOINT_ATTACK | SETPOINT_ATTACK | Ghi giá trị bất thường vào MD54/MD58/MD62 để thay đổi thời gian dừng. | Ngày 4 |
| Thao túng logic | SENSOR_SPOOF | SPOOF | Ghi đè các bit cảm biến được chọn theo chu kỳ 0,4-1,5 s. | Ngày 4 |
| Thao túng logic | STEALTHY_WRITE | STEALTHY | Chỉ ghi khi giá trị khác mục tiêu, chu kỳ ngẫu nhiên 1,5-3,0 s. | Ngày 4 |
| Từ chối dịch vụ | S7_FLOOD | FLOOD | Duy trì nhiều kết nối COTP đồng thời tới cổng 102 bằng 6 luồng. | Ngày 5 |
| Từ chối dịch vụ | SYN_FLOOD | FLOOD | Dùng 20 luồng gửi TCP SYN liên tục và không hoàn tất bắt tay. | Ngày 5 |
| Kiểm tra độ bền giao thức | PROTOCOL_FUZZ | FUZZ | Gửi TPKT hợp lệ kèm payload ngẫu nhiên 12-80 byte, chu kỳ 0,05-0,25 s. | Ngày 5 |

Lưu ý: Có 9 kịch bản tấn công nhưng chỉ có 8 nhãn tấn công, vì S7_FLOOD và SYN_FLOOD cùng được gán nhãn FLOOD. Ngày 1 chỉ thu BENIGN và không được tính là một kịch bản tấn công.

Trong đồ án, một kịch bản (scenario) biểu thị một loại hành vi kiểm thử cụ thể, chẳng hạn SCAN_PORT hoặc RWRITE_BURST. Mỗi kịch bản được thực hiện nhiều lần chạy độc lập (episode). Mỗi lần chạy được gắn mã kịch bản (scenario_id) và mã lần chạy (episode_id) để phục vụ gán nhãn, thống kê và phân chia dữ liệu.

### 3.5.3. Cách tổ chức theo ngày và lần chạy

**Hình 3.3. Lịch thu thập dữ liệu trong sáu ngày**

Ngày 1 được dành cho lưu lượng nền. Attacker Machine không thực hiện tấn công, trong khi Engineering Station và PLC vận hành bình thường. Ngày 2 đến Ngày 5 lần lượt thu các nhóm trinh sát, can thiệp ghi, thao túng logic và gây quá tải. Mỗi kịch bản trong các ngày huấn luyện được thực hiện ba lần độc lập. Giữa các lần chạy có khoảng vận hành BENIGN và thời gian hồi phục để tránh ảnh hưởng của lần chạy trước sang lần chạy sau.

Ngày 6 chạy lại toàn bộ chín kịch bản nhưng thay đổi thứ tự, khoảng nghỉ và tốc độ so với Ngày 2 đến Ngày 5. Toàn bộ dữ liệu của ngày này được giữ riêng để kiểm tra khả năng mô hình hoạt động trên một phiên thu thập mới; Ngày 6 không được dùng để chọn đặc trưng, điều chỉnh ngưỡng hoặc huấn luyện mô hình.

**Bảng 3.5. Vai trò của từng ngày thu thập**

| Ngày | Nội dung | Vai trò |
|---|---|---|
| Ngày 1 | Lưu lượng BENIGN: WinCC, hoạt động kỹ thuật hợp lệ, khoảng không hoạt động nhưng vẫn có gói tin. | Xây dựng nền vận hành. |
| Ngày 2 | SCAN_PORT và ENUM_TAGS. | Dữ liệu trinh sát cho tập huấn luyện. |
| Ngày 3 | RWRITE_BURST. | Dữ liệu can thiệp ghi cho tập huấn luyện. |
| Ngày 4 | SETPOINT_ATTACK, SENSOR_SPOOF, STEALTHY_WRITE. | Dữ liệu thao túng logic cho tập huấn luyện. |
| Ngày 5 | S7_FLOOD, SYN_FLOOD, PROTOCOL_FUZZ. | Dữ liệu gây gián đoạn và kiểm tra độ bền giao thức cho tập huấn luyện. |
| Ngày 6 | Trộn toàn bộ chín kịch bản với cấu hình giảm tốc và thứ tự mới. | Tập kiểm tra độc lập trên một phiên mới. |

### 3.5.4. Ý nghĩa của từng nhóm hành vi

Nhóm trinh sát gồm SCAN_PORT và ENUM_TAGS. SCAN_PORT chỉ kiểm tra khả năng kết nối tới cổng 102, vì vậy dấu hiệu chủ yếu nằm ở nhịp tạo phiên TCP. ENUM_TAGS tiến thêm một bước bằng cách đọc các vùng nhớ của PLC. Dữ liệu thu ở Ngày 2 cho thấy sự khác nhau giữa một kết nối dò cổng đơn giản và một phiên có thao tác đọc S7 lặp lại. Cơ chế của hai kịch bản được minh họa trong Hình 3.4 và Hình 3.5.

**Hình 3.4. Trình tự thực hiện SCAN_PORT**

Kết quả: Kiểm tra cổng TCP/102 có đang mở. Không thiết lập phiên COTP hoặc gửi lệnh S7comm. Không đọc hoặc thay đổi vùng nhớ PLC.

**Hình 3.5. Trình tự thực hiện ENUM_TAGS**

Kết quả: Chỉ đọc dữ liệu, không gửi lệnh ghi. Thu thập thông tin về các vùng nhớ và biến điều khiển.

RWRITE_BURST đại diện cho hành vi can thiệp trực tiếp vào tính toàn vẹn dữ liệu. PLC vẫn ở trạng thái RUN và tiếp tục trả lời HMI, nhưng giá trị điều khiển bị ghi đè nhiều lần. Vì dịch vụ không bị gián đoạn, việc phát hiện cần dựa vào hướng truyền, tần suất lệnh ghi, vùng nhớ và mối liên hệ với thay đổi trạng thái PLC. Trình tự đọc, so sánh và ghi đè được trình bày trong Hình 3.6.

**Hình 3.6. Trình tự thực hiện RWRITE_BURST**

Kết quả: Chương trình PLC vẫn tiếp tục chạy. Giá trị tại địa chỉ mục tiêu liên tục bị ghi đè. Trạng thái vận hành bị áp đặt theo giá trị của kịch bản.

Ba kịch bản của Ngày 4 tập trung vào thao túng logic. SETPOINT_ATTACK thay đổi tham số vận hành bằng một số ít lệnh ghi. SENSOR_SPOOF làm sai dữ liệu đầu vào mà chương trình điều khiển sử dụng. STEALTHY_WRITE cố tình ghi thưa và chỉ ghi khi cần thiết để giảm dấu vết trên mạng. Đây là nhóm khó phát hiện bằng các đặc trưng chỉ dựa trên số gói hoặc số byte. Trình tự của ba kịch bản được minh họa lần lượt trong Hình 3.7, Hình 3.8 và Hình 3.9.

**Hình 3.7. Trình tự thực hiện SETPOINT_ATTACK**

Kết quả: Lưu lượng tấn công chỉ xuất hiện trong thời gian ngắn. Ảnh hưởng tiếp tục cho đến khi các giá trị được khôi phục.

**Hình 3.8. Trình tự thực hiện SENSOR_SPOOF**

Kết quả: Các bit cảm biến giả được lưu trong vùng nhớ M. PLC xử lý các giá trị này như trạng thái của quá trình. Chương trình điều khiển có thể đưa ra quyết định không phù hợp.

**Hình 3.9. Trình tự thực hiện STEALTHY_WRITE**

Kết quả: Chỉ gửi lệnh ghi khi giá trị PLC khác trạng thái mục tiêu. Số lượng lệnh ghi thấp hơn RWRITE_BURST. Lưu lượng khó phân biệt với hoạt động đọc/ghi hợp lệ.

Nhóm kịch bản của Ngày 5 tạo áp lực lên khả năng giao tiếp của PLC theo ba cách khác nhau. S7_FLOOD chiếm dụng nhiều kết nối ở tầng COTP/S7. SYN_FLOOD tác động ở tầng TCP trước khi phiên S7 được thiết lập. PROTOCOL_FUZZ gửi payload không theo cấu trúc thông thường để kiểm tra phản ứng của thiết bị. Hai kịch bản flood được gộp cùng nhãn để đánh giá khả năng phát hiện hành vi quá tải nói chung, trong khi vẫn giữ scenario_id riêng để phục vụ phân tích chi tiết. Cơ chế của S7_FLOOD, SYN_FLOOD và PROTOCOL_FUZZ được trình bày trong Hình 3.10, Hình 3.11 và Hình 3.12.

**Hình 3.10. Trình tự thực hiện S7_FLOOD**

Kết quả: Số lượng phiên TCP/COTP đồng thời tăng cao. Tài nguyên xử lý kết nối của PLC bị chiếm dụng. Kết nối hợp lệ từ Engineering Station có thể bị chậm hoặc thất bại.

**Hình 3.11. Trình tự thực hiện SYN_FLOOD**

Kết quả: Tạo nhiều yêu cầu mở kết nối TCP đến cổng 102. Không thiết lập phiên COTP hoặc gửi lệnh S7comm. Kết nối hợp lệ có thể bị chậm hoặc bị từ chối.

**Hình 3.12. Trình tự thực hiện PROTOCOL_FUZZ**

Kết quả: Phần đầu TPKT hợp lệ nhưng nội dung phía sau không tuân theo cấu trúc COTP/S7comm. PLC phải kiểm tra và xử lý nhiều gói tin không hợp lệ. Không khẳng định PLC luôn trả TCP RST cho mọi gói fuzz.

## 3.6. Quy trình thu thập dữ liệu

Quy trình thu thập được thực hiện theo cùng một trình tự cho mỗi phiên, từ bước kiểm tra trạng thái ban đầu đến khi lưu đủ ba nguồn dữ liệu. Sơ đồ tổng quát được trình bày trong Hình 3.13.

**Hình 3.13. Quy trình thu thập và hình thành bộ dữ liệu**

Nguyên tắc đồng bộ: tệp PCAP, nhật ký trạng thái PLC và nhật ký thời gian sự kiện sử dụng chung một mã phiên thu thập (session_id). Đồng hồ trên các máy được đồng bộ hoặc ghi nhận độ lệch trước khi bắt đầu thu thập.

### 3.6.1. Chuẩn bị trước mỗi phiên

Trước khi bắt đầu bắt gói, nhóm đưa hệ thống về trạng thái ổn định. Các bước này được thực hiện theo cùng một thứ tự để hạn chế sai khác giữa các ngày. Quy trình được minh họa trong Hình 3.14.

**Hình 3.14. Quy trình chuẩn bị trước mỗi phiên thu thập dữ liệu**

1. Kiểm tra PLC đang ở chế độ RUN, chương trình điều khiển hoạt động bình thường và không còn giá trị bị thay đổi từ lần chạy trước.
2. Khởi động WinCC Runtime và xác nhận Engineering Station vẫn đọc được dữ liệu từ PLC.
3. Đồng bộ hoặc ghi nhận độ lệch thời gian giữa Capture Machine, chương trình ghi trạng thái PLC và chương trình chạy kịch bản.
4. Khởi động TShark trên Capture Machine đang nối với cổng mirror. Quá trình bắt gói không áp dụng bộ lọc thu thập nhằm tránh bỏ sót lưu lượng ngoài dự kiến.
5. Khởi động chương trình ghi trạng thái PLC và tạo mã phiên thu thập (session_id) dùng chung cho tệp PCAP, nhật ký trạng thái PLC và nhật ký thời gian sự kiện.
6. Chạy giai đoạn khởi động ổn định với lưu lượng BENIGN trước khi bắt đầu lần chạy đầu tiên.

### 3.6.2. Thu thập theo từng lần chạy

Mỗi lần chạy độc lập gồm bốn giai đoạn: vận hành bình thường trước tấn công, thực hiện kịch bản tấn công, khôi phục trạng thái hệ thống và vận hành bình thường sau tấn công. Chương trình điều phối ghi lại các mốc START và END, cùng với mã kịch bản (scenario_id), nhãn (label) và mã lần chạy (episode_id). Đối với các kịch bản có thao tác ghi giá trị, nhật ký sự kiện tấn công còn lưu địa chỉ tác động, giá trị trước khi ghi và giá trị sau khi ghi để phục vụ kiểm tra.

Trong Ngày 2 đến Ngày 5, mỗi kịch bản được thực hiện ba lần độc lập. Sau khi hoàn thành một nhóm kịch bản, hệ thống được dành một khoảng thời gian hồi phục để PLC và các phiên kết nối trở lại trạng thái bình thường. Quy trình này tạo ranh giới rõ ràng giữa các lần chạy và hạn chế ảnh hưởng của kịch bản trước tới dữ liệu của kịch bản sau.

### 3.6.3. Ba nguồn dữ liệu

**Bảng 3.6. Các nguồn dữ liệu được đồng bộ**

| Nguồn | Định dạng | Nội dung | Cách sử dụng |
|---|---|---|---|
| Dữ liệu lưu lượng mạng | PCAP/PCAPNG | Bản sao lưu lượng được switch gửi tới Capture Machine qua cổng mirror. | Trích xuất thống kê mạng, TCP, COTP và ngữ nghĩa S7 khi giải mã được. |
| Nhật ký trạng thái PLC | CSV | Thời điểm đọc và giá trị của cảm biến, bit điều khiển, bộ định thời, giá trị đặt và đầu ra trong PLC. | Tạo bảng trạng thái PLC; sau đó có thể ghép với bảng đặc trưng mạng theo cùng cửa sổ thời gian. |
| Nhật ký thời gian / sự kiện tấn công | CSV/JSONL | Mốc START/END, kịch bản, lần chạy, địa chỉ và giá trị ghi. | Dùng làm căn cứ gán nhãn và đối chiếu lại sự kiện; không dùng trực tiếp làm đặc trưng huấn luyện. |

### 3.6.4. Cấu trúc nhật ký thời gian sự kiện

**Bảng 3.7. Các trường chính trong nhật ký thời gian sự kiện**

| Trường | Ý nghĩa |
|---|---|
| session_id | Mã định danh một ngày hoặc một phiên thu thập. |
| scenario_id | Mã kịch bản, ví dụ SCAN_PORT hoặc RWRITE_BURST. |
| label | Nhãn dùng cho bài toán phân loại. |
| episode_id | Mã định danh một lần chạy độc lập của kịch bản. |
| t_start, t_end | Thời điểm bắt đầu và kết thúc theo cùng chuẩn thời gian. |
| pcap_file / capture_source | Tên tệp PCAP và nguồn thu qua cổng mirror. |
| notes / event detail | Thông tin khôi phục, địa chỉ ghi hoặc bất thường trong quá trình chạy. |

Tên tệp và siêu dữ liệu được thiết kế để liên kết ba nguồn theo cùng mã phiên thu thập (session_id) và mốc thời gian. Việc gán nhãn được thực hiện sau khi thu thập, dựa trên nhật ký thời gian sự kiện và nhật ký thao tác tấn công.

### 3.6.5. Giới hạn của nhật ký trạng thái PLC

Chương trình ghi trạng thái PLC đọc định kỳ một nhóm biến đã chọn trong PLC với chu kỳ khoảng 0,5 giây và lưu kết quả vào tệp CSV. Mỗi bản ghi gồm thời điểm đọc và giá trị của các biến. Trong một số phiên đã thu, chương trình được khởi động muộn hơn quá trình bắt gói hoặc kết thúc trước khi lần chạy hoàn thành. Vì vậy, không phải mọi cửa sổ mạng 2 giây đều có bản ghi trạng thái PLC trùng thời gian.

Để giữ cho các bảng có cùng số hàng, bước tiền xử lý có thể sử dụng bản ghi trạng thái gần nhất trước hoặc sau cửa sổ bị thiếu, nhưng chỉ trong phạm vi cùng một ngày. Giá trị này chỉ là dữ liệu bù để duy trì cấu trúc bảng, không được xem là phép đo thực tại cửa sổ đó. Cột proc_data_valid được đặt bằng 1 khi cửa sổ có bản ghi trạng thái thực và bằng 0 khi giá trị được bù. Cột này chỉ dùng để kiểm tra độ phủ dữ liệu và bị loại trước khi huấn luyện mô hình. Không có giá trị nào được sao chép từ ngày này sang ngày khác.

## 3.7. Thống kê bộ dữ liệu

Sau bước trích xuất và làm sạch, bảng đặc trưng mạng chính thức gồm 55.902 cửa sổ không chồng lấn, mỗi cửa sổ dài 2 giây. Trong đó có 47.460 cửa sổ BENIGN và 8.442 cửa sổ tấn công. Dữ liệu từ Ngày 1 đến Ngày 5 được dùng để phát triển mô hình. Ngày 6 gồm 7.288 cửa sổ và được giữ hoàn toàn riêng để đánh giá mô hình trên một phiên mới có thứ tự và tốc độ tấn công khác dữ liệu huấn luyện.

**Bảng 3.8. Phân bố cửa sổ theo ngày và nhãn**

| Ngày | BENIGN | ENUM | FLOOD | FUZZ | RWRITE | SCAN | SETPOINT | SPOOF | STEALTHY | Tổng |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Ngày 1 | 7.348 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 7.348 |
| Ngày 2 | 8.761 | 935 | 0 | 0 | 0 | 438 | 0 | 0 | 0 | 10.134 |
| Ngày 3 | 11.753 | 0 | 0 | 0 | 866 | 0 | 0 | 0 | 0 | 12.619 |
| Ngày 4 | 5.208 | 0 | 0 | 0 | 0 | 0 | 829 | 943 | 442 | 7.422 |
| Ngày 5 | 9.787 | 0 | 894 | 410 | 0 | 0 | 0 | 0 | 0 | 11.091 |
| Ngày 6 | 4.603 | 470 | 317 | 122 | 365 | 462 | 253 | 299 | 397 | 7.288 |
| Tổng | 47.460 | 1.405 | 1.211 | 532 | 1.231 | 900 | 1.082 | 1.242 | 839 | 55.902 |

**Hình 3.15. Phân bố nhãn trong bảng đặc trưng mạng**

Lớp BENIGN chiếm 84,9%, còn toàn bộ các lớp tấn công chiếm 15,1%. Đây là dạng mất cân bằng thường gặp trong dữ liệu vận hành, vì hệ thống bình thường trong phần lớn thời gian. Do đó, Accuracy không đủ để đánh giá mô hình. Các chương sau sử dụng thêm Macro-F1, MCC, balanced accuracy, PR-AUC và kết quả theo từng lớp.

Tổng cộng có 228 nhóm dữ liệu dùng cho đánh giá chéo theo nhóm (Grouped Cross-Validation), gồm 36 lần chạy tấn công và 192 đoạn BENIGN dài 10 phút. Cách chia này giữ các cửa sổ gần nhau của cùng một lần chạy trong cùng một phần dữ liệu, tránh trường hợp một chuỗi lưu lượng xuất hiện đồng thời ở cả phần huấn luyện và phần kiểm tra.

**Bảng 3.9. Thống kê theo kịch bản**

| Kịch bản | Nhãn | Số cửa sổ | Số lần chạy | Ngày xuất hiện |
|---|---|---:|---:|---|
| SCAN_PORT | SCAN | 900 | 4 | Ngày 2, Ngày 6 |
| ENUM_TAGS | ENUMERATION | 1.405 | 4 | Ngày 2, Ngày 6 |
| RWRITE_BURST | RWRITE | 1.231 | 4 | Ngày 3, Ngày 6 |
| SETPOINT_ATTACK | SETPOINT_ATTACK | 1.082 | 4 | Ngày 4, Ngày 6 |
| SENSOR_SPOOF | SPOOF | 1.242 | 4 | Ngày 4, Ngày 6 |
| STEALTHY_WRITE | STEALTHY | 839 | 4 | Ngày 4, Ngày 6 |
| S7_FLOOD | FLOOD | 623 | 4 | Ngày 5, Ngày 6 |
| SYN_FLOOD | FLOOD | 588 | 4 | Ngày 5, Ngày 6 |
| PROTOCOL_FUZZ | FUZZ | 532 | 4 | Ngày 5, Ngày 6 |

Khoảng thời gian thực tế giữa bản ghi đầu tiên và cuối cùng của sáu ngày là khoảng 49,8 giờ. Tuy nhiên, tổng thời lượng của các cửa sổ được phát hành là khoảng 31,1 giờ. Chênh lệch này xuất hiện vì các khoảng nghỉ qua đêm và khoảng im lặng không có gói tin không được tạo thành cửa sổ giả. Những khoảng nền có lưu lượng thật vẫn được giữ và gán BENIGN.

## 3.8. Quy trình gán nhãn và tạo các bảng dữ liệu

### 3.8.1. Tạo nhãn từ nhật ký thời gian sự kiện

**Hình 3.16. Luồng gán nhãn cho cửa sổ dữ liệu**

Tên cấu trúc AttackInterval chỉ là cách mã nguồn lưu khoảng thời gian bắt đầu–kết thúc của một lần chạy.

Nhật ký thời gian sự kiện ghi riêng các mốc START và END của từng lần chạy. Chương trình xử lý ghép hai mốc này thành một khoảng thời gian tấn công, kèm mã kịch bản, nhãn và mã lần chạy. Trong mã nguồn, cấu trúc lưu khoảng thời gian này được đặt tên là AttackInterval. Sau đó, từng cửa sổ 2 giây được đối chiếu với các khoảng đã tạo. Cửa sổ nằm trong khoảng tấn công và đáp ứng quy tắc chồng lấn được gán nhãn tương ứng; cửa sổ còn lại được gán BENIGN. Các cửa sổ ở vùng chuyển tiếp có thể bị loại khi không đủ căn cứ để gán một nhãn duy nhất.

Đối với các kịch bản ghi thưa hoặc chỉ ghi một lần, toàn bộ thời gian của phiên không được gán là tấn công. Nhật ký thao tác tấn công được dùng để thu hẹp khoảng thời gian mang nhãn tấn công vào thời điểm phát sinh lệnh và khoảng tác động cần thiết. Cách làm này tránh tạo nhiều mẫu dương không chứa hành vi tấn công thực tế.

**Bảng 3.10. Các trường của khoảng thời gian dùng để gán nhãn**

| Trường | Kiểu | Vai trò |
|---|---|---|
| start_ms, end_ms | Số nguyên 64 bit | Xác định khoảng thời gian của sự kiện. |
| scenario_id | Chuỗi | Giữ mã kịch bản để phân tích kết quả theo từng kịch bản. |
| label | Chuỗi | Nhãn BENIGN hoặc một trong tám lớp tấn công. |
| episode_id | Chuỗi | Giữ toàn bộ cửa sổ của một lần chạy trong cùng nhóm đánh giá. |
| session_id, pcap_file | Chuỗi | Xác định phiên thu thập và tệp PCAP được sử dụng. |

### 3.8.2. Bốn cách biểu diễn dữ liệu

Sau khi gán nhãn, dữ liệu được tổ chức thành bốn bảng phục vụ các mục đích khác nhau. Trong báo cáo, mỗi cách tổ chức này được gọi là một cách biểu diễn dữ liệu.

**Bảng 3.11. Các cách biểu diễn bộ dữ liệu**

| Cách biểu diễn | Dữ liệu | Mục đích |
|---|---|---|
| Chỉ dùng lưu lượng mạng (Network-only) | Chỉ gồm đặc trưng lấy từ PCAP: số gói, số byte, phiên TCP/COTP và trường S7 khi giải mã được. | Đánh giá mô hình khi chỉ quan sát lưu lượng mạng. |
| Chỉ dùng trạng thái PLC (Process-only) | Chỉ gồm các giá trị trạng thái PLC được tổng hợp theo cửa sổ 2 giây. | Đánh giá mô hình khi chỉ quan sát biến điều khiển và trạng thái quá trình. |
| Kết hợp mạng và trạng thái PLC (Fusion) | Mỗi hàng chứa đồng thời đặc trưng mạng và giá trị trạng thái PLC ở cùng cửa sổ thời gian. | Kiểm tra việc kết hợp hai nguồn có bổ sung thông tin hay không. |
| Bảng đối chiếu rò rỉ dữ liệu (Audit/Leakage-ablation) | Giữ thêm siêu dữ liệu, cờ luật và các cột phục vụ đối chiếu. | Kiểm tra mức tăng điểm số do thông tin rò rỉ; không dùng làm kết quả chính. |

### 3.8.3. Kiểm soát rò rỉ dữ liệu

Rò rỉ dữ liệu xảy ra khi mô hình nhận được một cột gần như tiết lộ đáp án. Ví dụ, nếu scenario_id, thời gian tuyệt đối hoặc cờ do một luật phát hiện tấn công tạo ra được đưa vào huấn luyện, mô hình có thể đạt điểm cao mà không học được đặc trưng hành vi. Vì vậy, bản dữ liệu dùng cho học máy chỉ giữ các đặc trưng có thể quan sát tại thời điểm triển khai.

**Bảng 3.12. Các nhóm cột bị loại khỏi ma trận đặc trưng**

| Nhóm | Ví dụ | Lý do |
|---|---|---|
| Nhãn và trạng thái đích | label, label_network, plc_under_attack | Tiết lộ trực tiếp hoặc gần trực tiếp kết quả cần dự đoán. |
| Thời gian và định danh phiên | timestamp, day, session_id, episode_id | Mô hình có thể học lịch thu thập thay vì hành vi. |
| Định danh thiết bị | src_ip, dst_ip, MAC, host_id | Mô hình có thể học máy tấn công thay vì mẫu tấn công. |
| Đầu ra của luật phát hiện | scan_detected_rule, anomaly_score, conflict_flag | Đây đã là kết quả của một cơ chế phát hiện khác. |
| Cờ độ phủ dữ liệu | proc_data_valid | Phản ánh việc chương trình ghi trạng thái PLC có hoạt động hay không, không phải trạng thái an ninh. |

Các cột trên vẫn được giữ trong tệp đối chiếu để kiểm tra và tái lập, nhưng bị loại trước khi huấn luyện mô hình. Danh sách cột bị loại được ghi lại trong tệp kê khai cấu hình (manifest) của mỗi lần chạy để tránh sai khác giữa các thí nghiệm.

## 3.9. Kiểm tra tính hợp lệ của bộ dữ liệu

Trước khi huấn luyện, bộ dữ liệu được kiểm tra ở bốn mức: nhãn, ranh giới huấn luyện - kiểm tra, cấu trúc nhóm và chất lượng đặc trưng. Mục tiêu của bước này là phát hiện lỗi trong quy trình thu thập hoặc xử lý trước khi lỗi đó bị che khuất bởi điểm số mô hình.

### 3.9.1. Kiểm tra nhãn và ranh giới dữ liệu

- Mọi cửa sổ phải có nhãn thuộc tập BENIGN, SCAN, ENUMERATION, RWRITE, SETPOINT_ATTACK, SPOOF, STEALTHY, FLOOD hoặc FUZZ.
- Không có session_id hoặc episode_id của Ngày 6 xuất hiện trong Ngày 1-5.
- Không có lần chạy nào bị chia đồng thời vào phần huấn luyện và phần kiểm tra.
- Các cửa sổ trùng khóa thời gian và nguồn thu phải được loại hoặc giải thích rõ.

### 3.9.2. Kiểm tra đặc trưng

- Loại đặc trưng hằng số và các cột trùng hoàn toàn.
- Kiểm tra tỷ lệ thiếu, giá trị vô hạn và các giá trị vượt miền hợp lý.
- Các bước chuẩn hóa, lọc tương quan và tiền xử lý được thực hiện riêng trên từng phần dữ liệu huấn luyện.
- Xác nhận danh sách cột an toàn không chứa scenario_id, session_id, episode_id, proc_data_valid, timestamp hoặc các cờ luật.

### 3.9.3. Kết quả kiểm tra và giới hạn còn lại

**Bảng 3.13. Kết quả rà soát bộ dữ liệu**

| Hạng mục | Kết quả | Nhận xét |
|---|---|---|
| Nhãn bảng đặc trưng mạng | Đạt | 55.902 cửa sổ có nhãn hợp lệ và thống kê khớp theo ngày/lớp. |
| Tách Ngày 1–5 và Ngày 6 | Đạt | Ngày 6 được giữ riêng, không dùng để điều chỉnh mô hình. |
| Đánh giá chéo theo nhóm lần chạy/phiên | Đạt | Không có nhóm dữ liệu nào xuất hiện đồng thời ở phần huấn luyện và phần kiểm tra. |
| Loại siêu dữ liệu và các cờ luật | Đạt sau sửa | proc_data_valid và các cột định danh đã được đưa vào danh sách loại. |
| Bù giá trị trạng thái PLC bị thiếu | Đạt sau sửa | Chỉ sao chép giá trị gần nhất trong cùng ngày và luôn giữ cờ phân biệt dữ liệu thật với dữ liệu bù. |
| Độ phủ bản ghi trạng thái PLC trong các cửa sổ tấn công | Hạn chế | 6.744/8.442 cửa sổ tấn công (79,9%) không có bản ghi trạng thái PLC được ghi đúng thời điểm. |
| Khả năng đánh giá bảng dữ liệu kết hợp | Chưa đầy đủ | RWRITE, FLOOD và SETPOINT_ATTACK không có cửa sổ trạng thái PLC hợp lệ; cần thu lại với các nguồn được khởi động đồng thời. |

Trong số các lớp tấn công, chỉ STEALTHY tạo ra dấu hiệu tương đối rõ trong dữ liệu trạng thái PLC hiện có: giá trị đầu ra Q0 thay đổi khi bit STOP bị tác động. Một phần cửa sổ SCAN, ENUMERATION và FUZZ có bản ghi trạng thái PLC, nhưng các giá trị này gần như không khác giai đoạn BENIGN. Vì vậy, kết quả trên bảng dữ liệu kết hợp mạng và trạng thái PLC (fusion.csv) ở Chương 6 cần được giải thích thận trọng; chưa đủ cơ sở để kết luận rằng việc ghép hai nguồn luôn cải thiện khả năng phát hiện cho mọi lớp.

## 3.10. Đánh giá tính hợp lệ của nghiên cứu

Các giới hạn của testbed và dữ liệu được xem xét theo bốn nhóm. Việc nêu rõ các giới hạn này giúp xác định phạm vi mà kết quả có thể được sử dụng, đồng thời tránh đưa ra kết luận rộng hơn bằng chứng hiện có.

**Bảng 3.14. Các mối đe dọa tới tính hợp lệ và cách xử lý**

| Nhóm | Vấn đề chính | Biện pháp đã áp dụng hoặc hướng khắc phục |
|---|---|---|
| Tính hợp lệ nội tại | Sai lệch đồng hồ, nhãn ở ranh giới, trạng thái còn lại từ lần chạy trước. | Dùng nhật ký thời gian chung, thời gian hồi phục, khôi phục trạng thái và kiểm tra từng lần chạy; loại cửa sổ chuyển tiếp khi cần. |
| Tính hợp lệ ngoại tại | Chỉ có một PLC, mạng phẳng và ít loại lưu lượng nền. | Mô tả rõ phạm vi; hướng tiếp theo là thêm PLC, VLAN, firewall và nhiều thiết bị nền. |
| Tính hợp lệ cấu trúc | Không giải mã đầy đủ mọi phiên S7comm-plus giữa Engineering Station và PLC; bản ghi trạng thái PLC không phủ đủ các cửa sổ tấn công. | Chỉ dùng các trường quan sát được; đánh giá riêng dữ liệu mạng, dữ liệu trạng thái PLC và dữ liệu kết hợp; công bố cờ proc_data_valid. |
| Tính hợp lệ kết luận | Mất cân bằng lớp, tương quan giữa các cửa sổ cùng lần chạy và sự khác biệt của Ngày 6. | Dùng Grouped Cross-Validation, giữ riêng Ngày 6 để kiểm tra và báo cáo Macro-F1, MCC, PR-AUC cùng kết quả theo từng lớp. |

Giới hạn lớn nhất của bộ dữ liệu hiện tại là độ phủ không đồng đều của chương trình ghi trạng thái PLC. Điều này không làm mất giá trị của bảng đặc trưng mạng, nhưng ảnh hưởng trực tiếp tới việc so sánh mô hình chỉ dùng mạng với mô hình kết hợp mạng và trạng thái PLC. Một đợt thu bổ sung với bộ ghi trạng thái được bật xuyên suốt tất cả lần chạy là cần thiết để đánh giá vai trò của dữ liệu quá trình một cách công bằng.

## 3.11. Tiểu kết chương 3

Chương 3 đã trình bày toàn bộ quá trình xây dựng môi trường thử nghiệm và hình thành bộ dữ liệu. Testbed gồm PLC Siemens S7-1500 CPU 1516-3 PN/DP, Engineering Station, Attacker Machine, switch TL-SG108E và Capture Machine trong mạng 192.168.210.0/24. Lưu lượng mạng được thu tập trung qua cổng mirror của switch; dữ liệu trạng thái PLC và nhật ký thời gian sự kiện được ghi thành các tệp riêng để đồng bộ sau thu thập.

Trong sáu ngày thu thập, Ngày 1 tạo lưu lượng BENIGN; Ngày 2 đến Ngày 5 thực hiện chín kịch bản thuộc bốn nhóm hành vi; Ngày 6 trộn lại toàn bộ kịch bản với cấu hình khác để tạo tập kiểm tra độc lập trên một phiên mới. Bảng đặc trưng mạng sau rà soát gồm 55.902 cửa sổ 2 giây, trong đó 47.460 cửa sổ BENIGN và 8.442 cửa sổ tấn công. Chín kịch bản được ánh xạ thành tám nhãn tấn công do hai kịch bản flood dùng chung nhãn FLOOD.

Quy trình gán nhãn dựa trên các mốc START/END trong nhật ký thời gian sự kiện, khoảng thời gian của từng lần chạy và mã lần chạy (episode_id). Các bảng dữ liệu được tách riêng để đánh giá dữ liệu mạng, dữ liệu trạng thái PLC và dữ liệu kết hợp. Những cột có nguy cơ rò rỉ, bao gồm siêu dữ liệu, định danh thiết bị, các cờ luật và proc_data_valid, không được đưa vào ma trận đặc trưng dùng cho kết quả chính.

Bộ dữ liệu đã đáp ứng các kiểm tra về nhãn, ranh giới giữa dữ liệu Ngày 1–5 và Ngày 6, cũng như yêu cầu không để cùng một lần chạy xuất hiện ở cả phần huấn luyện và phần kiểm tra. Tuy nhiên, độ phủ của bộ ghi trạng thái PLC còn hạn chế và chưa đồng đều giữa các lớp tấn công. Đây là giới hạn cần được nêu rõ khi phân tích kết quả của bảng dữ liệu kết hợp. Các thông tin trong chương này là cơ sở để Chương 4 trình bày cơ chế của các module tấn công, Chương 5 mô tả quá trình thực thi và Chương 6 xây dựng, đánh giá mô hình phát hiện xâm nhập.


---


# Chương 4 — Phân tích giao thức và triển khai module mô phỏng tấn công (bản sửa)

> Phần giải thích giao thức TPKT/COTP/S7comm/S7comm-plus (khoảng giữa chương gốc) **giữ nguyên**, đã kiểm chứng chính xác, không cần sửa. Tài liệu này chỉ thay thế các mục mô tả module bị sai/thiếu đồng bộ với Chương 3.

## Định hướng xây dựng module mô phỏng tấn công

*(Giữ phần lớn nội dung gốc, chỉ sửa một câu ở cuối để không ngụ ý DCP-scan là cơ chế chính tạo nhãn SCAN — xem mục "Module Dò quét" bên dưới để hiểu vì sao.)*

Việc xây dựng các module mô phỏng tấn công dành cho hệ thống PLC trong môi trường công nghiệp xuất phát từ yêu cầu thực tế của đồ án: để xây dựng một bộ dataset ICS có giá trị, cần tạo ra dữ liệu lưu lượng mạng phản ánh đúng các kỹ thuật tấn công thường gặp trong môi trường OT. Các module được phát triển nhằm mục đích nghiên cứu, giúp tái hiện có kiểm soát các tình huống tấn công để thu thập dữ liệu có nhãn chính xác.

Về mặt kỹ thuật, các module được triển khai bằng Python, sử dụng Scapy để xây dựng và phân tích gói tin ở tầng thấp, và Snap7 để giao tiếp với PLC qua S7comm. Cấu trúc chương trình chia thành các module riêng biệt, đảm bảo tính độc lập giữa các kịch bản, thuận tiện cho việc bật/tắt từng loại tấn công theo đúng lịch trình thu thập dữ liệu (mục 3.6).

## Nguyên lý hoạt động của các module

### Công cụ trinh sát mạng và module tạo nhãn SCAN — hai thứ khác nhau

Phần này cần tách bạch rõ ràng hai cơ chế trước đây bị gộp chung dưới tên "Module Dò quét", vì chúng phục vụ hai mục đích khác nhau và **chỉ một trong hai thực sự tạo ra nhãn SCAN trong bộ dữ liệu**.

**a) Công cụ trinh sát Profinet ban đầu (dựa trên DCP)**

Trước khi thiết lập testbed và cấu hình `testbed.conf`, một công cụ trinh sát riêng được dùng để khảo sát thiết bị Profinet trong mạng, hoạt động dựa trên Discovery and Configuration Protocol (DCP) — giao thức tầng 2 (Data Link Layer) cho phép thiết bị Profinet tự nhận diện lẫn nhau mà không cần địa chỉ IP.

Công cụ xây dựng gói tin Ethernet với EtherType `0x8892`, gửi đến địa chỉ MAC multicast `01:0e:cf:00:00:00` (địa chỉ mọi thiết bị Profinet đều lắng nghe), chứa yêu cầu DCP "Identify Request". Thiết bị nhận được sẽ phản hồi thông tin nhận dạng: tên trạm (NameOfStation), địa chỉ IP/MAC, Vendor ID (`002a` cho Siemens), Device ID và Device Role. Dựa vào Device ID, công cụ tra cứu bảng đã xây dựng sẵn để xác định model cụ thể (ví dụ `010e` tương ứng S7-1500).

Điểm yếu bị khai thác: DCP hoàn toàn không có cơ chế xác thực, và giao tiếp không đi qua tầng IP nên không để lại dấu vết trên các hệ thống giám sát dựa trên địa chỉ IP.

**Công cụ này được dùng một lần khi khảo sát/thiết lập testbed, không phải một kịch bản lặp lại trong lịch trình thu thập Day 1-6, và không tạo ra bất kỳ nhãn nào trong Bảng 3.4/3.9 của Chương 3.**

**b) SCAN_PORT — module thực sự tạo nhãn SCAN**

Khác hẳn về cơ chế, `SCAN_PORT` — module chạy trong Day 2 để tạo dữ liệu có nhãn SCAN — chỉ đơn giản là một vòng lặp kết nối TCP thuần tới cổng 102 của PLC, không dùng DCP, không thiết lập phiên COTP, không gửi bất kỳ lệnh S7comm nào:

```python
s = socket.create_connection((target, 102), timeout=1.0)
# lặp lại với chu kỳ ngẫu nhiên 0,4-1,5 giây
```

Mục đích chỉ là xác nhận cổng 102 đang mở — bước đầu tiên, tối thiểu nhất của chuỗi trinh sát, tạo ra lưu lượng TCP SYN/ACK lặp lại mà không để lộ ý định cụ thể qua nội dung gói tin. Đặc trưng lưu lượng: `tcp_syn_count` cao, `cotp_cr_count = 0`, `s7comm_packet_count = 0` — hoàn toàn không có dấu vết ở tầng ứng dụng.

### Module Liệt kê vùng nhớ (ENUM_TAGS)

*(Giữ nguyên nội dung gốc — đã đối chiếu đúng với Bảng 3.4 Chương 3.)*

Sau khi xác định PLC còn hoạt động, `ENUM_TAGS` đọc liên tục các vùng nhớ MK (Marker), PA (Process Output) và PE (Process Input) qua Snap7, đồng thời truy vấn thông tin CPU (tên module, trạng thái RUN/STOP). Hai chế độ tốc độ: chậm (2 giây/lần, gần với tần suất polling HMI hợp lệ, khó bị phát hiện bởi IDS dựa trên ngưỡng) và nhanh (0,05-0,5 giây/lần, tạo lưu lượng dày đặc dễ phát hiện nhưng thu được bức tranh đầy đủ hơn trong thời gian ngắn). Kết quả — đặc biệt sự thay đổi có chu kỳ của các byte M5, M6 (băng truyền) — là cơ sở xác định địa chỉ các biến điều khiển, phục vụ trực tiếp cho các module thao túng logic ở các bước sau.

### Module Đọc ghi biến và giám sát (read.py, write.py, monitor.py)

*(Giữ nguyên nội dung gốc về điểm yếu thiếu phân quyền của S7comm và cơ chế `monitor.py` theo dõi thay đổi vùng nhớ. Đây là công cụ nền tảng dùng để xác định địa chỉ biến, không trực tiếp tạo nhãn nào trong Bảng 3.4 — cần nói rõ điều này để tránh gây hiểu nhầm giống như trường hợp DCP-scan/SCAN_PORT ở trên.)*

### Module Điều khiển CPU (CPU_STOP)

Mục này gộp lại hai phát hiện trước đây bị tách rời, vì cả hai cùng giải thích lý do bộ dữ liệu cuối cùng không có nhãn CPU_CONTROL.

Thử nghiệm ban đầu bằng Snap7 cho thấy: với cấu hình bảo mật đang áp dụng trên PLC thử nghiệm, lệnh dừng CPU (STOP) qua S7comm bị PLC từ chối, trong khi các thao tác đọc/ghi biến vẫn thực hiện được bình thường — tức bản thân PLC đã có một lớp chặn ở mức cấu hình đối với riêng lệnh điều khiển CPU.

Độc lập với phát hiện đó, công cụ tấn công cũng tự khóa module `CPU_STOP` bằng một cờ cấu hình riêng (`ENABLE_CPU_CONTROL_ATTACK` trong `testbed.conf`, mặc định tắt), như một lớp an toàn bổ sung trong quá trình thu thập dữ liệu tự động Day 1-6 — không phụ thuộc vào việc PLC có chặn được lệnh này hay không.

Hai lý do này bổ sung cho nhau chứ không mâu thuẫn: dù cấu hình PLC có được nới lỏng trong một thử nghiệm khác, module vẫn không được kích hoạt trong lịch trình thu thập tự động. Kết quả là bộ dữ liệu Day 1-6 **không có nhãn CPU_CONTROL**, đúng như đã nêu ở mục 3.5.1 Chương 3.

### Module Thao túng logic điều khiển

Đây là nhóm module tác động trực tiếp vào trạng thái vận hành hệ thống vật lý thông qua ghi đè vùng nhớ PLC, khai thác chung một điểm yếu: S7comm không có cơ chế phân quyền chi tiết giữa đọc và ghi.

**Module ghi đè biến liên tục (rwrite.py → RWRITE_BURST)**

*(Giữ nguyên cơ chế gốc, bổ sung số liệu cho khớp Bảng 3.4.)* Mỗi chu kỳ, module đọc giá trị hiện tại của biến mục tiêu, so sánh với giá trị muốn áp đặt, và ghi đè nếu khác nhau — lặp lại với **chu kỳ 0,1-0,5 giây** (số liệu bổ sung, khớp Bảng 3.4 Chương 3). Địa chỉ mục tiêu được xác định từ kết quả `ENUM_TAGS`. Vì đọc-so sánh-ghi liên tục, PLC vẫn hoạt động về mặt hình thức nhưng giá trị vận hành bị áp đặt sai liên tục — khác biệt cơ bản so với `SETPOINT_ATTACK` bên dưới.

**Module thao túng thông số vận hành (SETPOINT_ATTACK) — đã sửa cơ chế**

> **Đây là điểm sửa quan trọng nhất của chương.** Bản gốc mô tả module này chạy vòng lặp liên tục (chu kỳ 0,4-1,2 giây, chọn giá trị ngẫu nhiên mỗi lần) — **sai**. Cơ chế thật, đã xác nhận qua Chương 3 (Hình 3.7, Bảng 3.4) và đối chiếu độc lập với mô tả kỹ thuật trong tài liệu tổng hợp dự án, là **ghi một lần duy nhất** rồi im lặng hoàn toàn.

Trong kịch bản băng truyền, các biến CD1, CD2, CD3 (thời gian dừng/xử lý tại ba trạm, dạng DINT, đơn vị millisecond) lưu tại MD54, MD58, MD62. Module đọc kết quả từ `ENUM_TAGS`, chọn một giá trị bất thường cho mỗi biến (ví dụ đổi từ 5.000ms mặc định sang các giá trị như 100, 250, 45.000, 60.000, 90.000ms), rồi ghi từng biến **đúng một lần**:

```python
write_dint(c, 54, cd1, "CD1_MS")
write_dint(c, 58, cd2, "CD2_MS")
write_dint(c, 62, cd3, "CD3_MS")
```

Không có vòng lặp đọc-ghi lặp lại như `RWRITE_BURST`. Vì vậy, lưu lượng tấn công chỉ xuất hiện trong một khoảng thời gian rất ngắn (vài gói Write Request liên tiếp), nhưng hậu quả — băng truyền vận hành sai nhịp — kéo dài cho đến khi có người phát hiện và khôi phục thủ công giá trị mặc định. Đây chính là lý do Chương 3 (Hình 3.7, "Kết quả") ghi: *"Lưu lượng tấn công chỉ xuất hiện trong thời gian ngắn. Ảnh hưởng tiếp tục cho đến khi các giá trị được khôi phục."*

**Module giả mạo tín hiệu cảm biến (SENSOR_SPOOF)**

*(Giữ nguyên nội dung gốc — chu kỳ 0,4-1,5 giây đã khớp Bảng 3.4.)* Ghi đè các bit cảm biến trong vùng Marker (M5.4/Vat_1, M5.6/Vat_2, M6.0/Vat_3 cho băng truyền) bằng tổ hợp giá trị giả, khiến PLC ra quyết định sai dựa trên dữ liệu đầu vào bị làm giả — chương trình điều khiển bản thân không hề sai.

**Module ghi đè tần suất thấp (STEALTHY_WRITE)**

*(Giữ nguyên cơ chế gốc — chu kỳ đã xác nhận lại là **1,5-3,0 giây**, không phải giá trị 20-60 giây từng xuất hiện ở một tài liệu tổng hợp khác của dự án; cần rà soát nếu tài liệu đó được dùng làm nguồn tham khảo ở nơi khác.)* Module đọc trạng thái hiện tại của bit STOP/START trước mỗi lần ghi, chỉ ghi khi giá trị chưa đúng với mục tiêu — giảm tối đa số gói tin phát sinh, khiến lưu lượng gần như không phân biệt được với polling HMI hợp lệ.

### Module Tấn công từ chối dịch vụ

**S7_FLOOD (flood.py)** — *(Giữ nguyên phần giải thích giao thức S7comm/TPKT/COTP đã kiểm chứng chính xác.)* Module giả mạo thiết bị yêu cầu kết nối, hoàn tất bắt tay COTP CR/CC nhưng không trao đổi COTP DT, chỉ duy trì bằng TCP Keepalive. Dùng threading để mở đồng thời **6 luồng** (số liệu bổ sung, khớp Bảng 3.4 Chương 3) chiếm slot kết nối giới hạn của PLC, khiến HMI/TIA Portal hợp lệ không thể kết nối.

**SYN_FLOOD** — *(Giữ nguyên — 20 luồng đã khớp Bảng 3.4.)* Tấn công ở tầng TCP thấp hơn S7_FLOOD: 20 luồng gửi TCP SYN liên tục tới cổng 102, không hoàn tất bắt tay, làm cạn hàng đợi SYN backlog trước khi COTP kịp thiết lập.

**PROTOCOL_FUZZ** — *(Giữ nguyên — payload 12-80 byte, chu kỳ 0,05-0,25 giây đã khớp Bảng 3.4.)* Gửi TPKT header hợp lệ kèm payload ngẫu nhiên, kiểm tra khả năng xử lý lỗi của PLC.

## Tiểu kết chương 4

*(Cập nhật lại để phản ánh đúng cấu trúc mới: tách công cụ trinh sát DCP khỏi SCAN_PORT, không còn liệt kê "sáu nhóm chức năng" gộp chung DCP với dò quét — thay bằng mô tả chín module Day 1-6 cộng một công cụ trinh sát ban đầu không sinh nhãn.)*

Chương 4 đã trình bày cơ chế giao thức TPKT/COTP/S7comm/S7comm-plus làm nền tảng cho các module tấn công, đồng thời mô tả chi tiết chín module thực sự tạo dữ liệu có nhãn trong Day 1-6 (SCAN_PORT, ENUM_TAGS, RWRITE_BURST, SETPOINT_ATTACK, SENSOR_SPOOF, STEALTHY_WRITE, S7_FLOOD, SYN_FLOOD, PROTOCOL_FUZZ), tách bạch rõ với công cụ trinh sát DCP dùng riêng cho việc khảo sát testbed ban đầu và module CPU_STOP tồn tại trong công cụ nhưng không tạo dữ liệu do bị khóa an toàn. Các module được tổ chức độc lập, thuận tiện bật/tắt theo đúng lịch trình Day 1-6 trình bày ở Chương 3, là nền tảng kỹ thuật trực tiếp cho quá trình thực thi và đánh giá ở các chương tiếp theo.
