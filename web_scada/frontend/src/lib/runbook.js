// Static per-label response suggestions (ISA-18.2 calls this an "alarm
// response procedure" — a short note on what to check/do first, paired with
// the alarm). Purely static text, no backend needed — kept next to the same
// label sets IdsUpload.jsx already uses for MITRE mapping so the two never
// drift apart silently.
export const RUNBOOK_BY_LABEL = {
  // S7comm (train_eval.py Layer 1/3 labels)
  CPU_CONTROL: "Lệnh STOP/START PLC — xác minh ngay với người vận hành xem có ai chủ đích gửi lệnh này không. Nếu không, coi là nghiêm trọng.",
  SCAN: "Có dò quét cổng/dịch vụ trên mạng PLC — đối chiếu IP nguồn trong pcap với danh sách máy trạm kỹ sư hợp lệ.",
  ENUMERATION: "Có dò danh sách tag/địa chỉ DB trên PLC — kiểm tra xem có máy lạ nào đang cố dựng bản đồ dữ liệu PLC không.",
  RWRITE: "Có lệnh ghi tag bất thường — đối chiếu ngay với lịch sử lệnh ghi thật trong 'Cảnh báo & Sự kiện' để xem có khớp thao tác của người vận hành không.",
  SPOOF: "Nghi giả mạo giá trị cảm biến — kiểm tra tại chỗ giá trị cảm biến vật lý thật có khớp với giá trị hiển thị trên web không.",
  STEALTHY: "Ghi lệnh âm thầm, thay đổi nhỏ khó nhận ra — rà lại toàn bộ log ghi lệnh gần đây, không chỉ riêng sự kiện này.",
  FLOOD: "Ngập gói tin/lệnh — kiểm tra băng thông và độ trễ phản hồi PLC, cân nhắc cô lập tạm nguồn gửi ở tầng mạng.",
  FUZZ: "Gói tin dị dạng liên tục — kiểm tra PLC có báo lỗi giao thức tăng bất thường không, có thể PLC đang bị dò lỗi phần mềm.",
  ANOMALY: "Dữ liệu lạ, model chưa từng thấy lúc train — chưa chắc là tấn công. Nghi ngờ thật thì cần admin xác nhận.",
  // OPC UA (train_opcua_eval.py labels)
  OPCUA_ENDPOINT_DISCOVERY: "Dò endpoint OPC UA — kiểm tra IP nguồn có nằm trong danh sách máy trạm được cấp phép không.",
  OPCUA_NODE_BROWSE: "Dò cây node/địa chỉ dữ liệu — theo dõi xem có tiếp tục leo thang sang đọc/ghi dữ liệu thật không.",
  OPCUA_SESSION_BURST: "Tạo session dồn dập — có thể là DoS ở tầng phiên, kiểm tra tải CPU của OPC UA server.",
  OPCUA_SUBSCRIPTION_FLOOD: "Đăng ký subscription hàng loạt — kiểm tra tải server, cân nhắc giới hạn số subscription mỗi session.",
  OPCUA_MALICIOUS_WRITE: "Lệnh ghi bị nghi ngờ/từ chối — đối chiếu ngay với lịch sử lệnh ghi thật, xác minh với người vận hành.",
  OPCUA_READ_SCRAPING: "Đọc dữ liệu hàng loạt, có hệ thống — nghi thu thập dữ liệu quy mô lớn, kiểm tra danh tính session.",
  OPCUA_PROTOCOL_FUZZ: "Gói tin OPC UA dị dạng liên tục — theo dõi log lỗi của OPC UA server, khả năng đang bị dò lỗi phần mềm.",
  OPCUA_BEHAVIORAL_PROFILING: "Theo dõi hành vi hệ thống có hệ thống trong thời gian dài — khả năng đang trinh sát trước khi tấn công thật.",
  OPCUA_SLOWLORIS: "Giữ kết nối mở kéo dài, gửi dữ liệu nhỏ giọt — kiểm tra số kết nối treo trên OPC UA server, có thể cạn tài nguyên.",
  OPCUA_RECURSIVE_BROWSE: "Duyệt đệ quy toàn bộ address space — nghi dựng bản đồ dữ liệu PLC quy mô lớn, theo dõi IP nguồn.",
};

export function runbookFor(label) {
  return RUNBOOK_BY_LABEL[label] || null;
}
