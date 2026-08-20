# Danh mục thư viện & công cụ

Thư mục `MaNguon/` chứa toàn bộ mã nguồn (bản sao trực tiếp từ repo làm việc, đã
loại bỏ file rác `__pycache__`, `node_modules`, dữ liệu runtime `*.db`, `.env`
chứa secret, và các bộ dataset thô dung lượng lớn không phải mã nguồn).

Thư viện được cài qua trình quản lý gói chuẩn (`pip`, `npm`) theo các file khai
báo đã có sẵn trong mã nguồn — không cần tải thủ công. Bảng dưới đây tổng hợp
để hội đồng nắm nhanh công nghệ sử dụng.

## 1. Backend Web-SCADA — `web_scada/backend/requirements.txt`

| Thư viện | Vai trò |
|---|---|
| fastapi, uvicorn | Web framework + ASGI server cho REST API/WebSocket |
| asyncua | Client giao tiếp giao thức OPC UA với PLC |
| sqlalchemy | ORM cho historian (SQLite) và cơ sở dữ liệu người dùng |
| bcrypt, pyjwt | Băm mật khẩu và phát hành/xác thực JWT cho xác thực người dùng |
| pandas | Đọc/tổng hợp kết quả mô hình ML (CSV) để hiển thị |
| scikit-learn, xgboost, imbalanced-learn, joblib | Nạp và chạy suy luận (predict) mô hình IDS 3 lớp đã huấn luyện |
| httpx | Gửi cảnh báo qua Telegram Bot API |
| psutil | Đo tải CPU/RAM của máy chạy backend |
| python-dotenv, pyyaml | Đọc cấu hình `.env` và danh mục tag `config/opcua_tags.yaml` |

## 2. Frontend Web-SCADA — `web_scada/frontend/package.json`

| Thư viện | Vai trò |
|---|---|
| react, react-dom, react-router-dom | Nền tảng giao diện SPA và định tuyến trang |
| recharts | Vẽ biểu đồ xu hướng/lịch sử tag |
| lucide-react | Bộ icon giao diện |
| jspdf, html2canvas | Xuất báo cáo/màn hình sang PDF |
| vite, @vitejs/plugin-react | Build tool & dev server |
| tailwindcss, postcss, autoprefixer | Framework CSS |

## 3. Pipeline thu thập dữ liệu & huấn luyện AI (thư mục gốc repo)

| Thư viện / công cụ | Vai trò |
|---|---|
| scapy | Bắt và phân tích gói tin mạng công nghiệp |
| python-snap7 | Giao tiếp giao thức S7 (PLC Siemens) |
| pymodbus | Giao tiếp giao thức Modbus |
| asyncua / opcua | Giao tiếp và mô phỏng OPC UA |
| pandas, numpy | Xử lý, tổng hợp dữ liệu thành đặc trưng (feature) |
| scikit-learn, xgboost | Huấn luyện & đánh giá mô hình học máy (`train_ml.py`) |
| matplotlib, seaborn | Vẽ biểu đồ đánh giá mô hình (confusion matrix, ROC...) |
| Wireshark / tshark (công cụ ngoài) | Bắt gói tin `.pcap` phục vụ trích xuất đặc trưng offline |
| Một OPC UA server / PLC giả lập (công cụ ngoài, không đi kèm mã nguồn) | Nguồn dữ liệu thật cho testbed |

Phiên bản chính xác của từng thư viện: xem trực tiếp trong `MaNguon/requirements.txt`,
`MaNguon/web_scada/backend/requirements.txt` và `MaNguon/web_scada/frontend/package.json`
— đây là nguồn chuẩn, bảng trên chỉ tóm tắt vai trò để dễ đọc.
