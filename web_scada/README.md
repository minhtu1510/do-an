# Web-SCADA

Nền tảng giám sát thời gian thực + điều khiển có kiểm soát + phân tích lưu lượng
bằng AI cho testbed ICS: đọc/ghi tag qua OPC UA, đẩy dữ liệu xuống trình duyệt qua
WebSocket, lưu lịch sử tag, sinh cảnh báo/sự kiện, và phân tích file pcap bằng mô
hình IDS 3 tầng ngay trên web.

Gồm 2 phần chạy độc lập:
- `backend/` — FastAPI + OPC UA gateway (Python)
- `frontend/` — React + Vite (Node)

## Yêu cầu

- Python 3.11+ (đã test với 3.11)
- Node.js 18+ và npm
- Một OPC UA server truy cập được (S7-1500 thật hoặc tương đương), địa chỉ cấu hình
  qua `OPCUA_ENDPOINT`
- `tshark` trong PATH — chỉ cần cho tính năng phân tích pcap (trích xuất đặc trưng)

## Chạy backend

```bash
cd web_scada/backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # rồi sửa .env, tối thiểu điền JWT_SECRET (xem bên dưới)
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Khi khởi động lần đầu, backend tự: tạo bảng SQLite (historian + người dùng), tạo tài
khoản admin đầu tiên từ `ADMIN_USERNAME`/`ADMIN_PASSWORD`, kết nối OPC UA endpoint, và
load tag registry từ `config/opcua_tags.yaml`. Mở:
- REST API tại `http://localhost:8000/api/...`
- WebSocket tại `ws://localhost:8000/ws/process?token=<JWT>`

## Chạy frontend

```bash
cd web_scada/frontend
npm install
npm run dev
```

Mở `http://localhost:5173`, đăng nhập bằng tài khoản admin ở `.env`. Vite đã cấu hình
proxy sẵn (`vite.config.js`) forward `/api` và `/ws` sang backend `127.0.0.1:8000` —
không cần sửa gì khi chạy backend/frontend trên cùng máy.

## Xác thực & phân quyền (RBAC)

Đăng nhập bằng JWT. Bốn vai trò phân cấp, mỗi cấp gồm mọi quyền của cấp dưới:

| Vai trò | Quyền |
|---|---|
| `viewer` | Xem các trang giám sát (Tổng quan, Giám sát tiến trình, Cảnh báo, Xu hướng, Trạng thái) |
| `operator` | viewer + Phân tích pcap (IDS Upload) + Lịch sử phân tích + xác nhận (ack) cảnh báo |
| `controller` | operator + **ghi lệnh** xuống tag PLC nằm trong whitelist (`writable` ở `opcua_tags.yaml`) |
| `admin` | controller + quản lý người dùng + mở khoá lệnh ghi |

## Các trang chính

- **Tổng quan** — KPI sản xuất, tiến độ, trạng thái băng tải theo thời gian thực.
- **Giám sát tiến trình** — sơ đồ luồng, tag quá trình; với role controller+ có bảng
  điều khiển ghi lệnh trực tiếp xuống PLC (chạy/dừng băng tải), mọi lệnh đều được ghi
  audit log.
- **Cảnh báo & Sự kiện** — sự kiện suy ra từ thay đổi tag/kết nối thật; lưu bền vào
  SQLite (sống qua restart); xuất CSV.
- **Phân tích lưu lượng mạng (IDS Upload)** — tải file pcap, mô hình IDS 3 tầng
  (rule-based → anomaly detection → ensemble) dự đoán nhãn tấn công, có phát lại
  timeline; hỗ trợ cả S7comm và OPC UA.
- **Lịch sử phân tích PCAP** — lưu lại các lần phân tích đã chạy.
- **Xu hướng & Lịch sử** — biểu đồ historian thật (SQLite), chỉ ghi khi giá trị đổi;
  xuất CSV/PDF.
- **Trạng thái hệ thống** — CPU/RAM/disk của máy chạy backend (không phải PLC).
- **Người dùng** (admin) — tạo/sửa vai trò/xoá tài khoản.

**Tự động khoá lệnh ghi (auto write-lock):** khi phân tích pcap phát hiện lệnh ghi giả
mạo độ tin cậy cao (RWRITE/SPOOF/OPCUA_MALICIOUS_WRITE), hệ thống tự khoá đường ghi lệnh
PLC qua web; chỉ admin mở lại được (`POST /api/control/unlock`).

## Biến môi trường (`web_scada/backend/.env`)

| Biến | Bắt buộc | Mặc định | Ý nghĩa |
|---|---|---|---|
| `OPCUA_ENDPOINT` | Có | `opc.tcp://192.168.210.211:4840` | Địa chỉ OPC UA server cần giám sát |
| `JWT_SECRET` | **Có** | (không có mặc định) | Khoá ký JWT — backend **từ chối chạy** nếu để trống. Sinh: `python3 -c "import secrets;print(secrets.token_hex(32))"` |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | Có (lần đầu) | `admin` / `changeme123` | Tài khoản admin tạo tự động khi bảng users còn trống |
| `JWT_EXPIRES_HOURS` | Không | `12` | Thời hạn token |
| `OPCUA_SECURITY` | Không | (rỗng = Anonymous) | Bật OPC UA security, vd `Basic256Sha256,SignAndEncrypt,client_cert.der,client_key.pem` (xem `HUONG_DAN_OPCUA_SECURITY_AB.md`) |
| `OPCUA_USER` / `OPCUA_PASSWORD` | Không | (rỗng) | User/mật khẩu OPC UA khi server yêu cầu xác thực |
| `CORS_ORIGINS` | Không | `http://localhost:5173` | Origin frontend được phép gọi API |
| `DATABASE_URL` | Không | SQLite (`backend/data/historian.db`) | Đặt để dùng PostgreSQL thay SQLite |
| `IDS_MODEL_DIR` | Không | `model/` ở gốc repo | Thư mục model IDS đã train (cho phân tích pcap) |
| `TAG_REGISTRY_PATH` | Không | `config/opcua_tags.yaml` | Đường dẫn khác tới file khai báo tag |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | Không | (rỗng) | Bật push Telegram cho event ERROR / ATTACK_*; để trống thì tắt |

`BACKEND_HOST`/`BACKEND_PORT` trong `.env` hiện chỉ mang tính ghi chú — host/port thực
tế truyền qua flag `--host`/`--port` của `uvicorn`.

## Lưu ý cho người chạy demo

- **Cần OPC UA server thật:** nếu `OPCUA_ENDPOINT` không kết nối được, giao diện vẫn
  chạy nhưng tag hiển thị OFFLINE/stale — đúng hành vi "không hiển thị số liệu giả",
  không phải lỗi.
- **Phân tích pcap** cần: `tshark` trong PATH + thư mục model đã train tại `IDS_MODEL_DIR`
  (chạy `python train_eval.py --mode train ...` ở gốc repo trước). Chưa có model thì
  trang báo rõ "chưa cấu hình", không bịa kết quả.
- **Historian** dùng SQLite mặc định, tự tạo tại `backend/data/historian.db` — không
  cần cài PostgreSQL. Biểu đồ Xu hướng chỉ có dữ liệu sau khi tag thật đổi giá trị.
- Sự kiện/cảnh báo và người dùng lưu bền trong SQLite (sống qua restart).
