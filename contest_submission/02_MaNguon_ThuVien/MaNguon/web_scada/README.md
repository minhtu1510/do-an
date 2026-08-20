# Web-SCADA

Giao diện giám sát thời gian thực (read-only) cho testbed ICS: đọc tag qua OPC UA,
đẩy dữ liệu xuống trình duyệt qua WebSocket, hiển thị alarm/event, kết quả kịch bản
tấn công (`tests/day8/run_day8.py`) và kết quả huấn luyện ML (`train_ml.py`).

Gồm 2 phần chạy độc lập:
- `backend/` — FastAPI + OPC UA gateway (Python)
- `frontend/` — React + Vite (Node)

## Yêu cầu

- Python 3.11+ (đã test với 3.11)
- Node.js 18+ và npm
- Một OPC UA server đang chạy và truy cập được (PLC thật hoặc simulator), địa chỉ
  cấu hình qua `OPCUA_ENDPOINT`

## Chạy backend

```bash
cd web_scada/backend
pip install -r requirements.txt
```

Backend đọc cấu hình từ file `.env` trong `web_scada/backend/` (xem bảng biến môi
trường bên dưới). Copy/sửa file này trước khi chạy, không hard-code endpoint trong code.

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Backend sẽ tự kết nối OPC UA endpoint khai báo trong `.env`, load tag registry từ
`config/opcua_tags.yaml` (ở thư mục gốc repo), và mở:
- REST API tại `http://localhost:8000/api/...`
- WebSocket tại `ws://localhost:8000/ws/process`

## Chạy frontend

```bash
cd web_scada/frontend
npm install
npm run dev
```

Mở `http://localhost:5173`. Vite dev server đã cấu hình proxy sẵn (`vite.config.js`)
để forward `/api` và `/ws` sang backend tại `127.0.0.1:8000` — không cần sửa gì thêm
khi chạy backend/frontend trên cùng máy.

## Biến môi trường (`web_scada/backend/.env`)

| Biến | Bắt buộc | Mặc định | Ý nghĩa |
|---|---|---|---|
| `OPCUA_ENDPOINT` | Có | `opc.tcp://192.168.210.211:4840` | Địa chỉ OPC UA server cần giám sát |
| `CORS_ORIGINS` | Không | `http://localhost:5173` | Danh sách origin được phép gọi API (phân tách bằng dấu phẩy) |
| `TELEGRAM_BOT_TOKEN` | Không | (rỗng) | Bật push Telegram cho event mức ERROR / ATTACK_* nếu điền cùng `TELEGRAM_CHAT_ID`; để trống thì bỏ qua hoàn toàn |
| `TELEGRAM_CHAT_ID` | Không | (rỗng) | Chat ID nhận thông báo Telegram |
| `ML_RESULTS_DIR` | Không | `ml_results/` ở thư mục gốc repo | Thư mục chứa output của `train_ml.py` (để trang Dataset & Model Stats đọc) |
| `TAG_REGISTRY_PATH` | Không | `config/opcua_tags.yaml` | Đường dẫn khác tới file khai báo tag, nếu không dùng file mặc định |

`BACKEND_HOST`/`BACKEND_PORT` trong `.env` hiện chỉ mang tính ghi chú — chưa được
code đọc, host/port thực tế truyền qua flag `--host`/`--port` của `uvicorn` như trên.

## Giới hạn hiện tại (để giám khảo/người chạy demo biết trước)

- **Chỉ đọc (read-only)**: không có endpoint ghi tag xuống PLC.
- **Trends & History**: chưa có historian, trang chỉ báo "Not configured" (xem
  `backend/app/history/`). Alarm/event và kết quả kịch bản chỉ lưu in-memory, mất khi
  restart backend.
- **Dataset & Model Stats**: trống cho đến khi chạy `python train_ml.py --output-dir
  ml_results` ở thư mục gốc repo (hoặc trỏ `ML_RESULTS_DIR` tới nơi đã copy output).
- **Security / IDS**: bảng kịch bản tấn công chỉ có dữ liệu sau khi chạy
  `python tests/day8/run_day8.py --execute` trong lúc backend đang bật.
- Không có xác thực người dùng (không phân quyền Admin/Operator/Viewer).
