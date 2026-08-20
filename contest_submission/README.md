# Hồ sơ dự thi — Web-SCADA & AI Giám sát An ninh Truyền thông Công nghiệp

Cấu trúc 3 phần theo yêu cầu hồ sơ:

```
contest_submission/
├── 01_TomTat_PhanMem/
│   └── TomTat_PhanMem.docx        # Tóm tắt <1000 từ: độc đáo, hữu ích, sáng tạo, chức năng
├── 02_MaNguon_ThuVien/
│   ├── THU_VIEN_CONG_CU.md        # Danh mục thư viện/công cụ sử dụng
│   └── MaNguon/                   # Toàn bộ mã nguồn (backend + frontend + pipeline AI)
└── 03_CaiDat_ChayThu/
    ├── install.sh / install.bat   # Cài đặt 1 lần (venv Python + npm)
    ├── run_backend.sh / .bat      # Chạy backend FastAPI (cổng 8000)
    ├── run_frontend.sh / .bat     # Chạy frontend Vite (cổng 5173)
    └── HUONG_DAN_TRIEN_KHAI_AI.md # Hướng dẫn thu thập dữ liệu, huấn luyện và
                                    # triển khai mô hình AI 3 tầng vào Web-SCADA
```

## Thứ tự chạy demo nhanh

```bash
cd 03_CaiDat_ChayThu
bash install.sh          # hoặc install.bat trên Windows — chỉ cần chạy 1 lần
bash run_backend.sh      # cửa sổ terminal 1
bash run_frontend.sh     # cửa sổ terminal 2
```

Mở `http://localhost:5173`, đăng nhập bằng tài khoản trong
`02_MaNguon_ThuVien/MaNguon/web_scada/backend/.env` (mặc định `admin` /
`changeme123` — đổi trong `.env` trước khi dùng thật).

**Lưu ý:** nếu chưa có OPC UA server/PLC thật kết nối tới `OPCUA_ENDPOINT`
trong `.env`, giao diện vẫn chạy được nhưng các tag sẽ hiển thị OFFLINE — đây
là hành vi đúng theo nguyên tắc "không hiển thị số liệu giả" của hệ thống, xem
`01_TomTat_PhanMem/TomTat_PhanMem.docx` mục 3.

Chi tiết huấn luyện/triển khai mô hình AI (pipeline 3 tầng: rule-based →
anomaly detection → ensemble classifier, và tính năng phân tích pcap trực
tiếp trên web): xem `03_CaiDat_ChayThu/HUONG_DAN_TRIEN_KHAI_AI.md`.
