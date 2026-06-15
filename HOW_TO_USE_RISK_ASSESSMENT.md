# 📖 HƯỚNG DẪN SỬ DỤNG RISK ASSESSMENT MODULE

## 🚀 Cách Truy Cập

### **Phương pháp 1: Demo Webapp (Khuyến nghị - Nhanh nhất)**

Demo webapp cho phép bạn **xem giao diện** Risk Assessment mà không cần cài đặt tất cả dependencies.

```bash
cd /home/user/S7.Pwn
python3 simple_risk_demo.py
```

**Sau đó truy cập:**
- 🏠 Main: http://localhost:5000/
- 🛡️ **Risk Assessment: http://localhost:5000/risk-assessment**

⚠️ **LƯU Ý**: Demo này dùng **mock data** (dữ liệu mẫu), không phải kết quả thật.

---

### **Phương pháp 2: Full Webapp (Thực tế)**

Để chạy với tính năng đầy đủ, cài đặt dependencies:

```bash
cd /home/user/S7.Pwn

# Cài đặt dependencies chính
pip3 install flask flask-socketio flask-cors python-snap7 scapy pymodbus

# Cài đặt dependencies cho Risk Assessment
pip3 install reportlab python-docx

# Khởi động webapp
python3 start_webapp.py
```

**Sau đó truy cập:**
- Main: http://localhost:5000/
- **Risk Assessment**: http://localhost:5000/risk-assessment

---

## 📍 Vị Trí trên Giao Diện

### **Từ Trang Chính:**

Khi vào http://localhost:5000/, bạn sẽ thấy header có các nút:

```
┌────────────────────────────────────────────────────────────┐
│  S7Pwn Web GUI                                             │
│                                                            │
│  [Devices: 0] [PLCs: 0] [No Target]                      │
│  [🗺️ Network Topology] [🛡️ Risk Assessment] ← Click đây! │
└────────────────────────────────────────────────────────────┘
```

**Nút 🛡️ Risk Assessment màu đỏ** nằm ở góc phải trên!

---

## 🎮 Quy Trình Sử Dụng

### **BƯỚC 1: Khởi động webapp**

**Demo (mock data):**
```bash
python3 simple_risk_demo.py
```

**Full (real data):**
```bash
python3 start_webapp.py
```

### **BƯỚC 2: Truy cập Dashboard**

Mở browser: http://localhost:5000

### **BƯỚC 3: (Optional) Quét mạng trước**

Từ trang chính:
1. Chọn protocols: Profinet DCP, Modbus TCP, S7
2. Click **"Start Scan"**
3. Đợi quét xong

### **BƯỚC 4: Vào Risk Assessment**

Click nút **🛡️ Risk Assessment** ở header

### **BƯỚC 5: Chạy đánh giá**

1. Click nút **"Run Assessment"** (màu xanh lá, góc phải)
2. Đợi 30-60 giây
3. Dashboard hiển thị kết quả:
   - Overall Risk Score (vòng tròn lớn)
   - 4 category scores (Network, Device, Vulnerability, Compliance)
   - Charts
   - Danh sách thiết bị nguy hiểm
   - Action plan

### **BƯỚC 6: Export báo cáo**

Cuối trang có 3 nút:
- **📄 Export PDF** → Báo cáo pentest chuyên nghiệp
- **📝 Export Word** → File DOCX có thể chỉnh sửa
- **💾 Export JSON** → Raw data

---

## 🖼️ Screenshots Giao Diện

### **Main Dashboard với Risk Assessment Link:**
```
┌─────────────────────────────────────────────────────────┐
│ S7Pwn Web GUI                                           │
│                                                         │
│ [Devices: 0] [PLCs: 0] [No Target]                    │
│ [🗺️ Network Topology] [🛡️ Risk Assessment] ← ĐÂY     │
└─────────────────────────────────────────────────────────┘
```

### **Risk Assessment Dashboard:**
```
┌─────────────────────────────────────────────────────────┐
│ 🛡️ ICSScout - Risk Assessment Dashboard               │
│                          [🏠 Home] [▶️ Run Assessment]  │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│           Overall Security Risk                         │
│                                                         │
│       ┌───────────┐      Total Devices: 15            │
│       │    75     │      Critical Findings: 5          │
│       │   HIGH    │      High Risk Devices: 3          │
│       └───────────┘                                     │
└─────────────────────────────────────────────────────────┘

┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│  Network    │ │   Device    │ │Vulnerability│ │ Compliance  │
│  65.5/100   │ │  45.2/100   │ │  55.0/100   │ │   40.0%     │
│   MEDIUM    │ │    HIGH     │ │   MEDIUM    │ │   SL-1      │
└─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘

[Charts: Findings by Severity, Risk by Category]

[High Risk Devices Table]

[Remediation Action Plan]

[Export Buttons: PDF | Word | JSON]
```

---

## 🎯 Mức Độ Rủi Ro

| Màu | Level | Điểm | Hành động |
|-----|-------|------|-----------|
| 🔴 | **CRITICAL** | 90-100 | Khắc phục ngay (24h) |
| 🟠 | **HIGH** | 70-89 | Ưu tiên cao (1 tuần) |
| 🟡 | **MEDIUM** | 40-69 | Kế hoạch (1 tháng) |
| 🟢 | **LOW** | 20-39 | Theo dõi (3 tháng) |
| ⚪ | **INFO** | 0-19 | Duy trì |

---

## 🔧 Troubleshooting

### **Vấn đề 1: Không thấy nút Risk Assessment**

**Giải pháp:**
- Đảm bảo đã pull code mới nhất
- Kiểm tra file `/home/user/S7.Pwn/s7pwn/templates/index.html` có dòng:
  ```html
  <a href="/risk-assessment" class="status-item" style="background: #dc3545; color: white;">
      🛡️ Risk Assessment
  </a>
  ```

### **Vấn đề 2: Click vào Risk Assessment bị "404 Not Found"**

**Giải pháp:**
- Dùng **demo webapp** thay vì webapp đầy đủ:
  ```bash
  python3 simple_risk_demo.py
  ```

### **Vấn đề 3: Webapp không khởi động (lỗi dependencies)**

**Giải pháp:**
- Dùng demo webapp (không cần full dependencies):
  ```bash
  python3 simple_risk_demo.py
  ```
- Hoặc cài đặt dependencies:
  ```bash
  pip3 install flask python-snap7 scapy reportlab python-docx
  ```

### **Vấn đề 4: "Run Assessment" không có kết quả**

**Giải pháp Demo:**
- Nếu dùng `simple_risk_demo.py`, nó sẽ hiển thị **mock data**
- Kết quả là dữ liệu mẫu cho demo, không phải scan thật

**Giải pháp Full:**
- Cần quét mạng trước từ trang chính
- Đảm bảo có devices đã được quét

---

## 📦 Files Liên Quan

| File | Mô tả |
|------|-------|
| `simple_risk_demo.py` | Demo webapp với mock data |
| `start_webapp.py` | Full webapp (cần dependencies) |
| `s7pwn/templates/risk_assessment.html` | Giao diện dashboard |
| `s7pwn/templates/index.html` | Trang chính có link |
| `icsscout/core/risk_assessment/` | Backend engine |
| `icsscout/interfaces/web/routes/` | API routes |

---

## 🌐 URLs Quan Trọng

| URL | Chức năng |
|-----|-----------|
| http://localhost:5000/ | Trang chính |
| http://localhost:5000/risk-assessment | **Risk Assessment Dashboard** |
| http://localhost:5000/topology | Network Topology |
| http://localhost:5000/api/risk/assess | API chạy assessment |
| http://localhost:5000/api/risk/reports | API lấy danh sách báo cáo |

---

## ✅ Checklist Nhanh

- [ ] Webapp đang chạy (`python3 simple_risk_demo.py`)
- [ ] Truy cập http://localhost:5000/ thành công
- [ ] Thấy nút **🛡️ Risk Assessment** màu đỏ ở header
- [ ] Click vào nút → chuyển đến dashboard
- [ ] Dashboard hiển thị đẹp với charts
- [ ] Click "Run Assessment" → có kết quả (hoặc mock data)
- [ ] Export PDF/Word hoạt động

---

## 📞 Hỗ Trợ

Nếu vẫn gặp vấn đề:

1. **Kiểm tra webapp đang chạy:**
   ```bash
   ps aux | grep simple_risk_demo
   ```

2. **Kiểm tra port 5000 có mở:**
   ```bash
   curl http://localhost:5000/
   ```

3. **Xem logs:**
   ```bash
   tail -f /tmp/demo.log
   ```

4. **Restart webapp:**
   ```bash
   pkill -9 -f simple_risk_demo
   python3 simple_risk_demo.py
   ```

---

## 🎉 Kết luận

Module **Risk Assessment** giờ đã:
✅ Có giao diện web đẹp
✅ Có nút truy cập từ trang chính
✅ Có demo webapp dễ sử dụng
✅ Có tài liệu đầy đủ

**URL chính**: http://localhost:5000/risk-assessment

Chúc bạn sử dụng thành công! 🚀
