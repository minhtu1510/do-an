# 🛡️ Risk Assessment Module - TÍCH HỢP HOÀN CHỈNH

## ✅ ĐÃ TÍCH HỢP VÀO WEBAPP CHÍNH!

Risk Assessment module giờ đã được **tích hợp hoàn toàn** vào **ICSScout Web Application** (`start_webapp.py`).

---

## 🚀 CÁCH SỬ DỤNG

### **Bước 1: Khởi động ICSScout Webapp**

```bash
cd /home/user/S7.Pwn
python3 start_webapp.py
```

Bạn sẽ thấy:
```
============================================================
ICSScout Web Application v1.x.x
============================================================
[✓] Risk Assessment module loaded
[✓] Risk Assessment routes registered
Server: http://0.0.0.0:5000
Press Ctrl+C to stop
============================================================
```

### **Bước 2: Truy cập Web Application**

Mở browser và vào: **http://localhost:5000/**

---

## 📍 VỊ TRÍ TRÊN GIAO DIỆN

### **Cách 1: Navigation Menu (Luôn luôn hiển thị)**

Ở top navigation bar, bạn sẽ thấy:

```
┌────────────────────────────────────────────────────────────────┐
│ 🛡️ ICSScout                                                    │
│                                                                │
│ Dashboard | Packet Analyzer | Network Scanner | Vulnerabilities│
│ Devices | Monitoring | S7 Auth | [🛡️ Risk Assessment] ← ĐÂY  │
└────────────────────────────────────────────────────────────────┘
```

**Risk Assessment link** ở cuối navigation menu, **màu đỏ** để nổi bật!

---

### **Cách 2: Dashboard Quick Actions**

Trên trang Dashboard chính, trong phần Welcome Banner:

```
┌─────────────────────────────────────────────────────────────┐
│ Welcome to ICSScout                                         │
│ Industrial Control Systems Security Assessment Platform     │
│                                                             │
│ [Start Packet Capture] [Scan Network] [Scan Vulnerabilities]│
│ [🛡️ Risk Assessment] ← Nút đỏ nổi bật                      │
└─────────────────────────────────────────────────────────────┘
```

**Risk Assessment button** màu đỏ (bg-red-500) để dễ nhận biết!

---

### **Cách 3: Direct URL**

Truy cập trực tiếp:
```
http://localhost:5000/risk-assessment
```

---

## 🎯 QUY TRÌNH SỬ DỤNG ĐẦY ĐỦ

### **1. Quét Mạng (Recommended)**

Trước tiên, quét mạng để thu thập thông tin thiết bị:

1. Click **"Network Scanner"** trong menu
2. Chọn network range (hoặc auto-detect)
3. Click **"Start Scan"**
4. Đợi quét xong → Devices sẽ được lưu trong session

### **2. (Optional) Scan Vulnerabilities**

1. Click **"Vulnerabilities"** trong menu
2. Click **"Scan Devices"**
3. Đợi scan CVEs xong

### **3. Chạy Risk Assessment**

1. Click **"Risk Assessment"** trong menu HOẶC nút đỏ trên dashboard
2. Trang Risk Assessment Dashboard sẽ mở ra
3. Click nút **"Run Assessment"** (màu xanh lá, góc phải trên)
4. Đợi 30-60 giây
5. Kết quả hiển thị:
   - Overall Risk Score (vòng tròn lớn với màu sắc)
   - 4 Category Scores (Network, Device, Vulnerability, Compliance)
   - Interactive Charts
   - High Risk Devices Table
   - Remediation Action Plan

### **4. Export Báo Cáo**

Cuối trang Risk Assessment Dashboard:

```
┌─────────────────────────────────────────────────────────────┐
│ 📥 Export Report                                            │
│                                                             │
│ [📄 Export PDF] [📝 Export Word] [💾 Export JSON]          │
└─────────────────────────────────────────────────────────────┘
```

Click một trong các nút để download báo cáo!

---

## 🌐 TÍNH NĂNG TÍCH HỢP

### **Chia sẻ dữ liệu với các module khác**

Risk Assessment **tự động sử dụng** dữ liệu từ:

- ✅ **Session Manager**: Devices đã scan
- ✅ **Vulnerability Scanner**: CVE results
- ✅ **Network Scanner**: Network topology
- ✅ **Device Manager**: Device information

→ **Không cần scan lại!** Dữ liệu được chia sẻ giữa các modules.

---

## 📊 GIAO DIỆN

### **Navigation Menu**
- **Icon**: 🛡️ (shield-virus)
- **Màu sắc**: Đỏ (text-red-500) để highlight security
- **Vị trí**: Cuối cùng trong navigation bar

### **Dashboard Button**
- **Style**: Red button (bg-red-500)
- **Size**: Large (px-6 py-3)
- **Effect**: Hover → darker red

### **Risk Assessment Page**
- **Style**: Bootstrap 5 + Chart.js
- **Layout**: Responsive, works on all screen sizes
- **Features**:
  - Real-time charts
  - Color-coded risk levels
  - Sortable device table
  - Expandable action items

---

## 🔧 DEPENDENCIES

Tất cả dependencies đã có sẵn trong ICSScout:

✅ Flask + Flask-SocketIO
✅ Chart.js (CDN)
✅ Bootstrap 5 (CDN)
✅ Font Awesome (CDN)

**Chỉ cần thêm** (cho PDF/Word export):
```bash
pip install reportlab python-docx
```

---

## 🎨 SO SÁNH VỚI DEMO WEBAPP

| Feature | Demo Webapp (`simple_risk_demo.py`) | ICSScout Integration |
|---------|-------------------------------------|----------------------|
| Data | Mock data (fake) | Real scan data ✅ |
| Integration | Standalone | Fully integrated ✅ |
| UI | Separate | Consistent with ICSScout ✅ |
| Session sharing | No | Yes ✅ |
| Navigation | None | Full navigation menu ✅ |
| Dependencies | Minimal | All ICSScout features ✅ |

**→ Nên dùng ICSScout Integration!**

---

## 📂 API ENDPOINTS

Tất cả endpoints hoạt động trong ICSScout webapp:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/risk-assessment` | GET | Dashboard page |
| `/api/risk/assess` | POST | Run assessment |
| `/api/risk/report/<id>` | GET | Get report details |
| `/api/risk/export/<id>/<format>` | GET | Export PDF/DOCX/JSON |
| `/api/risk/reports` | GET | List all reports |
| `/api/risk/devices` | GET | Device risk profiles |
| `/api/risk/compliance` | GET | Compliance status |

---

## ✨ TÍNH NĂNG NỔI BẬT

### **1. Tích hợp với ICSScout Platform**
- Dùng chung session manager
- Dùng chung device data
- Dùng chung vulnerability scanner
- Consistent UI/UX

### **2. Navigation dễ dàng**
- Luôn visible trong menu
- Quick access button trên dashboard
- Direct URL access

### **3. Professional UI**
- Tailwind CSS styling (consistent với ICSScout)
- Responsive design
- Dark theme matching ICSScout

### **4. Real Data Analysis**
- Phân tích thiết bị thật từ network scan
- CVE detection từ vulnerability scanner
- Network topology từ scanner results

---

## 🎯 USER FLOW

```
1. User visits http://localhost:5000/
   ↓
2. Clicks "Network Scanner" → Scans network
   ↓
3. Devices discovered and saved in session
   ↓
4. (Optional) Clicks "Vulnerabilities" → Scans CVEs
   ↓
5. Clicks "Risk Assessment" in menu
   ↓
6. Risk Assessment Dashboard opens
   ↓
7. Clicks "Run Assessment"
   ↓
8. System analyzes:
   - Network security (from topology)
   - Device security (from device info)
   - Vulnerabilities (from CVE scan)
   - Compliance (IEC 62443, NIST)
   ↓
9. Results displayed with charts
   ↓
10. User exports PDF/Word report
```

---

## 📖 FILES LIÊN QUAN

| File | Mô tả |
|------|-------|
| `start_webapp.py` | **Entry point** - Khởi động ICSScout |
| `icsscout/interfaces/web/app.py` | Main webapp với Risk Assessment integration |
| `icsscout/interfaces/web/templates/base.html` | Navigation menu (có Risk Assessment link) |
| `icsscout/interfaces/web/templates/index.html` | Dashboard (có Risk Assessment button) |
| `s7pwn/templates/risk_assessment.html` | Risk Assessment UI |
| `icsscout/interfaces/web/routes/risk_assessment_routes.py` | API routes |
| `icsscout/core/risk_assessment/` | Backend engine |

---

## 🆚 SO SÁNH VỚI S7PWN WEBAPP

Có 2 webapp trong project:

### **1. ICSScout Webapp** ⭐ (RECOMMENDED)
```bash
python3 start_webapp.py
```
- **Features**: Full platform (packet analyzer, vulnerability scanner, monitoring, S7 auth, **Risk Assessment**)
- **UI**: Professional Tailwind CSS dark theme
- **Integration**: All modules share data
- **Port**: 5000

### **2. S7Pwn Webapp**
```bash
python3 s7pwn/web_gui.py  # Nếu có
```
- **Features**: Simple S7 pentest tools
- **UI**: Basic Bootstrap
- **Integration**: Limited
- **Port**: 5000

**→ Dùng ICSScout Webapp (start_webapp.py) để có đầy đủ tính năng!**

---

## 🎉 TÓM TẮT

✅ **Risk Assessment đã được tích hợp hoàn toàn vào ICSScout**
✅ **2 cách truy cập**: Navigation menu + Dashboard button
✅ **Dùng real data** từ network scan và vulnerability scan
✅ **Consistent UI** với ICSScout platform
✅ **Export báo cáo** PDF/Word/JSON

**Khởi động ngay:**
```bash
python3 start_webapp.py
```

**Truy cập:**
```
http://localhost:5000/ → Click "Risk Assessment"
```

**Enjoy! 🚀**
