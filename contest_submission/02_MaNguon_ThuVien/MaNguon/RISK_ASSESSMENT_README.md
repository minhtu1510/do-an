# OT/ICS Risk Assessment Module

## Tổng quan

Module đánh giá rủi ro an toàn thông tin toàn diện cho hệ thống OT/ICS, tích hợp vào ICSScout platform.

## Tính năng chính

### 1. 🎯 Đánh giá Đa chiều

- **Network Security (25%)**: Phân đoạn mạng, giao thức bảo mật, firewall
- **Device Security (30%)**: Authentication, firmware, cấu hình thiết bị
- **Vulnerability Assessment (25%)**: CVE scanning, exploit detection
- **Compliance (20%)**: IEC 62443, NIST CSF

### 2. 📊 Mức độ rủi ro

| Mức độ | Điểm | Mô tả | Hành động |
|--------|------|-------|-----------|
| 🔴 CRITICAL | 90-100 | Nguy cơ cực kỳ cao | Khắc phục ngay (24h) |
| 🟠 HIGH | 70-89 | Nguy cơ cao | Ưu tiên cao (1 tuần) |
| 🟡 MEDIUM | 40-69 | Nguy cơ trung bình | Lên kế hoạch (1 tháng) |
| 🟢 LOW | 20-39 | Nguy cơ thấp | Theo dõi (3 tháng) |
| ⚪ INFO | 0-19 | Chấp nhận được | Duy trì |

### 3. 📝 Xuất báo cáo

- **PDF**: Báo cáo pentest chuyên nghiệp với charts và bảng
- **Word (DOCX)**: Báo cáo có thể chỉnh sửa
- **JSON**: Dữ liệu thô để tích hợp

### 4. 🎨 Web Dashboard

- Giao diện đẹp với Bootstrap 5
- Biểu đồ tương tác với Chart.js
- Real-time risk visualization
- Action plan chi tiết

## Cài đặt

### 1. Dependencies

```bash
pip install reportlab python-docx
# hoặc
pip install -r requirements-risk-assessment.txt
```

### 2. Khởi động Web Application

```bash
python3 start_webapp.py
```

### 3. Truy cập Dashboard

- Main: http://localhost:5000
- Risk Assessment: http://localhost:5000/risk-assessment

## API Endpoints

### POST /api/risk/assess

Thực hiện đánh giá rủi ro toàn diện.

**Request Body:**
```json
{
    "include_vulnerability_scan": true,
    "network_topology": {
        "has_segmentation": false,
        "has_firewall": true,
        "has_vlan": false,
        "it_ot_separated": false
    }
}
```

**Response:**
```json
{
    "success": true,
    "report_id": "RISK-20251106-xxxxx",
    "overall_risk_score": 75.5,
    "overall_risk_level": "HIGH",
    "summary": {
        "total_devices": 15,
        "critical_findings": 5,
        "high_findings": 12,
        "critical_devices": 3
    }
}
```

### GET /api/risk/report/{report_id}

Lấy báo cáo chi tiết.

### GET /api/risk/export/{report_id}/{format}

Xuất báo cáo (pdf, docx, json).

### GET /api/risk/reports

Danh sách tất cả báo cáo.

### GET /api/risk/devices

Danh sách thiết bị với risk profiles.

### GET /api/risk/compliance

Trạng thái tuân thủ IEC 62443, NIST CSF.

## Thuật toán Scoring

### Formula tổng thể:

```
Overall_Risk_Score = (
    Network_Score × 0.25 +
    Device_Score × 0.30 +
    Vulnerability_Score × 0.25 +
    Compliance_Score × 0.20
) × Criticality_Multiplier
```

### Criticality Multipliers:

- Safety PLC: **1.5x**
- SCADA Server: **1.3x**
- Production PLC: **1.2x**
- HMI: **1.1x**
- Network Equipment: **1.0x**

### Deductions:

**Network Security:**
- No segmentation: -40 điểm
- Internet exposed: -20 điểm/device
- Insecure protocols: -15 điểm/protocol

**Device Security:**
- Protection Level 0: -50 điểm
- Default credentials: -40 điểm
- Firmware >5 năm: -40 điểm

**Vulnerabilities:**
- CRITICAL CVE + exploit: -40 điểm
- HIGH CVE + exploit: -20 điểm

## Compliance Frameworks

### IEC 62443-3-3

Kiểm tra 7 Foundational Requirements:

- **FR1**: Identification & Authentication Control
- **FR2**: Use Control
- **FR3**: System Integrity
- **FR4**: Data Confidentiality
- **FR5**: Restricted Data Flow
- **FR6**: Timely Response to Events
- **FR7**: Resource Availability

**Security Levels:**
- SL-3 (High): ≥90% compliance
- SL-2 (Medium): ≥70% compliance
- SL-1 (Basic): ≥40% compliance
- SL-0 (None): <40% compliance

### NIST Cybersecurity Framework

5 Functions: IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER

**Maturity Tiers:**
- Tier 4 (Adaptive): ≥85%
- Tier 3 (Repeatable): ≥65%
- Tier 2 (Risk Informed): ≥40%
- Tier 1 (Partial): <40%

## Kiến trúc Code

```
icsscout/
├── domain/
│   └── risk_assessment.py       # Data models
├── core/
│   └── risk_assessment/
│       ├── __init__.py
│       ├── risk_engine.py       # Core engine
│       ├── scoring_rules.py     # Scoring logic
│       ├── checklist.py         # Compliance checker
│       └── report_generator.py  # PDF/DOCX generator
└── interfaces/
    └── web/
        └── routes/
            └── risk_assessment_routes.py  # API endpoints
```

## Ví dụ sử dụng

### 1. Chạy qua Web UI

1. Khởi động webapp: `python3 start_webapp.py`
2. Truy cập: http://localhost:5000/risk-assessment
3. Click **"Run Assessment"**
4. Xem kết quả và export báo cáo

### 2. Chạy qua API

```python
import requests

# Run assessment
response = requests.post('http://localhost:5000/api/risk/assess', json={
    "include_vulnerability_scan": True
})

report_id = response.json()['report_id']

# Export PDF
pdf_url = f'http://localhost:5000/api/risk/export/{report_id}/pdf'
```

### 3. Sử dụng trực tiếp

```python
from icsscout.core.risk_assessment import RiskAssessmentEngine
from icsscout.domain.device import Device

engine = RiskAssessmentEngine()

devices = [
    Device(ip="192.168.1.10", vendor="Siemens", model="S7-1500"),
    # ... more devices
]

report = engine.assess_risk(devices, vulnerability_reports, network_topology)

print(f"Risk Level: {report.overall_risk_level.value}")
print(f"Risk Score: {report.overall_risk_score:.2f}/100")
```

## Tính năng nổi bật

✅ **Scoring logic chi tiết** theo IEC 62443 và NIST
✅ **Xuất PDF/Word chuyên nghiệp** với logo và formatting
✅ **Web Dashboard đẹp** với charts và visualization
✅ **Action Plan ưu tiên** theo mức độ nguy cấp
✅ **Device-level risk profiling**
✅ **Compliance gap analysis**
✅ **RESTful API** đầy đủ

## Roadmap

- [ ] MITRE ATT&CK for ICS mapping
- [ ] Automated remediation suggestions
- [ ] Historical trend analysis
- [ ] Email report scheduling
- [ ] Multi-language support

## Tác giả

Phát triển bởi ICSScout Team
Date: November 2025

## License

Proprietary - Internal Use Only
