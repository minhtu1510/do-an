# 📊 Session & Database Management Guide

Hướng dẫn quản lý session, lưu trữ dữ liệu và xem lịch sử pentest trong S7.Pwn

---

## 1. Session Management - Quản Lý Phiên Làm Việc

### 📁 Lưu Trữ Session

Tất cả session được lưu dưới dạng **JSON files** tại:

```
data/
├── session_20251107_092248.json    # Session tạo lúc 09:22:48 ngày 07/11/2025
├── session_20251107_143055.json    # Session khác
└── ...
```

### 📝 Cấu Trúc File Session

```json
{
  "session_id": "session_20251107_092248",
  "name": "Default Session",
  "created_at": "2025-11-07T09:22:48.123456",
  "current_phase": "ASSESSMENT",
  "devices": [
    {
      "ip": "192.168.210.211",
      "mac": "ec:1c:5d:d5:2b:c3",
      "hostname": "plcxb1.profinetxainterfacexb1036c",
      "vendor": "Siemens",
      "model": "CPU 1516-3 PN/DP",
      "device_type": "PLC",
      "protocols": ["Profinet DCP", "S7"],
      "firmware_version": "V2.9",
      "serial_number": "S C-R9A11FPS2023",
      "metadata": {
        "profinet_info": {...},
        "s7_info": {...}
      }
    }
  ],
  "metadata": {}
}
```

---

## 2. Xem Lịch Sử Session

### Cách 1: Dùng File Explorer

```bash
cd data/
ls -lh session_*.json
```

Output:
```
-rw-r--r-- 1 user user  15K Nov  7 09:22 session_20251107_092248.json
-rw-r--r-- 1 user user  23K Nov  7 14:30 session_20251107_143055.json
```

### Cách 2: Xem Nội Dung Session

```bash
cat data/session_20251107_092248.json | python3 -m json.tool | less
```

### Cách 3: Python Script

```python
from pathlib import Path
import json
from datetime import datetime

# Liệt kê tất cả sessions
session_files = sorted(Path('data').glob('session_*.json'))

for session_file in session_files:
    with open(session_file, 'r') as f:
        data = json.load(f)
        print(f"\n{'='*60}")
        print(f"Session: {data['name']}")
        print(f"ID: {data['session_id']}")
        print(f"Created: {data['created_at']}")
        print(f"Phase: {data['current_phase']}")
        print(f"Devices: {len(data['devices'])}")

        # Liệt kê devices
        for device in data['devices']:
            print(f"  - {device['ip']}: {device['vendor']} {device['model']}")
```

---

## 3. Load Session Cũ

### Trong Code

```python
from icsscout.services import get_session_manager

sm = get_session_manager()

# Load session cụ thể
sm.load_session("session_20251107_092248")

# Lấy devices từ session
devices = sm.get_devices()
for device in devices:
    print(f"{device.ip}: {device.vendor} {device.model}")
```

### Qua Web UI (Manual)

1. Copy session file cần load vào `data/`
2. Restart webapp
3. Session sẽ tự động load (hoặc có thể thêm API endpoint để load)

---

## 4. Risk Assessment Reports - Báo Cáo Đánh Giá

### 📁 Lưu Trữ Reports

Reports được lưu **in-memory** trong runtime và có thể export ra files:

```
reports/
├── risk_assessment_20251107_093000.pdf     # PDF export
├── risk_assessment_20251107_093000.docx    # Word export
├── risk_assessment_20251107_093000.json    # JSON export (raw data)
└── ...
```

### 📝 Cấu Trúc Report JSON

```json
{
  "overview": {
    "report_id": "report_20251107_093000",
    "scan_timestamp": "2025-11-07T09:30:00",
    "total_devices": 8,
    "overall_risk_score": 75.5,
    "overall_risk_level": "HIGH"
  },
  "device_profiles": [...],
  "findings": {...},
  "compliance": [...],
  "action_plan": {...}
}
```

---

## 5. Quy Trình Làm Việc Chuẩn

### Workflow

```
1. Tạo Session Mới
   ↓
2. Chạy OT Scan (hoặc Network Scan)
   ↓
3. Devices được lưu vào Session (auto-save to JSON)
   ↓
4. Chạy Risk Assessment
   ↓
5. Report được tạo (in-memory)
   ↓
6. Export Report ra PDF/Word/JSON
   ↓
7. Lưu trữ reports trong thư mục reports/
```

### Auto-Save

Session được **tự động lưu** mỗi khi:
- Thêm device mới
- Cập nhật device
- Thay đổi phase

```python
# Mỗi lần add_device() được gọi
session_manager.add_device(device)
# → Tự động save vào data/session_*.json
```

---

## 6. Quản Lý Files

### Tổ Chức Thư Mục

```
S7.Pwn/
├── data/                           # ✅ LƯU VÀO GIT
│   ├── session_client1_*.json
│   └── session_client2_*.json
│
├── reports/                        # ❌ KHÔNG LƯU VÀO GIT
│   ├── risk_assessment_*.pdf
│   ├── risk_assessment_*.docx
│   └── risk_assessment_*.json
│
└── backups/                        # ❌ KHÔNG LƯU VÀO GIT
    └── data_backup_*.zip
```

### Git Ignore

```bash
# .gitignore
reports/*.pdf
reports/*.docx
backups/
```

### Backup Session

```bash
# Backup toàn bộ sessions
cd /home/user/S7.Pwn
zip -r backups/data_backup_$(date +%Y%m%d).zip data/

# Restore
unzip backups/data_backup_20251107.zip
```

---

## 7. Best Practices

### Đặt Tên Session

```python
# ❌ Không nên
"session_20251107_092248"  # Auto-generated, khó nhớ

# ✅ Nên
"Pentest_CompanyXYZ_2025-11-07"
"ICS_Audit_Factory_A_Nov_2025"
```

### Tạo Session Theo Project

```python
from icsscout.services import get_session_manager

sm = get_session_manager()

# Tạo session cho từng project riêng
sm.create_session("Pentest_CompanyA_Nov2025")
# ... scan devices ...
# ... run risk assessment ...
# ... export reports ...

# Tạo session mới cho project khác
sm.create_session("Pentest_CompanyB_Nov2025")
```

### Backup Theo Client

```
backups/
├── client_a/
│   ├── session_client_a_20251107.json
│   └── reports/
│       ├── risk_*.pdf
│       └── risk_*.docx
│
└── client_b/
    ├── session_client_b_20251108.json
    └── reports/
```

---

## 8. API Endpoints

### Session Management

```bash
# Lấy devices trong session hiện tại
GET /api/devices

# Thêm device vào session
POST /api/devices
{
  "ip": "192.168.1.10",
  "vendor": "Siemens"
}
```

### Risk Assessment

```bash
# Chạy assessment
POST /api/risk/assess

# Lấy report
GET /api/risk/report/{report_id}

# Export report
GET /api/risk/export/{report_id}/pdf
GET /api/risk/export/{report_id}/docx
GET /api/risk/export/{report_id}/json

# Liệt kê tất cả reports (in-memory)
GET /api/risk/reports
```

---

## 9. Database Schema (Hiện Tại vs Tương Lai)

### Hiện Tại: File-based JSON

```
Advantages:
✅ Đơn giản, không cần setup
✅ Human-readable
✅ Dễ backup (copy files)
✅ Version control friendly (Git)
✅ Không phụ thuộc external services

Limitations:
❌ Không phù hợp concurrent access
❌ Query phức tạp khó thực hiện
❌ Phải manual load session
❌ Không có built-in search
```

### Tương Lai: SQLite (Đề Xuất)

```sql
-- database/s7pwn.db

CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    name TEXT,
    created_at TIMESTAMP,
    current_phase TEXT,
    metadata TEXT
);

CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    ip TEXT,
    mac TEXT,
    vendor TEXT,
    model TEXT,
    device_type TEXT,
    protocols TEXT,  -- JSON array
    firmware_version TEXT,
    serial_number TEXT,
    metadata TEXT,   -- JSON object
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE risk_reports (
    report_id TEXT PRIMARY KEY,
    session_id TEXT,
    created_at TIMESTAMP,
    overall_risk_score REAL,
    overall_risk_level TEXT,
    report_data TEXT,  -- JSON
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id TEXT,
    severity TEXT,
    category TEXT,
    title TEXT,
    description TEXT,
    affected_devices TEXT,  -- JSON array
    recommendation TEXT,
    FOREIGN KEY (report_id) REFERENCES risk_reports(report_id)
);
```

Benefits:
✅ Fast queries
✅ JOIN giữa các bảng
✅ Full-text search
✅ Session history tracking
✅ Timeline analysis
✅ Report comparison

---

## 10. Migration Script (JSON → SQLite)

```python
import sqlite3
import json
from pathlib import Path
from datetime import datetime

def migrate_to_sqlite():
    """Migrate từ JSON files sang SQLite database"""

    # Kết nối database
    conn = sqlite3.connect('database/s7pwn.db')
    cursor = conn.cursor()

    # Tạo bảng
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            name TEXT,
            created_at TEXT,
            current_phase TEXT,
            metadata TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            ip TEXT,
            mac TEXT,
            vendor TEXT,
            model TEXT,
            device_type TEXT,
            protocols TEXT,
            firmware_version TEXT,
            serial_number TEXT,
            metadata TEXT,
            first_seen TEXT,
            last_seen TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        )
    ''')

    # Đọc tất cả session files
    session_files = Path('data').glob('session_*.json')

    for session_file in session_files:
        with open(session_file, 'r') as f:
            data = json.load(f)

            # Insert session
            cursor.execute('''
                INSERT OR REPLACE INTO sessions VALUES (?, ?, ?, ?, ?)
            ''', (
                data['session_id'],
                data['name'],
                data['created_at'],
                data['current_phase'],
                json.dumps(data.get('metadata', {}))
            ))

            # Insert devices
            for device in data.get('devices', []):
                cursor.execute('''
                    INSERT INTO devices VALUES (
                        NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                ''', (
                    data['session_id'],
                    device['ip'],
                    device.get('mac'),
                    device.get('vendor'),
                    device.get('model'),
                    device.get('device_type'),
                    json.dumps(device.get('protocols', [])),
                    device.get('firmware_version'),
                    device.get('serial_number'),
                    json.dumps(device.get('metadata', {})),
                    device.get('first_seen'),
                    device.get('last_seen')
                ))

    conn.commit()
    conn.close()
    print("✅ Migration completed!")

if __name__ == '__main__':
    migrate_to_sqlite()
```

---

## 11. Query Examples (SQLite)

```python
import sqlite3

conn = sqlite3.connect('database/s7pwn.db')
cursor = conn.cursor()

# 1. Liệt kê tất cả sessions
cursor.execute("SELECT * FROM sessions ORDER BY created_at DESC")
for row in cursor.fetchall():
    print(f"Session: {row[1]} | Created: {row[2]}")

# 2. Tìm tất cả Siemens devices
cursor.execute("""
    SELECT ip, model, firmware_version
    FROM devices
    WHERE vendor = 'Siemens'
    ORDER BY ip
""")

# 3. Tìm devices có firmware cũ
cursor.execute("""
    SELECT ip, vendor, model, firmware_version
    FROM devices
    WHERE firmware_version NOT LIKE 'V3%'
    AND vendor = 'Siemens'
""")

# 4. Thống kê devices theo vendor
cursor.execute("""
    SELECT vendor, COUNT(*) as count
    FROM devices
    GROUP BY vendor
    ORDER BY count DESC
""")

# 5. Timeline - Devices discovered theo ngày
cursor.execute("""
    SELECT DATE(first_seen) as date, COUNT(*) as devices_found
    FROM devices
    GROUP BY DATE(first_seen)
    ORDER BY date
""")

conn.close()
```

---

## 12. Web UI Features (Future)

### Session Browser

```
┌─────────────────────────────────────────────────────────┐
│ 📂 Session History                                      │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ 🗓️ 2025-11-07 09:22 | Pentest_CompanyA_Nov2025        │
│    8 devices | S7-1500, ET200SP, ...                   │
│    [Load] [View Report] [Export]                        │
│                                                         │
│ 🗓️ 2025-11-06 14:30 | ICS_Audit_Factory_B              │
│    12 devices | S7-1200, Modbus RTU, ...               │
│    [Load] [View Report] [Export]                        │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Device Timeline

```
┌─────────────────────────────────────────────────────────┐
│ 📊 Device History: 192.168.210.211                      │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ 2025-11-07 09:22 | First seen                           │
│ 2025-11-07 09:30 | Risk Assessment: HIGH (75.5)         │
│ 2025-11-07 10:15 | Firmware updated: V2.9 → V3.0        │
│ 2025-11-07 14:00 | Risk Assessment: MEDIUM (55.2)       │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 13. Tóm Tắt

### Hiện Tại

✅ **Sessions**: Lưu trong `data/session_*.json`
✅ **Reports**: Export ra `reports/*.{pdf,docx,json}`
✅ **Auto-save**: Mỗi khi thay đổi device
✅ **Lịch sử**: Xem qua JSON files
✅ **Backup**: Copy `data/` folder

### Tương Lai (Nếu Cần)

🔮 **SQLite Database**: `database/s7pwn.db`
🔮 **Web UI Browser**: Xem sessions và reports
🔮 **Timeline View**: Track device changes theo thời gian
🔮 **Search**: Full-text search trong findings
🔮 **Comparison**: So sánh reports giữa các sessions

### Khi Nào Cần SQLite?

- Có **>100 sessions**
- Cần **query phức tạp**
- Cần **concurrent access**
- Cần **timeline analysis**
- Cần **report comparison**

### File-based JSON Đủ Khi:

- **<100 sessions**
- **1 user** sử dụng
- **Simple workflow**
- **Manual review**

---

**📚 Kết Luận**: Hiện tại file-based JSON **đủ tốt** cho hầu hết use cases. Nếu cần tính năng nâng cao hơn, có thể migrate sang SQLite trong tương lai!
