# Cơ chế đánh giá S7 Protection Level

## 1. Protection Level (Mức độ bảo vệ)

### Cách thức phát hiện:
PLC S7 lưu trữ thông tin bảo vệ trong **SZL (System Status List)** - một bảng trạng thái hệ thống.

```
SZL ID: 0x0232 (Protection Level Information)
Index:  0x0004
```

### Quy trình phát hiện:

1. **Gửi S7 SZL Read Request** đến PLC
   - Function: 0x04 (Read Var)
   - SZL ID: 0x0232 (Protection information)

2. **Nhận phản hồi từ PLC**
   - Byte 17: Error Code (0x03 = Success)
   - Byte 39: Protection Byte
   - Bits 4-7: Protection Level

3. **Phân tích Protection Level:**

| Level | Giá trị | Ý nghĩa | Chi tiết |
|-------|---------|---------|----------|
| 0 | 0x00 | NO_PROTECTION | Không bảo vệ, cho phép đọc/ghi tự do |
| 1 | 0x01 | WRITE_PROTECTION | Bảo vệ ghi, chỉ cho phép đọc |
| 2 | 0x02 | READ_WRITE_PROTECTION | Bảo vệ đọc/ghi, yêu cầu password cho cả 2 |
| 3 | 0x03 | COMPLETE_PROTECTION | Bảo vệ hoàn toàn, yêu cầu password cho mọi thao tác |

### Trường hợp "Unknown":

**Protection Level: Unknown** xảy ra khi:
- PLC không phản hồi đúng format SZL
- Timeout kết nối
- PLC không hỗ trợ SZL ID 0x0232 (một số model cũ)
- Lỗi mạng/firewall chặn gói tin

**Cơ sở kết luận:**
```python
if response[17] != 0x03:  # Error code không phải Success
    return None  # -> "Unknown"

if len(response) < 40:    # Dữ liệu không đủ
    return None  # -> "Unknown"
```

---

## 2. Access Level (Quyền truy cập hiện tại)

### Cách thức xác định:
Thực hiện **kiểm tra thực tế** các thao tác để xác định quyền hiện có.

### Quy trình kiểm tra:

1. **Test Read Operation (Thử đọc)**
   ```
   Function: 0x04 (Read Var)
   Area: DB (Data Block)
   DB Number: 1
   Address: DBB0 (Byte 0)
   Length: 1 byte
   ```

2. **Test Write Operation (Thử ghi)**
   ```
   Function: 0x05 (Write Var)
   Area: DB (Data Block)
   DB Number: 1
   Address: DBB0
   Data: 0x00 (test value)
   ```

3. **Phân tích kết quả:**

| Read | Write | Access Level | Giải thích |
|------|-------|--------------|------------|
| ❌ | ❌ | NO_ACCESS | Không có quyền truy cập nào |
| ✅ | ❌ | READ_ACCESS | Chỉ được đọc, không được ghi |
| ✅ | ✅ | FULL_ACCESS | Được đọc và ghi tự do |
| ✅ | ⚠️ | HMI_ACCESS | Được đọc, một số lệnh điều khiển HMI |

**Cơ sở kết luận:**
```python
# Error codes in response:
0x00 0x00 = Success
0x05 0x00 = Address error (không có quyền)
0x0A 0x00 = Access denied (bị chặn)

if error_class == 0x00 and error_code == 0x00:
    return AccessLevel.FULL_ACCESS
else:
    return AccessLevel.NO_ACCESS
```

### Trường hợp "Unknown":

**Access Level: Unknown** xảy ra khi:
- Chưa kết nối đến PLC
- PLC không phản hồi trong timeout
- Không có DB1 để test
- Exception trong quá trình test

---

## 3. Requires Password (Yêu cầu mật khẩu)

### Cách thức xác định:
Dựa trên **Protection Level** và **Access Level** hiện tại.

### Logic xác định:

```python
Requires Password = (Protection Level >= 1) AND (Access Level < FULL_ACCESS)
```

### Bảng quyết định:

| Protection Level | Current Access | Requires Password | Giải thích |
|------------------|----------------|-------------------|------------|
| NO_PROTECTION | FULL_ACCESS | ❌ No | Không bảo vệ, không cần mật khẩu |
| WRITE_PROTECTION | READ_ACCESS | ✅ Yes | Cần mật khẩu để ghi |
| WRITE_PROTECTION | FULL_ACCESS | ❌ No | Đã có quyền đầy đủ |
| READ_WRITE_PROTECTION | NO_ACCESS | ✅ Yes | Cần mật khẩu cho mọi thao tác |
| COMPLETE_PROTECTION | NO_ACCESS | ✅ Yes | Cần mật khẩu để truy cập |

**Cơ sở kết luận:**
```python
if protection_level == ProtectionLevel.NO_PROTECTION:
    return False  # "No ✓"

if access_level == AccessLevel.FULL_ACCESS:
    return False  # "No ✓" - Đã có quyền đầy đủ

if protection_level.value >= 1 and access_level.value < 3:
    return True   # "Yes ⚠"
```

---

## 4. Ví dụ thực tế

### Scenario 1: PLC mở (No Protection)
```
[*] Connecting to 192.168.1.10...
[+] COTP Connection: Success
[+] S7 Setup Communication: Success
[*] Reading SZL ID 0x0232...
[+] Protection Level Detected: 0 (NO_PROTECTION)
    Cơ sở: Byte 39 = 0x00 -> Level = (0x00 >> 4) & 0x0F = 0

[*] Testing Read Access...
[+] Read DB1.DBB0: Success (Error: 0x00 0x00)
    Cơ sở: Response code = Success

[*] Testing Write Access...
[+] Write DB1.DBB0: Success (Error: 0x00 0x00)
    Cơ sở: Response code = Success

Kết luận:
- Protection Level: NO_PROTECTION
  (PLC không bật bảo vệ)
- Access Level: FULL_ACCESS
  (Có thể đọc/ghi tự do)
- Requires Password: No ✓
  (Không cần mật khẩu)
```

### Scenario 2: PLC có Write Protection
```
[*] Connecting to 192.168.1.20...
[+] COTP Connection: Success
[+] S7 Setup Communication: Success
[*] Reading SZL ID 0x0232...
[+] Protection Level Detected: 1 (WRITE_PROTECTION)
    Cơ sở: Byte 39 = 0x10 -> Level = (0x10 >> 4) & 0x0F = 1

[*] Testing Read Access...
[+] Read DB1.DBB0: Success (Error: 0x00 0x00)
    Cơ sở: Response code = Success

[*] Testing Write Access...
[-] Write DB1.DBB0: Access Denied (Error: 0x05 0x00)
    Cơ sở: Error code 0x05 = Address/Access error

Kết luận:
- Protection Level: WRITE_PROTECTION
  (PLC bảo vệ ghi)
- Access Level: READ_ACCESS
  (Chỉ được đọc, không được ghi)
- Requires Password: Yes ⚠
  (Cần mật khẩu để có quyền ghi)
```

### Scenario 3: PLC Complete Protection
```
[*] Connecting to 192.168.1.30...
[+] COTP Connection: Success
[+] S7 Setup Communication: Success
[*] Reading SZL ID 0x0232...
[+] Protection Level Detected: 3 (COMPLETE_PROTECTION)
    Cơ sở: Byte 39 = 0x30 -> Level = (0x30 >> 4) & 0x0F = 3

[*] Testing Read Access...
[-] Read DB1.DBB0: Access Denied (Error: 0x0A 0x00)
    Cơ sở: Error code 0x0A = Access denied

[*] Testing Write Access...
[-] Write DB1.DBB0: Access Denied (Error: 0x0A 0x00)
    Cơ sở: Error code 0x0A = Access denied

Kết luận:
- Protection Level: COMPLETE_PROTECTION
  (PLC bảo vệ hoàn toàn)
- Access Level: NO_ACCESS
  (Không có quyền truy cập)
- Requires Password: Yes ⚠
  (Cần mật khẩu để truy cập)
```

### Scenario 4: Detection Failed (Unknown)
```
[*] Connecting to 192.168.1.40...
[+] COTP Connection: Success
[+] S7 Setup Communication: Success
[*] Reading SZL ID 0x0232...
[-] SZL Read Response: Error (Response byte 17 = 0xFF)
    Cơ sở: PLC trả về error code, không phải Success (0x03)
    Có thể: PLC model cũ không hỗ trợ SZL 0x0232

[*] Testing Read Access...
[!] Timeout - No response
    Cơ sở: Socket timeout sau 5 giây

Kết luận:
- Protection Level: Unknown
  (Không xác định được từ SZL)
- Access Level: Unknown
  (Không test được do timeout)
- Requires Password: Unknown
  (Không đủ thông tin để kết luận)
```

---

## 5. Tham khảo kỹ thuật

### S7 Protocol Frame Structure:
```
TPKT Header (4 bytes):
  0x03 - Version
  0x00 - Reserved
  [2 bytes] - Total Length

COTP Header (3+ bytes):
  [1 byte] - Length
  [1 byte] - PDU Type (0xF0 = Data)
  [1 byte] - TPDU Number

S7 Header (10+ bytes):
  0x32 - Protocol ID (S7)
  [1 byte] - Message Type
  [2 bytes] - Reserved
  [2 bytes] - PDU Reference
  [2 bytes] - Parameter Length
  [2 bytes] - Data Length
```

### SZL Read Request Format:
```python
Function: 0x04 (Read Var)
Function Group: 0x04 (SZL Functions)
Sub-function: 0x01 (Read SZL)
Sequence Number: 0x00
SZL ID: 0x0232 (Protection)
Index: 0x0004
```

### Error Codes:
```
0x00 = No error
0x05 = Address error / Access denied
0x06 = Invalid data type
0x07 = Invalid data length
0x0A = Object access denied
0xFF = Unknown error
```

---

## Tóm tắt

**Protection Level:** Đọc từ SZL 0x0232 của PLC (thông tin cấu hình)
**Access Level:** Test thực tế các thao tác đọc/ghi (thử nghiệm)
**Requires Password:** Logic kết hợp từ Protection + Access Level

**Unknown** = Không kết nối được hoặc PLC không phản hồi đúng format
