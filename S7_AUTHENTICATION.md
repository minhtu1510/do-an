# S7 Protocol Authentication

## Tổng quan (Overview)

S7.Pwn hiện hỗ trợ **Password-based Authentication** cho Siemens S7 PLCs, cho phép kết nối với các PLC được bảo vệ bằng mật khẩu.

S7.Pwn now supports **Password-based Authentication** for Siemens S7 PLCs, enabling connections to password-protected PLCs.

## Giao thức S7 và Authentication

### S7 Protocol
**S7 Protocol** là giao thức độc quyền của Siemens để giao tiếp với PLC S7:
- **Port**: 102/TCP
- **Transport**: ISO-on-TCP (RFC 1006)
- **Layers**: TPKT → COTP → S7

### Authentication trong S7

#### S7-300/400 (Classic PLCs)
- **Protection Levels** (1-3) thay vì password
- Không có authentication mạnh native
- Bảo vệ qua configuration trong STEP 7

#### S7-1200/1500 (Modern PLCs)
- **Password-based Access Control**
- Cấu hình trong TIA Portal
- Hỗ trợ nhiều access levels

## Protection Levels

### Protection Level 0: No Protection
```
🟢 No Protection
- Không cần password
- Full read/write access
- Không có hạn chế
```

### Protection Level 1: Write Protection
```
🟡 Write Protection
- Read operations: Allowed
- Write operations: Require password
- Monitoring: Allowed
```

### Protection Level 2: Read/Write Protection
```
🟠 Read/Write Protection
- Read operations: Require password
- Write operations: Require password
- Limited monitoring without password
```

### Protection Level 3: Complete Protection
```
🔴 Complete Protection
- All operations require password
- Cannot connect without authentication
- Maximum security level
```

## Access Levels

### No Access
- Cannot connect
- Authentication required
- All operations blocked

### Read Access
- Can read memory areas
- Cannot write
- Can monitor values
- Limited control

### HMI Access
- Read/write specific areas
- Limited control operations
- Designed for HMI panels
- Restricted functionality

### Full Access
- Complete read/write access
- All control operations
- Configuration access
- Administrative privileges

## Sử dụng Authentication Module

### 1. Kiểm tra Protection Level

```bash
s7pwn> auth check
```

**Output Example:**
```
============================================================
S7 PROTECTION CHECK
============================================================
Target: 192.168.1.10 (Rack 0, Slot 1)
============================================================

[+] Connection successful

Protection Level: 🟠 Read/Write Protection
    → Password required for read and write

Current Access Level: 🔒 No Access
    → Authentication required

⚠️  Password Required
    Use 'auth login <password>' to authenticate
    Or 'auth bruteforce' for password testing (authorized only)

============================================================
```

### 2. Đăng nhập với Password

#### Interactive Mode (Secure)
```bash
s7pwn> auth login
Enter PLC password: ********
```

#### Direct Mode
```bash
s7pwn> auth login mypassword123
```

**Successful Login:**
```
[*] Authenticating to 192.168.1.10...
[+] Connected
[+] ✅ Authentication successful!
[+] Access granted with password: ********
[+] Access Level: FULL_ACCESS

[*] Session saved. Commands will use authenticated connection.
```

### 3. Brute Force Password Testing

⚠️ **WARNING**: Chỉ sử dụng trên hệ thống được ủy quyền!

#### Using Common Passwords
```bash
s7pwn> auth bruteforce
```

#### Using Custom Wordlist
```bash
s7pwn> auth bruteforce /path/to/wordlist.txt
```

**Example Session:**
```
============================================================
⚠️  PASSWORD BRUTE FORCE - AUTHORIZED TESTING ONLY
============================================================
WARNING: Only use on systems you own or have permission to test
============================================================

Continue? (yes/no): yes

[*] Using 30 common passwords
[*] Target: 192.168.1.10 (Rack 0, Slot 1)
[*] Max attempts: 30

[Attempt 1/30] Testing:
[Attempt 2/30] Testing: 123456
[Attempt 3/30] Testing: password
[Attempt 4/30] Testing: siemens

[+] SUCCESS! Valid password found: siemens

============================================================
✅ SUCCESS!
============================================================
Valid password: siemens
============================================================

[*] Session saved. Use 'auth check' to verify access level.
```

## Common Passwords List

Module bao gồm danh sách passwords phổ biến:

```python
- ""              # Empty password
- "123456"
- "password"
- "siemens"
- "SIEMENS"
- "Siemens"
- "plc"
- "s7-1200"
- "s7-1500"
- "tia"
- "portal"
- "automation"
- "admin"
- "root"
# ... và nhiều hơn
```

## Workflow Examples

### Example 1: Connecting to Protected PLC

```bash
# Step 1: Scan network
s7pwn> scan 192.168.1.0/24

# Step 2: Select target
s7pwn> select 1

# Step 3: Check protection
s7pwn> auth check
[+] Protection Level: Read/Write Protection
[+] Password Required

# Step 4: Login
s7pwn> auth login
Enter PLC password: ********
[+] Authentication successful!

# Step 5: Now you can use other commands
s7pwn> read MB0 10
s7pwn> monitor
```

### Example 2: Password Recovery (Authorized Testing)

```bash
# Step 1: Select target
s7pwn> select 1

# Step 2: Check if password protected
s7pwn> auth check
[+] Protection Level: Complete Protection
[+] Password Required

# Step 3: Try brute force
s7pwn> auth bruteforce
Continue? (yes/no): yes
[*] Testing passwords...
[Attempt 8/30] Testing: siemens
[+] SUCCESS! Valid password found: siemens

# Step 4: Verify access
s7pwn> auth check
[+] Access Level: FULL_ACCESS
```

### Example 3: Multiple PLCs with Different Passwords

```bash
# PLC 1
s7pwn> select 1
s7pwn> auth login password1
[+] Authentication successful!
s7pwn> read MB0 10

# PLC 2
s7pwn> select 2
s7pwn> auth login password2
[+] Authentication successful!
s7pwn> read MB0 10

# Note: Each PLC maintains its own auth session
```

## Technical Implementation

### Module Architecture

```
s7pwn/ext/s7_auth.py
├── S7AuthClient              # Main authentication client
│   ├── connect()            # Establish COTP + S7 connection
│   ├── detect_protection_level()
│   ├── authenticate_with_password()
│   ├── test_access()
│   └── brute_force_password()
│
├── ProtectionLevel (Enum)   # Protection level definitions
├── AccessLevel (Enum)       # Access level definitions
├── AuthSession (DataClass)  # Session information
└── Utility Functions
    ├── quick_auth_check()
    └── get_common_passwords()
```

### Protocol Flow

#### 1. Connection Establishment
```
Client                          PLC
  |                              |
  |--- COTP Connection Req ----->|
  |<-- COTP Connection Conf -----|
  |                              |
  |--- S7 Setup Communication -->|
  |<-- S7 Setup Comm Response ---|
  |                              |
```

#### 2. Protection Level Detection
```
Client                          PLC
  |                              |
  |--- SZL Read (ID 0x0232) ---->|
  |<-- SZL Data (Protection) ----|
  |                              |
  | Parse protection level       |
```

#### 3. Authentication
```
Client                          PLC
  |                              |
  |--- Auth Request (MD5) ------>|
  |<-- Auth Response ------------|
  |                              |
  | Check error code             |
  | 0x00/0x00 = Success          |
```

### S7 Authentication Packet Structure

```
TPKT Header (4 bytes)
├── Version: 0x03
├── Reserved: 0x00
└── Length: Total packet length

COTP Header (3 bytes)
├── Length: 0x02
├── PDU Type: 0xF0 (Data)
└── TPDU Number: 0x80

S7 Header (10 bytes)
├── Protocol ID: 0x32
├── ROSCTR: 0x01 (Job)
├── Redundancy ID: 0x0000
├── PDU Reference: 0x03XX
├── Parameter Length
└── Data Length

Authentication Parameters
├── Function: Security (0x1A)
├── Password Hash (MD5)
└── Challenge Response
```

## Security Considerations

### Limitations

1. **No Encryption**: S7 protocol doesn't encrypt passwords
2. **Simple Hashing**: Password hashing is weak (MD5)
3. **No Rate Limiting**: Some PLCs don't limit failed attempts
4. **Network Sniffing**: Passwords can be captured if network is compromised

### Best Practices

#### For PLC Administrators:
- ✅ Always use strong passwords (>12 characters)
- ✅ Enable Complete Protection for critical PLCs
- ✅ Use network segmentation (separate OT network)
- ✅ Monitor for unauthorized access attempts
- ✅ Regular password rotation
- ✅ Use TLS/VPN for remote access

#### For Security Testers:
- ✅ Only test on authorized systems
- ✅ Document all access attempts
- ✅ Use test environment first
- ✅ Be aware of lockout mechanisms
- ✅ Coordinate with operations team
- ✅ Have rollback plan

### Detection & Monitoring

PLCs may log authentication attempts:
- Failed login attempts
- Successful authentications
- Configuration changes
- Unusual access patterns

Monitor PLC logs in TIA Portal:
```
Diagnostics → System Diagnostics → Security Events
```

## Troubleshooting

### Issue: "Connection failed"
**Possible Causes:**
- PLC is offline
- Wrong IP address
- Firewall blocking port 102
- Wrong Rack/Slot configuration

**Solutions:**
```bash
# Check connectivity
ping 192.168.1.10

# Check port
nmap -p 102 192.168.1.10

# Verify Rack/Slot
# S7-1200/1500: Rack 0, Slot 1
# S7-300/400: Rack 0, Slot 2
```

### Issue: "Authentication failed"
**Possible Causes:**
- Wrong password
- PLC doesn't use password authentication
- Password method not supported by PLC firmware
- snap7 version limitations

**Solutions:**
- Verify password in TIA Portal
- Check protection level settings
- Try different password
- Update snap7 library

### Issue: "Protection level detection failed"
**Possible Causes:**
- PLC doesn't support SZL reads
- Firmware limitations
- Access already restricted

**Solutions:**
- Try direct authentication
- Check PLC documentation
- Use TIA Portal to verify settings

### Issue: Brute force not working
**Possible Causes:**
- Account lockout after failed attempts
- PLC rebooting/resetting connections
- Network instability

**Solutions:**
- Reduce attempt rate
- Check PLC security settings
- Use smaller password list
- Allow cooling period between attempts

## Integration with Existing Commands

Authentication module tích hợp với các commands hiện có:

### Read Command
```bash
s7pwn> auth login password123
s7pwn> read MB0 10
# Uses authenticated connection automatically
```

### Write Command
```bash
s7pwn> auth login password123
s7pwn> write MB0 42
# Write operation uses authenticated session
```

### Monitor Command
```bash
s7pwn> auth login password123
s7pwn> monitor
# Monitoring uses authenticated connection
```

## API Reference

### S7AuthClient

```python
from s7pwn.ext.s7_auth import S7AuthClient

# Create client
client = S7AuthClient(ip="192.168.1.10", rack=0, slot=1)

# Connect
if client.connect():
    # Detect protection
    protection = client.detect_protection_level()
    print(f"Protection: {protection.name}")

    # Authenticate
    if client.authenticate_with_password("mypassword"):
        print("Authenticated!")

        # Test access
        access = client.test_access()
        print(f"Access Level: {access.name}")

    client.disconnect()
```

### Quick Check Function

```python
from s7pwn.ext.s7_auth import quick_auth_check

result = quick_auth_check("192.168.1.10", rack=0, slot=1)

print(f"Connected: {result['connected']}")
print(f"Protection: {result['protection_level']}")
print(f"Access: {result['access_level']}")
print(f"Requires Password: {result['requires_password']}")
```

### Runtime Integration

```python
from s7pwn.runtime import set_auth_session, get_auth_session

# Store session
set_auth_session({
    'ip': '192.168.1.10',
    'rack': 0,
    'slot': 1,
    'password': 'secret123',
    'authenticated': True,
    'access_level': 'FULL_ACCESS'
})

# Retrieve session
session = get_auth_session()
if session and session['authenticated']:
    password = session['password']
    # Use password for connection
```

## Comparison with Other Tools

| Feature | S7.Pwn | PLCScan | s7-enumerate | Nmap NSE |
|---------|---------|---------|--------------|----------|
| Protection Detection | ✅ | ❌ | ✅ | ❌ |
| Password Auth | ✅ | ❌ | ❌ | ❌ |
| Brute Force | ✅ | ❌ | ❌ | ❌ |
| Session Management | ✅ | ❌ | ❌ | ❌ |
| Access Level Testing | ✅ | ❌ | ❌ | ❌ |

## Future Enhancements

Planned features:
- [ ] Challenge-response authentication (full implementation)
- [ ] Support for S7-Plus security (TIA Portal v16+)
- [ ] Certificate-based authentication
- [ ] Integration with password managers
- [ ] Automated password policy testing
- [ ] Multi-factor authentication detection
- [ ] Session timeout management
- [ ] Credential harvesting from memory

## Legal & Ethical Notice

### ⚠️ IMPORTANT

This authentication module is designed for:
- ✅ **Authorized security testing** of systems you own
- ✅ **Educational purposes** in controlled environments
- ✅ **Legitimate security research** with proper authorization
- ✅ **Incident response** and forensics with legal authority

**UNAUTHORIZED USE IS ILLEGAL**

Accessing systems without permission may violate:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar laws in other jurisdictions

**Always obtain written permission before testing any system.**

## References

### Siemens Documentation
- TIA Portal Security Documentation
- S7 Protocol Specification
- STEP 7 Security Guidelines

### Standards
- IEC 62443 - Industrial Cybersecurity
- ISA/IEC 62443-3-3 - System Security Requirements
- NIST SP 800-82 - Guide to Industrial Control Systems Security

### Related Tools
- snap7 - S7 protocol library
- python-snap7 - Python bindings
- PLCScan - PLC scanning tool
- ISF - Industrial Security Framework

## Support & Contributing

Issues and contributions: https://github.com/trangjackie/S7.Pwn

**For security vulnerabilities, please report privately.**

---

**Author**: S7.Pwn Development Team
**Version**: 2.0
**Last Updated**: 2025-11-06
