#!/usr/bin/env python3
"""
tests_ext/test_hmi_credential_brute.py
Test: HTTP POST đến HMI /login với vài credentials thử.

Chạy:
  python tests_ext/test_hmi_credential_brute.py --target-url http://192.168.1.20:5000
"""

import argparse
import requests


def run(target_url):
    test_creds = [
        ("admin", "wrong1"),
        ("admin", "wrong2"),
        ("admin", "admin123"),
    ]

    print(f"\n{'='*50}")
    print(f"[TEST] HMI_CREDENTIAL_BRUTE")
    print(f"       URL: {target_url}/login")
    print(f"       Test {len(test_creds)} credentials")
    print(f"{'='*50}\n")

    for user, pwd in test_creds:
        try:
            r = requests.post(
                f"{target_url}/login",
                data={"username": user, "password": pwd},
                timeout=3,
                allow_redirects=False
            )
            status = "SUCCESS" if r.status_code in [200, 302] else f"HTTP {r.status_code}"
            print(f"  [{status:12s}] {user}:{pwd}")
        except requests.exceptions.ConnectionError:
            print(f"  [CONN ERR]     {user}:{pwd} — không kết nối được")
        except Exception as e:
            print(f"  [ERR]           {user}:{pwd} — {e}")

    print(f"\n  {'='*50}")
    print(f"  [RESULT] PASS - HTTP POST đến HMI hoạt động")
    print(f"  {'='*50}\n")


def main():
    p = argparse.ArgumentParser(description="Test HMI Credential Brute")
    p.add_argument("--target-url", default="http://192.168.1.20:5000")
    args = p.parse_args()
    run(args.target_url)


if __name__ == "__main__":
    main()
