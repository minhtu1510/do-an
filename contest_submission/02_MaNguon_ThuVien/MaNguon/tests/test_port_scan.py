#!/usr/bin/env python3
"""
tests/test_port_scan.py
KỊCH BẢN 1 — Khảo sát dịch vụ mạng trên Engineering Station (.31)

3 phase (khớp mô tả trong báo cáo tuần):
  Phase 1: TCP connect scan đa luồng trên danh sách port phổ biến.
  Phase 2: Banner grabbing trên các port mở.
  Phase 3: Quét lại các port mở nhiều lần (timeout ngắn) để tạo lưu lượng
           đặc trưng recon cho IDS học.

MITRE ICS: T0846 Remote System Discovery.
Chạy: python tests/test_port_scan.py
"""

import sys
import os
import time
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *  # noqa: F401,F403

# Mục tiêu mặc định: Engineering Station .31 (đổi qua env SCAN_TARGET nếu cần).
TARGET = os.getenv("SCAN_TARGET", HMI_IP)

# Port phổ biến trên Windows Engineering Station + dịch vụ công nghiệp.
# Gồm các port đã quan sát trong báo cáo tuần (135/139/445/903/2179/3389/4840...).
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 102, 135, 139, 443, 445, 502,
    903, 1433, 2179, 3389, 4002, 4840, 5900, 7070, 8080, 20000,
]

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    102: "S7comm", 135: "MSRPC", 139: "NetBIOS-SSN", 443: "HTTPS", 445: "SMB",
    502: "Modbus", 903: "VMware-Auth", 1433: "MSSQL", 2179: "VMware-RDP",
    3389: "RDP", 4840: "OPC-UA", 5900: "VNC", 8080: "HTTP-Alt", 20000: "DNP3",
}

CONNECT_TIMEOUT = float(os.getenv("SCAN_TIMEOUT", "1.0"))
RESCAN_ROUNDS = int(os.getenv("SCAN_RESCAN_ROUNDS", "3"))
MAX_WORKERS = 50

_lock = threading.Lock()


def tcp_connect(ip, port, timeout=CONNECT_TIMEOUT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0, s
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return False, None


def grab_banner(ip, port):
    ok_conn, s = tcp_connect(ip, port, timeout=2.0)
    if not ok_conn or s is None:
        return None
    banner = None
    try:
        # HTTP-like port: chủ động gửi request nhỏ để lấy banner.
        if port in (80, 443, 8080, 7070):
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        s.settimeout(1.5)
        data = s.recv(128)
        banner = data.decode("latin-1", errors="replace").strip().replace("\r", " ").replace("\n", " ")
    except Exception:
        banner = None
    finally:
        try:
            s.close()
        except Exception:
            pass
    return banner or None


def main():
    print(f"\n{B}[TEST] PORT SCAN — Engineering Station{X}")
    info(f"Target: {TARGET}  |  {len(COMMON_PORTS)} ports  |  rescan x{RESCAN_ROUNDS}")

    observable = []
    notes = []
    error = None
    t0 = time.time()
    open_ports = []

    try:
        # ── Phase 1: TCP connect scan đa luồng ──────────────────────────────
        info("Phase 1: TCP connect scan...")

        def probe(port):
            ok_conn, s = tcp_connect(TARGET, port)
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
            if ok_conn:
                with _lock:
                    open_ports.append(port)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            ex.map(probe, COMMON_PORTS)
        open_ports.sort()

        for p in open_ports:
            name = SERVICE_NAMES.get(p, "unknown")
            ok(f"  OPEN {p:>5}/tcp  {name}")
            observable.append(f"port {p} open ({name})")
        if not open_ports:
            warn("Không port nào mở (kiểm tra target/firewall).")

        # ── Phase 2: Banner grabbing ────────────────────────────────────────
        info("Phase 2: Banner grabbing...")
        for p in open_ports:
            banner = grab_banner(TARGET, p)
            if banner:
                notes.append(f"banner {p}: {banner[:80]}")
                print(f"    [{p}] {banner[:80]}")

        # ── Phase 3: Re-scan tạo lưu lượng recon cho IDS ────────────────────
        info(f"Phase 3: Re-scan {RESCAN_ROUNDS} vòng (sinh traffic recon)...")
        rescan_hits = 0
        for _ in range(RESCAN_ROUNDS):
            for p in open_ports:
                ok_conn, s = tcp_connect(TARGET, p, timeout=0.5)
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
                if ok_conn:
                    rescan_hits += 1
                time.sleep(0.05)
        notes.append(f"rescan_rounds={RESCAN_ROUNDS} rescan_hits={rescan_hits}")

    except KeyboardInterrupt:
        info("Dừng bởi user (Ctrl+C)")
    except Exception as e:
        error = str(e)
        fail(str(e))

    duration = time.time() - t0
    notes.append(f"open_port_count={len(open_ports)}")
    notes.append(f"open_ports={open_ports}")
    success = len(open_ports) > 0 and error is None
    print_result("PORT_SCAN", success, [], observable, notes, duration, error)


if __name__ == "__main__":
    main()
