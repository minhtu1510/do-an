#!/usr/bin/env python3
"""
tests/test_smb_enum.py
SMB Enumeration đa tầng — KHÔNG dùng credentials/net use/net view
Tạo traffic SMB Reconnaissance thuần túy cho IDS dataset.
Traffic: TCP SYN/ACK + NetBIOS Query + DCERPC Bind (không có NTLMSSP)
"""

import sys, os, socket, time, csv, subprocess, random
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TARGET_IP   = "192.168.210.31"
OUTPUT_FILE = "logs/smb_enum_results.csv"

# ── Share list 50 tên — chỉ dùng để tạo UNC path trong log ───────────────────
SHARE_NAMES = [
    # Windows default
    "C$", "D$", "E$", "F$", "Z$",
    "ADMIN$", "IPC$", "PRINT$", "FAX$",
    # User shares
    "Users", "Public", "Shared", "Documents", "Downloads",
    "Desktop", "Temp", "Tmp", "Transfer",
    # ICS/SCADA đặc thù
    "WinCC", "SCADA", "HMI", "PLC", "OPC",
    "Historian", "ArchiveData", "AlarmLog",
    "Engineering", "Project", "Runtime",
    # IT/Admin shares
    "Backup", "Config", "Data", "Logs", "Scripts",
    "Software", "Tools", "Install", "Deploy",
    "NetLogon", "SysVol",
    # Misc
    "Media", "Reports", "Archive", "Old",
    "Test", "Dev", "Staging", "Prod",
    "Share", "Files", "Common",
]

# ── RPC Named Pipes ───────────────────────────────────────────────────────────
RPC_PIPES = [
    ("srvsvc",   "Server Service — liệt kê share"),
    ("wkssvc",   "Workstation Service — thông tin máy"),
    ("samr",     "SAM Remote — liệt kê user/group"),
    ("lsarpc",   "LSA Remote — policy, SID lookup"),
    ("netlogon", "Netlogon — domain info"),
    ("svcctl",   "Service Control — liệt kê services"),
    ("winreg",   "Remote Registry — đọc registry"),
    ("atsvc",    "Task Scheduler — scheduled tasks"),
]

# ── Helpers ───────────────────────────────────────────────────────────────────
def tcp_probe(ip, port, timeout=1.5):
    """TCP connect thuần — KHÔNG gửi bất kỳ payload nào sau handshake."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        open_ = s.connect_ex((ip, port)) == 0
        s.close()
        return open_
    except Exception:
        return False

def run_cmd(cmd, timeout=5):
    """Chỉ dùng cho nbtstat/nslookup — KHÔNG dùng net use/net view."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, shell=True)
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return str(e)

def smb_negotiate_only(ip, port=445, timeout=3.0):
    """
    Gửi SMB2 Negotiate Request rồi đóng kết nối ngay.
    KHÔNG thực hiện Session Setup → KHÔNG có NTLMSSP.
    Tạo traffic: TCP SYN → SMB2 NEGOTIATE REQUEST → close
    """
    # SMB2 Negotiate Protocol Request (minimal)
    smb2_negotiate = bytes([
        # NetBIOS Session Service header (4 bytes)
        0x00, 0x00, 0x00, 0x2e,
        # SMB2 Header
        0xfe, 0x53, 0x4d, 0x42,  # ProtocolId: \xfeSMB
        0x40, 0x00,              # StructureSize: 64
        0x00, 0x00,              # CreditCharge: 0
        0x00, 0x00,              # ChannelSequence: 0
        0x00, 0x00,              # Reserved
        0x00, 0x00,              # Command: NEGOTIATE (0)
        0x1f, 0x00,              # CreditRequest: 31
        0x00, 0x00, 0x00, 0x00,  # Flags: 0
        0x00, 0x00, 0x00, 0x00,  # NextCommand: 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # MessageId: 0
        0x00, 0x00, 0x00, 0x00,  # Reserved
        0x00, 0x00, 0x00, 0x00,  # TreeId: 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # SessionId: 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Signature
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        # Negotiate body
        0x24, 0x00,              # StructureSize: 36
        0x01, 0x00,              # DialectCount: 1
        0x00, 0x00,              # SecurityMode: 0
        0x00, 0x00,              # Reserved
        0x00, 0x00, 0x00, 0x00,  # Capabilities: 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # ClientGuid
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,  # ClientStartTime: 0
        0x02, 0x02,              # Dialect: SMB 2.0.2
    ])
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(smb2_negotiate)
        resp = s.recv(256)
        s.close()
        # Kiểm tra response có phải SMB2 không
        return len(resp) > 4 and resp[4:8] == b'\xfeSMB'
    except Exception:
        return False

# ── Phase 1: SMB/NetBIOS Port Probe ──────────────────────────────────────────
def phase_port_probe(log_rows):
    print("\n[Phase 1] 🔌 SMB/NetBIOS Port Probe")
    ports = {
        137: "NetBIOS Name Service",
        138: "NetBIOS Datagram",
        139: "NetBIOS Session",
        445: "SMB Direct",
    }
    open_smb = []
    for port, desc in ports.items():
        is_open = tcp_probe(TARGET_IP, port)
        status = "OPEN" if is_open else "CLOSED"
        if is_open:
            open_smb.append(port)
        print(f"  {port} ({desc}) → {status}")
        log_rows.append({
            "timestamp": datetime.now().isoformat(),
            "phase": "PORT_PROBE",
            "action": f"SMB_PORT_{port}",
            "target": TARGET_IP,
            "detail": desc,
            "result": status
        })
        time.sleep(0.2)
    return open_smb

# ── Phase 2: NetBIOS Deep Scan (nbtstat — không auth) ────────────────────────
def phase_netbios_deep(log_rows):
    print("\n[Phase 2] 🌐 NetBIOS Deep Scan")
    nb_cmds = [
        ("NBTSTAT_A",  f"nbtstat -A {TARGET_IP}"),   # query by IP
        ("NBTSTAT_a",  f"nbtstat -a {TARGET_IP}"),   # query by name
        ("NBTSTAT_n",  "nbtstat -n"),                 # local table
        ("NBTSTAT_c",  "nbtstat -c"),                 # cache
        ("NSLOOKUP",   f"nslookup {TARGET_IP}"),      # DNS reverse lookup
        ("NSLOOKUP2",  f"nslookup -type=PTR {TARGET_IP}"),
        ("PING_TTL",   f"ping -n 1 -w 500 {TARGET_IP}"),
        ("TRACERT",    f"tracert -d -h 3 -w 500 {TARGET_IP}"),
    ]
    for label, cmd in nb_cmds:
        output = run_cmd(cmd, timeout=6)
        print(f"  [{label}] → {output[:60]}")
        log_rows.append({
            "timestamp": datetime.now().isoformat(),
            "phase": "NETBIOS_DEEP",
            "action": label,
            "target": TARGET_IP,
            "detail": cmd,
            "result": output[:200]
        })
        time.sleep(random.uniform(0.3, 0.7))

# ── Phase 3: Share Enumeration — TCP probe only, KHÔNG net use ───────────────
def phase_share_enum(log_rows):
    """
    Với mỗi share: chỉ TCP connect vào port 445/139.
    Ghi lại UNC path vào log để IDS biết đây là share enum.
    KHÔNG gửi credentials → KHÔNG có NTLMSSP trong Wireshark.
    """
    print(f"\n[Phase 3] 📂 Share Enumeration ({len(SHARE_NAMES)} shares) — TCP only")
    for share in SHARE_NAMES:
        unc = f"\\\\{TARGET_IP}\\{share}"

        # TCP connect vào 445
        is_445 = tcp_probe(TARGET_IP, 445, timeout=1.0)
        # TCP connect vào 139
        is_139 = tcp_probe(TARGET_IP, 139, timeout=1.0)

        result = "REACHABLE" if (is_445 or is_139) else "UNREACHABLE"
        print(f"  {share:<20} → {result}")
        log_rows.append({
            "timestamp": datetime.now().isoformat(),
            "phase": "SHARE_ENUM",
            "action": f"TRY_SHARE_{share}",
            "target": TARGET_IP,
            "detail": unc,
            "result": result
        })
        time.sleep(0.15)

# ── Phase 4: SMB2 Negotiate Only Probe ───────────────────────────────────────
def phase_smb_negotiate(log_rows):
    """
    Gửi SMB2 Negotiate Request → nhận response → đóng ngay.
    Tạo traffic đặc trưng của scanner (nmap, enum4linux).
    KHÔNG có Session Setup → KHÔNG có NTLMSSP.
    """
    print(f"\n[Phase 4] 🤝 SMB2 Negotiate-Only Probe × 20 lần")
    for i in range(20):
        is_smb2 = smb_negotiate_only(TARGET_IP, 445)
        result = "SMB2_CONFIRMED" if is_smb2 else "NO_RESPONSE"
        print(f"  Probe {i+1:02d}/20 → {result}")
        log_rows.append({
            "timestamp": datetime.now().isoformat(),
            "phase": "SMB_NEGOTIATE",
            "action": f"NEGOTIATE_{i+1}",
            "target": TARGET_IP,
            "detail": "SMB2 Negotiate Request only — no auth",
            "result": result
        })
        time.sleep(random.uniform(0.2, 0.5))

# ── Phase 5: RPC Named Pipe Probe — TCP connect vào 445 ──────────────────────
def phase_rpc_pipe_probe(log_rows):
    """
    Probe từng named pipe bằng TCP connect + SMB2 Negotiate.
    Mô phỏng rpcclient / enum4linux thăm dò pipe.
    KHÔNG authenticate.
    """
    print(f"\n[Phase 5] 🔧 RPC Named Pipe Probe ({len(RPC_PIPES)} pipes)")
    for pipe_name, desc in RPC_PIPES:
        # SMB2 Negotiate để xác nhận port mở
        is_smb2 = smb_negotiate_only(TARGET_IP, 445)
        result = f"PIPE_PROBE_{'REACH' if is_smb2 else 'FAIL'}:{pipe_name}"
        print(f"  \\PIPE\\{pipe_name:<12} ({desc[:35]}) → {result}")
        log_rows.append({
            "timestamp": datetime.now().isoformat(),
            "phase": "RPC_PIPE_PROBE",
            "action": f"PIPE_{pipe_name.upper()}",
            "target": TARGET_IP,
            "detail": f"\\PIPE\\{pipe_name} — {desc}",
            "result": result
        })
        time.sleep(random.uniform(0.2, 0.5))

# ── Phase 6: Timing Variation Probe ──────────────────────────────────────────
def phase_timing_variation(log_rows):
    """
    Probe với 3 tốc độ khác nhau:
    - Slow (evasion): 3s delay
    - Fast (aggressive): 0.1s delay
    - Random (stealth): 0.5–4s random delay
    IDS học được cả 3 pattern.
    """
    print(f"\n[Phase 6] ⏱️  Timing Variation Probe")

    # Slow scan
    print("  [SLOW] 5 probes × 3s delay")
    for i in range(5):
        tcp_probe(TARGET_IP, 445, timeout=2.0)
        log_rows.append({
            "timestamp": datetime.now().isoformat(),
            "phase": "TIMING_VARIATION",
            "action": f"SLOW_PROBE_{i+1}",
            "target": TARGET_IP,
            "detail": "port=445 delay=3s",
            "result": "PROBED"
        })
        print(f"    Slow {i+1}/5 ✓")
        time.sleep(3.0)

    # Fast scan
    print("  [FAST] 20 probes × 0.1s delay")
    for i in range(20):
        tcp_probe(TARGET_IP, 445, timeout=0.5)
        tcp_probe(TARGET_IP, 139, timeout=0.5)
        log_rows.append({
            "timestamp": datetime.now().isoformat(),
            "phase": "TIMING_VARIATION",
            "action": f"FAST_PROBE_{i+1}",
            "target": TARGET_IP,
            "detail": "port=445+139 delay=0.1s",
            "result": "PROBED"
        })
        time.sleep(0.1)
    print(f"    Fast 20/20 ✓")

    # Random timing
    print("  [RAND] 10 probes × random delay")
    for i in range(10):
        delay = random.uniform(0.5, 4.0)
        port  = random.choice([139, 445])
        tcp_probe(TARGET_IP, port, timeout=1.0)
        log_rows.append({
            "timestamp": datetime.now().isoformat(),
            "phase": "TIMING_VARIATION",
            "action": f"RAND_PROBE_{i+1}",
            "target": TARGET_IP,
            "detail": f"port={port} delay={delay:.1f}s",
            "result": "PROBED"
        })
        print(f"    Rand {i+1}/10 ✓ (port={port} delay={delay:.1f}s)")
        time.sleep(delay)

# ── Phase 7: Repeated TCP Probe (volume) — KHÔNG net view ────────────────────
def phase_repeated_probe(log_rows, rounds=80):
    """
    TCP connect thuần vào 445 + 139.
    KHÔNG gọi net view / net use → KHÔNG trigger NTLM.
    """
    print(f"\n[Phase 7] 🔁 Repeated TCP Probe × {rounds} lần (volume traffic)")
    for i in range(rounds):
        tcp_probe(TARGET_IP, 445)
        tcp_probe(TARGET_IP, 139)
        log_rows.append({
            "timestamp": datetime.now().isoformat(),
            "phase": "REPEATED_PROBE",
            "action": f"ROUND_{i+1}",
            "target": TARGET_IP,
            "detail": "TCP_ONLY port=445+139",
            "result": "PROBED"
        })
        print(f"  Round {i+1:02d}/{rounds} ✓")
        time.sleep(0.4)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    os.makedirs("logs", exist_ok=True)
    print(f"\n{'='*50}")
    print(f"  [TEST] SMB_ENUMERATION")
    print(f"  Target : {TARGET_IP}")
    print(f"  Time   : {datetime.now()}")
    print(f"{'='*50}")

    log_rows = []
    fields = ["timestamp", "phase", "action", "target", "detail", "result"]

    phase_port_probe(log_rows)           # Phase 1 —   4 records
    phase_netbios_deep(log_rows)         # Phase 2 —   8 records
    phase_share_enum(log_rows)           # Phase 3 —  50 records
    phase_smb_negotiate(log_rows)        # Phase 4 —  20 records
    phase_rpc_pipe_probe(log_rows)       # Phase 5 —   8 records
    phase_timing_variation(log_rows)     # Phase 6 —  35 records
    phase_repeated_probe(log_rows, rounds=80)  # Phase 7 — 80 records

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(log_rows)

    print(f"\n{'='*50}")
    print(f"  ✅ Hoàn thành. {len(log_rows)} records → {OUTPUT_FILE}")
    print(f"{'='*50}\n")

if __name__ == "__main__":
    main()
