from __future__ import annotations
"""
sniff.py – Passive S7 / ICS Traffic Sniffer
--------------------------------------------
Listens on a network interface and decodes S7comm (port 102) and
Modbus TCP (port 502) packets in real-time WITHOUT sending any traffic.

Output modes
------------
  summary  (default) – one line per packet: timestamp, src->dst, PDU info
  hex                – full hex dump of the S7 payload
  csv                – write decoded fields to a .csv file for dataset use

Usage
-----
  sniff [iface] [--port 102|502|all] [--mode summary|hex|csv]
        [--output file.csv] [--count N] [--filter "host 192.168.1.10"]

Examples
--------
  sniff                              # sniff S7 on default iface (summary)
  sniff eth0 --port all              # S7 + Modbus on eth0
  sniff eth0 --mode csv --output capture.csv --count 500
  sniff eth0 --filter "host 10.0.0.5" --mode hex

Requirements
------------
  pip install scapy          (raw socket capture)

Dataset note
------------
Running `--mode csv` produces a row per packet with fields:
  timestamp, src_ip, dst_ip, src_port, dst_port, proto,
  payload_len, pdu_type, function_code, area, byte_index, data_hex
– ready for direct ingestion into the IDS training pipeline.
"""

import time
import csv
import sys
import os
from typing import List, Optional

# ──────────────────────────────────────────────
#  Scapy import guard
# ──────────────────────────────────────────────
try:
    from scapy.all import sniff as scapy_sniff, IP, TCP, Raw, conf as scapy_conf
    _SCAPY = True
except ImportError:
    _SCAPY = False

# ──────────────────────────────────────────────
#  S7comm PDU decoder (minimal, no external lib)
# ──────────────────────────────────────────────

# S7 TPKT header: 4 bytes (version=3, reserved=0, length 2B)
# COTP header   : starts at byte 4
# S7 PDU        : starts after COTP (usually byte 7)

S7_PORT  = 102
MOD_PORT = 502

_S7_ROSCTR = {
    0x01: "JOB",
    0x02: "ACK",
    0x03: "ACK_DATA",
    0x07: "USERDATA",
}

_S7_FUNC = {
    0x04: "READ_VAR",
    0x05: "WRITE_VAR",
    0x1A: "REQ_DOWNLOAD",
    0x1B: "DL_BLOCK",
    0x1C: "END_DOWNLOAD",
    0x1D: "INIT_UPLOAD",
    0x1E: "UPLOAD",
    0x1F: "END_UPLOAD",
    0x28: "INSERT_BLOCK",
    0x29: "PLC_STOP",
    0xF0: "NEGOTIATE_PDU",
}


def _parse_s7(raw: bytes) -> dict:
    """Return a best-effort dict of decoded S7comm fields."""
    result = {"proto": "S7", "pdu_type": "", "function_code": ""}
    if len(raw) < 10:
        return result
    # Check TPKT magic
    if raw[0] != 0x03 or raw[1] != 0x00:
        return result
    # COTP length byte at offset 4
    cotp_len = raw[4] + 1          # COTP header length including length byte
    s7_start = 4 + cotp_len
    if len(raw) < s7_start + 4:
        return result
    s7 = raw[s7_start:]
    if s7[0] != 0x32:              # S7 magic byte
        return result
    rosctr = s7[1]
    result["pdu_type"] = _S7_ROSCTR.get(rosctr, f"0x{rosctr:02x}")
    if len(s7) > 10:
        func = s7[10] if rosctr in (0x01, 0x03) else 0
        result["function_code"] = _S7_FUNC.get(func, f"0x{func:02x}" if func else "")
    result["payload_hex"] = raw[s7_start:s7_start + 32].hex()
    return result


def _parse_modbus(raw: bytes) -> dict:
    """Best-effort Modbus TCP decoder."""
    result = {"proto": "Modbus", "pdu_type": "", "function_code": ""}
    if len(raw) < 8:
        return result
    func = raw[7]
    _FUNC = {
        0x01: "READ_COILS", 0x02: "READ_DI", 0x03: "READ_HR",
        0x04: "READ_IR",    0x05: "WRITE_COIL", 0x06: "WRITE_REG",
        0x0F: "WRITE_MULTI_COILS", 0x10: "WRITE_MULTI_REGS",
        0x17: "READ_WRITE_REGS",
    }
    result["function_code"] = _FUNC.get(func, f"0x{func:02x}")
    result["payload_hex"] = raw[:32].hex()
    return result


# ──────────────────────────────────────────────
#  CSV writer context
# ──────────────────────────────────────────────

_CSV_FIELDS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "proto", "payload_len", "pdu_type", "function_code", "payload_hex",
]


class _CsvWriter:
    def __init__(self, path: str):
        self.path = path
        self._f   = open(path, "w", newline="")
        self._w   = csv.DictWriter(self._f, fieldnames=_CSV_FIELDS, extrasaction="ignore")
        self._w.writeheader()
        self.count = 0

    def write(self, row: dict):
        self._w.writerow(row)
        self.count += 1

    def close(self):
        self._f.close()


# ──────────────────────────────────────────────
#  Packet callback factory
# ──────────────────────────────────────────────

def _make_callback(mode: str, ports: List[int], csv_writer: Optional[_CsvWriter],
                   counter: list, max_count: int):

    def callback(pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if ports and (sport not in ports) and (dport not in ports):
            return

        raw     = bytes(pkt[Raw].load)
        ts      = time.strftime("%H:%M:%S")
        src_ip  = pkt[IP].src if pkt.haslayer(IP) else "?"
        dst_ip  = pkt[IP].dst if pkt.haslayer(IP) else "?"

        if dport == S7_PORT or sport == S7_PORT:
            fields = _parse_s7(raw)
        elif dport == MOD_PORT or sport == MOD_PORT:
            fields = _parse_modbus(raw)
        else:
            fields = {"proto": "TCP", "pdu_type": "", "function_code": "",
                      "payload_hex": raw[:16].hex()}

        row = {
            "timestamp":     ts,
            "src_ip":        src_ip,
            "dst_ip":        dst_ip,
            "src_port":      sport,
            "dst_port":      dport,
            "proto":         fields["proto"],
            "payload_len":   len(raw),
            "pdu_type":      fields.get("pdu_type", ""),
            "function_code": fields.get("function_code", ""),
            "payload_hex":   fields.get("payload_hex", ""),
        }

        if mode == "summary":
            fc  = f" func={row['function_code']}"  if row["function_code"] else ""
            pdu = f" pdu={row['pdu_type']}"         if row["pdu_type"]      else ""
            print(f"[{ts}] {src_ip}:{sport} -> {dst_ip}:{dport}  "
                  f"{row['proto']}{pdu}{fc}  len={len(raw)}")

        elif mode == "hex":
            print(f"[{ts}] {src_ip}:{sport} -> {dst_ip}:{dport}  "
                  f"{row['proto']} len={len(raw)}")
            for i in range(0, min(len(raw), 64), 16):
                chunk = raw[i:i + 16]
                print("  " + " ".join(f"{b:02x}" for b in chunk))
            print()

        elif mode == "csv" and csv_writer:
            csv_writer.write(row)
            if csv_writer.count % 50 == 0:
                print(f"[*] Captured {csv_writer.count} packets -> {csv_writer.path}")

        counter[0] += 1
        if max_count and counter[0] >= max_count:
            raise KeyboardInterrupt   # stop sniffing

    return callback


# ──────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────

def sniff(args: List[str]) -> None:
    if not _SCAPY:
        print("[!] scapy is not installed.")
        print("    Run: pip install scapy")
        return

    iface      = None
    port_arg   = "s7"
    mode       = "summary"
    output     = None
    count      = 0          # 0 = unlimited
    bpf_extra  = ""

    i = 0
    while i < len(args):
        a = args[i]
        if a == "--port" and i + 1 < len(args):
            port_arg = args[i + 1]; i += 2
        elif a == "--mode" and i + 1 < len(args):
            mode = args[i + 1].lower(); i += 2
        elif a == "--output" and i + 1 < len(args):
            output = args[i + 1]; i += 2
        elif a == "--count" and i + 1 < len(args):
            count = int(args[i + 1]); i += 2
        elif a == "--filter" and i + 1 < len(args):
            bpf_extra = args[i + 1]; i += 2
        elif not a.startswith("--"):
            iface = a; i += 1
        else:
            i += 1

    # Resolve ports
    if port_arg == "all":
        ports = [S7_PORT, MOD_PORT]
        bpf   = f"tcp port {S7_PORT} or tcp port {MOD_PORT}"
    elif port_arg in ("modbus", "502"):
        ports = [MOD_PORT]
        bpf   = f"tcp port {MOD_PORT}"
    else:  # default: s7 / 102
        ports = [S7_PORT]
        bpf   = f"tcp port {S7_PORT}"

    if bpf_extra:
        bpf = f"({bpf}) and ({bpf_extra})"

    if mode not in ("summary", "hex", "csv"):
        print(f"[!] Unknown mode '{mode}'. Valid: summary | hex | csv"); return

    csv_writer = None
    if mode == "csv":
        outpath = output or f"sniff_{int(time.time())}.csv"
        csv_writer = _CsvWriter(outpath)
        print(f"[*] CSV output: {os.path.abspath(outpath)}")

    iface_str = f"iface={iface}" if iface else "default iface"
    print(f"[*] Sniffing {port_arg.upper()} traffic  [{iface_str}]  mode={mode}")
    print(f"[*] BPF filter: {bpf}")
    if count:
        print(f"[*] Will capture {count} packets then stop.")
    print("[*] Press Ctrl+C to stop.\n")

    counter = [0]
    cb = _make_callback(mode, ports, csv_writer, counter, count)

    try:
        scapy_sniff(
            iface=iface,
            filter=bpf,
            prn=cb,
            store=False,
            stop_filter=lambda _: (count > 0 and counter[0] >= count),
        )
    except KeyboardInterrupt:
        print(f"\n[!] Sniff stopped. Total packets captured: {counter[0]}")
    except PermissionError:
        print("[!] Permission denied – run as root/administrator for raw capture.")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        if csv_writer:
            csv_writer.close()
            print(f"[+] Saved {csv_writer.count} rows -> {os.path.abspath(csv_writer.path)}")
