"""
barrier_sync.py -- diem hen (rendezvous) qua TCP giua 2 may attacker, dung de
dong bo cac buoc chuyen ROUND trong run_full_2attacker.sh (khong dung sleep
doan mo thoi gian).

Co che: 1 may luon dong vai SERVER (bind + listen + accept, block cho toi khi
may kia ket noi toi), may con lai luon dong vai CLIENT (retry connect cho toi
khi thanh cong). Ben nao den diem hen truoc se bi block cho toi khi ben kia
cung den -- ca 2 tiep tuc gan nhu dong thoi ngay sau do. Dung lai duoc nhieu
lan (nhieu barrier) vi moi lan goi la 1 socket moi, khong giu state.

Vi du (goi tu run_full_2attacker.sh):
  May A (server): python barrier_sync.py --role server --port 57123 --tag round1_done
  May B (client): python barrier_sync.py --role client --peer-ip 192.168.210.32 --port 57123 --tag round1_done
"""

import argparse
import socket
import sys
import time


def run_server(port: int, tag: str, timeout_s: float) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(1)
    s.settimeout(timeout_s if timeout_s > 0 else None)
    print(f"[barrier:{tag}] server dang cho peer ket noi vao port {port} ...", flush=True)
    try:
        conn, addr = s.accept()
    except socket.timeout:
        print(f"[barrier:{tag}] TIMEOUT sau {timeout_s}s -- khong thay peer.", flush=True)
        s.close()
        sys.exit(1)
    conn.recv(16)
    conn.sendall(b"GO")
    conn.close()
    s.close()
    print(f"[barrier:{tag}] peer {addr[0]} da toi -> GO", flush=True)


def run_client(peer_ip: str, port: int, tag: str, timeout_s: float) -> None:
    start = time.time()
    attempt = 0
    while True:
        attempt += 1
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((peer_ip, port))
            s.sendall(b"HELLO")
            s.recv(16)
            s.close()
            print(f"[barrier:{tag}] server da ack -> GO (attempt {attempt})", flush=True)
            return
        except OSError:
            if timeout_s > 0 and (time.time() - start) > timeout_s:
                print(f"[barrier:{tag}] TIMEOUT sau {timeout_s}s -- khong ket noi duoc server.", flush=True)
                sys.exit(1)
            time.sleep(3)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--role", choices=["server", "client"], required=True)
    p.add_argument("--peer-ip", help="Bat buoc voi --role client")
    p.add_argument("--port", type=int, default=57123)
    p.add_argument("--tag", default="barrier", help="Nhan in ra log de biet dang cho barrier nao")
    p.add_argument("--timeout", type=float, default=0, help="Giay, 0 = cho vo han (mac dinh)")
    args = p.parse_args()

    if args.role == "server":
        run_server(args.port, args.tag, args.timeout)
    else:
        if not args.peer_ip:
            sys.exit("[ERROR] --peer-ip bat buoc voi --role client")
        run_client(args.peer_ip, args.port, args.tag, args.timeout)


if __name__ == "__main__":
    main()
