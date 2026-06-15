from __future__ import annotations
from typing import List, Dict
import time
from snap7.util import get_bool
from s7pwn.runtime import get_current_target
from s7pwn.utils import s7_connect
from s7pwn.core_io import AREA_MAP, MONITOR_RANGE_DEFAULT, INTERVAL_DEFAULT, b01, bool_chain

def monitor(args: List[str]) -> None:
    mode = "bit"
    if len(args) == 1 and args[0] in ("--bit","--byte"):
        mode = "byte" if args[0] == "--byte" else "bit"

    t = get_current_target()
    if not t:
        print("No target selected. Use 'set_target' or 'select'."); return
    ip, rack, slot = t["ip"], t["rack"], t["slot"]

    c = s7_connect(ip, rack, slot)
    if not c:
        print("Connect failed."); return

    try:
        print(f"Starting monitor mode ({INTERVAL_DEFAULT}s interval, mode={mode}). Monitoring {MONITOR_RANGE_DEFAULT} bytes for I, Q, M. Press Ctrl+C to stop.")
        last_bytes = {"I": b"", "Q": b"", "M": b""}
        state_bits = {"I": {}, "Q": {}, "M": {}}
        history    = {"I": {}, "Q": {}, "M": {}}
        history_bytes = {"I": {}, "Q": {}, "M": {}} # For byte mode summary

        while True:
            for area_str, area_type in AREA_MAP.items():
                try:
                    data = c.read_area(area_type, 0, 0, MONITOR_RANGE_DEFAULT)
                except Exception as e:
                    print(f"Error monitoring {area_str}: {e}")
                    continue

                prev = last_bytes[area_str]
                if prev == data:
                    continue
                last_bytes[area_str] = data

                for byte_index in range(MONITOR_RANGE_DEFAULT):
                    prev_byte = prev[byte_index] if len(prev)==MONITOR_RANGE_DEFAULT else None
                    cur_byte  = data[byte_index]
                    if prev_byte is not None and prev_byte == cur_byte:
                        continue
                    
                    addr_byte = f"{area_str}{byte_index}"
                    if mode == "byte" and prev_byte is not None:
                        print(f"{addr_byte} {prev_byte}->{cur_byte}")
                        if addr_byte not in history_bytes[area_str]:
                            history_bytes[area_str][addr_byte] = [prev_byte, cur_byte]
                        else:
                            history_bytes[area_str][addr_byte].append(cur_byte)
                    
                    for bit_index in range(8):
                        addr  = f"{area_str}{byte_index}.{bit_index}"
                        val   = get_bool(data, byte_index, bit_index)
                        if addr not in state_bits[area_str]:
                            state_bits[area_str][addr] = val
                        else:
                            if state_bits[area_str][addr] != val:
                                if mode == "bit":
                                    print(f"{addr} {b01(state_bits[area_str][addr])}->{b01(val)}")
                                prev_val = state_bits[area_str][addr]
                                state_bits[area_str][addr] = val
                                if addr not in history[area_str]:
                                    history[area_str][addr] = [prev_val, val]
                                else:
                                    history[area_str][addr].append(val)
            time.sleep(INTERVAL_DEFAULT)

    except KeyboardInterrupt:
        print("\nMonitor stopped. Summary of changes:")
        
        if mode == "bit":
            def parse_bit_address(addr: str) -> tuple[int, int, int]:
                area_char = addr[0]
                rest = addr[1:]
                byte_str, bit_str = rest.split('.')
                byte_num = int(byte_str)
                bit_num = int(bit_str)
                area_priority_map = {'M': 0, 'I': 1, 'Q': 2}
                area_priority = area_priority_map.get(area_char, 99)
                return (area_priority, byte_num, bit_num)
            
            all_addresses = []
            for area_str in ("M", "I", "Q"): 
                if area_str in history:
                    for addr in history[area_str].keys():
                        if len(history[area_str].get(addr, [])) >= 2:
                            all_addresses.append(addr)
            
            sorted_addrs = sorted(all_addresses, key=parse_bit_address)
            
            if not sorted_addrs: print("No changes detected.")
            for addr in sorted_addrs:
                area_str = addr[0]
                seq = history[area_str][addr]
                print(f"{addr}:{bool_chain(seq)}")

        elif mode == "byte":
            def byte_chain(seq: List[int]) -> str:
                return "->".join(map(str, seq))

            def parse_byte_address(addr: str) -> tuple[int, int]:
                area_char = addr[0]
                byte_num = int(addr[1:])
                area_priority_map = {'M': 0, 'I': 1, 'Q': 2}
                area_priority = area_priority_map.get(area_char, 99)
                return (area_priority, byte_num)

            all_addresses = []
            for area_str in ("M", "I", "Q"):
                if area_str in history_bytes:
                    all_addresses.extend(history_bytes[area_str].keys())

            sorted_addrs = sorted(all_addresses, key=parse_byte_address)
            
            if not sorted_addrs: print("No changes detected.")
            for addr in sorted_addrs:
                area_str = addr[0]
                seq = history_bytes[area_str][addr]
                print(f"{addr}:{byte_chain(seq)}")

        print()
    finally:
        try: 
            c.disconnect()
        except Exception: 
            pass