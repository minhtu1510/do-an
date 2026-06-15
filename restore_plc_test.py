#!/usr/bin/env python3
"""Restore conveyor PLC Merker state safely.

This tool is for the bang-truyen/conveyor tag map. It intentionally does not
write PA/Q outputs and does not issue remote CPU STOP/START commands.
"""

from __future__ import annotations

import argparse
import os
import re
import time
from pathlib import Path

import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import set_bool, set_dint


def load_testbed_conf(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    conf = Path(path)
    if not conf.exists():
        return values
    pattern = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["\']?([^"\'#]*)["\']?')
    for line in conf.read_text(encoding='utf-8').splitlines():
        match = pattern.match(line)
        if match:
            values[match.group(1)] = match.group(2).strip()
    return values


def write_dint(client: snap7.client.Client, offset: int, value: int) -> None:
    buf = bytearray(4)
    set_dint(buf, 0, int(value))
    client.write_area(Areas.MK, 0, offset, buf)


def restore(args: argparse.Namespace) -> int:
    client = snap7.client.Client()
    try:
        print(f"[*] Connect PLC {args.target} rack={args.rack} slot={args.slot}")
        client.connect(args.target, args.rack, args.slot)
    except Exception as exc:
        print(f"[!] Cannot connect PLC: {exc}")
        print("[!] Check IP, rack/slot, network, Snap7, and PUT/GET access.")
        return 2

    try:
        try:
            state = str(client.get_cpu_state())
            print(f"[*] CPU state: {state}")
            if "Stop" in state or state == "4":
                print("[!] CPU appears STOP. Start it manually in TIA/PLC panel; this tool will not issue CPU control.")
        except Exception as exc:
            print(f"[!] Cannot read CPU state: {exc}")

        print("[*] Reset M5/M6 conveyor control and spoof bits")
        m5 = client.read_area(Areas.MK, 0, 5, 1)
        for bit in range(8):
            set_bool(m5, 0, bit, False)
        client.write_area(Areas.MK, 0, 5, m5)

        m6 = client.read_area(Areas.MK, 0, 6, 1)
        set_bool(m6, 0, 0, False)  # Vat_3
        set_bool(m6, 0, 1, False)  # S1
        set_bool(m6, 0, 2, False)  # Tag_8
        client.write_area(Areas.MK, 0, 6, m6)

        print("[*] Restore conveyor timers")
        write_dint(client, 50, args.times1_ms)
        write_dint(client, 54, args.default_cd_ms)
        write_dint(client, 58, args.default_cd_ms)
        write_dint(client, 62, args.default_cd_ms)
        print(f"[+] Times_1={args.times1_ms}, CD1/CD2/CD3={args.default_cd_ms}")

        if args.start_pulse:
            print("[*] Send START pulse on M5.0")
            m5 = client.read_area(Areas.MK, 0, 5, 1)
            set_bool(m5, 0, 0, True)
            set_bool(m5, 0, 1, False)
            client.write_area(Areas.MK, 0, 5, m5)
            time.sleep(0.3)
            m5 = client.read_area(Areas.MK, 0, 5, 1)
            set_bool(m5, 0, 0, False)
            client.write_area(Areas.MK, 0, 5, m5)
            print("[+] START pulse completed")

        return 0
    except Exception as exc:
        print(f"[!] Restore failed: {exc}")
        return 3
    finally:
        try:
            client.disconnect()
        except Exception:
            pass


def main() -> int:
    conf = load_testbed_conf('testbed.conf')
    parser = argparse.ArgumentParser(description='Restore bang-truyen/conveyor PLC Merker state')
    parser.add_argument('--target', default=os.getenv('TARGET_IP') or conf.get('TARGET_IP', '192.168.1.10'))
    parser.add_argument('--rack', type=int, default=int(os.getenv('RACK') or conf.get('RACK', 0)))
    parser.add_argument('--slot', type=int, default=int(os.getenv('SLOT') or conf.get('SLOT', 1)))
    parser.add_argument('--default-cd-ms', type=int, default=int(os.getenv('DEFAULT_CD_MS') or conf.get('DEFAULT_CD_MS', 5000)))
    parser.add_argument('--times1-ms', type=int, default=int(os.getenv('RESTORE_TIMES1_MS') or conf.get('RESTORE_TIMES1_MS', 0)))
    parser.add_argument('--no-start-pulse', dest='start_pulse', action='store_false')
    parser.set_defaults(start_pulse=(os.getenv('RESTORE_START_PULSE') or conf.get('RESTORE_START_PULSE', '1')) == '1')
    args = parser.parse_args()

    print('=' * 60)
    print('Conveyor PLC restore')
    print('=' * 60)
    rc = restore(args)
    print('=' * 60)
    print('DONE' if rc == 0 else 'FAILED')
    print('=' * 60)
    return rc


if __name__ == '__main__':
    raise SystemExit(main())
