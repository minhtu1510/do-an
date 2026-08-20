from __future__ import annotations
from s7pwn.runtime import get_current_target
from s7pwn.utils import s7_connect

def probe() -> None:
    t = get_current_target()
    if not t:
        print("No target selected. Use 'set_target' or 'select'.")
        return
    ip, rack, slot = t["ip"], t["rack"], t["slot"]
    print(f"Probing target: {ip} (rack {rack}, slot {slot})")
    c = s7_connect(ip, rack, slot)
    if not c:
        print("Probing failed: connect error")
        return
    try:
        cpu_info = c.get_cpu_info()
        cpu_state = c.get_cpu_state()
        def _s(x):
            try:
                return x.decode('utf-8', errors='replace') if isinstance(x,(bytes,bytearray)) else str(x)
            except Exception:
                return str(x)
        info = {
            "ModuleTypeName": _s(cpu_info.ModuleTypeName),
            "SerialNumber":    _s(cpu_info.SerialNumber),
            "ASName":          _s(cpu_info.ASName),
            "Copyright":       _s(cpu_info.Copyright),
            "ModuleName":      _s(cpu_info.ModuleName),
            "CPUState":        _s(cpu_state),
        }
        print("\nTarget Information:")
        for k,v in info.items():
            print(f"{k}: {v}")
        print()
    except Exception as e:
        print(f"Probing failed: {e}")
    finally:
        try: c.disconnect()
        except Exception: pass
