"""Resource usage of the machine running THIS backend process — i.e. the
Web-SCADA gateway host, not the PLC. A PLC doesn't run a general-purpose OS,
so there is no honest way to read its CPU/RAM from here. What this DOES show
truthfully: whether the gateway's own OPC UA client is under load (e.g. while
handling a subscription flood aimed at the PLC, the gateway still has to
process every notification it receives).
"""

import psutil


def sample() -> dict:
    return {
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory_percent": psutil.virtual_memory().percent,
    }


def warm_up() -> None:
    """psutil.cpu_percent(interval=None) compares against the last call: the
    very first reading right after import is meaningless. Call this once at
    startup and discard the result so the first real sample is accurate.
    """
    psutil.cpu_percent(interval=None)
