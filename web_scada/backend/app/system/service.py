"""Resource usage of the machine running THIS backend process — i.e. the
Web-SCADA gateway host, not the PLC. A PLC doesn't run a general-purpose OS,
so there is no honest way to read its CPU/RAM from here. What this DOES show
truthfully: whether the gateway's own OPC UA client is under load (e.g. while
handling a subscription flood aimed at the PLC, the gateway still has to
process every notification it receives).
"""

import time

import psutil

_last_net = {"t": None, "sent": 0, "recv": 0}


def sample() -> dict:
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters()
    now = time.monotonic()

    sent_rate = recv_rate = 0.0
    if _last_net["t"] is not None:
        dt = now - _last_net["t"]
        if dt > 0:
            sent_rate = max(0.0, (net.bytes_sent - _last_net["sent"]) / dt)
            recv_rate = max(0.0, (net.bytes_recv - _last_net["recv"]) / dt)
    _last_net.update(t=now, sent=net.bytes_sent, recv=net.bytes_recv)

    return {
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": disk.percent,
        "net_sent_bytes_per_sec": round(sent_rate, 1),
        "net_recv_bytes_per_sec": round(recv_rate, 1),
    }


def warm_up() -> None:
    """psutil.cpu_percent(interval=None) compares against the last call: the
    very first reading right after import is meaningless. Call this once at
    startup and discard the result so the first real sample is accurate.
    """
    psutil.cpu_percent(interval=None)
