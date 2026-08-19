"""Backend host resource sampling (CPU/RAM of the Web-SCADA gateway machine)."""

from .service import sample, warm_up

__all__ = ["sample", "warm_up"]
