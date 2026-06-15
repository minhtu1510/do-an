from __future__ import annotations
from typing import Optional, List, Dict, Any

# Danh sách toàn bộ thiết bị tìm được từ scan (mọi loại)
found_devices: List[Dict[str, Any]] = []

# Danh sách chỉ PLC Siemens (S7-1500/1200/300/400)
plc_devices: List[Dict[str, Any]] = []

# Mục tiêu hiện tại: {"ip": str, "rack": int, "slot": int}
current_target: Optional[Dict[str, Any]] = None
