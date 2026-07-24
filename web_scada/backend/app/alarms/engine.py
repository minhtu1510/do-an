"""Derive process events from real gateway status and tag updates."""

from typing import Any

from ..events.models import EventRecord


_MISSING = object()

# Stage sensor bits that can never all be True at once on a single-lane
# conveyor — if they are, the tag source is reporting an impossible physical
# state (spoofed/replayed values rather than a real sensor read).
_SPOOF_WATCH_KEYS = ("vat_1", "vat_2", "vat_3")


class AlarmEngine:
    def __init__(self):
        self._last_values: dict[str, Any] = {}
        self._last_stale: dict[str, bool] = {}
        self._last_connected: bool | None = None
        self._last_reconnect_count = 0
        self._active_alarms: set[str] = set()
        self.stale_event_count = 0
        self.rejected_operation_count = 0

    def process_tag_update(self, key: str, data: dict[str, Any]) -> list[EventRecord]:
        events: list[EventRecord] = []
        old_value = self._last_values.get(key, _MISSING)
        new_value = data.get("value")
        was_stale = self._last_stale.get(key, False)
        is_stale = bool(data.get("stale"))

        if old_value is not _MISSING and old_value != new_value:
            if key == "bang_tai" and isinstance(new_value, bool):
                events.append(EventRecord(
                    event_type="CONVEYOR_STARTED" if new_value else "CONVEYOR_STOPPED",
                    message="The conveyor started running" if new_value else "The conveyor stopped",
                    tag_key=key,
                    old_value=old_value,
                    new_value=new_value,
                ))
            elif key == "hien_thi":
                events.append(EventRecord(
                    event_type="PRODUCT_COUNT_CHANGED",
                    message="Completed production quantity changed",
                    tag_key=key,
                    old_value=old_value,
                    new_value=new_value,
                ))

        if not was_stale and is_stale:
            self.stale_event_count += 1
            self._active_alarms.add(f"stale:{key}")
            events.append(EventRecord(
                severity="WARN",
                event_type="OPCUA_STALE",
                message=f"Tag {key} became stale",
                tag_key=key,
                old_value=old_value if old_value is not _MISSING else None,
                new_value=new_value,
                status="ACTIVE",
            ))
        elif was_stale and not is_stale:
            self._active_alarms.discard(f"stale:{key}")
            events.append(EventRecord(
                event_type="OPCUA_RECONNECTED",
                message=f"Tag {key} returned to good quality",
                tag_key=key,
                old_value=old_value if old_value is not _MISSING else None,
                new_value=new_value,
            ))

        self._last_values[key] = new_value
        self._last_stale[key] = is_stale

        if key in _SPOOF_WATCH_KEYS:
            events.extend(self._check_sensor_spoof())

        return events

    def _check_sensor_spoof(self) -> list[EventRecord]:
        events: list[EventRecord] = []
        spoof_values = {k: self._last_values.get(k) for k in _SPOOF_WATCH_KEYS}
        all_active = all(v is True for v in spoof_values.values())
        was_active = "sensor_spoof" in self._active_alarms

        if all_active and not was_active:
            self._active_alarms.add("sensor_spoof")
            events.append(EventRecord(
                severity="ERROR",
                event_type="ATTACK_SENSOR_SPOOF_SUSPECTED",
                message="All 3 stage sensors (vat_1/vat_2/vat_3) are active simultaneously "
                        "— physically impossible on this conveyor, possible sensor spoofing",
                tag_key="process_integrity",
                new_value=spoof_values,
                status="ACTIVE",
            ))
        elif not all_active and was_active:
            self._active_alarms.discard("sensor_spoof")
            events.append(EventRecord(
                event_type="ATTACK_SENSOR_SPOOF_CLEARED",
                message="Stage sensors no longer all active — spoof condition cleared",
                tag_key="process_integrity",
                new_value=spoof_values,
                status="CLEARED",
            ))

        return events

    def process_gateway_status(self, status: dict[str, Any]) -> list[EventRecord]:
        events: list[EventRecord] = []
        connected = bool(status.get("connected"))
        reconnect_count = int(status.get("reconnect_count") or 0)

        if self._last_connected is None or self._last_connected != connected:
            if connected:
                self._active_alarms.discard("plc_connection")
            else:
                self._active_alarms.add("plc_connection")

            events.append(EventRecord(
                severity="INFO" if connected else "ERROR",
                event_type="PLC_CONNECTED" if connected else "PLC_DISCONNECTED",
                message="PLC connection is available" if connected else "PLC connection is unavailable",
                old_value=self._last_connected,
                new_value=connected,
                status="CLEARED" if connected else "ACTIVE",
            ))

        if reconnect_count > self._last_reconnect_count:
            events.append(EventRecord(
                event_type="OPCUA_RECONNECTED",
                message="OPC UA gateway reconnected",
                old_value=self._last_reconnect_count,
                new_value=reconnect_count,
            ))

        self._last_connected = connected
        self._last_reconnect_count = reconnect_count
        return events

    def security_metrics(self) -> dict[str, Any]:
        return {
            "active_alarm_count": self.active_alarm_count(),
            "stale_event_count": self.stale_event_count,
            "rejected_operation_count": self.rejected_operation_count,
        }

    def active_alarm_count(self) -> int:
        return len(self._active_alarms)


alarm_engine = AlarmEngine()
