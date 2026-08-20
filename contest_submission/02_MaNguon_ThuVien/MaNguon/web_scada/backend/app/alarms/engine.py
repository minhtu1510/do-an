"""Derive process events from real gateway status and tag updates."""

from datetime import datetime, timedelta, timezone
from typing import Any

from ..events.models import EventRecord

TZ = timezone(timedelta(hours=7))

_MISSING = object()

# Stage sensor bits that can never all be True at once on a single-lane
# conveyor — if they are, the tag source is reporting an impossible physical
# state (spoofed/replayed values rather than a real sensor read).
_SPOOF_WATCH_KEYS = ("vat_1", "vat_2", "vat_3")

# CD1/CD2/CD3 are live stage timers, not fixed setpoints — they legitimately
# reset to 0 at the start of every cycle and can briefly overshoot the
# configured maximum by a few percent right at a stage boundary due to ~1s
# poll granularity. Neither is an attack. A real SETPOINT_ATTACK holds a
# grossly out-of-band value (tens of thousands of ms) for as long as the
# attacker keeps rewriting it, so requiring the condition to persist for a
# few seconds — and never treating an exact 0 as "below minimum" — filters
# normal cyclic behavior without missing a real one.
TIMER_DEBOUNCE_S = 3.0


class AlarmEngine:
    def __init__(self):
        self._last_values: dict[str, Any] = {}
        self._last_stale: dict[str, bool] = {}
        self._last_connected: bool | None = None
        self._last_reconnect_count = 0
        self._active_alarms: set[str] = set()
        self._timer_candidate_since: dict[str, datetime] = {}
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
                if old_value is True and new_value is False:
                    events.extend(self._check_unexpected_halt())
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

        if key in ("cd1", "cd2", "cd3"):
            events.extend(self._check_stage_timer_range(key, new_value, data.get("minimum"), data.get("maximum")))

        return events

    def _check_unexpected_halt(self) -> list[EventRecord]:
        """bang_tai just went RUNNING -> STOPPED. If any stage bit is still
        active, the line stopped mid-cycle instead of at a normal cycle
        boundary — this cannot tell WHO issued the stop (Web-SCADA has no
        visibility into WinCC button presses), only WHEN it happened.
        """
        active_stages = [k for k in _SPOOF_WATCH_KEYS if self._last_values.get(k) is True]
        if not active_stages:
            return []
        return [EventRecord(
            severity="ERROR",
            event_type="UNEXPECTED_HALT",
            message=f"Conveyor stopped mid-cycle while {', '.join(active_stages)} still active",
            tag_key="bang_tai",
            new_value=False,
            status="ACTIVE",
        )]

    def _check_stage_timer_range(self, key: str, value: Any, minimum: Any, maximum: Any) -> list[EventRecord]:
        alarm_key = f"timer_range:{key}"
        was_active = alarm_key in self._active_alarms

        # value == 0 is a normal per-cycle reset, never treated as "below minimum".
        candidate = (
            isinstance(value, (int, float)) and value != 0
            and minimum is not None and maximum is not None
            and not (minimum <= value <= maximum)
        )

        if candidate:
            since = self._timer_candidate_since.setdefault(key, datetime.now(TZ))
            persisted_s = (datetime.now(TZ) - since).total_seconds()
            if persisted_s >= TIMER_DEBOUNCE_S and not was_active:
                self._active_alarms.add(alarm_key)
                return [EventRecord(
                    severity="ERROR",
                    event_type="STAGE_TIMER_OUT_OF_RANGE",
                    message=f"{key} = {value} outside safe range [{minimum}, {maximum}] for over {TIMER_DEBOUNCE_S:.0f}s",
                    tag_key=key,
                    new_value=value,
                    status="ACTIVE",
                )]
            return []

        self._timer_candidate_since.pop(key, None)
        if was_active:
            self._active_alarms.discard(alarm_key)
            return [EventRecord(
                event_type="STAGE_TIMER_RANGE_CLEARED",
                message=f"{key} = {value} back within safe range [{minimum}, {maximum}]",
                tag_key=key,
                new_value=value,
            )]
        return []

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
