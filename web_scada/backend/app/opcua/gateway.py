"""OPC UA Gateway — persistent session, auto-reconnect, polling + subscription, stale detection."""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Callable

from asyncua import Client, ua

from .tag_registry import TagRegistry, TagValue, get_tag_registry

logger = logging.getLogger("opcua_gateway")
TZ = timezone(timedelta(hours=7))

_VARIANT_TYPE_BY_DATA_TYPE = {
    "Boolean": ua.VariantType.Boolean,
    "Int16": ua.VariantType.Int16,
    "Int32": ua.VariantType.Int32,
    "Float": ua.VariantType.Float,
    "Double": ua.VariantType.Double,
    "String": ua.VariantType.String,
}


class TagWriteError(ValueError):
    """Raised for a write request that fails validation — not writable, out of
    range, or wrong type. Distinct from RuntimeError (connection problems) so
    the API layer can map it to a 4xx instead of a 5xx.
    """


class OPCUAGateway:
    def __init__(self, endpoint: str, tag_registry: TagRegistry = None):
        self.endpoint = endpoint
        self.registry = tag_registry or get_tag_registry()

        self.client: Optional[Client] = None
        self._values: Dict[str, TagValue] = {}
        self._subscription = None

        self._connected = False
        self._last_data_at: Optional[datetime] = None
        self._last_connected_at: Optional[datetime] = None
        self._reconnect_count = 0
        self._failed_tags = 0

        self._running = False
        self._callbacks: list = []

        self._task: Optional[asyncio.Task] = None
        self._poll_task: Optional[asyncio.Task] = None

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def status(self) -> dict:
        return {
            "connected": self._connected,
            "endpoint": self.endpoint,
            "last_connected_at": self._last_connected_at.isoformat() if self._last_connected_at else None,
            "last_data_at": self._last_data_at.isoformat() if self._last_data_at else None,
            "subscribed_tags": len(self._values),
            "failed_tags": self._failed_tags,
            "reconnect_count": self._reconnect_count,
        }

    def on_value_change(self, callback: Callable[[str, TagValue], None]):
        self._callbacks.append(callback)

    async def reconfigure_endpoint(self, new_endpoint: str) -> None:
        """Point at a different OPC UA server without restarting the backend
        process. Sets the new address first, then tears down the current
        session the same way a real disconnect does — start()'s reconnect
        loop picks the new self.endpoint up on its very next cycle, with no
        error logged since this isn't actually a failure.
        """
        self.endpoint = new_endpoint
        await self._disconnect()

    async def start(self):
        self._running = True
        self._task = asyncio.current_task()
        reconnect_delay = 3

        while self._running:
            try:
                await self._connect_and_subscribe()
                reconnect_delay = 3

                while self._connected and self._running:
                    # Nếu polling task chết, ép gateway reconnect
                    if self._poll_task and self._poll_task.done():
                        if self._poll_task.cancelled():
                            raise RuntimeError("OPC UA polling task cancelled")

                        exc = self._poll_task.exception()
                        if exc:
                            raise exc

                    await self._check_stale()
                    await asyncio.sleep(1)

            except asyncio.CancelledError:
                break

            except Exception as e:
                logger.warning(f"OPC UA disconnected: {e}")
                self._connected = False

                for cfg in self.registry.tags:
                    if cfg.key in self._values:
                        self._values[cfg.key].stale = True
                        self._values[cfg.key].quality = "Bad"

                await self._disconnect()

                if self._running:
                    logger.info(f"Reconnecting in {reconnect_delay}s...")
                    await asyncio.sleep(reconnect_delay)
                    self._reconnect_count += 1
                    reconnect_delay = min(reconnect_delay * 2, 60)

        logger.info("OPC UA gateway stopped")

    async def stop(self):
        self._running = False

        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
            self._poll_task = None

        await self._disconnect()

        if self._task and self._task is not asyncio.current_task():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
            self._task = None

    async def _connect_and_subscribe(self):
        self.client = Client(url=self.endpoint)
        await self.client.connect()

        self._connected = True
        self._last_connected_at = datetime.now(TZ)

        logger.info(f"OPC UA connected: {self.endpoint}")

        handler = _SubscriptionHandler(self)
        self._subscription = await self.client.create_subscription(500, handler)

        self._failed_tags = 0

        for tag_cfg in self.registry.tags:
            try:
                node = self.client.get_node(tag_cfg.node_id)

                tag_value = await self._read_tag_once(tag_cfg)

                self._values[tag_cfg.key] = tag_value

                await self._subscription.subscribe_data_change(node)

                self._last_data_at = datetime.now(TZ)

                logger.info(f"Subscribed tag {tag_cfg.key}: {tag_cfg.node_id}")

            except Exception as e:
                logger.warning(f"Subscribe failed {tag_cfg.key}: {e}")

                self._values[tag_cfg.key] = TagValue(
                    key=tag_cfg.key,
                    value=None,
                    data_type=tag_cfg.data_type,
                    quality="Bad",
                    stale=True,
                    config=tag_cfg,
                )

                self._failed_tags += 1

        # Polling loop giúp tag luôn được refresh,
        # tránh trường hợp giá trị không đổi nhưng bị đánh stale.
        if self._poll_task and not self._poll_task.done():
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass

        self._poll_task = asyncio.create_task(self._poll_loop())

    async def _read_tag_once(self, tag_cfg) -> TagValue:
        if not self.client:
            raise RuntimeError("OPC UA client is not connected")

        node = self.client.get_node(tag_cfg.node_id)
        now = datetime.now(TZ)

        try:
            data_value = await node.read_data_value()
            value = data_value.Value.Value

            src_ts = data_value.SourceTimestamp
            if src_ts:
                if src_ts.tzinfo is None:
                    src_ts = src_ts.replace(tzinfo=timezone.utc)
                source_timestamp = src_ts.astimezone(TZ).isoformat()
            else:
                source_timestamp = now.isoformat()

        except Exception:
            # Fallback nếu server không hỗ trợ read_data_value đầy đủ
            value = await node.read_value()
            source_timestamp = now.isoformat()

        return TagValue(
            key=tag_cfg.key,
            value=value,
            data_type=tag_cfg.data_type,
            quality="Good",
            source_timestamp=source_timestamp,
            received_timestamp=now.isoformat(),
            stale=False,
            config=tag_cfg,
        )

    async def write_value(self, key: str, value) -> TagValue:
        """Write a value to a whitelisted tag, then read it back so the caller
        (and the UI, via the normal tag_update broadcast) sees the PLC's real
        resulting state rather than an assumed echo of what was sent.
        """
        cfg = self.registry.get_by_key(key)
        if cfg is None:
            raise TagWriteError(f"Tag '{key}' does not exist in registry")
        if not cfg.writable:
            raise TagWriteError(f"Tag '{key}' is not writable")

        if cfg.data_type == "Boolean":
            if not isinstance(value, bool):
                raise TagWriteError(f"Tag '{key}' expects a boolean value")
        else:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TagWriteError(f"Tag '{key}' expects a numeric value")
            if cfg.minimum is not None and value < cfg.minimum:
                raise TagWriteError(f"Value {value} is below minimum {cfg.minimum} for '{key}'")
            if cfg.maximum is not None and value > cfg.maximum:
                raise TagWriteError(f"Value {value} is above maximum {cfg.maximum} for '{key}'")

        variant_type = _VARIANT_TYPE_BY_DATA_TYPE.get(cfg.data_type)
        if variant_type is None:
            raise TagWriteError(f"Tag '{key}' has unsupported data_type '{cfg.data_type}' for writing")

        if not self._connected or not self.client:
            raise RuntimeError("OPC UA gateway is not connected")

        node = self.client.get_node(cfg.node_id)
        await node.write_value(ua.DataValue(ua.Variant(value, variant_type)))

        tag_value = await self._read_tag_once(cfg)
        self._values[key] = tag_value
        self._notify_callbacks(key, tag_value)
        return tag_value

    async def _poll_loop(self):
        logger.info("OPC UA polling loop started")

        while self._running and self._connected:
            success_count = 0
            fail_count = 0

            for tag_cfg in self.registry.tags:
                try:
                    tag_value = await self._read_tag_once(tag_cfg)

                    self._values[tag_cfg.key] = tag_value
                    self._notify_callbacks(tag_cfg.key, tag_value)

                    success_count += 1

                except Exception as e:
                    fail_count += 1
                    logger.debug(f"Poll failed {tag_cfg.key}: {e}")

                    if tag_cfg.key in self._values:
                        self._values[tag_cfg.key].quality = "Bad"
                        self._values[tag_cfg.key].stale = True
                    else:
                        self._values[tag_cfg.key] = TagValue(
                            key=tag_cfg.key,
                            value=None,
                            data_type=tag_cfg.data_type,
                            quality="Bad",
                            stale=True,
                            config=tag_cfg,
                        )

            if success_count > 0:
                self._last_data_at = datetime.now(TZ)

            if fail_count == len(self.registry.tags):
                raise RuntimeError("All OPC UA tag polling failed")

            await asyncio.sleep(1)

        logger.info("OPC UA polling loop stopped")

    async def _disconnect(self):
        self._connected = False

        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
            self._poll_task = None

        try:
            if self._subscription:
                await self._subscription.delete()
        except Exception:
            pass

        self._subscription = None

        try:
            if self.client:
                await self.client.disconnect()
        except Exception:
            pass

        self.client = None

    async def _check_stale(self):
        if not self._last_data_at:
            return

        now = datetime.now(TZ)

        for cfg in self.registry.tags:
            v = self._values.get(cfg.key)

            if v and v.received_timestamp and not v.stale:
                try:
                    ts = datetime.fromisoformat(v.received_timestamp)

                    if (now - ts).total_seconds() > cfg.stale_timeout:
                        v.stale = True
                        v.quality = "Uncertain"

                except Exception:
                    pass

    def get_value(self, key: str) -> Optional[dict]:
        if key in self._values:
            return self._values[key].to_dict()

        return None

    def get_all_values(self) -> list:
        return [v.to_dict() for v in self._values.values()]

    def _notify_callbacks(self, key: str, value: TagValue):
        for cb in self._callbacks:
            try:
                cb(key, value.to_dict())
            except Exception:
                pass


class _SubscriptionHandler:
    def __init__(self, gateway: OPCUAGateway):
        self.gateway = gateway

    def datachange_notification(self, node, val, data):
        try:
            node_id = str(node.nodeid)
            cfg = self.gateway.registry.get_by_node_id(node_id)

            if cfg:
                src_ts = (
                    data.monitored_item.SourceTimestamp.isoformat()
                    if data.monitored_item.SourceTimestamp
                    else datetime.now(TZ).isoformat()
                )

                tag_value = TagValue(
                    key=cfg.key,
                    value=val,
                    data_type=cfg.data_type,
                    quality="Good",
                    source_timestamp=src_ts,
                    received_timestamp=datetime.now(TZ).isoformat(),
                    stale=False,
                    config=cfg,
                )

                self.gateway._values[cfg.key] = tag_value
                self.gateway._last_data_at = datetime.now(TZ)
                self.gateway._notify_callbacks(cfg.key, tag_value)

        except Exception as e:
            logger.debug(f"Subscription error: {e}")