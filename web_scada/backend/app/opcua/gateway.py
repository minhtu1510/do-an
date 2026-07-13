"""OPC UA Gateway — persistent session, auto-reconnect, stale detection."""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Callable

from asyncua import Client

from .tag_registry import TagRegistry, TagValue, get_tag_registry

logger = logging.getLogger("opcua_gateway")
TZ = timezone(timedelta(hours=7))


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

    async def start(self):
        self._running = True
        self._task = asyncio.current_task()
        reconnect_delay = 3

        while self._running:
            try:
                await self._connect_and_subscribe()
                reconnect_delay = 3  # reset delay sau khi connect thành công
                while self._connected and self._running:
                    await self._check_stale()
                    await asyncio.sleep(1)
            except Exception as e:
                logger.warning(f"OPC UA disconnected: {e}")
                self._connected = False
                for cfg in self.registry.tags:
                    if cfg.key in self._values:
                        self._values[cfg.key].stale = True
                        self._values[cfg.key].quality = "Bad"
                if self._running:
                    logger.info(f"Reconnecting in {reconnect_delay}s...")
                    await asyncio.sleep(reconnect_delay)
                    self._reconnect_count += 1
                    reconnect_delay = min(reconnect_delay * 2, 60)

        logger.info("OPC UA gateway stopped")

    async def stop(self):
        self._running = False
        await self._disconnect()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
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
                value = await node.read_value()
                tag_value = TagValue(
                    key=tag_cfg.key, value=value, data_type=tag_cfg.data_type,
                    quality="Good",
                    source_timestamp=datetime.now(TZ).isoformat(),
                    received_timestamp=datetime.now(TZ).isoformat(),
                    stale=False, config=tag_cfg,
                )
                self._values[tag_cfg.key] = tag_value
                await self._subscription.subscribe_data_change(node)
                self._last_data_at = datetime.now(TZ)
            except Exception as e:
                logger.warning(f"Subscribe failed {tag_cfg.key}: {e}")
                self._values[tag_cfg.key] = TagValue(
                    key=tag_cfg.key, value=None, data_type=tag_cfg.data_type,
                    quality="Bad", stale=True, config=tag_cfg,
                )
                self._failed_tags += 1

    async def _disconnect(self):
        self._connected = False
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
                src_ts = (data.monitored_item.SourceTimestamp.isoformat()
                          if data.monitored_item.SourceTimestamp
                          else datetime.now(TZ).isoformat())
                tag_value = TagValue(
                    key=cfg.key, value=val, data_type=cfg.data_type,
                    quality="Good", source_timestamp=src_ts,
                    received_timestamp=datetime.now(TZ).isoformat(),
                    stale=False, config=cfg,
                )
                self.gateway._values[cfg.key] = tag_value
                self.gateway._last_data_at = datetime.now(TZ)
                self.gateway._notify_callbacks(cfg.key, tag_value)
        except Exception as e:
            logger.debug(f"Subscription error: {e}")
