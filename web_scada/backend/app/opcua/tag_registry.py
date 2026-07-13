"""OPC UA tag registry loader — reads from config/opcua_tags.yaml"""

import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class TagConfig:
    key: str
    node_id: str
    display_name: str = ""
    description: str = ""
    data_type: str = "String"
    unit: str = ""
    group: str = "default"
    writable: bool = False
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    history_enabled: bool = True
    stale_timeout: int = 10


@dataclass
class TagValue:
    key: str
    value: object = None
    data_type: str = "String"
    quality: str = "Bad"
    source_timestamp: str = ""
    received_timestamp: str = ""
    stale: bool = True
    config: Optional[TagConfig] = None

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "value": self.value,
            "data_type": self.data_type,
            "quality": self.quality,
            "source_timestamp": self.source_timestamp,
            "received_timestamp": self.received_timestamp,
            "stale": self.stale,
            "display_name": self.config.display_name if self.config else "",
            "unit": self.config.unit if self.config else "",
            "group": self.config.group if self.config else "default",
            "writable": self.config.writable if self.config else False,
        }


class TagRegistry:
    def __init__(self, config_path: str = None):
        if config_path is None:
            config_path = Path(__file__).parent.parent.parent.parent / "config" / "opcua_tags.yaml"
        self.tags: List[TagConfig] = []
        self._by_key: dict = {}
        self._by_node_id: dict = {}
        self.load(config_path)

    def load(self, config_path: str):
        with open(config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)

        self.tags = []
        for item in data.get("tags", []):
            cfg = TagConfig(
                key=item["key"],
                node_id=item["node_id"],
                display_name=item.get("display_name", item["key"]),
                description=item.get("description", ""),
                data_type=item.get("data_type", "String"),
                unit=item.get("unit", ""),
                group=item.get("group", "default"),
                writable=item.get("writable", False),
                minimum=item.get("minimum"),
                maximum=item.get("maximum"),
                history_enabled=item.get("history_enabled", True),
                stale_timeout=item.get("stale_timeout", 10),
            )
            self.tags.append(cfg)
            self._by_key[cfg.key] = cfg
            self._by_node_id[cfg.node_id] = cfg

    def get_by_key(self, key: str) -> Optional[TagConfig]:
        return self._by_key.get(key)

    def get_by_node_id(self, node_id: str) -> Optional[TagConfig]:
        return self._by_node_id.get(node_id)

    def keys(self) -> List[str]:
        return list(self._by_key.keys())

    def list_writable(self) -> List[TagConfig]:
        return [t for t in self.tags if t.writable]


_tag_registry: Optional[TagRegistry] = None


def get_tag_registry() -> TagRegistry:
    global _tag_registry
    if _tag_registry is None:
        _tag_registry = TagRegistry()
    return _tag_registry
