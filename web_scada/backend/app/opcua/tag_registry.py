"""OPC UA tag registry loader — reads from config/opcua_tags.yaml"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import yaml

REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_CONFIG_PATH = REPO_ROOT / "config" / "opcua_tags.yaml"


def resolve_config_path(config_path: str | Path | None = None) -> Path:
    raw_path = config_path or os.getenv("TAG_REGISTRY_PATH")
    if raw_path:
        path = Path(raw_path).expanduser()
        if not path.is_absolute():
            path = REPO_ROOT / path
    else:
        path = DEFAULT_CONFIG_PATH
    path = path.resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Không tìm thấy tag registry: {path}")
    return path


@dataclass(slots=True)
class TagConfig:
    key: str
    node_id: str
    display_name: str = ""
    data_type: str = "String"
    unit: str = ""
    group: str = "default"
    writable: bool = False
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    history_enabled: bool = True
    stale_timeout: int = 10


@dataclass(slots=True)
class TagValue:
    key: str
    value: Any = None
    data_type: str = "String"
    quality: str = "Bad"
    source_timestamp: str = ""
    received_timestamp: str = ""
    stale: bool = True
    config: Optional[TagConfig] = None

    def to_dict(self) -> dict[str, Any]:
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
    def __init__(self, config_path: str | Path | None = None):
        self.config_path = resolve_config_path(config_path)
        self.tags: list[TagConfig] = []
        self._by_key: dict[str, TagConfig] = {}
        self._by_node_id: dict[str, TagConfig] = {}
        self.load(self.config_path)

    def load(self, config_path: str | Path):
        path = resolve_config_path(config_path)
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        raw_tags = data.get("tags", [])
        if not isinstance(raw_tags, list):
            raise ValueError("'tags' phải là danh sách.")

        self.tags.clear()
        self._by_key.clear()
        self._by_node_id.clear()

        for i, item in enumerate(raw_tags, 1):
            key = str(item["key"]).strip()
            nid = str(item["node_id"]).strip()
            if key in self._by_key:
                raise ValueError(f"Trùng key: {key}")
            if nid in self._by_node_id:
                raise ValueError(f"Trùng node_id: {nid}")

            cfg = TagConfig(
                key=key, node_id=nid,
                display_name=item.get("display_name", key),
                data_type=item.get("data_type", "String"),
                unit=item.get("unit", ""),
                group=item.get("group", "default"),
                writable=bool(item.get("writable", False)),
                minimum=item.get("minimum"),
                maximum=item.get("maximum"),
                history_enabled=bool(item.get("history_enabled", True)),
                stale_timeout=int(item.get("stale_timeout", 10)),
            )
            self.tags.append(cfg)
            self._by_key[key] = cfg
            self._by_node_id[nid] = cfg

        self.config_path = path

    def get_by_key(self, key: str) -> Optional[TagConfig]:
        return self._by_key.get(key)

    def get_by_node_id(self, nid: str) -> Optional[TagConfig]:
        return self._by_node_id.get(nid)

    def keys(self) -> list[str]:
        return list(self._by_key.keys())

    def __len__(self) -> int:
        return len(self.tags)


_tag_registry: Optional[TagRegistry] = None


def get_tag_registry() -> TagRegistry:
    global _tag_registry
    if _tag_registry is None:
        _tag_registry = TagRegistry()
    return _tag_registry
