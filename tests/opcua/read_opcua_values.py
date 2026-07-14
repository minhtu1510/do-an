#!/usr/bin/env python3
"""Read all OPC UA values from tag registry."""

import asyncio
from pathlib import Path

import yaml
from asyncua import Client


PLC_ENDPOINT = "opc.tcp://192.168.210.211:4840"
REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = REPO_ROOT / "config" / "opcua_tags.yaml"


def load_tag_config() -> list[dict]:
    if not CONFIG_PATH.is_file():
        raise FileNotFoundError(f"Không tìm thấy tag registry: {CONFIG_PATH}")
    with CONFIG_PATH.open("r", encoding="utf-8-sig") as file:
        data = yaml.safe_load(file) or {}
    tags = data.get("tags", [])
    if not isinstance(tags, list):
        raise ValueError("Trường 'tags' phải là danh sách.")
    return tags


async def main() -> None:
    try:
        tags_config = load_tag_config()
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"[FAIL] {exc}")
        return

    if not tags_config:
        print("[FAIL] Không có tag trong config/opcua_tags.yaml")
        return

    print(f"[*] Endpoint: {PLC_ENDPOINT}  Tags: {len(tags_config)}\n")

    try:
        async with Client(url=PLC_ENDPOINT, timeout=10) as client:
            print("[OK] Kết nối OPC UA thành công.\n")
            for tag in tags_config:
                key = tag.get("key", "<missing>")
                nid = tag.get("node_id")
                if not nid:
                    print(f"  {key:<15} — error: thiếu node_id")
                    continue
                try:
                    node = client.get_node(nid)
                    val = await node.read_value()
                    dt = await node.read_data_type_as_variant_type()
                    print(f"  {key:<15} = {val!r:<12} | type={dt.name:<10} | {nid}")
                except Exception as exc:
                    print(f"  {key:<15} — error: {exc}")
    except Exception as exc:
        print(f"\n[FAIL] {exc}")


if __name__ == "__main__":
    asyncio.run(main())
