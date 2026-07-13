#!/usr/bin/env python3
"""
Read all OPC UA values from tag registry.
"""

import asyncio
import sys
import os
import json
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))


def load_tag_config():
    try:
        import yaml
    except ImportError:
        print("[FAIL] pyyaml not installed: pip install pyyaml")
        return []

    config_path = Path(__file__).parent.parent.parent / "config" / "opcua_tags.yaml"
    with open(config_path) as f:
        data = yaml.safe_load(f)
    return data.get("tags", [])


async def main():
    try:
        from asyncua import Client
    except ImportError:
        print("[FAIL] asyncua not installed")
        return

    tags_config = load_tag_config()
    if not tags_config:
        print("[FAIL] No tags in config")
        return

    url = "opc.tcp://192.168.210.211:4840"
    print(f"[*] Connecting to {url}...")

    async with Client(url=url) as client:
        for tag in tags_config:
            key = tag["key"]
            nid = tag["node_id"]
            try:
                node = client.get_node(nid)
                val = await node.read_value()
                print(f"  {key:<15} = {val}")
            except Exception as e:
                print(f"  {key:<15} — error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
