#!/usr/bin/env python3
"""Preflight checks for Day 8 multi-surface scenarios."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tests.common import HMI_URL, OPC_URL, PLC_IP, RACK, SLOT, ok, warn, fail, info  # noqa: E402


WEB_SCADA_API = os.getenv("WEB_SCADA_API", "http://127.0.0.1:8000/api").rstrip("/")
KNOWN_OPCUA_NODES = [
    'ns=3;s="BangTai"',
    'ns=3;s="Nhap"',
    'ns=3;s="HienThi"',
    'ns=3;s="Vat 1"',
    'ns=3;s="Vat 2"',
    'ns=3;s="Vat 3"',
]


def tcp_check(host: str, port: int, timeout: float = 3.0) -> tuple[bool, str]:
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"reachable in {time.time() - start:.2f}s"
    except OSError as exc:
        return False, str(exc)


def parse_opc_host_port(url: str) -> tuple[str, int]:
    raw = url.replace("opc.tcp://", "", 1)
    host_port = raw.split("/", 1)[0]
    if ":" in host_port:
        host, port = host_port.rsplit(":", 1)
        return host, int(port)
    return host_port, 4840


def http_json(path: str, timeout: float = 3.0) -> tuple[bool, object]:
    try:
        with urlopen(f"{WEB_SCADA_API}{path}", timeout=timeout) as res:
            body = res.read().decode("utf-8", errors="replace")
            return True, json.loads(body) if body else {}
    except (OSError, URLError, ValueError) as exc:
        return False, str(exc)


async def opcua_check(url: str) -> tuple[bool, str]:
    try:
        from asyncua import Client
    except ImportError:
        return False, "asyncua not installed"

    try:
        async with Client(url=url, timeout=5) as client:
            details = ["connected"]

            try:
                namespace_array = await client.get_namespace_array()
                details.append(f"namespaces={len(namespace_array)}")
            except Exception as exc:
                details.append(f"namespace_array_unsupported={exc}")

            try:
                children = await client.nodes.objects.get_children()
                details.append(f"objects={len(children)}")
            except Exception as exc:
                details.append(f"browse_unsupported={exc}")

            read_ok = 0
            read_errors = []
            for node_id in KNOWN_OPCUA_NODES:
                try:
                    value = await client.get_node(node_id).read_value()
                    read_ok += 1
                    details.append(f"read:{node_id}={value!r}")
                except Exception as exc:
                    read_errors.append(f"{node_id}:{exc}")

            if read_ok > 0:
                details.append(f"known_node_reads={read_ok}/{len(KNOWN_OPCUA_NODES)}")
                return True, "; ".join(details)

            if any(item.startswith("namespaces=") or item.startswith("objects=") for item in details):
                details.append("known_node_reads=0")
                return True, "; ".join(details)

            details.append("known_node_reads=0")
            if read_errors:
                details.append(f"first_read_error={read_errors[0]}")
            return False, "; ".join(details)
    except Exception as exc:
        return False, str(exc)


def main() -> int:
    print("\n[DAY8 PREFLIGHT]")
    info(f"PLC_IP={PLC_IP} rack={RACK} slot={SLOT}")
    info(f"OPC_URL={OPC_URL}")
    info(f"WEB_SCADA_API={WEB_SCADA_API}")
    info(f"HMI_URL={HMI_URL}")

    results: dict[str, dict[str, object]] = {}

    s7_ok, s7_msg = tcp_check(PLC_IP, 102)
    results["s7_tcp_102"] = {"ok": s7_ok, "detail": s7_msg}
    ok(f"S7 TCP/102: {s7_msg}") if s7_ok else warn(f"S7 TCP/102: {s7_msg}")

    opc_host, opc_port = parse_opc_host_port(OPC_URL)
    opc_tcp_ok, opc_tcp_msg = tcp_check(opc_host, opc_port)
    results["opcua_tcp"] = {"ok": opc_tcp_ok, "detail": opc_tcp_msg}
    ok(f"OPC UA TCP/{opc_port}: {opc_tcp_msg}") if opc_tcp_ok else warn(f"OPC UA TCP/{opc_port}: {opc_tcp_msg}")

    opc_ok, opc_msg = asyncio.run(opcua_check(OPC_URL))
    results["opcua_client"] = {"ok": opc_ok, "detail": opc_msg}
    ok(f"OPC UA client: {opc_msg}") if opc_ok else warn(f"OPC UA client: {opc_msg}")

    api_status_ok, api_status = http_json("/plc/status")
    results["web_scada_status"] = {"ok": api_status_ok, "detail": api_status}
    ok("Web-SCADA /plc/status reachable") if api_status_ok else warn(f"Web-SCADA /plc/status: {api_status}")

    api_tags_ok, api_tags = http_json("/tags")
    tag_count = len(api_tags.get("tags", [])) if isinstance(api_tags, dict) else 0
    stale_count = sum(1 for tag in api_tags.get("tags", []) if tag.get("stale")) if isinstance(api_tags, dict) else 0
    results["web_scada_tags"] = {"ok": api_tags_ok, "tag_count": tag_count, "stale_count": stale_count}
    if api_tags_ok:
        ok(f"Web-SCADA /tags reachable; tags={tag_count} stale={stale_count}")
    else:
        warn(f"Web-SCADA /tags: {api_tags}")

    out_dir = Path("test_results/day8")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"preflight_{time.strftime('%Y%m%d_%H%M%S')}.json"
    out_file.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    info(f"Saved: {out_file}")

    if not opc_tcp_ok and not api_status_ok:
        fail("Neither OPC UA nor Web-SCADA API is reachable; Day 8 cannot run yet.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
