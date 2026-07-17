#!/usr/bin/env python3
"""Day 8 scenario runner.

The runner is intentionally safe by default. It lists and records scenarios,
and only executes bounded read-only/denied checks marked safe in the catalog.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tests.common import OPC_URL, info, ok, warn, fail  # noqa: E402


CATALOG_PATH = Path(__file__).with_name("scenarios.yaml")
WEB_SCADA_API = os.getenv("WEB_SCADA_API", "http://127.0.0.1:8000/api").rstrip("/")
CONTROLLED_GATED_SCENARIOS = {"OPCUA_WRITE_DENIED", "OPCUA_INVALID_WRITE"}
NOT_CONFIGURED_SAFE_SCENARIOS = {
    "WEB_LOGIN_FAILURE": "Auth/login endpoint is not implemented in the current Web-SCADA backend.",
    "WEB_ROLE_VIOLATION": "Role-based authorization is not implemented in the current Web-SCADA backend.",
    "OPCUA_UNAUTHORIZED_SESSION": "No OPC UA username/password policy is configured in the current testbed.",
    "OPCUA_CERTIFICATE_REJECTED": "No OPC UA certificate trust-list scenario is configured in the current testbed.",
}


def load_catalog() -> dict:
    with CATALOG_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def iter_scenarios(catalog: dict):
    for group_id, group in catalog["groups"].items():
        for scenario in group.get("scenarios", []):
            yield group_id, group, scenario


def select_scenarios(catalog: dict, group_filter: str | None, scenario_filter: str | None):
    selected = []
    for group_id, group, scenario in iter_scenarios(catalog):
        if group_filter and group_filter != group_id:
            continue
        if scenario_filter and scenario_filter != scenario["id"]:
            continue
        selected.append((group_id, group, scenario))
    return selected


def print_scenarios(items) -> None:
    for group_id, group, scenario in items:
        safe = "safe" if scenario.get("safe_to_execute") else "gated"
        print(f"{group_id:15} {scenario['id']:<36} {safe:<6} {scenario['objective']}")


async def opcua_benign_reconnect(repeat: int = 3) -> list[str]:
    from asyncua import Client

    evidence = []
    for i in range(repeat):
        async with Client(url=OPC_URL, timeout=5) as client:
            namespace_array = await client.get_namespace_array()
            evidence.append(f"reconnect_{i + 1}: namespaces={len(namespace_array)}")
        await asyncio.sleep(0.5)
    return evidence


async def opcua_node_browse(limit: int = 30) -> list[str]:
    from asyncua import Client

    evidence = []
    async with Client(url=OPC_URL, timeout=5) as client:
        children = await client.nodes.objects.get_children()
        for child in children[:limit]:
            name = (await child.read_browse_name()).Name
            evidence.append(f"object: {name} {child.nodeid}")
            for sub in (await child.get_children())[:5]:
                sub_name = (await sub.read_browse_name()).Name
                evidence.append(f"node: {sub_name} {sub.nodeid}")
                if len(evidence) >= limit:
                    return evidence
    return evidence


async def opcua_endpoint_discovery() -> list[str]:
    from asyncua import Client

    async with Client(url=OPC_URL, timeout=5) as client:
        endpoints = await client.connect_and_get_server_endpoints()
        return [f"endpoint: {ep.EndpointUrl} policy={ep.SecurityPolicyUri}" for ep in endpoints]


async def opcua_benign_subscription(duration: float = 5.0) -> list[str]:
    from asyncua import Client

    evidence = []
    nodes = [
        'ns=3;s="BangTai"',
        'ns=3;s="Nhap"',
        'ns=3;s="HienThi"',
        'ns=3;s="Vat 1"',
        'ns=3;s="Vat 2"',
        'ns=3;s="Vat 3"',
    ]

    class Handler:
        def datachange_notification(self, node, val, data):
            evidence.append(f"datachange: {node.nodeid}={val!r}")

    async with Client(url=OPC_URL, timeout=5) as client:
        sub = await client.create_subscription(500, Handler())
        handles = []
        for node_id in nodes:
            node = client.get_node(node_id)
            try:
                value = await node.read_value()
                evidence.append(f"initial: {node_id}={value!r}")
                handles.append(await sub.subscribe_data_change(node))
            except Exception as exc:
                evidence.append(f"read_failed: {node_id}: {exc}")
        await asyncio.sleep(duration)
        await sub.delete()
    return evidence


async def opcua_write_denied() -> list[str]:
    """Attempt same-value writes to read-mostly nodes and record server response.

    Writing the current value is intentional: if the server unexpectedly accepts
    the write, the process value should not change.
    """
    from asyncua import Client

    nodes = [
        'ns=3;s="HienThi"',
        'ns=3;s="Nhap"',
        'ns=3;s="BangTai"',
    ]
    evidence = []
    async with Client(url=OPC_URL, timeout=5) as client:
        for node_id in nodes:
            node = client.get_node(node_id)
            try:
                before = await node.read_value()
                await node.write_value(before)
                after = await node.read_value()
                evidence.append(f"{node_id}: UNEXPECTED_WRITE_SUCCESS same_value={before!r} after={after!r}")
            except Exception as exc:
                evidence.append(f"{node_id}: write_rejected={type(exc).__name__}: {exc}")
                return evidence
    evidence.append("No node rejected same-value write; review PLC OPC UA write permissions before using this as WRITE_DENIED evidence.")
    return evidence


async def opcua_invalid_write() -> list[str]:
    """Attempt invalid typed writes that should be rejected by the OPC UA server."""
    from asyncua import Client, ua

    attempts = [
        ('ns=3;s="BangTai"', ua.Variant("invalid_boolean", ua.VariantType.String)),
        ('ns=3;s="Nhap"', ua.Variant("invalid_int", ua.VariantType.String)),
        ('ns=3;s="HienThi"', ua.Variant(True, ua.VariantType.Boolean)),
    ]
    evidence = []
    async with Client(url=OPC_URL, timeout=5) as client:
        for node_id, variant in attempts:
            node = client.get_node(node_id)
            before = None
            try:
                before = await node.read_value()
                await node.write_value(ua.DataValue(variant))
                after = await node.read_value()
                evidence.append(f"{node_id}: UNEXPECTED_INVALID_WRITE_SUCCESS before={before!r} after={after!r} variant={variant.Value!r}/{variant.VariantType.name}")
            except Exception as exc:
                evidence.append(f"{node_id}: invalid_write_rejected={type(exc).__name__}: {exc}; before={before!r}")
                return evidence
    evidence.append("All invalid-write attempts unexpectedly succeeded; stop and review OPC UA permissions/types.")
    return evidence


def http_request(method: str, path: str, body: bytes | None = None) -> tuple[int | None, str]:
    try:
        req = Request(f"{WEB_SCADA_API}{path}", data=body, method=method)
        if body is not None:
            req.add_header("Content-Type", "application/json")
        with urlopen(req, timeout=5) as res:
            return res.status, res.read().decode("utf-8", errors="replace")[:300]
    except HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")[:300]
    except (OSError, URLError) as exc:
        return None, str(exc)


def web_invalid_parameter() -> list[str]:
    status, body = http_request("GET", "/tags/__invalid_tag_key__")
    return [f"GET /tags/__invalid_tag_key__ -> {status}: {body}"]


def web_command_rejected() -> list[str]:
    status, body = http_request("POST", "/commands/start", b"{}")
    return [f"POST /commands/start -> {status}: {body or 'empty'}"]


async def execute_safe(scenario_id: str) -> list[str] | None:
    if scenario_id == "OPCUA_BENIGN_RECONNECT":
        return await opcua_benign_reconnect()
    if scenario_id == "OPCUA_NODE_BROWSE":
        return await opcua_node_browse()
    if scenario_id == "OPCUA_ENDPOINT_DISCOVERY":
        return await opcua_endpoint_discovery()
    if scenario_id == "OPCUA_BENIGN_SUBSCRIPTION":
        return await opcua_benign_subscription()
    if scenario_id == "API_INVALID_PARAMETER":
        return web_invalid_parameter()
    if scenario_id in {"API_COMMAND_REJECTED", "WEB_UNAUTHORIZED_COMMAND"}:
        return web_command_rejected()
    if scenario_id == "WEB_LOG_AND_PLC_STATE_DIVERGENCE":
        status, body = http_request("GET", "/events")
        return [f"GET /events -> {status}: {body}"]
    return None


async def execute_controlled_gated(scenario_id: str) -> list[str] | None:
    if scenario_id == "OPCUA_WRITE_DENIED":
        return await opcua_write_denied()
    if scenario_id == "OPCUA_INVALID_WRITE":
        return await opcua_invalid_write()
    return None


def save_result(group_id: str, scenario: dict, status: str, evidence: list[str], notes: list[str], start: float) -> Path:
    out_dir = Path("test_results/day8")
    out_dir.mkdir(parents=True, exist_ok=True)
    result = {
        "scenario_id": scenario["id"],
        "label": scenario.get("label", scenario["id"]),
        "group": group_id,
        "status": status,
        "start_time": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(start)),
        "end_time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "duration_s": round(time.time() - start, 3),
        "preconditions": scenario.get("preconditions", []),
        "evidence": evidence,
        "notes": notes,
    }
    path = out_dir / f"{scenario['id']}_{time.strftime('%Y%m%d_%H%M%S')}.json"
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


async def run_items(items, execute: bool, allow_gated: bool) -> int:
    rc = 0
    for group_id, _group, scenario in items:
        start = time.time()
        scenario_id = scenario["id"]
        print(f"\n[DAY8] {scenario_id}")
        info(scenario["objective"])
        notes = []
        evidence = []

        if scenario.get("requires_manual_gate") and not allow_gated:
            notes.append("requires_manual_gate=true; not executed by runner")
            status = "GATED"
            warn("Manual safety gate required; catalog entry recorded only.")
        elif scenario.get("requires_manual_gate") and scenario_id not in CONTROLLED_GATED_SCENARIOS:
            notes.append("requires_manual_gate=true; no controlled executor is available for this scenario")
            status = "GATED"
            warn("Manual safety gate required; no controlled executor available.")
        elif not execute:
            notes.append("dry-run only; add --execute for safe executor")
            status = "DRY_RUN"
            info("Dry-run; no traffic generated.")
        elif not scenario.get("safe_to_execute"):
            try:
                evidence = await execute_controlled_gated(scenario_id)
                if evidence is None:
                    notes.append("safe_to_execute=false; no controlled gated executor implemented")
                    status = "BLOCKED"
                    warn("Blocked because safe_to_execute=false.")
                else:
                    notes.append("Executed with --allow-gated; bounded OPC UA write-denial/invalid-write check only.")
                    status = "EXECUTED_GATED"
                    ok(f"Executed controlled gated scenario; evidence={len(evidence)}")
            except ImportError as exc:
                status = "FAILED"
                rc = 1
                fail(f"Missing dependency: {exc}")
                notes.append(f"Missing dependency: {exc}")
            except Exception as exc:
                status = "FAILED"
                rc = 1
                fail(str(exc))
                notes.append(str(exc))
        elif scenario_id in NOT_CONFIGURED_SAFE_SCENARIOS:
            notes.append(NOT_CONFIGURED_SAFE_SCENARIOS[scenario_id])
            status = "NOT_CONFIGURED"
            warn(NOT_CONFIGURED_SAFE_SCENARIOS[scenario_id])
        else:
            try:
                evidence = await execute_safe(scenario_id)
                if evidence is None:
                    notes.append("No safe executor implemented for this catalog scenario.")
                    status = "NO_EXECUTOR"
                    warn("No safe executor implemented; catalog entry recorded only.")
                else:
                    status = "EXECUTED"
                    ok(f"Executed safe scenario; evidence={len(evidence)}")
            except ImportError as exc:
                status = "FAILED"
                rc = 1
                fail(f"Missing dependency: {exc}")
                notes.append(f"Missing dependency: {exc}")
            except Exception as exc:
                status = "FAILED"
                rc = 1
                fail(str(exc))
                notes.append(str(exc))

        path = save_result(group_id, scenario, status, evidence, notes, start)
        info(f"Saved: {path}")
    return rc


def main() -> int:
    parser = argparse.ArgumentParser(description="Day 8 multi-surface scenario runner")
    parser.add_argument("--list", action="store_true", help="List scenarios and exit")
    parser.add_argument("--group", choices=["s7_traditional", "opcua", "web_api", "logic_aware", "cross_layer"], help="Run/list one group")
    parser.add_argument("--scenario", help="Run/list one scenario id")
    parser.add_argument("--execute", action="store_true", help="Execute safe scenarios; default is dry-run")
    parser.add_argument("--allow-gated", action="store_true", help="Allow controlled executors for selected gated scenarios only")
    args = parser.parse_args()

    catalog = load_catalog()
    items = select_scenarios(catalog, args.group, args.scenario)
    if not items:
        fail("No matching scenarios")
        return 2
    if args.list:
        print_scenarios(items)
        return 0
    return asyncio.run(run_items(items, args.execute, args.allow_gated))


if __name__ == "__main__":
    raise SystemExit(main())
