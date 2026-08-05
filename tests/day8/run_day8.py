#!/usr/bin/env python3
"""Day 8 scenario runner -- OPC UA attack surface only.

The runner is intentionally safe by default. It lists and records scenarios,
and only executes bounded read-only/denied checks marked safe in the catalog.
S7comm, Web/API, logic-aware, and cross-layer scenarios were removed from
this catalog: S7comm continuity scenarios live in the Day 1-6 dataset, and
the rest either had no controlled executor here or conceptually duplicated
attacks_ext/logic_aware.py and attacks_ext/kill_chain.py (Day 7).
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
CONTROLLED_GATED_SCENARIOS = {
    "OPCUA_WRITE_DENIED",
    "OPCUA_INVALID_WRITE",
    "OPCUA_SESSION_BURST",
    "OPCUA_SUBSCRIPTION_FLOOD",
    "OPCUA_MALICIOUS_WRITE",
    "OPCUA_CONFIG_MANIPULATION",
    "OPCUA_ALARM_FLOOD",
    "OPCUA_REPLAY_ATTEMPT",
    "OPCUA_METHOD_CALL_ABUSE",
    "OPCUA_PROTOCOL_FUZZ",
}
MAX_SESSION_BURST_COUNT = 10
MIN_SESSION_BURST_DELAY_S = 0.2
MAX_SUBSCRIPTION_ITEMS = 200
MIN_SUBSCRIPTION_INTERVAL_MS = 50
DEFAULT_SUBSCRIPTION_HOLD_S = 10.0
MAX_READ_SCRAPING_COUNT = 500
MIN_READ_SCRAPING_INTERVAL_S = 0.02
MAX_FUZZ_FRAME_COUNT = 5

# The default node for write-impact scenarios. Override it only after the
# writable node has been intentionally confirmed and documented in TIA Portal.
WRITABLE_TEST_NODE = os.getenv("DAY8_WRITABLE_TEST_NODE", 'ns=3;s="Nhap"')
CONFIG_MANIPULATION_NODE = os.getenv("DAY8_CONFIG_NODE", "").strip()
MALICIOUS_WRITE_DELTA = int(os.getenv("DAY8_MALICIOUS_WRITE_DELTA", "3"))

# Tags this run's results with the OPC UA server security policy that was
# actually active when the run happened (e.g. "Anonymous", "Basic256Sha256").
# Set by the operator per run -- never inferred -- so the Security/IDS
# comparator can group real outcomes by mode instead of guessing.
OPCUA_SECURITY_MODE = os.getenv("OPCUA_SECURITY_MODE", "").strip() or None

# Any scenario that actually changes a live value on the real PLC (not just a
# same-value or invalid-type probe) requires this explicit opt-in on top of
# --execute --allow-gated. This is intentionally separate from
# CONTROLLED_GATED_SCENARIOS so a operator cannot trigger real process impact
# by muscle memory alone.
REQUIRE_IMPACT_OPT_IN_ENV = "DAY8_ALLOW_PROCESS_IMPACT"
IMPACT_SCENARIOS = {
    "OPCUA_MALICIOUS_WRITE",
    "OPCUA_CONFIG_MANIPULATION",
}

NOT_CONFIGURED_SCENARIOS = {
    "OPCUA_UNAUTHORIZED_SESSION": "No OPC UA username/password policy is configured in the current testbed.",
    "OPCUA_CERTIFICATE_REJECTED": "No OPC UA certificate trust-list scenario is configured in the current testbed.",
    "OPCUA_ALARM_FLOOD": "OPC UA Alarms & Conditions is not configured in the current Web-SCADA/PLC pipeline.",
    "OPCUA_REPLAY_ATTEMPT": "Packet-level OPC UA replay requires a capture/replay harness and session/channel-state handling; not implemented in the current runner.",
}


class ProcessImpactNotAuthorized(Exception):
    """Raised when an impact scenario is selected without the explicit env opt-in."""


def require_impact_opt_in(scenario_id: str) -> None:
    if scenario_id in IMPACT_SCENARIOS and os.getenv(REQUIRE_IMPACT_OPT_IN_ENV) != "1":
        raise ProcessImpactNotAuthorized(
            f"{scenario_id} writes a changed value to a real PLC node ({WRITABLE_TEST_NODE}). "
            f"Set {REQUIRE_IMPACT_OPT_IN_ENV}=1 to confirm this is authorized before rerunning."
        )


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
        try:
            async with Client(url=OPC_URL, timeout=5) as client:
                namespace_array = await client.get_namespace_array()
                evidence.append(f"reconnect_{i + 1}: namespaces={len(namespace_array)}")
        except Exception as exc:
            evidence.append(f"reconnect_{i + 1}: failed={type(exc).__name__}: {exc or '(empty message)'}")
        await asyncio.sleep(0.5)
    return evidence


async def opcua_node_browse(limit: int = 30) -> list[str]:
    from asyncua import Client

    evidence = []
    try:
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
    except Exception as exc:
        evidence.append(f"aborted_after_error={type(exc).__name__}: {exc or '(empty message)'}")
    return evidence


async def opcua_endpoint_discovery() -> list[str]:
    from asyncua import Client

    evidence = []
    try:
        async with Client(url=OPC_URL, timeout=5) as client:
            endpoints = await client.connect_and_get_server_endpoints()
            evidence.extend(f"endpoint: {ep.EndpointUrl} policy={ep.SecurityPolicyUri}" for ep in endpoints)
    except Exception as exc:
        evidence.append(f"aborted_after_error={type(exc).__name__}: {exc or '(empty message)'}")
    return evidence


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

    # Needs to outlast connect + create_subscription + 6 reads + the sleep(duration)
    # itself + delete -- a flat 5s timeout is tighter than duration=5.0 alone
    # already requires, so it was tripping on almost every run.
    client_timeout_s = min(25, int(duration) + 10)
    try:
        async with Client(url=OPC_URL, timeout=client_timeout_s) as client:
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
    except Exception as exc:
        evidence.append(f"aborted_after_error={type(exc).__name__}: {exc or '(empty message)'}; client_timeout_s={client_timeout_s}")
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
    try:
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
    except Exception as exc:
        evidence.append(f"aborted_after_error={type(exc).__name__}: {exc or '(empty message)'}")
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
    try:
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
    except Exception as exc:
        evidence.append(f"aborted_after_error={type(exc).__name__}: {exc or '(empty message)'}")
        return evidence
    evidence.append("All invalid-write attempts unexpectedly succeeded; stop and review OPC UA permissions/types.")
    return evidence


async def opcua_session_burst() -> list[str]:
    """Create a small bounded burst of OPC UA sessions.

    This is a characterization scenario, not a DoS attempt. Hard caps prevent
    accidentally turning the runner into an aggressive flood tool.
    """
    from asyncua import Client

    requested_count = int(os.getenv("DAY8_SESSION_BURST_COUNT", "5"))
    requested_delay = float(os.getenv("DAY8_SESSION_BURST_DELAY_S", "0.5"))
    count = max(1, min(requested_count, MAX_SESSION_BURST_COUNT))
    delay_s = max(requested_delay, MIN_SESSION_BURST_DELAY_S)
    evidence = [
        f"configured_count={requested_count}; effective_count={count}; max_count={MAX_SESSION_BURST_COUNT}",
        f"configured_delay_s={requested_delay}; effective_delay_s={delay_s}",
    ]

    before_status, before_body = http_request("GET", "/plc/status")
    evidence.append(f"web_scada_before_status={before_status}: {before_body}")

    successes = 0
    failures = 0
    for i in range(count):
        try:
            async with Client(url=OPC_URL, timeout=5) as client:
                namespace_array = await client.get_namespace_array()
                successes += 1
                evidence.append(f"session_{i + 1}: connected namespaces={len(namespace_array)}")
        except Exception as exc:
            failures += 1
            evidence.append(f"session_{i + 1}: failed={type(exc).__name__}: {exc}")
        await asyncio.sleep(delay_s)

    # Give the Web-SCADA poller one cycle to reflect any transient effects.
    await asyncio.sleep(1.0)
    after_status, after_body = http_request("GET", "/plc/status")
    tags_status, tags_body = http_request("GET", "/tags")
    evidence.append(f"summary: successes={successes} failures={failures}")
    evidence.append(f"web_scada_after_status={after_status}: {after_body}")
    evidence.append(f"web_scada_tags_after={tags_status}: {tags_body}")
    return evidence


async def opcua_subscription_flood() -> list[str]:
    """Single session, bounded number of monitored items at a short publishing interval.

    Targets the OPC UA *application* layer (subscription/monitored-item
    handling), distinct from S7_FLOOD (transport/session-level) and from
    OPCUA_SESSION_BURST (many short-lived sessions). Item count, interval and
    hold time are all hard-capped so this stays a characterization run and
    not the naive "5000 items / 10ms" flood tooling this scenario is
    sometimes prototyped with.
    """
    from asyncua import Client

    requested_items = int(os.getenv("DAY8_SUBSCRIPTION_FLOOD_ITEMS", "50"))
    requested_interval_ms = int(os.getenv("DAY8_SUBSCRIPTION_FLOOD_INTERVAL_MS", "200"))
    requested_hold_s = float(os.getenv("DAY8_SUBSCRIPTION_FLOOD_HOLD_S", str(DEFAULT_SUBSCRIPTION_HOLD_S)))

    item_count = max(1, min(requested_items, MAX_SUBSCRIPTION_ITEMS))
    interval_ms = max(requested_interval_ms, MIN_SUBSCRIPTION_INTERVAL_MS)
    hold_s = min(requested_hold_s, 30.0)

    evidence = [
        f"configured_items={requested_items}; effective_items={item_count}; max_items={MAX_SUBSCRIPTION_ITEMS}",
        f"configured_interval_ms={requested_interval_ms}; effective_interval_ms={interval_ms}; min_interval_ms={MIN_SUBSCRIPTION_INTERVAL_MS}",
        f"effective_hold_s={hold_s} (hard capped at 30s)",
    ]

    before_status, before_body = http_request("GET", "/plc/status")
    evidence.append(f"web_scada_before_status={before_status}: {before_body}")

    class _QuietHandler:
        def datachange_notification(self, node, val, data):
            pass

    # Same class of bug as opcua_benign_subscription: the client has to stay
    # connected through connect + subscribe + sleep(hold_s) + delete, so the
    # timeout must exceed hold_s with margin, not a flat 5s.
    client_timeout_s = min(35, int(hold_s) + 10)

    node_id = 'ns=3;s="HienThi"'
    try:
        async with Client(url=OPC_URL, timeout=client_timeout_s) as client:
            node = client.get_node(node_id)
            sub = await client.create_subscription(interval_ms, _QuietHandler())
            try:
                handles = await sub.subscribe_data_change([node for _ in range(item_count)])
                evidence.append(f"subscribed monitored_items={len(handles)} on node={node_id}")
                await asyncio.sleep(hold_s)
            finally:
                await sub.delete()
                evidence.append("subscription deleted")
    except Exception as exc:
        evidence.append(f"aborted_after_error={type(exc).__name__}: {exc or '(empty message)'}")
        return evidence

    after_status, after_body = http_request("GET", "/plc/status")
    evidence.append(f"web_scada_after_status={after_status}: {after_body}")
    return evidence


async def opcua_read_scraping() -> list[str]:
    """Rapid repeated Read requests against real process tags on a single
    session -- data-exfiltration-style scraping, distinct from
    OPCUA_NODE_BROWSE (structure discovery, not value reads) and
    OPCUA_SUBSCRIPTION_FLOOD (server-push volume, not client-pull rate).
    Read-only, single session, bounded count and rate.
    """
    from asyncua import Client

    requested_reads = int(os.getenv("DAY8_READ_SCRAPING_COUNT", "100"))
    requested_interval_s = float(os.getenv("DAY8_READ_SCRAPING_INTERVAL_S", "0.05"))
    read_count = max(1, min(requested_reads, MAX_READ_SCRAPING_COUNT))
    interval_s = max(requested_interval_s, MIN_READ_SCRAPING_INTERVAL_S)

    nodes = [
        'ns=3;s="BangTai"', 'ns=3;s="Nhap"', 'ns=3;s="HienThi"',
        'ns=3;s="Vat 1"', 'ns=3;s="Vat 2"', 'ns=3;s="Vat 3"',
    ]
    evidence = [
        f"configured_reads={requested_reads}; effective_reads={read_count}; max={MAX_READ_SCRAPING_COUNT}",
        f"configured_interval_s={requested_interval_s}; effective_interval_s={interval_s}",
        f"targets={nodes}",
    ]

    # The read loop is expected to run for roughly read_count * interval_s
    # (plus per-read latency), which can comfortably exceed a small fixed
    # client timeout -- the asyncua Client also uses `timeout` for internal
    # keepalive/session requests, not just the initial connect. Size it to
    # the scenario's own expected runtime instead of a flat 5s, and stay
    # under the ~30s session ceiling this testbed's server was observed to
    # grant regardless of what is requested.
    estimated_runtime_s = read_count * interval_s
    client_timeout_s = min(25, max(10, int(estimated_runtime_s) + 5))
    completed_reads = 0

    t0 = time.time()
    try:
        async with Client(url=OPC_URL, timeout=client_timeout_s) as client:
            node_objs = [client.get_node(n) for n in nodes]
            sample_every = max(1, read_count // 10)
            for i in range(read_count):
                values = []
                for node in node_objs:
                    try:
                        values.append(await node.read_value())
                    except Exception as exc:
                        values.append(f"ERR:{type(exc).__name__}")
                completed_reads = i + 1
                if i % sample_every == 0:
                    evidence.append(f"read_{i + 1}: {dict(zip(nodes, values))}")
                await asyncio.sleep(interval_s)
    except Exception as exc:
        # Keep whatever evidence was already collected instead of losing it
        # to an exception that unwinds past `async with` -- an empty-message
        # asyncio.TimeoutError here is expected if completed_reads is high
        # (session/keepalive limit hit near the end), not a read failure.
        elapsed = max(time.time() - t0, 0.001)
        evidence.append(
            f"aborted_after_error={type(exc).__name__}: {exc or '(empty message)'}; "
            f"completed_reads={completed_reads}/{read_count} elapsed_s={elapsed:.1f} client_timeout_s={client_timeout_s}"
        )
        return evidence

    elapsed = max(time.time() - t0, 0.001)
    total_reads = read_count * len(nodes)
    evidence.append(f"summary: total_reads={total_reads} elapsed_s={elapsed:.1f} reads_per_s={total_reads / elapsed:.1f} client_timeout_s={client_timeout_s}")
    return evidence


async def opcua_method_call_abuse() -> list[str]:
    """Discover any exposed Method node under Objects and attempt to invoke
    it without prior authorization context. Reports honestly if the server
    exposes no callable Method nodes rather than faking a target.
    """
    from asyncua import Client, ua

    evidence = []
    try:
        async with Client(url=OPC_URL, timeout=5) as client:
            objects = client.nodes.objects
            method_nodes = []
            for child in await objects.get_children():
                try:
                    if await child.read_node_class() == ua.NodeClass.Method:
                        name = (await child.read_browse_name()).Name
                        method_nodes.append((name, child))
                except Exception:
                    continue

            evidence.append(f"method_nodes_found={len(method_nodes)}")
            if not method_nodes:
                evidence.append("No exposed Method node under Objects on this server; Call-service abuse is not applicable to this configuration (not forced/faked).")
                return evidence

            for name, node in method_nodes[:3]:
                try:
                    result = await objects.call_method(node)
                    evidence.append(f"UNEXPECTED_CALL_SUCCESS: {name} -> {result!r}")
                except Exception as exc:
                    evidence.append(f"{name}: call_rejected={type(exc).__name__}: {exc}")
    except Exception as exc:
        evidence.append(f"aborted_after_error={type(exc).__name__}: {exc or '(empty message)'}")
    return evidence


async def opcua_protocol_fuzz() -> list[str]:
    """Send a small bounded set of malformed OPC UA binary (UA-TCP) frames
    and record how the server responds -- ERR message, clean disconnect, or
    no response. Each case uses a fresh TCP connection so one bad frame
    cannot desync a shared session; frame count is hard-capped.
    """
    import struct
    from urllib.parse import urlparse

    parsed = urlparse(OPC_URL)
    host, port = parsed.hostname, parsed.port or 4840
    fuzz_count = max(1, min(int(os.getenv("DAY8_FUZZ_COUNT", "5")), MAX_FUZZ_FRAME_COUNT))
    evidence = [f"target={host}:{port}; fuzz_count={fuzz_count}"]

    endpoint = OPC_URL.encode()
    good_body = struct.pack("<IIIII", 0, 65536, 65536, 2097152, 0) + struct.pack("<I", len(endpoint)) + endpoint
    all_cases = [
        ("bad_message_size", b"HEL" + b"F" + struct.pack("<I", 99999) + good_body),
        ("truncated_body", b"HEL" + b"F" + struct.pack("<I", 8 + len(good_body)) + good_body[:4]),
        ("unknown_msg_type", b"XXX" + b"F" + struct.pack("<I", 8 + len(good_body)) + good_body),
        ("zero_length_body", b"HEL" + b"F" + struct.pack("<I", 8)),
        ("oversized_size_claim", b"HEL" + b"F" + struct.pack("<I", 0x7FFFFFFF) + good_body),
    ]

    for name, frame in all_cases[:fuzz_count]:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3)
            writer.write(frame)
            await writer.drain()
            try:
                resp = await asyncio.wait_for(reader.read(64), timeout=2)
                evidence.append(f"{name}: sent={len(frame)}B resp_prefix={resp[:3]!r} resp_len={len(resp)}")
            except asyncio.TimeoutError:
                evidence.append(f"{name}: sent={len(frame)}B no_response_within_timeout")
        except Exception as exc:
            evidence.append(f"{name}: connection_error={type(exc).__name__}: {exc}")
        finally:
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        await asyncio.sleep(0.5)

    return evidence


async def _attempt_write_and_rollback(client, node_id: str, compute_new_value, evidence: list[str]) -> bool:
    """Write compute_new_value(baseline) to node_id, confirm it landed, then always roll back.

    Returns True if the write actually changed the live value (the
    successful-manipulation case), False if the server rejected the write
    outright (no process impact occurred). A failed rollback is never
    swallowed — it is always appended to evidence as ROLLBACK_FAILED so it
    cannot be missed when reviewing a run.
    """
    node = client.get_node(node_id)
    baseline = await node.read_value()
    new_value = compute_new_value(baseline)
    evidence.append(f"baseline_value={baseline!r} target_node={node_id} attempted_value={new_value!r}")

    try:
        await node.write_value(new_value)
    except Exception as exc:
        evidence.append(f"write_rejected={type(exc).__name__}: {exc}; no process impact occurred")
        return False

    confirmed = await node.read_value()
    evidence.append(f"WRITE_SUCCEEDED: wrote={new_value!r} confirmed_value={confirmed!r}")

    try:
        await node.write_value(baseline)
        restored = await node.read_value()
        if restored == baseline:
            evidence.append(f"rollback_confirmed: restored_value={restored!r}")
        else:
            evidence.append(f"ROLLBACK_MISMATCH: expected={baseline!r} got={restored!r}; manual correction required")
    except Exception as exc:
        evidence.append(f"ROLLBACK_FAILED={type(exc).__name__}: {exc}; manual correction required on node {node_id}")
    return True


def _bounded_delta(baseline):
    return baseline + MALICIOUS_WRITE_DELTA if isinstance(baseline, int) else baseline


async def opcua_malicious_write() -> list[str]:
    """Successfully write a plausible-but-wrong value to a real writable node.

    Unlike OPCUA_WRITE_DENIED/OPCUA_INVALID_WRITE (which expect rejection),
    this is the successful-manipulation case: change a real value, confirm
    the change (process anomaly, not just protocol noise), then roll back.
    """
    from asyncua import Client

    if os.getenv("DAY8_CONFIRM_WRITABLE_NODE") != "1":
        return [
            "blocked: set DAY8_CONFIRM_WRITABLE_NODE=1 only after documenting that this is a deliberately writable production/configuration node in TIA Portal",
            f"target_node={WRITABLE_TEST_NODE}",
        ]

    evidence = [
        "human_misconfiguration_model=Anonymous/No-Security endpoint exposes a writable node",
        f"target_node={WRITABLE_TEST_NODE}; delta={MALICIOUS_WRITE_DELTA}",
    ]
    try:
        async with Client(url=OPC_URL, timeout=15) as client:
            await _attempt_write_and_rollback(client, WRITABLE_TEST_NODE, _bounded_delta, evidence)
    except Exception as exc:
        evidence.append(f"aborted_after_error={type(exc).__name__}: {exc or '(empty message)'}; if a write already succeeded above, verify {WRITABLE_TEST_NODE} was restored manually")
    return evidence


async def opcua_config_manipulation() -> list[str]:
    """Modify a real writable configuration node, if one exists, and roll back."""
    from asyncua import Client

    if not CONFIG_MANIPULATION_NODE:
        return ["blocked: set DAY8_CONFIG_NODE to a real writable configuration/threshold node before running this scenario"]
    if os.getenv("DAY8_CONFIRM_CONFIG_NODE") != "1":
        return [
            "blocked: set DAY8_CONFIRM_CONFIG_NODE=1 only after documenting safe bounds and rollback for the configuration node",
            f"target_config_node={CONFIG_MANIPULATION_NODE}",
        ]

    evidence = [f"target_config_node={CONFIG_MANIPULATION_NODE}; delta={MALICIOUS_WRITE_DELTA}"]
    try:
        async with Client(url=OPC_URL, timeout=15) as client:
            await _attempt_write_and_rollback(client, CONFIG_MANIPULATION_NODE, _bounded_delta, evidence)
    except Exception as exc:
        evidence.append(f"aborted_after_error={type(exc).__name__}: {exc or '(empty message)'}; if a write already succeeded above, verify {CONFIG_MANIPULATION_NODE} was restored manually")
    return evidence


async def opcua_read_timing_covert() -> list[str]:
    """Generate a benign-read timing pattern that encodes a short bit string."""
    from asyncua import Client

    pattern = os.getenv("DAY8_COVERT_BITS", "10110")[:16]
    short_s = max(0.1, float(os.getenv("DAY8_COVERT_SHORT_S", "0.2")))
    long_s = max(short_s + 0.1, float(os.getenv("DAY8_COVERT_LONG_S", "0.8")))
    node_id = os.getenv("DAY8_COVERT_NODE", 'ns=3;s="HienThi"')
    evidence = [f"node={node_id}; bits={pattern}; short_s={short_s}; long_s={long_s}"]

    try:
        async with Client(url=OPC_URL, timeout=5) as client:
            node = client.get_node(node_id)
            for i, bit in enumerate(pattern, 1):
                t0 = time.time()
                value = await node.read_value()
                delay = long_s if bit == "1" else short_s
                evidence.append(f"symbol_{i}: bit={bit} value={value!r} read_ts={t0:.3f} next_delay_s={delay}")
                await asyncio.sleep(delay)
    except Exception as exc:
        evidence.append(f"aborted_after_error={type(exc).__name__}: {exc or '(empty message)'}")
        return evidence
    evidence.append("no PLC value was written; covert signal exists only in read timing")
    return evidence


def http_request(method: str, path: str, body: bytes | None = None, timeout: float = 5) -> tuple[int | None, str]:
    try:
        req = Request(f"{WEB_SCADA_API}{path}", data=body, method=method)
        if body is not None:
            req.add_header("Content-Type", "application/json")
        with urlopen(req, timeout=timeout) as res:
            return res.status, res.read().decode("utf-8", errors="replace")[:300]
    except HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")[:300]
    except (OSError, URLError) as exc:
        return None, str(exc)


async def execute_safe(scenario_id: str) -> list[str] | None:
    if scenario_id == "OPCUA_BENIGN_RECONNECT":
        return await opcua_benign_reconnect()
    if scenario_id == "OPCUA_NODE_BROWSE":
        return await opcua_node_browse()
    if scenario_id == "OPCUA_ENDPOINT_DISCOVERY":
        return await opcua_endpoint_discovery()
    if scenario_id == "OPCUA_BENIGN_SUBSCRIPTION":
        return await opcua_benign_subscription()
    if scenario_id == "READ_TIMING_COVERT":
        return await opcua_read_timing_covert()
    if scenario_id == "OPCUA_READ_SCRAPING":
        return await opcua_read_scraping()
    return None


async def execute_controlled_gated(scenario_id: str) -> list[str] | None:
    if scenario_id == "OPCUA_WRITE_DENIED":
        return await opcua_write_denied()
    if scenario_id == "OPCUA_INVALID_WRITE":
        return await opcua_invalid_write()
    if scenario_id == "OPCUA_SESSION_BURST":
        return await opcua_session_burst()
    if scenario_id == "OPCUA_SUBSCRIPTION_FLOOD":
        return await opcua_subscription_flood()
    if scenario_id == "OPCUA_MALICIOUS_WRITE":
        require_impact_opt_in(scenario_id)
        return await opcua_malicious_write()
    if scenario_id == "OPCUA_CONFIG_MANIPULATION":
        require_impact_opt_in(scenario_id)
        return await opcua_config_manipulation()
    if scenario_id == "OPCUA_METHOD_CALL_ABUSE":
        return await opcua_method_call_abuse()
    if scenario_id == "OPCUA_PROTOCOL_FUZZ":
        return await opcua_protocol_fuzz()
    return None


def push_result_to_webscada(result: dict) -> None:
    """Best-effort live demo feed: POST to the Web-SCADA Security/IDS console.

    Failures are swallowed on purpose — the runner's job is to produce the
    JSON file in test_results/day8/; the web push is a bonus for live demos
    and must never fail the run if the backend isn't up.
    """
    try:
        body = json.dumps(result, ensure_ascii=False).encode("utf-8")
        http_request("POST", "/security/scenario-result", body, timeout=1)
    except Exception:
        pass


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
        "security_mode": OPCUA_SECURITY_MODE,
    }
    path = out_dir / f"{scenario['id']}_{time.strftime('%Y%m%d_%H%M%S')}.json"
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    if status != "DRY_RUN":
        push_result_to_webscada(result)
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

        if not execute:
            notes.append("dry-run only; add --execute for safe executor")
            status = "DRY_RUN"
            info("Dry-run; no traffic generated.")
        elif scenario_id in NOT_CONFIGURED_SCENARIOS:
            notes.append(NOT_CONFIGURED_SCENARIOS[scenario_id])
            status = "NOT_CONFIGURED"
            warn(NOT_CONFIGURED_SCENARIOS[scenario_id])
        elif scenario.get("requires_manual_gate") and not allow_gated:
            notes.append("requires_manual_gate=true; not executed by runner")
            status = "GATED"
            warn("Manual safety gate required; catalog entry recorded only.")
        elif scenario.get("requires_manual_gate") and scenario_id not in CONTROLLED_GATED_SCENARIOS:
            notes.append("requires_manual_gate=true; no controlled executor is available for this scenario")
            status = "GATED"
            warn("Manual safety gate required; no controlled executor available.")
        elif not scenario.get("safe_to_execute"):
            try:
                evidence = await execute_controlled_gated(scenario_id)
                if evidence is None:
                    notes.append("safe_to_execute=false; no controlled gated executor implemented")
                    status = "BLOCKED"
                    warn("Blocked because safe_to_execute=false.")
                else:
                    notes.append("Executed with --allow-gated; controlled bounded gated check only.")
                    status = "EXECUTED_GATED"
                    ok(f"Executed controlled gated scenario; evidence={len(evidence)}")
            except ProcessImpactNotAuthorized as exc:
                status = "IMPACT_NOT_AUTHORIZED"
                notes.append(str(exc))
                warn(str(exc))
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
    parser.add_argument("--group", choices=["opcua"], help="Run/list one group (only opcua exists in this catalog)")
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
