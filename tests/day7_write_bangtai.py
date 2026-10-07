#!/usr/bin/env python3
"""Day 7: bounded OPC UA BangTai write/read-back/rollback verification.

This is a testbed check of the same status tag used by Web-SCADA. It never
loops writes and always attempts to restore the original value in finally.
"""

import asyncio
import json
import os
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

from asyncua import Client, ua

from tests.common import OPC_URL

NODE_ID = os.getenv("DAY7_BANGTAI_NODE", 'ns=3;s="BangTai"')
OUT_DIR = Path("test_results/day7")
TZ7 = timezone(timedelta(hours=7))


def stamp():
    return datetime.now(TZ7).isoformat(timespec="milliseconds")


async def write_value_only(node, value):
    # Do not use node.write_value(bool): asyncua adds SourceTimestamp.
    await node.write_value(ua.DataValue(ua.Variant(value, ua.VariantType.Boolean)))


async def main():
    if os.getenv("DAY7_ALLOW_BANGTAI_WRITE") != "1":
        raise SystemExit(
            "Blocked. Set DAY7_ALLOW_BANGTAI_WRITE=1 only for the authorized simulation testbed."
        )

    evidence = []
    baseline = None
    result = {
        "scenario_id": "DAY7_OPCUA_BANGTAI_WRITE_VERIFY",
        "node_id": NODE_ID,
        "opc_url": OPC_URL,
        "started_at": stamp(),
        "evidence": evidence,
    }

    async with Client(url=OPC_URL, timeout=10) as client:
        node = client.get_node(NODE_ID)
        baseline = await node.read_value()
        target = not bool(baseline)
        evidence.append({"step": "baseline", "time": stamp(), "value": baseline})
        evidence.append({"step": "attempt", "time": stamp(), "value": target})

        try:
            await write_value_only(node, target)
            readback = await node.read_value()
            evidence.append({
                "step": "readback_after_write",
                "time": stamp(),
                "value": readback,
                "write_call_no_exception": True,
                "value_changed": readback == target,
            })
        except Exception as exc:
            evidence.append({
                "step": "write_rejected",
                "time": stamp(),
                "error_type": type(exc).__name__,
                "error": str(exc),
            })
        finally:
            try:
                await write_value_only(node, baseline)
                restored = await node.read_value()
                evidence.append({
                    "step": "rollback",
                    "time": stamp(),
                    "value": restored,
                    "rollback_confirmed": restored == baseline,
                })
            except Exception as exc:
                evidence.append({
                    "step": "rollback_failed",
                    "time": stamp(),
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "manual_restore_required": True,
                })

    result["finished_at"] = stamp()
    result["interpretation"] = (
        "value_changed_and_restored" if any(
            x.get("step") == "readback_after_write" and x.get("value_changed")
            for x in evidence
        ) and any(x.get("step") == "rollback" and x.get("rollback_confirmed") for x in evidence)
        else "write_not_confirmed_or_rollback_not_confirmed"
    )
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / f"DAY7_OPCUA_BANGTAI_WRITE_VERIFY_{time.strftime('%Y%m%d_%H%M%S')}.json"
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"Saved: {path}")


if __name__ == "__main__":
    asyncio.run(main())
