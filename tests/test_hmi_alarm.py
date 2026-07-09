#!/usr/bin/env python3
"""
tests/test_hmi_alarm.py
Xóa OPC-UA subscription -> HMI không nhận alarm.
Yêu cầu opcua_sim_server đang chạy.

Chạy: python tests/test_hmi_alarm.py
"""

import sys
import os
import asyncio
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.common import *


class AlarmHandler:
    """Handler nhận alarm events — verify subscription hoạt động."""

    def __init__(self):
        self.events = []

    def datachange_notification(self, node, val, data):
        self.events.append((node, val))


async def run_test():
    print(f"\n{B}[TEST] HMI_ALARM_SUPPRESS (OPC-UA Subscription){X}")
    info(f"Server: {OPC_URL}")

    changes = []
    observable = []
    notes = []
    error = None
    t0 = time.time()

    try:
        from asyncua import Client

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

            # Subscribe to alarm tags
            handler = AlarmHandler()
            sub = await client.create_subscription(100, handler)

            alarm_nodes = []
            try:
                alarms_node = await client.nodes.objects.get_child(f"{ns_idx}:PLC/Alarms")
                for child in await alarms_node.get_children():
                    name = (await child.read_browse_name()).Name
                    await sub.subscribe_data_change(child)
                    alarm_nodes.append(name)
                    print(f"  [SUB] {name}")
            except Exception:
                # Fallback: subscribe bất kỳ tag nào
                plc = await client.nodes.objects.get_child(f"{ns_idx}:PLC")
                for child in await plc.get_children():
                    name = (await child.read_browse_name()).Name
                    if "Alarm" in name:
                        await sub.subscribe_data_change(child)
                        alarm_nodes.append(name)
                        print(f"  [SUB] {name}")
                        if len(alarm_nodes) >= 2:
                            break
                if not alarm_nodes:
                    # Last resort: subscribe to any tag
                    child = await (await plc.get_children()).__anext__()
                    name = (await child.read_browse_name()).Name
                    await sub.subscribe_data_change(child)
                    alarm_nodes.append(name)
                    print(f"  [SUB] {name}")

            ok(f"Subscribed to {len(alarm_nodes)} alarms")
            observable.append(f"CreateSubscription: {alarm_nodes}")
            info("Wait 3s for subscription active...")
            await asyncio.sleep(3)

            # Trigger an alarm change to verify subscription works
            alarm_node = None
            for child in await (await client.nodes.objects.get_child(f"{ns_idx}:PLC/Alarms")).get_children():
                alarm_node = child
                break
            if alarm_node:
                await alarm_node.write_value(True)
                await asyncio.sleep(1)
                await alarm_node.write_value(False)

            # ATTACK: Delete subscription
            await sub.delete()
            ok("Deleted subscription — HMI blind to alarms")
            observable.append("DeleteSubscriptions — HMI mat alarm")
            notes.append("Wireshark: opcua service DeleteSubscriptions")
            info("Wait 5s observing no subscription state...")
            await asyncio.sleep(5)

            # Verify can re-subscribe (server still alive)
            sub2 = await client.create_subscription(100, handler)
            ok(f"Re-subscribed OK — server still functional")
            await sub2.delete()

    except ImportError:
        error = "asyncua not installed: pip install asyncua cryptography"
        fail(error)
    except ConnectionRefusedError:
        error = f"OPC-UA server not running at {OPC_URL}"
        fail(error)
    except Exception as e:
        error = str(e)
        fail(str(e))

    success = error is None
    print_result("HMI_ALARM_SUPPRESS", success, changes, observable, notes, time.time() - t0, error)


def main():
    asyncio.run(run_test())


if __name__ == "__main__":
    main()
