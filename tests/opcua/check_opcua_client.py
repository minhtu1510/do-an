#!/usr/bin/env python3
"""
Check OPC UA client connectivity and browse tags.
Xác nhận baseline trước khi xây dựng web-scada.
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))


async def main():
    try:
        from asyncua import Client

        url = "opc.tcp://192.168.210.211:4840"
        print(f"[*] Connecting to {url}...")

        async with Client(url=url) as client:
            print("[OK] Connected!")

            ns_array = await client.get_namespace_array()
            print(f"\nNamespaces: {ns_array}")

            ns_idx = await client.get_namespace_index("http://www.siemens.com/simatic-s7-opcua")
            if ns_idx == 0:
                ns_idx = 3
            print(f"Siemens namespace index: {ns_idx}")

            print("\n[*] Browsing available tags...")
            objects = client.nodes.objects
            children = await objects.get_children()

            tags = []
            for child in children:
                name = (await child.read_browse_name()).Name
                nid = str(child.nodeid)
                print(f"  Object: {name} ({nid})")

                try:
                    sub_children = await child.get_children()
                    for sub in sub_children:
                        sname = (await sub.read_browse_name()).Name
                        snid = str(sub.nodeid)
                        try:
                            val = await sub.read_value()
                            dt = type(val).__name__
                            print(f"    Tag: {sname} = {val} ({dt}) [{snid}]")
                            tags.append((sname, snid, dt))
                        except Exception as e:
                            print(f"    Tag: {sname} — read error: {e}")
                except Exception as e:
                    print(f"    Cannot browse children: {e}")

            print(f"\n{'='*50}")
            print(f"Summary: {len(tags)} tags found")
            print(f"{'='*50}")
            for name, nid, dt in tags:
                print(f"  {name:<20} {dt:<10} {nid}")

    except ImportError:
        print("[FAIL] asyncua not installed: pip install asyncua cryptography")
    except Exception as e:
        print(f"[FAIL] {e}")


if __name__ == "__main__":
    asyncio.run(main())
