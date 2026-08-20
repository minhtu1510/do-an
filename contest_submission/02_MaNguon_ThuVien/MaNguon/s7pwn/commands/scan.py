from __future__ import annotations
from typing import List
from s7pwn.ext.scan_module import scan_network, get_rack_slot, PLC_FAMILIES
from s7pwn.runtime import set_scan_results

def scan(args: List[str]) -> None:
    """
    Scan network for OT devices using multiple protocols

    Usage:
        scan                                    # Profinet DCP scan only (legacy mode)
        scan --help                             # Show this help
        scan <network/mask>                     # Scan specific network with all protocols
        scan <network/mask> --protocols <list>  # Scan with specific protocols

    Supported protocols:
        profinet     - Profinet DCP (Layer 2, requires admin)
        modbus       - Modbus TCP (port 502)
        ethernet_ip  - EtherNet/IP (port 44818) - Allen-Bradley/Rockwell
        s7           - S7 Protocol (port 102) - Siemens
        bacnet       - BACnet (port 47808) - Building automation
        fins         - FINS (port 9600) - Omron

    Examples:
        scan 192.168.1.0/24
        scan 192.168.1.0/24 --protocols profinet,modbus,s7
        scan 192.168.1.0/24 --protocols all
    """

    # Parse arguments
    network_cidr = None
    protocols = None

    if len(args) > 0 and args[0] == '--help':
        print(scan.__doc__)
        return

    # Parse network and protocols
    i = 0
    auto_select = False
    while i < len(args):
        if args[i] == '--auto':
            auto_select = True
            i += 1
            continue
        if args[i] == '--protocols':
            if i + 1 < len(args):
                proto_str = args[i + 1]
                if proto_str.lower() == 'all':
                    protocols = ['profinet', 'modbus', 'ethernet_ip', 's7', 'bacnet', 'fins']
                else:
                    protocols = [p.strip() for p in proto_str.split(',')]
                i += 2
            else:
                print("[!] --protocols requires a value")
                return
        elif '/' in args[i]:
            network_cidr = args[i]
            i += 1
        else:
            print(f"[!] Unknown argument: {args[i]}")
            print("Usage: scan [network/mask] [--protocols protocol1,protocol2,...]")
            print("       scan --help  # for more information")
            return

    # If no network specified but protocols require it, show error
    if protocols and any(p in protocols for p in ['modbus', 'ethernet_ip', 's7', 'bacnet', 'fins']):
        if not network_cidr:
            print("[!] Network CIDR required for IP-based protocols")
            print("Usage: scan <network/mask> --protocols <protocol_list>")
            print("Example: scan 192.168.1.0/24 --protocols modbus,s7")
            return

    # Display scan configuration
    print("\n" + "="*60)
    print("OT NETWORK SCANNER")
    print("="*60)
    if network_cidr:
        print(f"Network: {network_cidr}")
    if protocols:
        print(f"Protocols: {', '.join(protocols)}")
    else:
        print("Protocols: profinet (default)")
    print("="*60 + "\n")

    # Perform scan
    devices = scan_network(
        timeout=3,
        retries=2,
        protocols=protocols,
        network_cidr=network_cidr,
        auto_select_interface=auto_select
    )

    # Build PLC list for backward compatibility
    plc_list = []
    for d in devices:
        if d.get("vendor") == "Siemens" and d.get("device_model") in PLC_FAMILIES:
            rack, slot = get_rack_slot(d["device_model"])
            plc_list.append({
                "ip": d["ip"],
                "mac": d.get("mac", "Unknown"),
                "vendor": d["vendor"],
                "model": d["device_model"],
                "rack": rack,
                "slot": slot
            })

    print(f"\n[+] Summary: {len(devices)} device(s) found")
    if plc_list:
        print(f"[+] Siemens PLCs: {len(plc_list)}")

    set_scan_results(devices, plc_list)
