#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_opcua_features_ext.py

Bản MỞ RỘNG của extract_opcua_features.py: từ 28 -> ~60 đặc trưng/cửa sổ.
Giữ nguyên file gốc; script này là superset, dùng cùng timeline/gán nhãn.

Động cơ (xem bao-cao/opcua_bao_cao_chi_tiet.md §8.5): 28 đặc trưng gốc đều là
tổng hợp TOÀN cửa sổ -> trộn traffic attacker (.32) với benign đều đặn (.31),
làm loãng tấn công thưa gói. Các nhóm mới cô lập nguồn tấn công, thêm chiều
gói, cờ TCP (slowloris/fuzz), timing/burst, dịch vụ mở rộng (Publish, Call...),
phân bố kích thước và lỗi.

Nhóm đặc trưng MỚI so với bản gốc:
  - per-source : max_*_by_client, busiest_client_frac, service diversity/src
  - chiều gói  : c2s/s2c pkt&byte, req/resp ratio
  - cờ TCP     : syn/rst/fin/retransmission, half-open ratio
  - timing     : inter-arrival mean/std/min, max_pkts_per_sec (burst)
  - dịch vụ+   : publish, call, translate_browse, register_nodes, read_resp
  - kích thước : frame_len min/max/median/p90
  - lỗi        : transport_error, distinct_status

Usage giống bản gốc:
  python extract_opcua_features_ext.py --pcap x.pcap --timeline t.csv \
     --output feat_ext.csv --window 5 --plc-ip 192.168.210.211 --role mirror
"""
from __future__ import annotations

import argparse
import csv
import statistics
import subprocess
import sys
from collections import defaultdict
from typing import Dict, List, Optional, Set

from extract_s7_features import (
    choose_existing_fields, find_tshark, get_available_fields,
    mean, normalize_epoch_ms, safe_float, safe_int, std,
)

# Dịch vụ: id request VÀ response (bản gốc chỉ đếm request). Đối chiếu NodeIds.csv.
SERVICE_NODE_IDS: Dict[str, Set[int]] = {
    "get_endpoints":          {426, 428},
    "open_secure_channel":    {444, 446},
    "close_secure_channel":   {448, 450},
    "create_session":         {459, 461},
    "activate_session":       {465, 467},
    "close_session":          {471, 473},
    "browse":                 {523, 525, 527},
    "browse_next":            {531, 533},
    "translate_browse_paths": {552, 554},
    "register_nodes":         {558, 560},
    "read":                   {629, 631},
    "read_response":          {634},
    "write":                  {671, 673},
    "call":                   {710, 712},
    "create_subscription":    {785, 787},
    "create_monitored_items": {749, 751},
    "publish":                {824, 826, 829},
}

STATUS_SEVERITY_MASK = 0xC0000000
STATUS_SEVERITY_BAD = 0x80000000
STATUS_SEVERITY_UNCERTAIN = 0x40000000

BENIGN_CHUNK_WINDOWS = 12


def build_cmd(tshark_cmd, pcap, avail, plc_ip):
    base = ["frame.time_epoch", "frame.len", "ip.src", "ip.dst",
            "tcp.srcport", "tcp.dstport", "tcp.stream",
            "tcp.flags.syn", "tcp.flags.reset", "tcp.flags.fin",
            "tcp.analysis.retransmission"]
    opc = ["opcua.transport.type", "opcua.servicenodeid.numeric",
           "opcua.StatusCode", "opcua.ServiceResult", "opcua.transport.error"]
    fields = []
    for g in (base, opc):
        fields.extend(choose_existing_fields(avail, g))
    seen = set()
    fields = [f for f in fields if not (f in seen or seen.add(f))]
    df = f"tcp.port == 4840 && ip.addr == {plc_ip}" if plc_ip else "tcp.port == 4840"
    cmd = [tshark_cmd, "-r", pcap, "-o", "tcp.desegment_tcp_streams:TRUE",
           "-Y", df, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=a"]
    return cmd, fields


def new_window():
    w = {
        "pkt": 0, "byte": 0, "flens": [], "epochs": [],
        "src_ips": set(), "dst_ips": set(), "streams": set(),
        "hel": 0, "opn": 0, "msg": 0, "clo": 0, "err": 0,
        "st_good": 0, "st_unc": 0, "st_bad": 0, "st_values": set(),
        "syn": 0, "rst": 0, "fin": 0, "retrans": 0, "transport_err": 0,
        "c2s_pkt": 0, "s2c_pkt": 0, "c2s_byte": 0, "s2c_byte": 0,
        "syn_streams": set(), "has_attacker": False,
        # per source (client)
        "by_src": defaultdict(lambda: {"pkt": 0, "byte": 0, "svcset": set(),
                                       "opn": 0, "read": 0, "create_session": 0,
                                       "browse": 0}),
    }
    for s in SERVICE_NODE_IDS:
        w[f"svc_{s}"] = 0
    return w


def classify_service(nid):
    for s, ids in SERVICE_NODE_IDS.items():
        if nid in ids:
            return s
    return None


def status_sev(v):
    sev = v & STATUS_SEVERITY_MASK
    if sev == STATUS_SEVERITY_BAD:
        return "bad"
    if sev == STATUS_SEVERITY_UNCERTAIN:
        return "unc"
    return "good"


def truthy(s):
    return s.strip().strip('"').lower() in ("1", "true")


def extract(pcap, out, window, plc_ip, role, label, timeline, meta, attacker_ip=None):
    tshark_cmd = find_tshark()
    avail = get_available_fields(tshark_cmd)
    cmd, fields = build_cmd(tshark_cmd, pcap, avail, plc_ip)
    idx = {n: i for i, n in enumerate(fields)}

    def get(parts, name):
        i = idx.get(name)
        if i is None or i >= len(parts):
            return ""
        return parts[i].strip().strip('"')

    wms = int(window * 1000)
    windows: Dict[int, dict] = {}
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, encoding="utf-8", errors="ignore")
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed: {proc.stderr[:400]}")

    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        t = safe_float(get(parts, "frame.time_epoch"), -1)
        if t < 0:
            continue
        tms = int(t * 1000)
        ws = (tms // wms) * wms
        w = windows.setdefault(ws, new_window())

        w["pkt"] += 1
        flen = safe_int(get(parts, "frame.len"))
        w["byte"] += flen
        w["flens"].append(flen)
        w["epochs"].append(t)

        src, dst = get(parts, "ip.src"), get(parts, "ip.dst")
        stream = get(parts, "tcp.stream")
        if attacker_ip and (src == attacker_ip or dst == attacker_ip):
            w["has_attacker"] = True
        if src:
            w["src_ips"].add(src)
        if dst:
            w["dst_ips"].add(dst)
        if stream:
            w["streams"].add(stream)

        # chiều gói (client<->server) dựa trên plc_ip
        if plc_ip:
            if dst == plc_ip:
                w["c2s_pkt"] += 1
                w["c2s_byte"] += flen
            elif src == plc_ip:
                w["s2c_pkt"] += 1
                w["s2c_byte"] += flen

        # cờ TCP
        if truthy(get(parts, "tcp.flags.syn")):
            w["syn"] += 1
            if stream:
                w["syn_streams"].add(stream)
        if truthy(get(parts, "tcp.flags.reset")):
            w["rst"] += 1
        if truthy(get(parts, "tcp.flags.fin")):
            w["fin"] += 1
        if get(parts, "tcp.analysis.retransmission"):
            w["retrans"] += 1
        if get(parts, "opcua.transport.error"):
            w["transport_err"] += 1

        tt = get(parts, "opcua.transport.type").upper()
        if tt == "HEL":
            w["hel"] += 1
        elif tt == "OPN":
            w["opn"] += 1
        elif tt == "MSG":
            w["msg"] += 1
        elif tt == "CLO":
            w["clo"] += 1
        elif tt == "ERR":
            w["err"] += 1

        # per-source: chỉ tính client (khác server) cho các max-by-client
        is_client = bool(src) and src != plc_ip
        if is_client:
            bs = w["by_src"][src]
            bs["pkt"] += 1
            bs["byte"] += flen

        nid_raw = get(parts, "opcua.servicenodeid.numeric")
        if nid_raw:
            for single in nid_raw.split(","):
                nid = safe_int(single, -1)
                if nid < 0:
                    continue
                svc = classify_service(nid)
                if svc:
                    w[f"svc_{svc}"] += 1
                    if is_client:
                        bs = w["by_src"][src]
                        bs["svcset"].add(svc)
                        if svc == "open_secure_channel":
                            bs["opn"] += 1
                        elif svc == "read":
                            bs["read"] += 1
                        elif svc == "create_session":
                            bs["create_session"] += 1
                        elif svc in ("browse", "browse_next"):
                            bs["browse"] += 1

        st_raw = get(parts, "opcua.StatusCode") or get(parts, "opcua.ServiceResult")
        if st_raw:
            for single in st_raw.split(","):
                v = safe_int(single, -1)
                if v < 0:
                    continue
                w["st_values"].add(v)
                sev = status_sev(v)
                w[{"bad": "st_bad", "unc": "st_unc", "good": "st_good"}[sev]] += 1

    episodes = load_episodes(timeline)
    write_out(windows, out, wms, role, label, plc_ip, episodes, meta, attacker_ip)


def load_episodes(path):
    if not path:
        return []
    out = []
    try:
        with open(path, encoding="utf-8-sig", newline="") as f:
            r = csv.DictReader(f)
            if not r.fieldnames:
                return []
            low = {c.lower().strip(): c for c in r.fieldnames}
            sc = low.get("start"); ec = low.get("end")
            lc = low.get("label") or low.get("scenario")
            ep = low.get("episode"); cy = low.get("cycle")
            if not (sc and ec and lc):
                return []
            for i, row in enumerate(r, 1):
                s = normalize_epoch_ms(row.get(sc)); e = normalize_epoch_ms(row.get(ec))
                lab = str(row.get(lc, "")).strip()
                if s < 0 or e < s or not lab:
                    continue
                if ep and row.get(ep):
                    epi = str(row.get(ep)).strip()
                elif cy and row.get(cy):
                    epi = f"{lab}#c{str(row.get(cy)).strip()}"
                else:
                    epi = f"{lab}#i{i}"
                out.append((s, e, lab, epi))
    except OSError:
        return []
    return out


def episode_for(ws, we, intervals):
    best, bo = None, 0
    for s, e, lab, ep in intervals:
        ov = max(0, min(we, e) - max(ws, s))
        if ov > bo:
            bo, best = ov, (lab, ep)
    return best


def pct(vals, q):
    if not vals:
        return 0.0
    xs = sorted(vals)
    k = (len(xs) - 1) * q
    lo = int(k)
    hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def iat_stats(epochs):
    if len(epochs) < 2:
        return 0.0, 0.0, 0.0
    xs = sorted(epochs)
    d = [xs[i + 1] - xs[i] for i in range(len(xs) - 1)]
    return mean(d), std(d), min(d)


def max_pkts_per_sec(epochs):
    if not epochs:
        return 0
    bins = defaultdict(int)
    for t in epochs:
        bins[int(t)] += 1
    return max(bins.values())


def write_out(windows, out, wms, role, label, plc_ip, episodes, meta, attacker_ip=None):
    svc_cols = [f"{s}_count" for s in SERVICE_NODE_IDS]
    cols = [
        "window_start_ms", "window_end_ms", "label", "capture_role", "plc_ip",
        "session_id", "host_id", "scenario_id", "episode_id",
        # volume
        "opcua_packet_count", "opcua_byte_count",
        "opcua_frame_len_mean", "opcua_frame_len_std",
        "opcua_frame_len_min", "opcua_frame_len_max",
        "opcua_frame_len_median", "opcua_frame_len_p90",
        # net structure
        "opcua_unique_src_ip_count", "opcua_unique_dst_ip_count",
        "opcua_unique_tcp_stream_count", "opcua_client_src_count",
        # direction
        "opcua_c2s_pkt_count", "opcua_s2c_pkt_count",
        "opcua_c2s_byte_count", "opcua_s2c_byte_count", "opcua_req_resp_pkt_ratio",
        # tcp dynamics
        "opcua_syn_count", "opcua_rst_count", "opcua_fin_count",
        "opcua_retransmission_count", "opcua_new_conn_stream_count",
        # timing
        "opcua_iat_mean", "opcua_iat_std", "opcua_iat_min", "opcua_max_pkts_per_sec",
        # transport
        "opcua_hel_count", "opcua_opn_count", "opcua_msg_count",
        "opcua_clo_count", "opcua_err_count", "opcua_transport_error_count",
        # status
        "opcua_status_good_count", "opcua_status_uncertain_count",
        "opcua_status_bad_count", "opcua_distinct_status_count",
        # services
        *[f"opcua_{c}" for c in svc_cols],
        # per-source
        "opcua_max_pkts_by_client", "opcua_max_bytes_by_client",
        "opcua_max_services_by_client", "opcua_busiest_client_pkt_frac",
        "opcua_max_opn_by_single_src", "opcua_max_read_by_single_src",
        "opcua_max_create_session_by_single_src", "opcua_max_browse_by_single_src",
    ]

    if not windows:
        print("[WARN] No OPC UA packets matched -- empty file.", file=sys.stderr)

    with open(out, "w", newline="", encoding="utf-8") as f:
        wr = csv.DictWriter(f, fieldnames=cols)
        wr.writeheader()
        bidx = 0
        for ws in sorted(windows):
            w = windows[ws]
            we = ws + wms
            m = episode_for(ws, we, episodes)
            # Activity-aware labeling: window trong episode chỉ mang nhãn attack
            # nếu THỰC SỰ có traffic của attacker; window chỉ có benign (dù rơi
            # trong khoảng episode) -> benign. Sửa mislabel "đuôi im lặng" khi
            # khoảng episode dài hơn hoạt động tấn công thực. Không truyền
            # --attacker-ip -> giữ hành vi cũ (mọi window overlap = attack).
            if m and (attacker_ip is None or w["has_attacker"]):
                lab, epi = m
            else:
                lab = label
                epi = f"benign#chunk{bidx // BENIGN_CHUNK_WINDOWS}"
                bidx += 1
            iatm, iats, iatmin = iat_stats(w["epochs"])
            bysrc = w["by_src"]
            row = {
                "window_start_ms": ws, "window_end_ms": we, "label": lab,
                "capture_role": role, "plc_ip": plc_ip or "",
                "session_id": meta["session_id"], "host_id": meta["host_id"],
                "scenario_id": meta["scenario_id"], "episode_id": epi,
                "opcua_packet_count": w["pkt"], "opcua_byte_count": w["byte"],
                "opcua_frame_len_mean": round(mean(w["flens"]), 3),
                "opcua_frame_len_std": round(std(w["flens"]), 3),
                "opcua_frame_len_min": min(w["flens"]) if w["flens"] else 0,
                "opcua_frame_len_max": max(w["flens"]) if w["flens"] else 0,
                "opcua_frame_len_median": round(pct(w["flens"], 0.5), 1),
                "opcua_frame_len_p90": round(pct(w["flens"], 0.9), 1),
                "opcua_unique_src_ip_count": len(w["src_ips"]),
                "opcua_unique_dst_ip_count": len(w["dst_ips"]),
                "opcua_unique_tcp_stream_count": len(w["streams"]),
                "opcua_client_src_count": len([s for s in w["src_ips"] if s != plc_ip]),
                "opcua_c2s_pkt_count": w["c2s_pkt"], "opcua_s2c_pkt_count": w["s2c_pkt"],
                "opcua_c2s_byte_count": w["c2s_byte"], "opcua_s2c_byte_count": w["s2c_byte"],
                "opcua_req_resp_pkt_ratio": round(w["c2s_pkt"] / w["s2c_pkt"], 3) if w["s2c_pkt"] else 0.0,
                "opcua_syn_count": w["syn"], "opcua_rst_count": w["rst"],
                "opcua_fin_count": w["fin"], "opcua_retransmission_count": w["retrans"],
                "opcua_new_conn_stream_count": len(w["syn_streams"]),
                "opcua_iat_mean": round(iatm, 5), "opcua_iat_std": round(iats, 5),
                "opcua_iat_min": round(iatmin, 5),
                "opcua_max_pkts_per_sec": max_pkts_per_sec(w["epochs"]),
                "opcua_hel_count": w["hel"], "opcua_opn_count": w["opn"],
                "opcua_msg_count": w["msg"], "opcua_clo_count": w["clo"],
                "opcua_err_count": w["err"], "opcua_transport_error_count": w["transport_err"],
                "opcua_status_good_count": w["st_good"],
                "opcua_status_uncertain_count": w["st_unc"],
                "opcua_status_bad_count": w["st_bad"],
                "opcua_distinct_status_count": len(w["st_values"]),
                "opcua_max_pkts_by_client": max((s["pkt"] for s in bysrc.values()), default=0),
                "opcua_max_bytes_by_client": max((s["byte"] for s in bysrc.values()), default=0),
                "opcua_max_services_by_client": max((len(s["svcset"]) for s in bysrc.values()), default=0),
                "opcua_busiest_client_pkt_frac": round(
                    max((s["pkt"] for s in bysrc.values()), default=0) / w["pkt"], 3) if w["pkt"] else 0.0,
                "opcua_max_opn_by_single_src": max((s["opn"] for s in bysrc.values()), default=0),
                "opcua_max_read_by_single_src": max((s["read"] for s in bysrc.values()), default=0),
                "opcua_max_create_session_by_single_src": max((s["create_session"] for s in bysrc.values()), default=0),
                "opcua_max_browse_by_single_src": max((s["browse"] for s in bysrc.values()), default=0),
            }
            for s in SERVICE_NODE_IDS:
                row[f"opcua_{s}_count"] = w[f"svc_{s}"]
            wr.writerow(row)
    n_feat = len([c for c in cols if c.startswith("opcua_")])
    print(f"[OK] Wrote {len(windows)} window(s), {n_feat} feature -> {out}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--pcap", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--window", type=float, default=5.0)
    p.add_argument("--plc-ip", default=None)
    p.add_argument("--attacker-ip", default=None,
                   help="IP máy tấn công; bật activity-aware labeling (window trong episode "
                        "chỉ là attack nếu có traffic attacker). Bỏ trống = nhãn theo khoảng episode như cũ.")
    p.add_argument("--role", default="unknown")
    p.add_argument("--label", default="benign")
    p.add_argument("--timeline", default=None)
    p.add_argument("--session-id", default="unknown_session")
    p.add_argument("--host-id", default="unknown_host")
    p.add_argument("--scenario-id", default="unlabeled")
    a = p.parse_args()
    try:
        extract(a.pcap, a.output, a.window, a.plc_ip, a.role, a.label, a.timeline,
                {"session_id": a.session_id, "host_id": a.host_id, "scenario_id": a.scenario_id},
                attacker_ip=a.attacker_ip)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
