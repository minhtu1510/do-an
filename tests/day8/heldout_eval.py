#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/day8/heldout_eval.py

Danh gia HELD-OUT cross-capture: train tren 1 tap dac trung, test tren tap khac
(khac phien/khac ngay). Dung cho tap test moi thu bang collect_opcua.py.

Khac evaluate_opcua.py (vốn dùng GroupKFold TRONG 1 capture) — script nay do
kha nang KHAI QUAT HOA sang capture chua tung thay, la con so trung thuc nhat.

Tuy chon --timeline: neu dua timeline cua tap test, script se BAO CAO nhung
episode "khong thuc thi" (duration < --min-dur giay) de minh bach, va cho phep
--drop-nonexec de loai chung khoi tap test (chi lam khi co bang chung 0 goi
tan cong — xem opcua_bao_cao_chi_tiet.md).

Chay:
  python tests/day8/heldout_eval.py \
    --train data_opc/day8_out/opcua_harvest_features.csv \
    --test  data_opc/day8_out/opcua_testclean_features.csv \
    --timeline test_results/day8/timeline_test_clean.csv \
    --out-dir data_opc/day8_out/eval_heldout
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, f1_score

WMERGE = {"OPCUA_INVALID_WRITE": "OPCUA_MALICIOUS_WRITE",
          "OPCUA_WRITE_DENIED": "OPCUA_MALICIOUS_WRITE"}


def nonexec_cycles(timeline: str, min_dur: float):
    """Tra ve (set episode_id khong thuc thi, list dong bang chung)."""
    bad, ev = set(), []
    if not timeline or not Path(timeline).is_file():
        return bad, ev
    for x in csv.DictReader(open(timeline, encoding="utf-8-sig")):
        try:
            dur = float(x["end"]) - float(x["start"])
        except (KeyError, ValueError):
            continue
        st = str(x.get("status", ""))
        executed = st.startswith("executed") or st == "timeout"
        if dur < min_dur and not executed:
            cyc = x.get("cycle", "")
            bad.add(f"{x['label']}#c{cyc}")
            ev.append({"label": x["label"], "cycle": cyc,
                       "duration_s": round(dur, 3), "status": st})
    return bad, ev


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", required=True, help="Feature CSV dung de train (vd harvest C)")
    ap.add_argument("--test", required=True, help="Feature CSV tap test doc lap")
    ap.add_argument("--timeline", default=None, help="Timeline cua tap test (de bao cao episode khong thuc thi)")
    ap.add_argument("--min-dur", type=float, default=1.0, help="Nguong giay coi la 'khong thuc thi'")
    ap.add_argument("--drop-nonexec", action="store_true", help="Loai episode khong thuc thi khoi tap test")
    ap.add_argument("--out-dir", default=None)
    args = ap.parse_args()

    tr = pd.read_csv(args.train)
    te = pd.read_csv(args.test)
    feat = [c for c in tr.columns if c.startswith("opcua_")]
    for d in (tr, te):
        d["label"] = d["label"].replace(WMERGE)

    bad, ev = nonexec_cycles(args.timeline, args.min_dur)
    if ev:
        print(f"[!] {len(ev)} episode KHONG thuc thi (duration < {args.min_dur}s, status completed):")
        for e in ev:
            print(f"    {e['label']:30s} cycle={e['cycle']:>3} {e['duration_s']:.3f}s {e['status']}")
        n_att_epi = te[te.label != "benign"].episode_id.nunique()
        print(f"    -> tap test co {n_att_epi} attack-episode, {len(bad & set(te.episode_id))} trong so do khong thuc thi")
    if args.drop_nonexec and bad:
        keep = ~(te.episode_id.isin(bad) & (te.label != "benign"))
        te = te[keep].reset_index(drop=True)
        print(f"[*] Da loai {(~keep).sum()} window khong thuc thi khoi tap test")

    Xtr, Xte = tr[feat].fillna(0).values, te[feat].fillna(0).values
    ytr = (tr.label != "benign").astype(int).values
    yte = (te.label != "benign").astype(int).values

    print(f"\nTRAIN: {len(tr)} window | TEST: {len(te)} window "
          f"({(yte==1).sum()} attack / {(yte==0).sum()} benign)")

    # ---- BINARY ----
    clf = RandomForestClassifier(n_estimators=400, random_state=0, n_jobs=-1).fit(Xtr, ytr)
    proba = clf.predict_proba(Xte)[:, 1]
    pred = (proba >= 0.5).astype(int)
    print("\n=== HELD-OUT BINARY (benign vs attack) ===")
    print(classification_report(yte, pred, target_names=["benign", "attack"], digits=3))

    te = te.assign(_p=proba)
    att = te[te.label != "benign"]
    epi = att.assign(d=att._p >= 0.5).groupby("episode_id").d.max()
    fp = int(((yte == 0) & (pred == 1)).sum()); nb = int((yte == 0).sum())
    ep_det = f"{int(epi.sum())}/{len(epi)}"
    print(f"Phat hien muc episode : {ep_det} ({epi.mean()*100:.0f}%)")
    print(f"False-positive benign : {fp}/{nb} ({fp/nb*100:.2f}%)")

    # ---- MULTICLASS ----
    clfm = RandomForestClassifier(n_estimators=400, random_state=0, n_jobs=-1).fit(Xtr, tr.label.values)
    pm = clfm.predict(Xte)
    labels = sorted(te.label.unique())
    macro = f1_score(te.label.values, pm, average="macro", labels=labels)
    print(f"\n=== HELD-OUT MULTICLASS macro-F1 = {macro:.3f} ===")

    if args.out_dir:
        out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
        rep = classification_report(yte, pred, target_names=["benign", "attack"],
                                    digits=3, output_dict=True)
        json.dump({
            "train_windows": len(tr), "test_windows": len(te),
            "binary_attack_precision": rep["attack"]["precision"],
            "binary_attack_recall": rep["attack"]["recall"],
            "binary_attack_f1": rep["attack"]["f1-score"],
            "episode_detection": ep_det,
            "benign_fp_rate": fp / nb,
            "multiclass_macro_f1": macro,
            "nonexec_episodes": ev,
            "dropped_nonexec": bool(args.drop_nonexec and bad),
        }, open(out / "heldout_results.json", "w"), indent=2, ensure_ascii=False)
        print(f"\n[OK] -> {out}/heldout_results.json")


if __name__ == "__main__":
    main()
