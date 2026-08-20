#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/day8/plot_opcua_eval.py

Xuat bieu do PNG tu ket qua evaluate_opcua.py de chen thang vao bao cao
(bao-cao/opcua_bao_cao_chi_tiet.md / .docx):

  1. cm_opcua.png        -- confusion matrix (chuan hoa theo hang = recall),
                            sequential 1 hue, annotate so dem tuyet doi.
  2. f1_per_class.png    -- bar ngang F1 theo lop, sap xep giam dan, nhan truc tiep;
                            2 lop low-volume to mau cam de luu y.
  3. macrof1_configs.png -- so sanh macro-F1 cua 4 cau hinh (chung minh 2 xu ly).

Chay:
  python tests/day8/plot_opcua_eval.py \
    --confusion data_opc/day8_out/eval/confusion_matrix.csv \
    --results   data_opc/day8_out/eval/eval_results.json \
    --out-dir   data_opc/day8_out/eval
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.patches import Patch

# --- Design tokens (nen sang cho tai lieu) ---
BLUE = "#0072B2"      # Okabe-Ito, CVD-safe
ORANGE = "#E69F00"    # Okabe-Ito, CVD-safe
INK = "#1a1a1a"
MUTED = "#6b6b6b"
GRID = "#e4e4e4"
SURFACE = "#ffffff"
SEQ = LinearSegmentedColormap.from_list("blues1", ["#f2f7fb", BLUE, "#00456e"])

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 11,
    "axes.edgecolor": GRID,
    "axes.linewidth": 0.8,
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
    "text.color": INK,
    "axes.labelcolor": INK,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
})

SHORT = lambda s: s.replace("OPCUA_", "").replace("_", " ").title() if s != "benign" else "Benign"
LOW_VOLUME = {"OPCUA_SESSION_BURST", "OPCUA_SUBSCRIPTION_FLOOD"}


def plot_confusion(cm_csv: str, out: Path):
    df = pd.read_csv(cm_csv, index_col=0)
    labels = [SHORT(x) for x in df.index]
    M = df.values.astype(float)
    row_sum = M.sum(axis=1, keepdims=True)
    R = np.divide(M, row_sum, out=np.zeros_like(M), where=row_sum > 0)  # recall

    n = len(labels)
    fig, ax = plt.subplots(figsize=(9.2, 8.0))
    im = ax.imshow(R, cmap=SEQ, vmin=0, vmax=1, aspect="equal")

    ax.set_xticks(range(n)); ax.set_yticks(range(n))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=9)
    ax.set_yticklabels(labels, fontsize=9)
    ax.set_xlabel("Nhãn dự đoán", fontsize=11, labelpad=8)
    ax.set_ylabel("Nhãn thật", fontsize=11, labelpad=8)
    ax.set_title("Ma trận nhầm lẫn — OPC UA (GroupKFold theo episode)\n"
                 "màu = recall theo hàng, số = số window", fontsize=12, pad=12, color=INK)

    for i in range(n):
        for j in range(n):
            c = int(M[i, j])
            if c == 0:
                continue
            ax.text(j, i, str(c), ha="center", va="center", fontsize=8.5,
                    color="white" if R[i, j] > 0.55 else INK,
                    fontweight="bold" if i == j else "normal")

    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.set_xticks(np.arange(-.5, n, 1), minor=True)
    ax.set_yticks(np.arange(-.5, n, 1), minor=True)
    ax.grid(which="minor", color=SURFACE, linewidth=2)
    ax.tick_params(which="minor", length=0)

    cb = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.03)
    cb.set_label("Recall", fontsize=10)
    cb.outline.set_visible(False)
    fig.tight_layout()
    fig.savefig(out / "cm_opcua.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"[OK] {out/'cm_opcua.png'}")


def plot_f1(results_json: str, out: Path):
    d = json.loads(Path(results_json).read_text())
    per = d["multiclass_best_per_class"]
    items = [(k, v["f1"], v["support"]) for k, v in per.items()]
    items.sort(key=lambda t: t[1])  # tang dan -> ve tu duoi len
    names = [SHORT(k) for k, _, _ in items]
    f1 = [v for _, v, _ in items]
    colors = [ORANGE if k in LOW_VOLUME else BLUE for k, _, _ in items]

    fig, ax = plt.subplots(figsize=(8.6, 5.4))
    y = np.arange(len(names))
    bars = ax.barh(y, f1, color=colors, height=0.66, zorder=3)
    # bo tron dau thanh
    for b in bars:
        b.set_capstyle("round")

    ax.set_yticks(y); ax.set_yticklabels(names, fontsize=10)
    ax.set_xlim(0, 1.08)
    ax.set_xlabel("F1-score (đa lớp, cấu hình khuyến nghị)", fontsize=11)
    ax.set_title("F1 theo lớp — macro-F1 = %.3f" % d["multiclass_macro_f1"]
                 ["merge-write + no-weight (KHUYEN NGHI)"],
                 fontsize=12, pad=10, color=INK)
    ax.axvline(0.90, color=MUTED, lw=1, ls="--", zorder=1)
    ax.text(0.90, len(names) - 0.3, " ngưỡng 0.90", fontsize=8.5, color=MUTED, va="top")

    for yi, (v, (k, _, sup)) in enumerate(zip(f1, items)):
        ax.text(v + 0.012, yi, f"{v:.3f}", va="center", ha="left",
                fontsize=9, color=INK, fontweight="bold")
        ax.text(0.008, yi, f"n={int(sup)}", va="center", ha="left",
                fontsize=7.5, color="white")

    ax.grid(axis="x", color=GRID, lw=0.8, zorder=0)
    ax.set_axisbelow(True)
    for sp in ["top", "right", "left"]:
        ax.spines[sp].set_visible(False)
    ax.tick_params(length=0)
    leg = [Patch(color=BLUE, label="Đủ tin ở mức window"),
           Patch(color=ORANGE, label="Low-volume (chỉ tin ở mức episode)")]
    ax.legend(handles=leg, loc="upper center", bbox_to_anchor=(0.5, -0.12),
              ncol=2, frameon=False, fontsize=9)
    fig.tight_layout()
    fig.savefig(out / "f1_per_class.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"[OK] {out/'f1_per_class.png'}")


def plot_configs(results_json: str, out: Path):
    d = json.loads(Path(results_json).read_text())
    cfg = d["multiclass_macro_f1"]
    order = [
        ("raw + balanced (baseline ban dau)", "Baseline\n(raw + balanced)"),
        ("raw + no-weight", "Bỏ balanced"),
        ("merge-write + balanced", "Gộp Write"),
        ("merge-write + no-weight (KHUYEN NGHI)", "Gộp Write\n+ bỏ balanced"),
    ]
    vals = [cfg[k] for k, _ in order]
    labs = [l for _, l in order]
    colors = [MUTED, "#7fb3d5", "#4a90c2", BLUE]

    fig, ax = plt.subplots(figsize=(7.6, 4.6))
    x = np.arange(len(vals))
    bars = ax.bar(x, vals, color=colors, width=0.62, zorder=3)
    ax.set_xticks(x); ax.set_xticklabels(labs, fontsize=9.5)
    ax.set_ylim(0.75, 0.96)
    ax.set_ylabel("macro-F1 (đa lớp)", fontsize=11)
    ax.set_title("Tác động của 2 xử lý lên phân loại đa lớp", fontsize=12, pad=10, color=INK)
    for xi, v in zip(x, vals):
        ax.text(xi, v + 0.004, f"{v:.3f}", ha="center", va="bottom",
                fontsize=10, fontweight="bold", color=INK)
    ax.grid(axis="y", color=GRID, lw=0.8, zorder=0)
    ax.set_axisbelow(True)
    for sp in ["top", "right"]:
        ax.spines[sp].set_visible(False)
    ax.tick_params(length=0)
    fig.tight_layout()
    fig.savefig(out / "macrof1_configs.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"[OK] {out/'macrof1_configs.png'}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--confusion", required=True)
    ap.add_argument("--results", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    plot_confusion(args.confusion, out)
    plot_f1(args.results, out)
    plot_configs(args.results, out)


if __name__ == "__main__":
    main()
