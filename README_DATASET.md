# ICS-S7comm-IDS Dataset

**An ICS/IIoT Intrusion Detection Dataset with Deep S7comm Protocol Inspection and Process-Level Ground Truth**

> **Status:** legacy draft. Do not use this file as the authoritative current release specification. The current release uses 55,902 non-overlapping 2-second windows and is documented in `SemanticAware-S7comm-Dataset/README.md` plus `SemanticAware-S7comm-Dataset/docs/DATA_CARD.md`. The reproducible group/split audit is `run_group_split_audit.py`, with outputs in `ml_results/group_split_audit/`.

---

## Overview

This dataset was collected from a physical ICS testbed running a Siemens S7-1500/S7-1200 PLC with a Conveyor Belt (Băng Truyền) control program. It provides multi-modal security monitoring data combining **network traffic features** (full S7comm protocol stack, L2–L7) and **process-level features** (PLC tag polling logs), enabling research in industrial IDS/anomaly detection at a semantic depth not available in prior public ICS datasets.

**Key contributions over existing datasets (SWaT, BATADAL, CIC-ICS2024):**
- Full S7comm Deep Packet Inspection (L5 TPKT / L6 COTP / L7 S7comm semantics)
- Profinet DCP (L2) features for device discovery detection
- Three independent dataset views: Network-only, Process-only, Fusion
- Real-time millisecond-precision attack timeline labeling
- Signal-level attack event ground truth (`attack_events.csv`)
- OOD robustness test day (Day 6) with shuffled low-rate attack variants
- Explicit leakage-free ML split (GroupKFold by session, held-out OOD day)

---

## Dataset Statistics

| Attribute | Value |
|---|---|
| Collection period | 6 days |
| Attack scenarios | 9 scenarios + OOD variants |
| Window size | 5 seconds (sliding, non-overlapping) |
| Network feature columns | ~180 |
| Process feature columns | ~120 |
| Fusion feature columns | ~300 |
| Label granularity | Per 5-second window (binary + multiclass) |
| Protocols covered | S7comm, S7comm-plus, Profinet DCP, TCP, ARP, ICMP |
| PLC hardware | Siemens S7-1500 / S7-1200 (real hardware + PLCSIM) |

### Sample counts per day

| Day | Scenario | Network windows | Process windows |
|---|---|---|---|
| Day 1 | BENIGN (baseline) | ~7,300 | ~1,800 |
| Day 2 | SCAN_PORT, ENUM_TAGS | ~9,600 | ~2,400 |
| Day 3 | RWRITE_BURST, SETPOINT_ATTACK | ~9,500 | ~2,400 |
| Day 4 | SENSOR_SPOOF, STEALTHY_WRITE | ~9,400 | ~2,400 |
| Day 5 | S7_FLOOD, SYN_FLOOD, PROTOCOL_FUZZ | ~9,200 | ~2,300 |
| Day 6 | OOD variants of all 9 scenarios | ~6,500 | ~1,600 |

---

## Attack Scenarios

All scenarios are mapped to MITRE ATT&CK for ICS framework.

### Group A — Reconnaissance

| ID | Name | MITRE TTP | Description |
|---|---|---|---|
| A1 | SCAN_PORT | T0846 Remote System Discovery | Continuous TCP port 102 probing to confirm PLC S7comm availability |
| A2 | ENUM_TAGS | T0861 Point & Tag Identification | Full Merker area scan (M[0..80]) to map PLC memory layout |

### Group B — Integrity Attacks

| ID | Name | MITRE TTP | Description |
|---|---|---|---|
| B1 | RWRITE_BURST | T0836 Modify Parameter | High-rate toggle of START/STOP bits (M5.0/M5.1), 2–3 writes/second |
| B2 | SETPOINT_ATTACK | T0836 Modify Parameter | Modification of timer parameters (CD1/CD2/CD3, MD50) to abnormal values |
| B3 | SENSOR_SPOOF | T0836 Spoof Reporting Message | Falsification of object detection flags (Vat_1/Vat_2/Vat_3 in Merker) |
| B4 | STEALTHY_WRITE | T0836 Low-rate evasion | Single STOP bit write every 20–60 seconds, evades threshold-based IDS |

### Group C — Availability / Protocol Attacks

| ID | Name | MITRE TTP | Description |
|---|---|---|---|
| C1 | S7_FLOOD | T0814 Denial of Service | 6 threads exhausting PLC S7comm session slots via rapid connect/disconnect |
| C2 | SYN_FLOOD | T0814 Denial of Service | 20 threads flooding TCP SYN to port 102 without completing handshake |
| C3 | PROTOCOL_FUZZ | T0819 Exploitation of Remote Services | Valid TPKT headers with random payload bytes to stress PLC protocol parser |

### Day 6 — OOD Robustness Test

Day 6 replays all 9 scenarios with intentional distribution shifts:
- Shuffled scenario order
- 5–20× slower packet intervals (stealthy profiles)
- Reduced attacker thread count (S7_FLOOD: 6→2, SYN_FLOOD: 20→3)
- Randomized inter-episode gaps (2–15 minutes)

**Purpose:** Verify that ML models learn semantic features (S7 command type, memory area) rather than timing/intensity patterns.

---

## Dataset Structure

```
dataset/
├── README_DATASET.md              ← This file
│
├── raw/                           ← Raw packet captures
│   ├── day1/
│   │   └── merged_all.pcapng     ← Full merged capture (Wireshark-compatible)
│   ├── day2/
│   │   └── merged_all.pcapng
│   ├── day3/
│   │   └── merged_all.pcapng
│   ├── day4/
│   │   └── merged_all.pcapng
│   ├── day5/
│   │   └── merged_all.pcapng
│   └── day6/
│       └── merged_all.pcapng
│
├── features/                      ← Extracted feature CSV files (5-second windows)
│   ├── day1/
│   │   ├── network.csv            ← Network features (L2–L7, ~180 columns)
│   │   ├── network_robust.csv     ← Same, leakage-control columns removed
│   │   ├── process.csv            ← PLC tag log features (~120 columns)
│   │   ├── process_robust.csv     ← Same, leakage-control columns removed
│   │   ├── fusion.csv             ← Network + Process joined by window_start_ms
│   │   ├── fusion_robust.csv      ← Same, leakage-control columns removed
│   │   └── extract.csv            ← Raw S7comm DPI output (per-window DPI dump)
│   ├── day2/
│   │   ├── network.csv
│   │   ├── network_robust.csv
│   │   ├── network_bounded.csv    ← Network features with bounded/clipped outliers
│   │   ├── process.csv
│   │   ├── process_robust.csv
│   │   ├── fusion.csv
│   │   ├── fusion_robust.csv
│   │   └── extract.csv
│   ├── day3/  (same structure as day2, also includes network_refined.csv)
│   ├── day4/  (same structure as day3)
│   ├── day5/  (same structure as day2)
│   └── day6/  (same structure as day3)
│
├── labels/                        ← Attack timeline ground truth
│   ├── day2_attacker_timeline.csv ← START/END timestamps per attack episode
│   ├── day3_attacker_timeline.csv
│   ├── day3_attacker_timeline_refined.csv
│   ├── day4_attacker_timeline.csv
│   ├── day4_attacker_timeline_refined.csv
│   ├── day5_attacker_timeline.csv
│   ├── day6_attacker_timeline.csv
│   └── day6_attacker_timeline_refined.csv
│
└── ml_results/                    ← Pre-computed ML evaluation results
    └── robust_hybrid/
        ├── summary_mean_std.csv   ← Cross-validation summary (mean ± std)
        ├── all_fold_metrics.csv   ← Per-fold detailed metrics
        ├── leakage_control_report.json
        ├── leakage_control_report.md
        ├── network_only/          ← Network-only view results
        ├── process_only/          ← Process-only view results
        ├── fusion/                ← Fusion view results
        ├── network_only_host_holdout/
        ├── process_only_host_holdout/
        └── fusion_host_holdout/
```

---

## File Format Reference

### network.csv / network_robust.csv

One row per 5-second time window. Key column groups:

| Column group | Example columns | Description |
|---|---|---|
| Window metadata | `window_start_ms`, `window_end_ms` | Unix epoch in milliseconds |
| L3/L4 basics | `packet_count`, `byte_count`, `packet_rate`, `tcp_count`, `udp_count` | Standard flow features |
| TCP semantics | `tcp_syn_count`, `tcp_rst_count`, `tcp_ack_count`, `tcp_syn_ack_ratio`, `tcp_active_streams` | TCP connection behavior |
| ARP | `arp_request_count`, `arp_unique_target_ip_count`, `arp_scan_score` | ARP-based recon detection |
| Profinet DCP (L2) | `dcp_identify_request_count`, `dcp_discovered_ip_count`, `dcp_scan_detected_rule` | L2 device enumeration |
| TPKT/COTP (L5/L6) | `tpkt_count`, `cotp_cr_count`, `cotp_cc_count`, `cotp_dt_count`, `cotp_dr_count` | S7 session setup behavior |
| S7comm semantics (L7) | `s7_read_count`, `s7_write_count`, `s7_setup_count`, `s7_error_count` | S7 command type distribution |
| S7 memory areas | `s7_merker_area_count`, `s7_output_write_count`, `s7_input_write_count`, `s7_unique_db_count` | Which PLC memory areas are accessed |
| S7 derived | `s7_write_read_ratio`, `s7_sequential_offset_score`, `s7_negotiation_only_ratio` | Semantic attack indicators |
| Payload analysis | `payload_entropy_mean`, `payload_hash_unique_ratio`, `malformed_packet_count` | Fuzzing/replay indicators |
| Labels | `label`, `binary_label`, `scenario_id`, `episode_id` | Ground truth columns |

**Decode level column:** `decode_level` ∈ {`network_only`, `cotp_tpkt`, `s7_partial`, `s7_full`}. Only windows with `decode_level = s7_full` have complete semantic features.

### process.csv / process_robust.csv

One row per 5-second window from PLC tag polling (0.5s poll interval → ~10 samples/window). Each PLC tag is aggregated as `proc__<TagName>__<stat>` where `<stat>` ∈ {`mean`, `std`, `min`, `max`}.

Key PLC tags monitored:

| Tag | PLC Address | Description |
|---|---|---|
| `Start_1` | I0.0 | Physical start button |
| `Stop_1` | I0.1 | Physical emergency stop |
| `Cam_bien` | I0.2 | Optical sensor (object detection) |
| `BangTai` | Q0.0 | Conveyor belt motor: RUN(1)/STOP(0) |
| `START` | M5.0 | HMI/SCADA remote start command |
| `STOP` | M5.1 | HMI/SCADA remote stop command |
| `Vat_1/2/3` | M5.4, M5.6, M6.0 | Object presence flags (targets of SENSOR_SPOOF) |
| `CD1/CD2/CD3` | MD54, MD58, MD62 | Countdown timers in ms (targets of SETPOINT_ATTACK) |
| `Times_1` | MD50 | Total cycle counter |

### labels/\*_timeline.csv

```
attacker_timestamp_ms | scenario_label | action | session_id | host_id | episode_id | day | note
```

- `action` ∈ {`START`, `END`} — exact millisecond when attack episode began/ended
- `episode_id` — unique identifier linking timeline events to feature CSV rows

### ml_results/robust_hybrid/summary_mean_std.csv

Cross-validation results summary with columns:
`balanced_accuracy`, `macro_f1`, `macro_precision`, `macro_recall`, `mcc`, `false_positive_rate_macro`, `pr_auc_macro`

Each metric has `_mean` and `_std` columns across folds.

---

## Experimental Setup

### Testbed Topology

```
┌──────────────────────────────────────────────┐
│         Industrial Network 192.168.1.0/24     │
│          (Layer-2 switch, SPAN port)          │
│                                               │
│  ┌─────────────┐    ┌──────────────────┐     │
│  │ Engineering │    │ Controller Host  │     │
│  │ Station     │    │ (HMI/SCADA)      │     │
│  │ (TIA Portal)│    │ Snap7 S7comm     │     │
│  └──────┬──────┘    └────────┬─────────┘     │
│         └──────────┬─────────┘               │
│                    │                          │
│             ┌──────┴──────┐                  │
│             │  PLC TARGET  │                 │
│             │ S7-1500/1200 │  ← Real device  │
│             │ 192.168.1.10 │    or PLCSIM    │
│             └─────────────┘                  │
│                                               │
│  ┌──────────────┐                            │
│  │ Attacker Host│  192.168.1.100             │
│  │ tshark+snap7 │                            │
│  └──────────────┘                            │
└──────────────────────────────────────────────┘
```

### Collection Protocol

- **Controller host** runs HMI polling (Snap7, random 1–2s interval) + tag logger (0.5s) **simultaneously**
- **TShark** captures independently on both hosts (no shared capture → no ground-truth leakage through timing)
- **Attack scripts** log START/END timestamps to CSV at the exact millisecond of execution
- **Day 1** = pure benign baseline (attacker host idle)
- **Days 2–5** = one attack group per day with benign gaps between episodes
- **Day 6** = OOD robustness test (all 9 scenarios, shuffled order, slower rates)

### Benign Traffic Diversity

Four benign operating modes create realistic traffic variety:

| Profile | Duration | Mechanism | Distinguishing pattern |
|---|---|---|---|
| `normal_hmi` | 90 min | Snap7 poll 1–2s + tag logger 0.5s | Two parallel S7comm TCP streams |
| `sparse_hmi` | 60 min | Snap7 poll 5–20s + tag logger 2s | High IAT, frequent silent windows |
| `tia_portal_only` | 60 min | TIA Portal online (engineer monitoring) | S7comm UserData (ROSCTR=0x07) |
| `idle_quiet` | 30 min | No polling, no logger | TCP keepalive + periodic ARP only |

---

## ML Usage Guide

### Recommended splits

| Use case | Training data | Test data |
|---|---|---|
| Standard IDS benchmark | Days 1–5 (5-fold GroupKFold by session) | Internal CV folds |
| OOD generalization | Days 1–5 | Day 6 (held-out, never seen during training) |
| Host holdout | Days 1–5 excluding one host | Held-out host |

### Leakage-safe features

Use the `*_robust.csv` files which have the following columns **already removed**:

- IP/MAC identity columns (`src_ip`, `dst_ip`, `src_mac`, `top_src_ip`)
- Timestamp columns (`window_start_ms`, `window_end_ms`)
- Session metadata (`session_id`, `episode_id`, `host_id`)
- Hand-crafted rule flags (`scan_detected_rule`, `dcp_scan_detected_rule`)
- Derived score columns (`port_scan_score`, `arp_scan_score`, `plc_scan_score`)

### Label columns

| Column | Type | Values |
|---|---|---|
| `label` | Multiclass | `BENIGN`, `SCAN_PORT`, `ENUM_TAGS`, `RWRITE_BURST`, `SETPOINT_ATTACK`, `SENSOR_SPOOF`, `STEALTHY_WRITE`, `S7_FLOOD`, `SYN_FLOOD`, `PROTOCOL_FUZZ` |
| `binary_label` | Binary | `0` = BENIGN, `1` = ATTACK |

### Quick start (Python)

```python
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedGroupKFold

# Load robust features (leakage columns already removed)
days_train = []
for day in ['day1', 'day2', 'day3', 'day4', 'day5']:
    df = pd.read_csv(f'features/{day}/network_robust.csv')
    days_train.append(df)

df_train = pd.concat(days_train, ignore_index=True)

# Separate features and labels
feature_cols = [c for c in df_train.columns
                if c not in ['label', 'binary_label', 'session_id']]
X = df_train[feature_cols].select_dtypes(include='number').fillna(0)
y = df_train['binary_label']
groups = df_train['session_id']

# GroupKFold to prevent session leakage
cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
for fold, (train_idx, val_idx) in enumerate(cv.split(X, y, groups)):
    clf = RandomForestClassifier(n_estimators=200, random_state=42)
    clf.fit(X.iloc[train_idx], y.iloc[train_idx])
    score = clf.score(X.iloc[val_idx], y.iloc[val_idx])
    print(f"Fold {fold}: accuracy={score:.4f}")

# OOD test on Day 6
df_ood = pd.read_csv('features/day6/network_robust.csv')
X_ood = df_ood[feature_cols].select_dtypes(include='number').fillna(0)
y_ood = df_ood['binary_label']
print(f"OOD Day6 accuracy: {clf.score(X_ood, y_ood):.4f}")
```

---

## Key Semantic Features

Features unique to this dataset (not available in any prior public ICS dataset):

| Feature | Attack discriminated | Formula / Extraction |
|---|---|---|
| `s7_write_read_ratio` | RWRITE_BURST (ratio >> 1), BENIGN (ratio < 0.1) | `s7_write_count / max(s7_read_count, 1)` |
| `s7_sequential_offset_score` | ENUM_TAGS (≈1.0), BENIGN (≈0) | Fraction of offset diffs ∈ {1,2,4,8} per window |
| `s7_merker_area_count` | All integrity attacks | Count of S7 ops targeting Merker (M) area |
| `s7_output_write_count` | Direct actuator manipulation | Count of S7 Write ops to Output (Q) area |
| `s7_negotiation_only_ratio` | S7_FLOOD, SYN_FLOOD | Ratio of sessions with COTP but no S7 commands |
| `payload_entropy_mean` | PROTOCOL_FUZZ (≈7.5–8.0 bits/byte) | Shannon entropy of TCP payload bytes |
| `payload_hash_unique_ratio` | FUZZ (≈1.0), REPLAY (≈0) | Unique payload hashes / total payloads |
| `cotp_cr_count` | S7_FLOOD (very high) | Count of COTP Connection Requests per window |
| `dcp_identify_request_count` | SCAN scenarios | Count of Profinet DCP Identify Requests |
| `tcp_102_probe_count` | SCAN_PORT, SYN_FLOOD | TCP probes specifically to port 102 |

---

## Citation

If you use this dataset, please cite:

```bibtex
@dataset{ics_s7comm_ids_dataset_2024,
  title     = {ICS-S7comm-IDS: An ICS Intrusion Detection Dataset with Deep
               S7comm Protocol Inspection and Process-Level Ground Truth},
  author    = {[Author names]},
  year      = {2024},
  publisher = {Zenodo},
  doi       = {10.5281/zenodo.XXXXXXX},
  url       = {https://doi.org/10.5281/zenodo.XXXXXXX}
}
```

---

## License

This dataset is released under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.

You are free to share and adapt this material for any purpose, provided appropriate credit is given and the source is cited.

---

## Ethical Statement

All data was collected on a **private testbed** with no connection to production industrial systems. No real-world critical infrastructure was involved or affected. The testbed PLC and network equipment were owned and operated exclusively by the research team. Attack scenarios were executed in an isolated lab environment.

---

## Contact

For questions about the dataset, please open an issue on the accompanying GitHub repository or contact the corresponding author via the paper's author information.
