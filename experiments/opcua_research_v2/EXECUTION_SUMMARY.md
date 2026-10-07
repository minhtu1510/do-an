# OPC UA research v2 - execution summary

Run date: 2026-09-24

All outputs in this directory were generated from existing CSV/model artifacts.
No PCAP capture, attack script, or PLC connection was used. Existing datasets,
models, evaluation directories, and the thesis document were not modified.

## 1. Activity-aware label audit

- Windows compared: 3,427.
- Changed windows: 29.
- `OPCUA_SESSION_BURST -> benign`: 24.
- `OPCUA_SUBSCRIPTION_FLOOD -> benign`: 4.
- `OPCUA_PROTOCOL_FUZZ -> benign`: 1.
- Attack windows decreased from 747 to 718; benign windows increased from
  2,680 to 2,709.

The feature CSV does not persist an attacker packet count. The manifest can
therefore prove which labels changed and preserve protocol counters, but the
absence of attacker traffic is inferred from the extractor's activity-aware
rule rather than independently recomputed from PCAP.

## 2. OOD warmup and episode analysis

The persisted ExtraTrees model was applied to 605 OOD2 windows.

| Measure | Result |
| --- | ---: |
| Benign / attack windows | 480 / 125 |
| TP / FP / TN / FN | 124 / 23 / 457 / 1 |
| Binary precision / recall / F1 | 0.8435 / 0.9920 / 0.9118 |
| Binary FPR | 0.0479 |
| Multiclass macro-F1 | 0.517804 |
| Steady benign FP | 0 / 444 |
| Warmup benign FP | 23 / 36 |
| Attack episodes detected | 17 / 17 (1.0000) |
| Episode TP / FP / TN / FN | 17 / 23 / 46 / 0 |
| Episode precision / recall | 0.425 / 1.000 |

All false-positive windows occurred during warmup. At the episode threshold,
they span 23 of 69 benign episode/chunk identifiers; all 23 belong to the 32
warmup/cooldown identifiers, while the 37 steady-state identifiers have no
false alert. Episode detection uses the sum of non-benign class
probabilities (`pred_attack_score >= 0.5`), not the maximum single-class
confidence. This distinction recovers
`day8_train_attacker_host_c028_OPCUA_SESSION_BURST_slow`: two windows are
misclassified as `OPCUA_PROTOCOL_FUZZ` but have attack scores 0.795 and 0.761;
the third is the single binary false negative. Thus binary episode detection is
complete even though attack-type classification remains imperfect.

## 3. Feature ablation

ExtraTrees uses the same core recipe as the repository model:
400 trees, maximum depth 10, random seed 0, and no class weighting. Labels
`OPCUA_INVALID_WRITE` and `OPCUA_WRITE_DENIED` are merged into
`OPCUA_MALICIOUS_WRITE`, matching the original evaluator.

| Profile | Features | Group-CV macro-F1 | OOD macro-F1 | OOD binary F1 | OOD FPR | Testclean macro-F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| All recorded features | 61 | 0.961831 | 0.517804 | 0.911765 | 0.047917 | 0.949340 |
| No client/source identity proxies | 50 | 0.953913 | 0.408665 | 0.627027 | 0.268750 | 0.940504 |
| OPC UA service/status only | 24 | 0.891816 | 0.429433 | 0.550000 | 0.041667 | 0.924602 |
| Simple protocol threshold | 11 | n/a | n/a | 0.670423 | 0.231250 | n/a |

Interpretation:

- Removing the source-structure aggregation features (the artifact profile is
  named `no_client_identity_proxy`) barely changes grouped CV or
  testclean macro-F1, but increases OOD false positives from 23 to 129 and
  reduces attack recall from 0.992 to 0.928. The model is strongly dependent
  on these features for OOD calibration. This is evidence of testbed/context
  dependence. The removed values are counts, maxima, and fractions rather than
  raw addresses, so this is not by itself proof of direct metadata leakage.
- Service-only features lower OOD FPR slightly (0.0479 to 0.0417) but miss 70
  of 125 attack windows. Protocol service counters alone are insufficient for
  the current scenario mix.
- The simple threshold baseline retains high recall (0.952) but produces 111
  OOD false positives. The learned model's advantage is therefore not explained
  by a trivial one-feature threshold rule.
- The full model reproduces the stored OOD and testclean metrics, providing an
  internal consistency check for the label normalization and feature order.

OOD2 was directly used to compare candidate algorithms before ExtraTrees was
persisted. Its results therefore describe cross-session behavior during model
development and error analysis, not an untouched final test estimate.

## Reproducibility caveat

The persisted model was created with scikit-learn 1.8.0 and was loaded with
scikit-learn 1.9.1 from a temporary dependency directory. Loading emitted the
official version-mismatch warning. Its predictions nevertheless reproduced the
stored OOD confusion counts and macro-F1 exactly. Newly trained ablation models
use scikit-learn 1.9.1, pandas 3.0.6, NumPy 2.5.3, and joblib 1.6.0. The new
group-CV score (0.961831) should not be presented as bitwise reproduction of the
metadata score (0.959851); the small difference is consistent with the runtime
version change and should be resolved by rerunning under scikit-learn 1.8.0 if
exact reproducibility is required.
