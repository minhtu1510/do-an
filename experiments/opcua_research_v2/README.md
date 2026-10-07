# OPC UA research verification v2

This directory is reserved for reproducible outputs from the OPC UA research
checks. Existing datasets, legacy model directories, and thesis files are not
overwritten.

## Experiments

1. `label_audit/`: compares the original and activity-aware window labels and
   creates a traceable manifest of every changed window.
2. `warmup_ood/`: exports row-level predictions, separates warmup from
   steady-state benign traffic, and reports episode-level detection.
3. `feature_ablation/`: compares the full feature set, a profile without
   client/source identity proxies, a protocol-service-only profile, and a
   simple threshold baseline.

## Commands

Run these commands from the repository root using the same Python environment
that provides pandas, NumPy, scikit-learn, and joblib for the existing OPC UA
training scripts.

```bash
python tools/opcua_label_manifest.py
python tools/opcua_export_predictions.py
python tools/opcua_episode_eval.py
python tools/opcua_warmup_error_analysis.py
python tools/opcua_feature_ablation.py
```

The first command is a CSV-only audit. Prediction export loads the existing
model but does not modify it. Feature ablation trains new models exclusively
under `feature_ablation/models/`.

## Interpretation constraints

- `attacker_packet_count` cannot be reconstructed from the existing feature
  CSV because the extractor did not persist that value. The label manifest
  therefore marks attacker-traffic presence as inferred from the implemented
  activity-aware relabeling rule.
- OOD and test-clean results must be reported separately from grouped
  cross-validation results.
- Multiclass metrics must be accompanied by per-class support because several
  OOD attack classes have no true windows.
