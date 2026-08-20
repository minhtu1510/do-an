"""Reads train_ml.py output (ml_results/ by default) from disk.

This mirrors the project's no-fake-data rule used elsewhere (see
scenarios/store.py, history/service.py): every method returns None/empty when
the expected file is missing instead of inventing numbers. Run
`python train_ml.py --output-dir <dir>` at the repo root first, or point
ML_RESULTS_DIR at wherever the output was copied.
"""

from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Any

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_RESULTS_DIR = REPO_ROOT / "ml_results"


def _safe_float(value: Any) -> float | None:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


class MLResultsService:
    def __init__(self, results_dir: str | Path | None = None):
        raw = results_dir if results_dir is not None else os.getenv("ML_RESULTS_DIR")
        self.results_dir = Path(raw).expanduser().resolve() if raw else DEFAULT_RESULTS_DIR

    def configured(self) -> bool:
        return self.results_dir.is_dir()

    def experiments(self) -> list[str]:
        if not self.configured():
            return []
        return sorted(p.name for p in self.results_dir.iterdir() if p.is_dir())

    def summary(self) -> list[dict] | None:
        path = self.results_dir / "summary_mean_std.csv"
        if not path.is_file():
            return None

        # Line 3 names however many index columns this run produced. Newer
        # train_ml.py runs add levels (feature_profile, binary_threshold_mode)
        # beyond the original experiment/validation_type/task/model, so read
        # the count from the file itself instead of assuming exactly 4.
        with path.open() as f:
            f.readline()
            f.readline()
            label_row = f.readline().strip().split(",")
        index_names = [n for n in label_row if n]

        df = pd.read_csv(path, header=[0, 1], index_col=list(range(len(index_names))))
        df.index.names = index_names
        rows: list[dict] = []
        metric_names = sorted({metric for metric, _ in df.columns})

        for index, row in df.iterrows():
            index_values = dict(zip(index_names, index if isinstance(index, tuple) else (index,)))
            metrics = {}
            for metric in metric_names:
                if (metric, "mean") not in row or (metric, "std") not in row:
                    continue
                metrics[metric] = {
                    "mean": _safe_float(row[(metric, "mean")]),
                    "std": _safe_float(row[(metric, "std")]),
                }
            rows.append({
                "experiment": index_values.get("experiment"),
                "validation_type": index_values.get("validation_type"),
                "task": index_values.get("task"),
                "model": index_values.get("model"),
                "metrics": metrics,
            })

        return rows

    def list_runs(self, experiment: str) -> list[str]:
        exp_dir = self.results_dir / experiment
        if not exp_dir.is_dir():
            return []
        return sorted({
            p.name[: -len("_confusion.csv")]
            for p in exp_dir.glob("*_confusion.csv")
        })

    def confusion_matrix(self, experiment: str, run: str) -> dict | None:
        path = self._safe_run_path(experiment, f"{run}_confusion.csv")
        if path is None or not path.is_file():
            return None
        df = pd.read_csv(path, index_col=0)
        return {
            "labels": [str(c) for c in df.columns],
            "matrix": df.values.tolist(),
        }

    def feature_importance(self, experiment: str, run: str, top_n: int = 25) -> list[dict] | None:
        path = self._safe_run_path(experiment, f"{run}_feature_importance.csv")
        if path is None or not path.is_file():
            return None
        df = pd.read_csv(path, index_col=0)
        column = df.columns[0]
        series = df[column].head(top_n)
        return [
            {"feature": str(feature), "importance": _safe_float(value)}
            for feature, value in series.items()
        ]

    def _safe_run_path(self, experiment: str, filename: str) -> Path | None:
        exp_dir = (self.results_dir / experiment).resolve()
        if not exp_dir.is_dir() or exp_dir.parent != self.results_dir.resolve():
            return None
        path = (exp_dir / filename).resolve()
        if path.parent != exp_dir:
            return None
        return path


ml_results_service = MLResultsService()
