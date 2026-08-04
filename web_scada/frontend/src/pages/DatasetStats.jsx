import { useEffect, useMemo, useState } from "react";
import {
  fetchMlStatus,
  fetchMlSummary,
  fetchMlRuns,
  fetchMlConfusionMatrix,
  fetchMlFeatureImportance,
} from "../services/api";
import PageHeader from "../components/PageHeader";
import Gauge from "../components/Gauge";

const BLUE = "#3987e5";
const AQUA = "#199e70";
const VIOLET = "#9085e9";
const GOOD_GREEN = "#0ca30c";
const WARN_AMBER = "#c98500";

// Single-hue sequential ramp for magnitude (confusion-matrix cell intensity):
// dark surface -> vivid sky blue, interpolated smoothly instead of a few
// discrete steps so the heatmap actually pops.
function heatColor(ratio) {
  const from = [26, 32, 44];
  const to = [56, 189, 248];
  const r = Math.round(from[0] + (to[0] - from[0]) * ratio);
  const g = Math.round(from[1] + (to[1] - from[1]) * ratio);
  const b = Math.round(from[2] + (to[2] - from[2]) * ratio);
  return `rgb(${r},${g},${b})`;
}

export default function DatasetStats() {
  const [status, setStatus] = useState(null);
  const [summary, setSummary] = useState(null);
  const [selectedExperiment, setSelectedExperiment] = useState("");
  const [runs, setRuns] = useState([]);
  const [selectedRun, setSelectedRun] = useState("");
  const [confusion, setConfusion] = useState(null);
  const [featureImportance, setFeatureImportance] = useState(null);

  useEffect(() => {
    fetchMlStatus().then((data) => {
      setStatus(data);
      if (data.experiments?.length) setSelectedExperiment(data.experiments[0]);
    });
    fetchMlSummary().then((data) => setSummary(data.rows || null));
  }, []);

  useEffect(() => {
    if (!selectedExperiment) return;
    fetchMlRuns(selectedExperiment).then((data) => {
      setRuns(data.runs || []);
      setSelectedRun(data.runs?.[0] || "");
    });
  }, [selectedExperiment]);

  useEffect(() => {
    if (!selectedExperiment || !selectedRun) {
      setConfusion(null);
      setFeatureImportance(null);
      return;
    }
    fetchMlConfusionMatrix(selectedExperiment, selectedRun).then((data) =>
      setConfusion(data.labels ? data : null)
    );
    fetchMlFeatureImportance(selectedExperiment, selectedRun).then((data) =>
      setFeatureImportance(data.features || null)
    );
  }, [selectedExperiment, selectedRun]);

  const configured = Boolean(status?.configured);

  const bestAccuracyPct = useMemo(() => {
    if (!summary || summary.length === 0) return null;
    const values = summary.map((row) => row.metrics?.balanced_accuracy?.mean).filter((v) => typeof v === "number");
    return values.length ? Math.max(...values) * 100 : null;
  }, [summary]);

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        title="Dataset & Model Stats"
        subtitle="Read directly from train_ml.py output on disk. No number here is synthesized — this page is empty until real results exist."
      />

      {!configured ? (
        <div className="bg-gray-800 rounded border border-gray-700 p-6">
          <div className="text-sm font-semibold text-gray-200">ML results directory</div>
          <div className="mt-2 text-2xl font-bold text-yellow-400">Not configured</div>
          <div className="mt-2 text-sm text-gray-500">
            No directory found at <code className="rounded bg-gray-900 px-1.5 py-0.5 text-gray-300">{status?.results_dir || "ml_results/"}</code>.
            Run <code className="rounded bg-gray-900 px-1.5 py-0.5 text-gray-300">python train_ml.py --output-dir ml_results</code> at
            the repo root (on a machine with the real dataset), then copy the output directory here — or set{" "}
            <code className="rounded bg-gray-900 px-1.5 py-0.5 text-gray-300">ML_RESULTS_DIR</code> to wherever it was copied — and reload this page.
          </div>
        </div>
      ) : (
        <>
          {/* Z-pattern hero row — best result at a glance before the detail tables */}
          <div className="grid gap-4 lg:grid-cols-[auto_1fr_1fr]">
            <div className="flex items-center justify-center rounded border border-gray-700 bg-gray-800 p-4">
              {bestAccuracyPct !== null ? (
                <Gauge value={bestAccuracyPct} color={bestAccuracyPct >= 80 ? GOOD_GREEN : bestAccuracyPct >= 60 ? WARN_AMBER : "#e66767"} label="Best balanced acc." />
              ) : (
                <div className="text-center text-xs text-gray-500">Chưa có metric</div>
              )}
            </div>
            <div className="overflow-hidden rounded border border-gray-700 bg-gray-800">
              <div className="h-1" style={{ backgroundColor: BLUE }} />
              <div className="p-4">
                <div className="text-xs uppercase text-gray-500">Số experiment</div>
                <div className="mt-1 text-2xl font-bold" style={{ color: BLUE }}>{status.experiments?.length ?? 0}</div>
              </div>
            </div>
            <div className="overflow-hidden rounded border border-gray-700 bg-gray-800">
              <div className="h-1" style={{ backgroundColor: AQUA }} />
              <div className="p-4">
                <div className="text-xs uppercase text-gray-500">Run trong experiment đang chọn</div>
                <div className="mt-1 text-2xl font-bold" style={{ color: AQUA }}>{runs.length}</div>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded border border-gray-700 overflow-hidden">
            <div className="border-b border-gray-700 px-4 py-3 text-sm font-semibold text-gray-200">
              Model performance summary (mean ± std across folds/seeds)
            </div>
            {!summary || summary.length === 0 ? (
              <div className="p-6 text-sm text-gray-500">
                Results dir found ({status.results_dir}) but <code className="rounded bg-gray-900 px-1.5 py-0.5 text-gray-300">summary_mean_std.csv</code> is missing.
                Re-run train_ml.py — it writes this file at the end of a full run.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-gray-900/60 text-xs uppercase text-gray-500">
                    <tr>
                      <th className="px-4 py-2">Experiment</th>
                      <th className="px-4 py-2">Validation</th>
                      <th className="px-4 py-2">Task</th>
                      <th className="px-4 py-2">Model</th>
                      <th className="px-4 py-2">Balanced acc.</th>
                      <th className="px-4 py-2">Macro F1</th>
                      <th className="px-4 py-2">MCC</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-700">
                    {summary.map((row, i) => (
                      <tr key={i}>
                        <td className="px-4 py-2 text-gray-200">{row.experiment}</td>
                        <td className="px-4 py-2 text-gray-400">{row.validation_type}</td>
                        <td className="px-4 py-2 text-gray-400">{row.task}</td>
                        <td className="px-4 py-2 text-gray-400">{row.model}</td>
                        <td className="px-4 py-2 font-mono text-blue-300">{formatMeanStd(row.metrics?.balanced_accuracy)}</td>
                        <td className="px-4 py-2 font-mono text-blue-300">{formatMeanStd(row.metrics?.macro_f1)}</td>
                        <td className="px-4 py-2 font-mono text-blue-300">{formatMeanStd(row.metrics?.mcc)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {status.experiments?.length > 0 && (
            <div className="grid gap-4 lg:grid-cols-2">
              <div className="bg-gray-800 rounded border border-gray-700 p-4 space-y-4">
                <div className="flex flex-wrap items-center gap-3">
                  <div className="text-sm font-semibold text-gray-200">Confusion matrix</div>
                  <RunPicker
                    experiments={status.experiments}
                    selectedExperiment={selectedExperiment}
                    onExperiment={setSelectedExperiment}
                    runs={runs}
                    selectedRun={selectedRun}
                    onRun={setSelectedRun}
                  />
                </div>
                {confusion ? <ConfusionMatrix data={confusion} /> : <EmptyNote text="No confusion-matrix CSV for this run." />}
              </div>

              <div className="bg-gray-800 rounded border border-gray-700 p-4 space-y-4">
                <div className="text-sm font-semibold text-gray-200">Feature importance (top features)</div>
                {featureImportance ? (
                  <FeatureImportanceBars features={featureImportance} />
                ) : (
                  <EmptyNote text="No feature-importance CSV for this run." />
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function RunPicker({ experiments, selectedExperiment, onExperiment, runs, selectedRun, onRun }) {
  return (
    <div className="flex flex-wrap gap-2 text-xs">
      <select
        className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-gray-300"
        value={selectedExperiment}
        onChange={(e) => onExperiment(e.target.value)}
      >
        {experiments.map((exp) => (
          <option key={exp} value={exp}>{exp}</option>
        ))}
      </select>
      <select
        className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-gray-300"
        value={selectedRun}
        onChange={(e) => onRun(e.target.value)}
        disabled={runs.length === 0}
      >
        {runs.length === 0 ? <option>No runs</option> : runs.map((run) => <option key={run} value={run}>{run}</option>)}
      </select>
    </div>
  );
}

function ConfusionMatrix({ data }) {
  const flat = data.matrix.flat();
  const max = Math.max(1, ...flat);

  return (
    <div className="overflow-x-auto">
      <table className="text-xs">
        <thead>
          <tr>
            <th className="px-2 py-1" />
            {data.labels.map((label) => (
              <th key={label} className="px-2 py-1 text-gray-500 font-normal">{label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.matrix.map((row, i) => (
            <tr key={i}>
              <th className="px-2 py-1 text-right text-gray-500 font-normal">{data.labels[i]}</th>
              {row.map((value, j) => {
                const ratio = value > 0 ? value / max : 0;
                return (
                  <td
                    key={j}
                    title={`true=${data.labels[i]} pred=${data.labels[j]}: ${value}`}
                    className="px-2 py-1 text-center font-mono font-semibold rounded"
                    style={{ backgroundColor: heatColor(ratio), color: ratio > 0.55 ? "#0b0b0b" : "#e5e7eb" }}
                  >
                    {value}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const IMPORTANCE_COLORS = [BLUE, AQUA, VIOLET, "#d95926", "#d55181", "#c98500"];

function FeatureImportanceBars({ features }) {
  const max = Math.max(1e-9, ...features.map((f) => f.importance ?? 0));
  return (
    <div className="space-y-2">
      {features.map((f, i) => {
        const color = IMPORTANCE_COLORS[i % IMPORTANCE_COLORS.length];
        return (
          <div key={f.feature} title={`${f.feature}: ${f.importance}`}>
            <div className="flex justify-between text-xs text-gray-400">
              <span className="truncate pr-2">{f.feature}</span>
              <span className="font-mono font-semibold" style={{ color }}>{f.importance?.toFixed(3)}</span>
            </div>
            <div className="mt-1 h-2 rounded-full bg-gray-900">
              <div
                className="h-2 rounded-full transition-all"
                style={{ width: `${Math.max(2, ((f.importance ?? 0) / max) * 100)}%`, backgroundColor: color }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function EmptyNote({ text }) {
  return <div className="text-sm text-gray-500">{text}</div>;
}

function formatMeanStd(metric) {
  if (!metric || metric.mean === null || metric.mean === undefined) return "—";
  const mean = metric.mean.toFixed(3);
  const std = metric.std !== null && metric.std !== undefined ? metric.std.toFixed(3) : null;
  return std ? `${mean} ± ${std}` : mean;
}
