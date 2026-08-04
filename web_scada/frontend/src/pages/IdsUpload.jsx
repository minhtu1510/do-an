import { useEffect, useMemo, useState } from "react";
import {
  Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis,
} from "recharts";
import PageHeader from "../components/PageHeader";
import Gauge from "../components/Gauge";
import Sparkline from "../components/Sparkline";
import { analyzeIdsPcap, fetchIdsStatus } from "../services/api";

// Same validated categorical order used in Trends.jsx — fixed, never cycled.
const CATEGORICAL = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"];
const BENIGN_COLOR = "#52697a";
const GRID = "#2c2c2a";
const AXIS = "#383835";
const MUTED = "#898781";

function colorFor(label, colorMap) {
  if (label === "BENIGN") return BENIGN_COLOR;
  if (!colorMap.has(label)) colorMap.set(label, CATEGORICAL[colorMap.size % CATEGORICAL.length]);
  return colorMap.get(label);
}

// Buckets result.timeline into N time slices so the stat-tile sparklines show
// a real trend (flow volume, attack ratio) instead of a single flat number —
// derived from the same data already in the response, nothing synthetic.
function bucketTimeline(timeline, bucketCount = 16) {
  if (!timeline || timeline.length === 0) return [];
  const times = timeline.map((p) => p.timestamp_ms);
  const min = Math.min(...times);
  const span = Math.max(Math.max(...times) - min, 1);
  const buckets = Array.from({ length: bucketCount }, () => ({ count: 0, attack: 0 }));
  timeline.forEach((p) => {
    const idx = Math.min(bucketCount - 1, Math.floor(((p.timestamp_ms - min) / span) * bucketCount));
    buckets[idx].count += 1;
    if (p.prediction !== "BENIGN") buckets[idx].attack += 1;
  });
  return buckets.map((b) => ({ value: b.count, attackRatio: b.count > 0 ? (b.attack / b.count) * 100 : 0 }));
}

export default function IdsUpload() {
  const [status, setStatus] = useState(null);
  const [file, setFile] = useState(null);
  const [plcIp, setPlcIp] = useState("192.168.210.211");
  const [windowS, setWindowS] = useState(5.0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  useEffect(() => {
    fetchIdsStatus().then(setStatus).catch(() => setStatus({ configured: false, model_dir: "" }));
  }, []);

  const colorMap = useMemo(() => new Map(), [result]);
  const buckets = useMemo(() => bucketTimeline(result?.timeline), [result]);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const data = await analyzeIdsPcap(file, plcIp, windowS);
      setResult(data);
    } catch (err) {
      setError(err.message);
      setResult(null);
    } finally {
      setBusy(false);
    }
  }

  const predictionRows = result
    ? Object.entries(result.prediction_counts).sort((a, b) => (a[0] === "BENIGN" ? -1 : b[0] === "BENIGN" ? 1 : b[1] - a[1]))
    : [];

  const layerLabel = { 1: "Layer 1 — Rule-based", 2: "Layer 2 — Anomaly", 3: "Layer 3 — ML Classifier" };
  const layerRows = result ? Object.entries(result.layer_counts).map(([k, v]) => ({ layer: layerLabel[k] || `Layer ${k}`, count: v })) : [];

  const timelineAlerts = result ? result.timeline.filter((p) => p.prediction !== "BENIGN") : [];
  const feedRows = result
    ? [...result.flow_table].sort((a, b) => (a.window_start_ms ?? 0) - (b.window_start_ms ?? 0))
    : [];

  const attackPct = result ? result.attack_ratio * 100 : 0;
  const attackColor = attackPct > 0 ? "#e66767" : "#0ca30c";

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        title="IDS — Upload Pcap"
        subtitle="Trích xuất đặc trưng (extract_s7_features.py) rồi chấm điểm qua IDS 3 lớp (train_eval.py) — chỉ hiện kết quả thật từ model đã train."
      />

      {status && !status.configured && (
        <div className="rounded border border-yellow-900/50 bg-yellow-950/20 px-4 py-3 text-xs text-yellow-500">
          Chưa có model đã train tại <code className="rounded bg-gray-900 px-1">{status.model_dir}</code>. Chạy{" "}
          <code className="rounded bg-gray-900 px-1">python train_eval.py --dataset &lt;day1_6_labeled.csv&gt; --mode train --output {status.model_dir}</code>{" "}
          trên dữ liệu Day 1-6 thật trước.
        </div>
      )}

      <form onSubmit={handleSubmit} className="flex flex-wrap items-end gap-3 rounded border border-gray-700 bg-gray-800 p-4">
        <label className="flex flex-col gap-1">
          <span className="text-xs uppercase text-gray-500">File pcap/pcapng</span>
          <input
            type="file"
            accept=".pcap,.pcapng"
            onChange={(e) => setFile(e.target.files?.[0] || null)}
            className="text-xs text-gray-300 file:mr-2 file:rounded file:border-0 file:bg-gray-900 file:px-3 file:py-1.5 file:text-xs file:text-gray-300"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-xs uppercase text-gray-500">PLC IP</span>
          <input value={plcIp} onChange={(e) => setPlcIp(e.target.value)} className="rounded border border-gray-700 bg-gray-950 px-3 py-1.5 text-sm text-gray-200" />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-xs uppercase text-gray-500">Window (s)</span>
          <input type="number" step="0.5" value={windowS} onChange={(e) => setWindowS(e.target.value)} className="w-24 rounded border border-gray-700 bg-gray-950 px-3 py-1.5 text-sm text-gray-200" />
        </label>
        <button
          type="submit"
          disabled={busy || !file}
          className="rounded bg-blue-600 px-4 py-1.5 text-sm font-semibold text-white hover:bg-blue-500 disabled:opacity-50"
        >
          {busy ? "Đang phân tích..." : "Phân tích"}
        </button>
      </form>

      {error && (
        <div className="rounded border border-red-900/50 bg-red-950/30 px-4 py-3 text-sm text-red-400">{error}</div>
      )}

      {result && (
        <>
          {/* Z-pattern: most important numbers top-left, gauge (the "headline" ratio) top-right */}
          <div className="grid gap-4 lg:grid-cols-[1fr_1fr_auto]">
            <StatTile label="Tổng số flow" value={result.total_flows} accent={CATEGORICAL[0]}>
              <Sparkline data={buckets} dataKey="value" color={CATEGORICAL[0]} />
            </StatTile>
            <StatTile
              label="Flow bị gắn nhãn tấn công"
              value={result.attack_flows}
              color={result.attack_flows > 0 ? "text-red-400" : "text-green-400"}
              accent={attackColor}
            >
              <Sparkline data={buckets} dataKey="attackRatio" color={attackColor} />
            </StatTile>
            <div className="flex items-center justify-center rounded border border-gray-700 bg-gray-800 p-4">
              <Gauge value={attackPct} color={attackColor} label="Tỷ lệ tấn công" />
            </div>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <ChartPanel title="Phân bố loại nhãn">
              <BarChart data={predictionRows.map(([label, count]) => ({ label, count }))} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="label" stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} />
                <YAxis stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#111827", border: "1px solid #374151", fontSize: 12 }} />
                <Bar dataKey="count">
                  {predictionRows.map(([label], i) => <Cell key={i} fill={colorFor(label, colorMap)} />)}
                </Bar>
              </BarChart>
            </ChartPanel>

            <ChartPanel title="Layer nào bắt được" subtitle="Rule-based (tức thì) / Anomaly (thống kê) / ML Classifier (chi tiết)">
              <BarChart data={layerRows} layout="vertical" margin={{ top: 10, right: 20, left: 20, bottom: 0 }}>
                <CartesianGrid stroke={GRID} strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} allowDecimals={false} />
                <YAxis type="category" dataKey="layer" stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} width={160} />
                <Tooltip contentStyle={{ background: "#111827", border: "1px solid #374151", fontSize: 12 }} />
                <Bar dataKey="count" fill={CATEGORICAL[0]} />
              </BarChart>
            </ChartPanel>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <ChartPanel title="Độ tin cậy của model (confidence)">
              <BarChart data={result.confidence_histogram} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="range" stroke={AXIS} tick={{ fill: MUTED, fontSize: 10 }} />
                <YAxis stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#111827", border: "1px solid #374151", fontSize: 12 }} />
                <Bar dataKey="count" fill={CATEGORICAL[0]} />
              </BarChart>
            </ChartPanel>

            <ChartPanel title="Timeline cảnh báo" subtitle="Chỉ hiện các flow không phải BENIGN, theo đúng thời điểm">
              {timelineAlerts.length === 0 ? (
                <div className="flex h-full items-center justify-center text-sm text-gray-500">Không có cảnh báo nào — toàn bộ flow là BENIGN.</div>
              ) : (
                <ScatterChart margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                  <CartesianGrid stroke={GRID} strokeDasharray="3 3" />
                  <XAxis dataKey="timestamp_ms" type="number" domain={["dataMin", "dataMax"]} tickFormatter={(t) => new Date(t).toLocaleTimeString()} stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} />
                  <YAxis dataKey="confidence" domain={[0, 1]} stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{ background: "#111827", border: "1px solid #374151", fontSize: 12 }}
                    labelFormatter={(t) => new Date(t).toLocaleTimeString()}
                    formatter={(value, name, props) => [value, props.payload.prediction]}
                  />
                  <Scatter data={timelineAlerts}>
                    {timelineAlerts.map((p, i) => <Cell key={i} fill={colorFor(p.prediction, colorMap)} />)}
                  </Scatter>
                </ScatterChart>
              )}
            </ChartPanel>
          </div>

          <div className="rounded border border-gray-700 bg-gray-800 overflow-hidden">
            <div className="border-b border-gray-700 px-4 py-3 text-sm font-semibold text-gray-200">
              Chi tiết flow không phải BENIGN ({feedRows.length})
            </div>
            {feedRows.length === 0 ? (
              <div className="p-6 text-sm text-gray-500">Không có flow bất thường nào.</div>
            ) : (
              <>
                <div className="grid grid-cols-[140px_140px_80px_100px_1fr] gap-3 border-b border-gray-700 px-4 py-2 text-xs uppercase text-gray-500">
                  <div>Thời điểm</div>
                  <div>Nhãn</div>
                  <div>Layer</div>
                  <div>Confidence</div>
                  <div>Flow</div>
                </div>
                <div className="max-h-96 overflow-y-auto divide-y divide-gray-700">
                  {feedRows.map((row, i) => (
                    <div key={i} className="grid grid-cols-[140px_140px_80px_100px_1fr] items-center gap-3 px-4 py-2 text-xs hover:bg-gray-900/40">
                      <div className="text-gray-500">{row.window_start_ms ? new Date(row.window_start_ms).toLocaleTimeString() : "—"}</div>
                      <span className="w-fit rounded px-2 py-1 text-[10px] font-bold" style={{ backgroundColor: `${colorFor(row.prediction, colorMap)}33`, color: colorFor(row.prediction, colorMap) }}>
                        {row.prediction}
                      </span>
                      <div className="text-gray-400">L{row.layer_used}</div>
                      <div className="text-gray-400">{(row.confidence * 100).toFixed(1)}%</div>
                      <div className="text-gray-600 truncate">
                        {row.src_ip ? `${row.src_ip} -> ${row.dst_ip}` : "—"}
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function StatTile({ label, value, color = "text-white", accent, children }) {
  return (
    <div className="overflow-hidden rounded border border-gray-700 bg-gray-800">
      {accent && <div className="h-1" style={{ backgroundColor: accent }} />}
      <div className="p-4">
        <div className="text-xs uppercase text-gray-500">{label}</div>
        <div className={`mt-1 text-2xl font-bold ${color}`}>{value}</div>
        {children}
      </div>
    </div>
  );
}

function ChartPanel({ title, subtitle, children }) {
  return (
    <div className="rounded border border-gray-700 bg-gray-800 p-4">
      <div className="mb-3">
        <div className="text-sm font-semibold text-gray-200">{title}</div>
        {subtitle && <div className="text-xs text-gray-500">{subtitle}</div>}
      </div>
      <ResponsiveContainer width="100%" height={260}>
        {children}
      </ResponsiveContainer>
    </div>
  );
}
