import { useEffect, useMemo, useRef, useState } from "react";
import {
  Bar, BarChart, CartesianGrid, Cell, ComposedChart, Legend, Line,
  ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis,
} from "recharts";
import { jsPDF } from "jspdf";
import html2canvas from "html2canvas";
import PageHeader from "../components/PageHeader";
import Gauge from "../components/Gauge";
import Sparkline from "../components/Sparkline";
import { analyzeIdsPcap, fetchIdsStatus, fetchProcessHistory } from "../services/api";

// Same validated categorical order used in Trends.jsx — fixed, never cycled.
const CATEGORICAL = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"];
const BENIGN_COLOR = "#52697a";
const BLUE = "#3987e5";
const ORANGE = "#d95926";
const AQUA = "#199e70";
const ATTACK_RED = "#e66767";
const GOOD_GREEN = "#0ca30c";
const GRID = "#2c2c2a";
const AXIS = "#383835";
const MUTED = "#898781";

function colorFor(label, colorMap) {
  if (label === "BENIGN") return BENIGN_COLOR;
  if (!colorMap.has(label)) colorMap.set(label, CATEGORICAL[colorMap.size % CATEGORICAL.length]);
  return colorMap.get(label);
}

function formatTime(t) {
  return new Date(t).toLocaleTimeString();
}

// Buckets timeline into N time slices so the stat-tile sparklines show a real
// trend (flow volume, attack ratio) instead of a single flat number.
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

// Recomputes the same aggregates the backend returns (prediction_counts,
// layer_counts, confidence_histogram, totals) but over a REVEALED SUBSET of
// result.timeline — this is what makes playback animate every panel instead
// of just a scrubbing dot, using only data the backend already sent once.
const CONF_BINS = [0, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.0];
function aggregateFromPoints(points) {
  const prediction_counts = {};
  const layer_counts = {};
  const confidence_histogram = CONF_BINS.slice(0, -1).map((lo, i) => ({ range: `${lo.toFixed(2)}-${CONF_BINS[i + 1].toFixed(2)}`, count: 0 }));
  points.forEach((p) => {
    prediction_counts[p.prediction] = (prediction_counts[p.prediction] || 0) + 1;
    layer_counts[p.layer_used] = (layer_counts[p.layer_used] || 0) + 1;
    for (let i = 0; i < CONF_BINS.length - 1; i++) {
      const lo = CONF_BINS[i], hi = CONF_BINS[i + 1];
      if (p.confidence >= lo && (hi < 1 ? p.confidence < hi : p.confidence <= hi)) {
        confidence_histogram[i].count += 1;
        break;
      }
    }
  });
  const total = points.length;
  const attack = points.filter((p) => p.prediction !== "BENIGN").length;
  return { prediction_counts, layer_counts, confidence_histogram, total_flows: total, attack_flows: attack, attack_ratio: total ? attack / total : 0 };
}

function toEpoch(iso) {
  return new Date(iso).getTime();
}

// Merges real historian tag series with the pcap analysis timeline onto one
// shared clock, forward-filling tag values — the left axis is real process
// data, the right axis is real per-window model confidence. Only meaningful
// where their real timestamp ranges genuinely overlap (see hasOverlap).
function mergeFusion(historianSeries, pcapPoints) {
  const allTimes = new Set();
  Object.values(historianSeries).forEach((arr) => arr.forEach((p) => allTimes.add(toEpoch(p.timestamp))));
  pcapPoints.forEach((p) => allTimes.add(p.timestamp_ms));
  const sorted = [...allTimes].sort((a, b) => a - b);

  const lastVal = {};
  return sorted.map((t) => {
    const row = { t };
    for (const [key, arr] of Object.entries(historianSeries)) {
      const match = arr.find((p) => toEpoch(p.timestamp) === t);
      if (match) lastVal[key] = match.value;
      row[key] = lastVal[key] ?? null;
    }
    const pcapMatch = pcapPoints.find((p) => p.timestamp_ms === t);
    row.anomalyScore = pcapMatch ? (pcapMatch.prediction !== "BENIGN" ? pcapMatch.confidence * 100 : 0) : null;
    return row;
  });
}

function beep(ctx) {
  if (!ctx) return;
  try {
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "sine";
    osc.frequency.value = 880;
    gain.gain.setValueAtTime(0.15, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3);
    osc.connect(gain).connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.3);
  } catch { /* audio not available — playback still works silently */ }
}

export default function IdsUpload() {
  const [status, setStatus] = useState(null);
  const [file, setFile] = useState(null);
  const [plcIp, setPlcIp] = useState("192.168.210.211");
  const [windowS, setWindowS] = useState(2.0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [historian, setHistorian] = useState(null);

  // --- Playback engine state ---
  const [virtualMs, setVirtualMs] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(5);
  const audioCtxRef = useRef(null);
  const prevAttackCountRef = useRef(0);
  const reportRef = useRef(null);
  const [exportingPdf, setExportingPdf] = useState(false);

  useEffect(() => {
    fetchIdsStatus().then(setStatus).catch(() => setStatus({ configured: false, model_dir: "" }));
  }, []);

  const sortedTimeline = useMemo(
    () => (result ? [...result.timeline].sort((a, b) => a.timestamp_ms - b.timestamp_ms) : []),
    [result]
  );
  const tMin = sortedTimeline.length ? sortedTimeline[0].timestamp_ms : 0;
  const tMax = sortedTimeline.length ? sortedTimeline[sortedTimeline.length - 1].timestamp_ms : 0;
  const span = Math.max(tMax - tMin, 1);

  // New analysis result -> reset to "fully revealed" (matches old static behavior) and stop any playback.
  useEffect(() => {
    setVirtualMs(span);
    setPlaying(false);
    prevAttackCountRef.current = 0;
  }, [result]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!playing) return;
    const tickMs = 150;
    const id = setInterval(() => {
      setVirtualMs((v) => {
        const next = v + tickMs * speed;
        if (next >= span) {
          setPlaying(false);
          return span;
        }
        return next;
      });
    }, tickMs);
    return () => clearInterval(id);
  }, [playing, speed, span]);

  const currentAbsoluteMs = tMin + virtualMs;
  const revealedTimeline = useMemo(
    () => sortedTimeline.filter((p) => p.timestamp_ms <= currentAbsoluteMs),
    [sortedTimeline, currentAbsoluteMs]
  );
  const currentFlow = revealedTimeline.length ? revealedTimeline[revealedTimeline.length - 1] : null;

  // Beep once per newly-revealed batch that contains a fresh attack detection.
  useEffect(() => {
    const attackCount = revealedTimeline.filter((p) => p.prediction !== "BENIGN").length;
    if (attackCount > prevAttackCountRef.current) beep(audioCtxRef.current);
    prevAttackCountRef.current = attackCount;
  }, [revealedTimeline]);

  function handlePlay() {
    if (!audioCtxRef.current) {
      try { audioCtxRef.current = new (window.AudioContext || window.webkitAudioContext)(); } catch { /* no audio */ }
    }
    if (virtualMs >= span) setVirtualMs(0);
    setPlaying(true);
  }
  function handlePause() { setPlaying(false); }
  function handleSeek(e) { setVirtualMs(Number(e.target.value)); setPlaying(false); }
  function handleReset() { setVirtualMs(0); setPlaying(false); }

  async function handleExportPdf() {
    if (!reportRef.current || !result) return;
    setExportingPdf(true);
    try {
      const canvas = await html2canvas(reportRef.current, { backgroundColor: "#030712", scale: 2 });
      const imgData = canvas.toDataURL("image/png");

      const pdf = new jsPDF({ orientation: "p", unit: "pt", format: "a4" });
      const pageWidth = pdf.internal.pageSize.getWidth();
      const pageHeight = pdf.internal.pageSize.getHeight();

      pdf.setFontSize(16);
      pdf.text("IDS Upload — Bao cao phan tich", 40, 50);
      pdf.setFontSize(10);
      pdf.text(`File pcap: ${result.source_file || "-"}`, 40, 75);
      pdf.text(`Model: ${result.model_dir || "-"}`, 40, 90);
      pdf.text(`Thoi gian xuat: ${new Date().toLocaleString()}`, 40, 105);
      pdf.text(`Tong flow: ${result.total_flows}  |  Flow tan cong: ${result.attack_flows} (${(result.attack_ratio * 100).toFixed(1)}%)`, 40, 120);
      pdf.text("Toan bo bieu do/bang duoi day la trang thai dang hien thi tren man hinh (ke ca vi tri phat lai neu dang tua).", 40, 140);

      const imgWidth = pageWidth;
      const imgHeight = (canvas.height * imgWidth) / canvas.width;
      let heightLeft = imgHeight;
      let position = 0;

      pdf.addPage();
      pdf.addImage(imgData, "PNG", 0, position, imgWidth, imgHeight);
      heightLeft -= pageHeight;
      while (heightLeft > 0) {
        position = heightLeft - imgHeight;
        pdf.addPage();
        pdf.addImage(imgData, "PNG", 0, position, imgWidth, imgHeight);
        heightLeft -= pageHeight;
      }

      pdf.save(`ids_report_${Date.now()}.pdf`);
    } finally {
      setExportingPdf(false);
    }
  }

  const live = useMemo(() => aggregateFromPoints(revealedTimeline), [revealedTimeline]);
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
      fetchProcessHistory().then((h) => setHistorian(h.tags || {})).catch(() => setHistorian({}));
    } catch (err) {
      setError(err.message);
      setResult(null);
    } finally {
      setBusy(false);
    }
  }

  const predictionRows = Object.entries(live.prediction_counts).sort((a, b) => (a[0] === "BENIGN" ? -1 : b[0] === "BENIGN" ? 1 : b[1] - a[1]));
  const layerLabel = { 1: "Layer 1 — Rule-based", 2: "Layer 2 — Anomaly", 3: "Layer 3 — ML Classifier" };
  const layerRows = Object.entries(live.layer_counts).map(([k, v]) => ({ layer: layerLabel[k] || `Layer ${k}`, count: v }));
  const timelineAlerts = revealedTimeline.filter((p) => p.prediction !== "BENIGN");
  const feedRows = result
    ? [...result.flow_table].filter((r) => (r.window_start_ms ?? 0) <= currentAbsoluteMs).sort((a, b) => (a.window_start_ms ?? 0) - (b.window_start_ms ?? 0))
    : [];

  const attackPct = live.attack_ratio * 100;
  const attackColor = attackPct > 0 ? ATTACK_RED : GOOD_GREEN;
  const currentColor = currentFlow ? (currentFlow.prediction !== "BENIGN" ? ATTACK_RED : GOOD_GREEN) : MUTED;

  // --- Fusion chart: only meaningful when the historian actually has data in the same real time window as the pcap ---
  const fusionSeries = useMemo(() => {
    if (!historian || sortedTimeline.length === 0) return null;
    const wanted = { cd1: historian.cd1 || [], cd2: historian.cd2 || [], cd3: historian.cd3 || [] };
    const anyHistorian = Object.values(wanted).some((a) => a.length > 0);
    if (!anyHistorian) return null;

    const histTimes = Object.values(wanted).flat().map((p) => toEpoch(p.timestamp));
    const histMin = Math.min(...histTimes), histMax = Math.max(...histTimes);
    const overlapStart = Math.max(histMin, tMin);
    const overlapEnd = Math.min(histMax, tMax);
    if (overlapStart >= overlapEnd) return { hasOverlap: false };

    const merged = mergeFusion(wanted, sortedTimeline).filter((r) => r.t <= currentAbsoluteMs);
    return { hasOverlap: true, data: merged, domain: [overlapStart, Math.min(overlapEnd, currentAbsoluteMs)] };
  }, [historian, sortedTimeline, tMin, tMax, currentAbsoluteMs]);

  const canPlay = sortedTimeline.length > 1;

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
          <span className="text-[10px] text-gray-600">Model hiện tại train trên cửa sổ 2s — đổi giá trị này sẽ lệch phân bố đặc trưng.</span>
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
          <div className="flex justify-end">
            <button
              onClick={handleExportPdf}
              disabled={exportingPdf}
              className="rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs font-semibold text-gray-300 hover:border-blue-600 hover:text-blue-300 disabled:opacity-50"
            >
              {exportingPdf ? "Đang xuất..." : "⬇ Xuất báo cáo PDF"}
            </button>
          </div>

          {canPlay && (
            <div className="flex flex-wrap items-center gap-3 rounded border border-gray-700 bg-gray-800 p-4">
              <button
                onClick={playing ? handlePause : handlePlay}
                className="rounded bg-blue-600 px-4 py-1.5 text-sm font-semibold text-white hover:bg-blue-500"
              >
                {playing ? "⏸ Tạm dừng" : "▶ Phát lại"}
              </button>
              <button onClick={handleReset} className="rounded border border-gray-700 px-3 py-1.5 text-xs text-gray-400 hover:text-gray-200">
                ⏮ Về đầu
              </button>
              <select
                value={speed}
                onChange={(e) => setSpeed(Number(e.target.value))}
                className="rounded border border-gray-700 bg-gray-950 px-2 py-1.5 text-xs text-gray-300"
              >
                <option value={1}>x1</option>
                <option value={5}>x5</option>
                <option value={10}>x10</option>
                <option value={30}>x30</option>
              </select>
              <input
                type="range"
                min={0}
                max={span}
                value={virtualMs}
                onChange={handleSeek}
                className="h-1.5 flex-1 accent-blue-500"
              />
              <div className="w-36 shrink-0 text-right font-mono text-xs text-gray-400">
                {formatTime(currentAbsoluteMs)} / {formatTime(tMax)}
              </div>
            </div>
          )}

          <div ref={reportRef} className="space-y-6 bg-gray-950 p-1">
          {/* Z-pattern: most important numbers top-left, gauges top-right */}
          <div className="grid gap-4 lg:grid-cols-[1fr_1fr_auto_auto]">
            <StatTile label="Tổng số flow" value={live.total_flows} accent={CATEGORICAL[0]}>
              <Sparkline data={buckets} dataKey="value" color={CATEGORICAL[0]} />
            </StatTile>
            <StatTile label="Flow bị gắn nhãn tấn công" value={live.attack_flows} color={live.attack_flows > 0 ? "text-red-400" : "text-green-400"} accent={attackColor}>
              <Sparkline data={buckets} dataKey="attackRatio" color={attackColor} />
            </StatTile>
            <div className="flex items-center justify-center rounded border border-gray-700 bg-gray-800 p-4">
              <Gauge value={attackPct} color={attackColor} label="Tỷ lệ tấn công" />
            </div>
            <div className="flex flex-col items-center justify-center rounded border border-gray-700 bg-gray-800 p-4">
              <Gauge value={currentFlow ? currentFlow.confidence * 100 : 0} color={currentColor} label="Confidence hiện tại" />
              {currentFlow && (
                <span className="mt-1 rounded px-2 py-0.5 text-[10px] font-bold" style={{ backgroundColor: `${colorFor(currentFlow.prediction, colorMap)}33`, color: colorFor(currentFlow.prediction, colorMap) }}>
                  {currentFlow.prediction}
                </span>
              )}
            </div>
          </div>

          {fusionSeries?.hasOverlap && (
            <ChartPanel title="Fusion Chart — Process (CD1-3) vs Anomaly Score" subtitle="Trục trái: timer thật từ historian. Trục phải: confidence tấn công thật từ model. Chỉ vẽ trong khoảng thời gian 2 nguồn dữ liệu thật sự trùng nhau.">
              <ComposedChart data={fusionSeries.data} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="t" type="number" domain={fusionSeries.domain} tickFormatter={formatTime} stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} />
                <YAxis yAxisId="left" stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} label={{ value: "ms", angle: -90, position: "insideLeft", fill: MUTED, fontSize: 11 }} />
                <YAxis yAxisId="right" orientation="right" domain={[0, 100]} stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} label={{ value: "%", angle: 90, position: "insideRight", fill: MUTED, fontSize: 11 }} />
                <Tooltip contentStyle={{ background: "#111827", border: "1px solid #374151", fontSize: 12 }} labelFormatter={formatTime} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <Line yAxisId="left" type="stepAfter" dataKey="cd1" name="CD1 (ms)" stroke={BLUE} strokeWidth={2} dot={false} connectNulls />
                <Line yAxisId="left" type="stepAfter" dataKey="cd2" name="CD2 (ms)" stroke={ORANGE} strokeWidth={2} dot={false} connectNulls />
                <Line yAxisId="left" type="stepAfter" dataKey="cd3" name="CD3 (ms)" stroke={AQUA} strokeWidth={2} dot={false} connectNulls />
                <Scatter yAxisId="right" data={fusionSeries.data.filter((d) => d.anomalyScore !== null)} dataKey="anomalyScore" name="Anomaly score (%)" fill={ATTACK_RED} />
              </ComposedChart>
            </ChartPanel>
          )}
          {historian && !fusionSeries?.hasOverlap && (
            <div className="rounded border border-gray-700 bg-gray-800 p-4 text-xs text-gray-500">
              Không có dữ liệu historian trùng khung thời gian với file pcap này — Fusion Chart chỉ vẽ khi Trends historian thật sự đang ghi trong lúc pcap được thu (không suy diễn/nội suy).
            </div>
          )}

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
              <BarChart data={live.confidence_histogram} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="range" stroke={AXIS} tick={{ fill: MUTED, fontSize: 10 }} />
                <YAxis stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#111827", border: "1px solid #374151", fontSize: 12 }} />
                <Bar dataKey="count" fill={CATEGORICAL[0]} />
              </BarChart>
            </ChartPanel>

            <ChartPanel title="Timeline cảnh báo (swimlane)" subtitle="Mỗi hàng là 1 loại nhãn — chỉ hiện flow không phải BENIGN, theo đúng thời điểm">
              {timelineAlerts.length === 0 ? (
                <div className="flex h-full items-center justify-center text-sm text-gray-500">Chưa có cảnh báo nào trong đoạn đang phát.</div>
              ) : (
                <ScatterChart margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                  <CartesianGrid stroke={GRID} strokeDasharray="3 3" />
                  <XAxis dataKey="timestamp_ms" type="number" domain={[tMin, tMax]} tickFormatter={formatTime} stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} />
                  <YAxis type="category" dataKey="prediction" allowDuplicatedCategory={false} stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} width={90} />
                  <Tooltip
                    contentStyle={{ background: "#111827", border: "1px solid #374151", fontSize: 12 }}
                    labelFormatter={formatTime}
                    formatter={(value, name, props) => [`${(props.payload.confidence * 100).toFixed(1)}%`, props.payload.prediction]}
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
              <div className="p-6 text-sm text-gray-500">Không có flow bất thường nào trong đoạn đang phát.</div>
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
