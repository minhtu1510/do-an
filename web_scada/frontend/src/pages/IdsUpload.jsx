import { useEffect, useMemo, useRef, useState } from "react";
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ComposedChart, Legend, Line,
  ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis,
} from "recharts";
import { jsPDF } from "jspdf";
import html2canvas from "html2canvas";
import {
  UploadCloud, Play, Pause, RotateCcw, FileDown, Loader2, AlertTriangle, X,
} from "lucide-react";
import PageHeader from "../components/PageHeader";
import Gauge from "../components/Gauge";
import Sparkline from "../components/Sparkline";
import NotConfiguredNotice from "../components/NotConfiguredNotice";
import { analyzeIdsPcap, analyzeIdsPcapOpcua, fetchIdsStatus, fetchIdsStatusOpcua, fetchProcessHistory } from "../services/api";
import { idsUploadStore } from "./idsUploadPersist";

// Same validated categorical order used in Trends.jsx — fixed, never cycled.
const CATEGORICAL = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"];
const BENIGN_COLOR = "#52697a";
const BLUE = "#3987e5";
const ORANGE = "#d95926";
const AQUA = "#199e70";
const ATTACK_RED = "#e66767";
const GOOD_GREEN = "#0ca30c";
const GRID = "#1e293b";
const AXIS = "#475569";
const MUTED = "#64748b";

// MITRE ATT&CK for ICS mapping per real attack label — sourced from
// SemanticAware-S7comm-Dataset/docs/ATTACK_DESCRIPTION.md (verified live
// against attack.mitre.org, same technique IDs already used in
// tests/day8/scenarios.yaml). Not shown for BENIGN or ANOMALY — ANOMALY
// means Layer 2 flagged the window as statistically off but Layer 3 could
// not classify it as a specific known attack type, so no technique applies.
const MITRE_BY_LABEL = {
  SCAN: { id: "T0846", name: "Remote System Discovery" },
  ENUMERATION: { id: "T0888", name: "Remote System Information Discovery" },
  RWRITE: { id: "T0855", name: "Unauthorized Command Message" },
  SPOOF: { id: "T0856", name: "Spoof Reporting Message" },
  STEALTHY: { id: "T0836", name: "Modify Parameter" },
  FLOOD: { id: "T0814", name: "Denial of Service" },
  FUZZ: { id: "T0814", name: "Denial of Service" },
  CPU_CONTROL: { id: "T0816", name: "Device Restart/Shutdown" },
};

// OPC UA counterpart to MITRE_BY_LABEL — sourced from tests/day8/scenarios.yaml
// (mitre_technique / mitre_technique_name there are verified against the live
// MITRE ATT&CK for ICS matrix, not guessed). OPCUA_MALICIOUS_WRITE covers what
// model_opcua/ was trained on after merging OPCUA_INVALID_WRITE +
// OPCUA_WRITE_DENIED (see train_opcua_eval.py — they're wire-identical, a
// single Write the server rejected, and can't be told apart from features
// alone). Not shown for "benign".
const MITRE_BY_LABEL_OPCUA = {
  OPCUA_ENDPOINT_DISCOVERY: { id: "T0888", name: "Remote System Information Discovery" },
  OPCUA_NODE_BROWSE: { id: "T0861", name: "Point & Tag Identification" },
  OPCUA_SESSION_BURST: { id: "T0814", name: "Denial of Service" },
  OPCUA_SUBSCRIPTION_FLOOD: { id: "T0814", name: "Denial of Service" },
  OPCUA_MALICIOUS_WRITE: { id: "T0836", name: "Modify Parameter" },
  OPCUA_READ_SCRAPING: { id: "T0802", name: "Automated Collection" },
  OPCUA_PROTOCOL_FUZZ: { id: "T0814", name: "Denial of Service" },
  OPCUA_BEHAVIORAL_PROFILING: { id: "T0801", name: "Monitor Process State" },
  OPCUA_SLOWLORIS: { id: "T0814", name: "Denial of Service" },
  OPCUA_RECURSIVE_BROWSE: { id: "T0814", name: "Denial of Service" },
};

function mitreUrl(techniqueId) {
  const [base, sub] = techniqueId.split(".");
  return sub ? `https://attack.mitre.org/techniques/${base}/${sub}/` : `https://attack.mitre.org/techniques/${base}/`;
}

function colorFor(label, colorMap) {
  if (label === "BENIGN") return BENIGN_COLOR;
  if (!colorMap.has(label)) colorMap.set(label, CATEGORICAL[colorMap.size % CATEGORICAL.length]);
  return colorMap.get(label);
}

function formatTime(t) {
  return new Date(t).toLocaleTimeString();
}

// Real per-window counters the backend actually sends (see flow_cols in
// service.py / service_opcua.py) — src_ip/dst_ip were shown here before but
// neither extractor emits per-window IP columns, so that cell was always
// empty. This renders whatever real fields exist instead of a fixed pair.
function flowDetail(row, isOpcua) {
  const parts = isOpcua
    ? [
        row.opcua_write_count != null && `Write: ${row.opcua_write_count}`,
        row.opcua_browse_count != null && `Browse: ${row.opcua_browse_count}`,
        row.opcua_read_count != null && `Read: ${row.opcua_read_count}`,
        row.opcua_create_session_count != null && `Session: ${row.opcua_create_session_count}`,
      ]
    : [
        row.s7_input_write_count != null && `Ghi vào: ${row.s7_input_write_count}`,
        row.s7_output_write_count != null && `Ghi ra: ${row.s7_output_write_count}`,
      ];
  const shown = parts.filter(Boolean);
  return shown.length ? shown.join(" · ") : "—";
}

// Recharts renders every row as real SVG geometry — a pcap with tens of
// thousands of flow windows would freeze the tab drawing Fusion Chart/swimlane
// points one by one. Same fix as Trends.jsx's downsampleForChart: a display-
// only stride cap (always keeps the last point so nothing recent is silently
// dropped) — full-resolution data is untouched everywhere else (PDF export
// captures whatever is on screen, flow table below reads straight from
// `result`, not this downsampled view).
function downsampleForChart(rows, maxPoints = 3000) {
  if (!rows || rows.length <= maxPoints) return rows || [];
  const step = Math.ceil(rows.length / maxPoints);
  const out = [];
  for (let i = 0; i < rows.length; i += step) out.push(rows[i]);
  if (out[out.length - 1] !== rows[rows.length - 1]) out.push(rows[rows.length - 1]);
  return out;
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

// Same idea as bucketTimeline, but keyed by real wall-clock time (not bucket
// index) so it can share an x-axis with the Fusion Chart — a genuine
// "attack density over time" panel, the kind of threat-activity trend line
// real ICS IDS products lead with, built only from timestamps already returned.
function bucketTimelineByTime(timeline, tMin, tMax, bucketCount = 24) {
  if (!timeline || timeline.length === 0 || tMax <= tMin) return [];
  const span = tMax - tMin;
  const bucketMs = span / bucketCount;
  const buckets = Array.from({ length: bucketCount }, (_, i) => ({
    t: tMin + (i + 0.5) * bucketMs,
    count: 0,
    attack: 0,
  }));
  timeline.forEach((p) => {
    const idx = Math.min(bucketCount - 1, Math.floor((p.timestamp_ms - tMin) / bucketMs));
    if (idx >= 0) {
      buckets[idx].count += 1;
      if (p.prediction !== "BENIGN") buckets[idx].attack += 1;
    }
  });
  return buckets.map((b) => ({ t: b.t, attackRatio: b.count > 0 ? (b.attack / b.count) * 100 : 0, count: b.count }));
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

// The OPC UA backend (service_opcua.py) returns the same shape as the
// S7comm one (total_flows/attack_flows/prediction_counts/timeline/flow_table)
// but with two real differences: labels are lowercase "benign" instead of
// "BENIGN" (that's literally what's in the training CSV — see
// data_opc/day8_out/opcua_harvest_features.csv), and there's no layer_used
// (model_opcua/ is a single classifier, not a 3-layer pipeline, so faking a
// layer number would misrepresent how the prediction was made). Normalizing
// here — once, right after the fetch — means every chart/table below can
// keep using the same "!== BENIGN" checks it already had instead of branching
// on protocol everywhere.
function normalizeOpcuaResult(raw) {
  const upper = (p) => (p === "benign" ? "BENIGN" : p);
  return {
    ...raw,
    protocol: "opcua",
    prediction_counts: Object.fromEntries(Object.entries(raw.prediction_counts).map(([k, v]) => [upper(k), v])),
    timeline: raw.timeline.map((p) => ({ ...p, prediction: upper(p.prediction), layer_used: null })),
    flow_table: raw.flow_table.map((r) => ({ ...r, prediction: upper(r.prediction), layer_used: null })),
  };
}

function toEpoch(iso) {
  return new Date(iso).getTime();
}

// Merges real historian tag series with the pcap analysis timeline onto one
// shared clock, forward-filling tag values — the left axis is real process
// data, the right axis is real per-window model confidence. Only meaningful
// where their real timestamp ranges genuinely overlap (see hasOverlap).
//
// Each input array is already sorted by time (historian query is ORDER BY
// timestamp; pcapPoints is sortedTimeline, sorted client-side), so this walks
// each with a single advancing pointer instead of `.find()`-scanning it for
// every merged timestamp — same O(n) fix as Trends.jsx's mergeSeries. This
// one matters even more here: the caller used to re-run the O(n²) version on
// every ~150ms playback tick (see fusionMerged below), which would visibly
// stutter or freeze the "Phát lại" animation on any non-trivial pcap.
function mergeFusion(historianSeries, pcapPoints) {
  const seriesKeys = Object.keys(historianSeries);
  const allTimes = new Set();
  Object.values(historianSeries).forEach((arr) => arr.forEach((p) => allTimes.add(toEpoch(p.timestamp))));
  pcapPoints.forEach((p) => allTimes.add(p.timestamp_ms));
  const sorted = [...allTimes].sort((a, b) => a - b);

  const pointers = {};
  const lastVal = {};
  seriesKeys.forEach((key) => { pointers[key] = 0; lastVal[key] = null; });
  let pcapIdx = 0;

  return sorted.map((t) => {
    const row = { t };
    for (const key of seriesKeys) {
      const arr = historianSeries[key];
      let idx = pointers[key];
      while (idx < arr.length && toEpoch(arr[idx].timestamp) <= t) {
        lastVal[key] = arr[idx].value;
        idx++;
      }
      pointers[key] = idx;
      row[key] = lastVal[key];
    }
    // Exact-match only (not forward-filled): anomaly score should only show
    // at the flow's own timestamp, not smeared across later ticks. Both
    // `sorted` and `pcapPoints` are ascending, so a single pointer that only
    // ever advances past timestamps strictly before `t` lands exactly on the
    // matching entry (if any) once `t` reaches it.
    while (pcapIdx < pcapPoints.length && pcapPoints[pcapIdx].timestamp_ms < t) pcapIdx++;
    const pcapMatch = pcapIdx < pcapPoints.length && pcapPoints[pcapIdx].timestamp_ms === t ? pcapPoints[pcapIdx] : null;
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
  // file/result/etc are seeded from — and written back to — a module-level
  // store so switching pages and coming back doesn't lose the pcap you
  // picked or the analysis you already ran (see idsUploadPersist.js).
  const [status, setStatusState] = useState(idsUploadStore.status);
  const setStatus = (v) => { idsUploadStore.status = v; setStatusState(v); };
  const [protocol, setProtocolState] = useState(idsUploadStore.protocol);
  // model_opcua/ was trained on 5s-aggregated windows (extract_opcua_features.py
  // default), while the S7comm model was trained on 2s windows — auto-switching
  // this on protocol change keeps inference windowing aligned with how each
  // model was actually trained, instead of silently reusing the wrong one.
  const setProtocol = (v) => {
    idsUploadStore.protocol = v;
    setProtocolState(v);
    const defaultWindow = v === "opcua" ? 5.0 : 2.0;
    idsUploadStore.windowS = defaultWindow;
    setWindowSState(defaultWindow);
  };
  const [file, setFileState] = useState(idsUploadStore.file);
  const setFile = (v) => { idsUploadStore.file = v; setFileState(v); };
  const [plcIp, setPlcIpState] = useState(idsUploadStore.plcIp);
  const setPlcIp = (v) => { idsUploadStore.plcIp = v; setPlcIpState(v); };
  const [windowS, setWindowSState] = useState(idsUploadStore.windowS);
  const setWindowS = (v) => { idsUploadStore.windowS = v; setWindowSState(v); };
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResultState] = useState(idsUploadStore.result);
  const setResult = (v) => { idsUploadStore.result = v; setResultState(v); };
  const [historian, setHistorianState] = useState(idsUploadStore.historian);
  const setHistorian = (v) => { idsUploadStore.historian = v; setHistorianState(v); };

  // --- Playback engine state ---
  const [virtualMs, setVirtualMs] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(5);
  const audioCtxRef = useRef(null);
  const prevAttackCountRef = useRef(0);
  const reportRef = useRef(null);
  const [exportingPdf, setExportingPdf] = useState(false);

  useEffect(() => {
    const fetchStatus = protocol === "opcua" ? fetchIdsStatusOpcua : fetchIdsStatus;
    fetchStatus().then(setStatus).catch(() => setStatus({ configured: false, model_dir: "" }));
  }, [protocol]); // eslint-disable-line react-hooks/exhaustive-deps

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
  const densitySeries = useMemo(() => bucketTimelineByTime(revealedTimeline, tMin, tMax), [revealedTimeline, tMin, tMax]);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const data = protocol === "opcua"
        ? normalizeOpcuaResult(await analyzeIdsPcapOpcua(file, plcIp, windowS))
        : { ...(await analyzeIdsPcap(file, plcIp, windowS)), protocol: "s7comm" };
      setResult(data);
      fetchProcessHistory().then((h) => setHistorian(h.tags || {})).catch(() => setHistorian({}));
    } catch (err) {
      setError(err.message);
      setResult(null);
    } finally {
      setBusy(false);
    }
  }

  function handleClearAll() {
    setFile(null);
    setResult(null);
    setHistorian(null);
    setError(null);
    setPlcIp("192.168.210.211");
    setWindowS(2.0);
  }

  const mitreMap = result?.protocol === "opcua" ? MITRE_BY_LABEL_OPCUA : MITRE_BY_LABEL;
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
  // Split in two: the O(n) merge below only depends on the analysis result
  // itself, so it runs once per upload. Slicing by currentAbsoluteMs for
  // playback is a separate, much cheaper useMemo — it used to be bundled
  // into this one, which meant the full merge re-ran on every ~150ms
  // playback tick (see mergeFusion's comment for why that was slow).
  const fusionBase = useMemo(() => {
    if (!historian || sortedTimeline.length === 0) return null;
    const wanted = { cd1: historian.cd1 || [], cd2: historian.cd2 || [], cd3: historian.cd3 || [] };
    const anyHistorian = Object.values(wanted).some((a) => a.length > 0);
    if (!anyHistorian) return null;

    const histTimes = Object.values(wanted).flat().map((p) => toEpoch(p.timestamp));
    const histMin = Math.min(...histTimes), histMax = Math.max(...histTimes);
    const overlapStart = Math.max(histMin, tMin);
    const overlapEnd = Math.min(histMax, tMax);
    if (overlapStart >= overlapEnd) return { hasOverlap: false };

    return { hasOverlap: true, merged: mergeFusion(wanted, sortedTimeline), overlapStart, overlapEnd };
  }, [historian, sortedTimeline, tMin, tMax]);

  const fusionSeries = useMemo(() => {
    if (!fusionBase) return null;
    if (!fusionBase.hasOverlap) return { hasOverlap: false };
    // Downsample only the CD1-3 line series — a stride cap here just thins
    // out an otherwise-continuous timer trace, which is fine for display.
    // The anomaly-score points are rendered separately (fusionAnomalyPoints,
    // below) straight from the pcap timeline instead of being filtered out
    // of this array, so a real attack marker can never be silently dropped
    // by the downsample the way it would if we capped this array and then
    // filtered it for non-null anomalyScore.
    const data = downsampleForChart(fusionBase.merged.filter((r) => r.t <= currentAbsoluteMs));
    return { hasOverlap: true, data, domain: [fusionBase.overlapStart, Math.min(fusionBase.overlapEnd, currentAbsoluteMs)] };
  }, [fusionBase, currentAbsoluteMs]);

  const fusionAnomalyPoints = useMemo(
    () => timelineAlerts.map((p) => ({ t: p.timestamp_ms, anomalyScore: p.confidence * 100 })),
    [timelineAlerts]
  );

  const canPlay = sortedTimeline.length > 1;

  return (
    <div className="p-6 space-y-6">
      <PageHeader icon={UploadCloud} title="Tải PCAP phân tích" />

      {status && !status.configured && (
        <NotConfiguredNotice
          title="Model AI chưa được huấn luyện"
          message={protocol === "opcua"
            ? "Cần train trên dữ liệu OPC UA thật (Day 8) trước khi phân tích pcap OPC UA ở đây."
            : "Cần train trên dữ liệu Day 1-6 thật trước khi phân tích pcap S7comm ở đây."}
          detail={protocol === "opcua"
            ? `Thư mục model: ${status.model_dir}\n\nLệnh train:\npython train_opcua_eval.py --dataset <opcua_features.csv> --output "${status.model_dir}"`
            : `Thư mục model: ${status.model_dir}\n\nLệnh train:\npython train_eval.py --dataset <day1_6_labeled.csv> --mode train --output "${status.model_dir}"`}
        />
      )}

      <form onSubmit={handleSubmit} className="rounded-lg border border-slate-700 bg-slate-800 p-4 shadow-sm shadow-black/20">
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1">
            <span className="text-xs uppercase text-slate-500">Giao thức</span>
            <div className="flex overflow-hidden rounded border border-slate-700">
              <button
                type="button"
                onClick={() => setProtocol("s7comm")}
                className={`px-3 py-1.5 text-xs font-semibold transition-colors ${protocol === "s7comm" ? "bg-blue-600 text-white" : "bg-slate-950 text-slate-400 hover:text-slate-200"}`}
              >
                S7comm
              </button>
              <button
                type="button"
                onClick={() => setProtocol("opcua")}
                className={`px-3 py-1.5 text-xs font-semibold transition-colors ${protocol === "opcua" ? "bg-blue-600 text-white" : "bg-slate-950 text-slate-400 hover:text-slate-200"}`}
              >
                OPC UA
              </button>
            </div>
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs uppercase text-slate-500">File pcap/pcapng</span>
            <input
              type="file"
              accept=".pcap,.pcapng"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              className="text-xs text-slate-300 file:mr-2 file:rounded file:border-0 file:bg-slate-900 file:px-3 file:py-1.5 file:text-xs file:text-slate-300 file:transition-colors file:hover:bg-slate-800"
            />
            {file && <span className="text-[10px] text-cyan-400">Đang giữ: {file.name}</span>}
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs uppercase text-slate-500">PLC IP</span>
            <input value={plcIp} onChange={(e) => setPlcIp(e.target.value)} className="rounded border border-slate-700 bg-slate-950 px-3 py-1.5 text-sm text-slate-200 outline-none transition-colors focus:border-blue-600" />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs uppercase text-slate-500">Window (s)</span>
            <input type="number" step="0.5" value={windowS} onChange={(e) => setWindowS(e.target.value)} className="w-24 rounded border border-slate-700 bg-slate-950 px-3 py-1.5 text-sm text-slate-200 outline-none transition-colors focus:border-blue-600" />
          </label>
          <button
            type="submit"
            disabled={busy || !file}
            className="flex items-center gap-1.5 rounded bg-blue-600 px-4 py-1.5 text-sm font-semibold text-white shadow-sm shadow-blue-950 transition-colors hover:bg-blue-500 disabled:opacity-50"
          >
            {busy && <Loader2 size={14} className="animate-spin" />}
            {busy ? "Đang phân tích..." : "Phân tích"}
          </button>
          {(file || result) && (
            <button
              type="button"
              onClick={handleClearAll}
              disabled={busy}
              className="flex items-center gap-1.5 rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-400 transition-colors hover:border-red-500/50 hover:text-red-300 disabled:opacity-50"
            >
              <X size={12} />
              Xoá / Reset
            </button>
          )}
        </div>
        <div className="mt-2 text-[10px] text-slate-600">
          Model hiện tại train trên cửa sổ 2s — đổi giá trị này sẽ lệch phân bố đặc trưng. Chọn đúng giao thức của file
          đang tải lên: {protocol === "opcua" ? "OPC UA" : "S7comm"} dùng model và bộ trích xuất đặc trưng riêng, pcap
          sai giao thức sẽ không trích được flow nào (báo lỗi rõ, không đoán bừa).
        </div>
      </form>

      {error && (
        <div className="flex items-start gap-2 rounded-lg border border-red-900/50 bg-red-950/30 px-4 py-3 text-sm text-red-400 animate-fade-in">
          <AlertTriangle size={15} className="mt-0.5 shrink-0" />
          {error}
        </div>
      )}

      {result && (
        <>
          <div className="flex justify-end animate-fade-in">
            <button
              onClick={handleExportPdf}
              disabled={exportingPdf}
              className="flex items-center gap-1.5 rounded border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-300 transition-colors hover:border-blue-600 hover:text-blue-300 disabled:opacity-50"
            >
              {exportingPdf ? <Loader2 size={13} className="animate-spin" /> : <FileDown size={13} />}
              {exportingPdf ? "Đang xuất..." : "Xuất báo cáo PDF"}
            </button>
          </div>

          {canPlay && (
            <div className="flex flex-wrap items-center gap-3 rounded-lg border border-slate-700 bg-slate-800 p-4 shadow-sm shadow-black/20 animate-fade-in">
              <button
                onClick={playing ? handlePause : handlePlay}
                className="flex items-center gap-1.5 rounded bg-blue-600 px-4 py-1.5 text-sm font-semibold text-white shadow-sm shadow-blue-950 transition-colors hover:bg-blue-500"
              >
                {playing ? <Pause size={14} /> : <Play size={14} />}
                {playing ? "Tạm dừng" : "Phát lại"}
              </button>
              <button onClick={handleReset} className="flex items-center gap-1.5 rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-400 transition-colors hover:border-slate-600 hover:text-slate-200">
                <RotateCcw size={12} />
                Về đầu
              </button>
              <select
                value={speed}
                onChange={(e) => setSpeed(Number(e.target.value))}
                className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-xs text-slate-300 transition-colors hover:border-slate-600"
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
              <div className="w-36 shrink-0 text-right font-mono text-xs text-slate-400">
                {formatTime(currentAbsoluteMs)} / {formatTime(tMax)}
              </div>
            </div>
          )}

          <div ref={reportRef} className="space-y-6 bg-slate-950 p-1">
          {/* Z-pattern: most important numbers top-left, gauges top-right */}
          <div className="grid gap-4 lg:grid-cols-[1fr_1fr_auto_auto]">
            <StatTile label="Tổng số flow" value={live.total_flows} accent={CATEGORICAL[0]}>
              <Sparkline data={buckets} dataKey="value" color={CATEGORICAL[0]} />
            </StatTile>
            <StatTile label="Flow bị dự đoán là tấn công" value={live.attack_flows} color={live.attack_flows > 0 ? "text-red-400" : "text-green-400"} accent={attackColor}>
              <Sparkline data={buckets} dataKey="attackRatio" color={attackColor} />
            </StatTile>
            <div className="flex items-center justify-center rounded-lg border border-slate-700 bg-slate-800 p-4 shadow-sm shadow-black/20">
              <Gauge value={attackPct} color={attackColor} label="Tỷ lệ tấn công" />
            </div>
            <div className="flex flex-col items-center justify-center rounded-lg border border-slate-700 bg-slate-800 p-4 shadow-sm shadow-black/20">
              <Gauge value={currentFlow ? currentFlow.confidence * 100 : 0} color={currentColor} label="Confidence hiện tại" />
              {currentFlow && (
                <span className="mt-1 rounded px-2 py-0.5 text-[10px] font-bold" style={{ backgroundColor: `${colorFor(currentFlow.prediction, colorMap)}33`, color: colorFor(currentFlow.prediction, colorMap) }}>
                  {currentFlow.prediction}
                </span>
              )}
              {currentFlow && mitreMap[currentFlow.prediction] && (
                <a
                  href={mitreUrl(mitreMap[currentFlow.prediction].id)}
                  target="_blank"
                  rel="noreferrer"
                  title={mitreMap[currentFlow.prediction].name}
                  className="mt-1 rounded border border-violet-400/20 bg-violet-400/[0.07] px-1.5 py-0.5 font-mono text-[9px] text-violet-300 transition hover:border-violet-400/40 hover:bg-violet-400/10"
                >
                  ATT&CK {mitreMap[currentFlow.prediction].id}
                </a>
              )}
            </div>
          </div>

          {fusionSeries?.hasOverlap && (
            <ChartPanel title="Biểu đồ kết hợp — Tiến trình (CD1-3) và Điểm bất thường" subtitle="Trục trái: timer thật từ historian. Trục phải: confidence tấn công thật từ model. Chỉ vẽ trong khoảng thời gian 2 nguồn dữ liệu thật sự trùng nhau.">
              <ComposedChart data={fusionSeries.data} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="t" type="number" domain={fusionSeries.domain} tickFormatter={formatTime} stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} />
                <YAxis yAxisId="left" stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} label={{ value: "ms", angle: -90, position: "insideLeft", fill: MUTED, fontSize: 11 }} />
                <YAxis yAxisId="right" orientation="right" domain={[0, 100]} stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} label={{ value: "%", angle: 90, position: "insideRight", fill: MUTED, fontSize: 11 }} />
                <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", fontSize: 12 }} labelFormatter={formatTime} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <Line yAxisId="left" type="stepAfter" dataKey="cd1" name="CD1 (ms)" stroke={BLUE} strokeWidth={2} dot={false} connectNulls />
                <Line yAxisId="left" type="stepAfter" dataKey="cd2" name="CD2 (ms)" stroke={ORANGE} strokeWidth={2} dot={false} connectNulls />
                <Line yAxisId="left" type="stepAfter" dataKey="cd3" name="CD3 (ms)" stroke={AQUA} strokeWidth={2} dot={false} connectNulls />
                <Scatter yAxisId="right" data={fusionAnomalyPoints} dataKey="anomalyScore" name="Điểm bất thường (%)" fill={ATTACK_RED} />
              </ComposedChart>
            </ChartPanel>
          )}
          {historian && !fusionSeries?.hasOverlap && (
            <div className="rounded-lg border border-slate-700 bg-slate-800 p-4 text-xs text-slate-500 shadow-sm shadow-black/20">
              Không có dữ liệu historian trùng khung thời gian với file pcap này — Fusion Chart chỉ vẽ khi Trends historian thật sự đang ghi trong lúc pcap được thu (không suy diễn/nội suy).
            </div>
          )}

          {densitySeries.length > 0 && (
            <ChartPanel title="Mật độ tấn công theo thời gian" subtitle="Tỷ lệ % flow bị model dự đoán là tấn công trong từng lát thời gian — nơi đường càng cao, tấn công càng dồn dập lúc đó.">
              <AreaChart data={densitySeries} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="densityFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={ATTACK_RED} stopOpacity={0.35} />
                    <stop offset="100%" stopColor={ATTACK_RED} stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="t" type="number" domain={[tMin, tMax]} tickFormatter={formatTime} stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} />
                <YAxis domain={[0, 100]} stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} label={{ value: "%", angle: -90, position: "insideLeft", fill: MUTED, fontSize: 11 }} />
                <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", fontSize: 12 }} labelFormatter={formatTime} formatter={(v) => [`${v.toFixed(1)}%`, "Tỷ lệ tấn công"]} />
                <Area type="monotone" dataKey="attackRatio" stroke={ATTACK_RED} strokeWidth={2} fill="url(#densityFill)" />
              </AreaChart>
            </ChartPanel>
          )}

          <div className="grid gap-4 lg:grid-cols-2">
            <ChartPanel title="Phân bố kết quả dự đoán">
              <BarChart data={predictionRows.map(([label, count]) => ({ label, count }))} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="label" stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} />
                <YAxis stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", fontSize: 12 }} />
                <Bar dataKey="count">
                  {predictionRows.map(([label], i) => <Cell key={i} fill={colorFor(label, colorMap)} />)}
                </Bar>
              </BarChart>
            </ChartPanel>

            {result?.protocol === "opcua" ? (
              <ChartPanel title="Model" subtitle="model_opcua/ là 1 classifier duy nhất (không phải pipeline 3 tầng) — CV macro-F1 dưới đây là ước lượng trung thực từ grouped 5-fold cross-validation lúc train, không phải điểm trên chính dữ liệu đang phân tích.">
                <div className="flex h-full flex-col items-center justify-center gap-1">
                  <div className="font-mono text-3xl font-bold text-cyan-300">
                    {result.model_cv_macro_f1 != null ? `${(result.model_cv_macro_f1 * 100).toFixed(1)}%` : "—"}
                  </div>
                  <div className="text-xs text-slate-500">CV macro-F1 (RandomForest, GroupKFold theo episode)</div>
                </div>
              </ChartPanel>
            ) : (
              <ChartPanel title="Layer nào bắt được" subtitle="Rule-based (tức thì) / Anomaly (thống kê) / ML Classifier (chi tiết)">
                <BarChart data={layerRows} layout="vertical" margin={{ top: 10, right: 20, left: 20, bottom: 0 }}>
                  <CartesianGrid stroke={GRID} strokeDasharray="3 3" horizontal={false} />
                  <XAxis type="number" stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} allowDecimals={false} />
                  <YAxis type="category" dataKey="layer" stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} width={160} />
                  <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", fontSize: 12 }} />
                  <Bar dataKey="count" fill={CATEGORICAL[0]} />
                </BarChart>
              </ChartPanel>
            )}
          </div>

          {result?.feature_importance?.length > 0 && (
            <ChartPanel
              title="Đặc trưng quan trọng nhất"
              subtitle={`Model dùng ${result.feature_count} đặc trưng thật (${result.protocol === "opcua" ? "OPC UA" : "S7comm"}) — top ${result.feature_importance.length} đóng góp nhiều nhất theo độ quan trọng Random Forest (Gini importance), tính trên toàn bộ model lúc train, không phải riêng file đang phân tích.`}
            >
              <BarChart
                data={result.feature_importance.map((f) => ({ feature: f.feature, importance: f.importance * 100 }))}
                layout="vertical"
                margin={{ top: 10, right: 30, left: 20, bottom: 0 }}
              >
                <CartesianGrid stroke={GRID} strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} unit="%" />
                <YAxis type="category" dataKey="feature" stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} width={220} />
                <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", fontSize: 12 }} formatter={(v) => [`${v.toFixed(1)}%`, "Độ quan trọng"]} />
                <Bar dataKey="importance" fill={CATEGORICAL[2]} />
              </BarChart>
            </ChartPanel>
          )}

          <div className="grid gap-4 lg:grid-cols-2">
            <ChartPanel title="Độ tin cậy của model (confidence)">
              <BarChart data={live.confidence_histogram} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="range" stroke={AXIS} tick={{ fill: MUTED, fontSize: 10 }} />
                <YAxis stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", fontSize: 12 }} />
                <Bar dataKey="count" fill={CATEGORICAL[0]} />
              </BarChart>
            </ChartPanel>

            <ChartPanel title="Timeline cảnh báo (swimlane)" subtitle="Mỗi hàng là 1 loại dự đoán — chỉ hiện flow không phải BENIGN, theo đúng thời điểm">
              {timelineAlerts.length === 0 ? (
                <div className="flex h-full items-center justify-center text-sm text-slate-500">Chưa có cảnh báo nào trong đoạn đang phát.</div>
              ) : (
                <ScatterChart margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                  <CartesianGrid stroke={GRID} strokeDasharray="3 3" />
                  <XAxis dataKey="timestamp_ms" type="number" domain={[tMin, tMax]} tickFormatter={formatTime} stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} />
                  <YAxis type="category" dataKey="prediction" allowDuplicatedCategory={false} stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} width={90} />
                  <Tooltip
                    contentStyle={{ background: "#0f172a", border: "1px solid #334155", fontSize: 12 }}
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

          <div className="overflow-hidden rounded-lg border border-slate-700 bg-slate-800 shadow-sm shadow-black/20">
            <div className="border-b border-slate-700 px-4 py-3 text-sm font-semibold text-slate-200">
              Chi tiết flow không phải BENIGN ({feedRows.length})
            </div>
            {feedRows.length === 0 ? (
              <div className="p-6 text-sm text-slate-500">Không có flow bất thường nào trong đoạn đang phát.</div>
            ) : (
              <>
                {(() => {
                  const isOpcua = result?.protocol === "opcua";
                  const gridCls = isOpcua
                    ? "grid grid-cols-[140px_140px_110px_100px_1fr]"
                    : "grid grid-cols-[140px_140px_110px_80px_100px_1fr]";
                  return (
                    <>
                      <div className={`${gridCls} gap-3 border-b border-slate-700 px-4 py-2 text-xs uppercase text-slate-500`}>
                        <div>Thời điểm</div>
                        <div>Dự đoán</div>
                        <div>MITRE ATT&CK</div>
                        {!isOpcua && <div>Layer</div>}
                        <div>Confidence</div>
                        <div>Chi tiết</div>
                      </div>
                      <div className="max-h-96 overflow-y-auto divide-y divide-slate-700">
                        {feedRows.map((row, i) => {
                          const mitre = mitreMap[row.prediction];
                          return (
                            <div key={i} className={`${gridCls} items-center gap-3 px-4 py-2 text-xs hover:bg-slate-900/40`}>
                              <div className="text-slate-500">{row.window_start_ms ? new Date(row.window_start_ms).toLocaleTimeString() : "—"}</div>
                              <span className="w-fit rounded px-2 py-1 text-[10px] font-bold" style={{ backgroundColor: `${colorFor(row.prediction, colorMap)}33`, color: colorFor(row.prediction, colorMap) }}>
                                {row.prediction}
                              </span>
                              {mitre ? (
                                <a
                                  href={mitreUrl(mitre.id)}
                                  target="_blank"
                                  rel="noreferrer"
                                  title={mitre.name}
                                  className="w-fit rounded border border-violet-400/20 bg-violet-400/[0.07] px-1.5 py-0.5 font-mono text-[9px] text-violet-300 transition hover:border-violet-400/40 hover:bg-violet-400/10"
                                >
                                  {mitre.id}
                                </a>
                              ) : (
                                <span className="text-slate-700">—</span>
                              )}
                              {!isOpcua && <div className="text-slate-400">L{row.layer_used}</div>}
                              <div className="text-slate-400">{(row.confidence * 100).toFixed(1)}%</div>
                              <div className="text-slate-600 truncate">{flowDetail(row, isOpcua)}</div>
                            </div>
                          );
                        })}
                      </div>
                    </>
                  );
                })()}
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
    <div className="overflow-hidden rounded-lg border border-slate-700 bg-slate-800 shadow-sm shadow-black/20 transition-colors hover:border-slate-600">
      {accent && <div className="h-1" style={{ backgroundColor: accent }} />}
      <div className="p-4">
        <div className="text-xs uppercase text-slate-500">{label}</div>
        <div className={`mt-1 font-mono text-2xl font-bold ${color}`}>{value}</div>
        {children}
      </div>
    </div>
  );
}

function ChartPanel({ title, subtitle, children }) {
  return (
    <div className="rounded-lg border border-slate-700 bg-slate-800 p-4 shadow-sm shadow-black/20">
      <div className="mb-3">
        <div className="text-sm font-semibold text-slate-200">{title}</div>
        {subtitle && <div className="text-xs text-slate-500">{subtitle}</div>}
      </div>
      <ResponsiveContainer width="100%" height={260}>
        {children}
      </ResponsiveContainer>
    </div>
  );
}
