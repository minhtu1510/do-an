import { useEffect, useMemo, useRef, useState } from "react";
import {
  Area, AreaChart, CartesianGrid, Legend, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { TrendingUp, History, FileDown, Loader2, Download } from "lucide-react";
import { jsPDF } from "jspdf";
import html2canvas from "html2canvas";
import { fetchProcessHistory } from "../services/api";
import PageHeader from "../components/PageHeader";
import Gauge from "../components/Gauge";
import Sparkline from "../components/Sparkline";

// Validated categorical slots (dark mode) — fixed order, never cycled per series identity.
const BLUE = "#3987e5";
const ORANGE = "#d95926";
const AQUA = "#199e70";
const VIOLET = "#9085e9";
const ATTACK_RED = "#e66767";
const GOOD_GREEN = "#0ca30c";
const GRID = "#2c2c2a";
const AXIS = "#383835";
const MUTED = "#898781";

function toEpoch(iso) {
  return new Date(iso).getTime();
}

// Forward-fill merge: each tag changes independently and asynchronously, so a
// shared chart needs one row per distinct timestamp with each series carrying
// its last known value forward — this is a step representation, not
// interpolation, matching how a boolean/discrete PLC value actually behaves.
//
// Each series' points already arrive sorted by timestamp (backend query is
// ORDER BY timestamp), so forward-filling can walk each series with a single
// advancing pointer instead of re-scanning it for every merged timestamp —
// O(n) total instead of O(distinct_timestamps * points_per_series), which on
// a historian with tens of thousands of rows was taking 10+ seconds and
// freezing the tab (single-threaded JS, nothing else can run meanwhile).
function mergeSeries(seriesMap) {
  const keys = Object.keys(seriesMap);
  const allTimestamps = new Set();
  Object.values(seriesMap).forEach((points) => points.forEach((p) => allTimestamps.add(p.timestamp)));
  const sorted = [...allTimestamps].sort();

  const pointers = {};
  const last = {};
  keys.forEach((key) => {
    pointers[key] = 0;
    last[key] = null;
  });

  return sorted.map((ts) => {
    const row = { timestamp: ts, t: toEpoch(ts) };
    for (const key of keys) {
      const points = seriesMap[key];
      let idx = pointers[key];
      while (idx < points.length && points[idx].timestamp <= ts) {
        last[key] = points[idx].value;
        idx++;
      }
      pointers[key] = idx;
      row[key] = last[key];
    }
    return row;
  });
}

// Recharts renders every row as real SVG geometry — tens of thousands of
// points froze the tab for 10-15s. This is a display-only cap (stride pick,
// always keeps the last point so a chart never silently drops its most
// recent reading); the real full-resolution data is untouched everywhere
// else — CSV export reads straight from `tags`, not this downsampled view.
function downsampleForChart(rows, maxPoints = 3000) {
  if (rows.length <= maxPoints) return rows;
  const step = Math.ceil(rows.length / maxPoints);
  const out = [];
  for (let i = 0; i < rows.length; i += step) out.push(rows[i]);
  if (out[out.length - 1] !== rows[rows.length - 1]) out.push(rows[rows.length - 1]);
  return out;
}

// Buckets any {t,...} series into N time slices for a stat-tile sparkline —
// real activity density derived from the same historian rows, not synthetic.
function bucketActivity(rows, bucketCount = 16) {
  if (!rows || rows.length === 0) return [];
  const times = rows.map((r) => r.t ?? toEpoch(r.timestamp));
  const min = Math.min(...times);
  const span = Math.max(Math.max(...times) - min, 1);
  const buckets = Array.from({ length: bucketCount }, () => 0);
  times.forEach((t) => {
    const idx = Math.min(bucketCount - 1, Math.floor(((t - min) / span) * bucketCount));
    buckets[idx] += 1;
  });
  return buckets.map((v) => ({ value: v }));
}

// Time-weighted % of the observed window where bang_tai was true — a real
// uptime ratio, not a sample count (a value can be "true" for a long stretch
// with very few change-rows, so counting rows would understate it).
function computeUptimePct(runData) {
  if (!runData || runData.length < 2) return 0;
  let runningMs = 0;
  let totalMs = 0;
  for (let i = 0; i < runData.length - 1; i++) {
    const dt = runData[i + 1].t - runData[i].t;
    totalMs += dt;
    // Backend serializes booleans as 1.0/0.0 (numeric), not JS true/false —
    // Number(...) handles both that and a real boolean transparently.
    if (Number(runData[i].bang_tai) === 1) runningMs += dt;
  }
  return totalMs > 0 ? (runningMs / totalMs) * 100 : 0;
}

function formatTime(t) {
  return new Date(t).toLocaleTimeString();
}

// Reusable gradient-fill defs so every Area chart gets the same "glow" look.
function GradientDefs({ id, color }) {
  return (
    <defs>
      <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
        <stop offset="5%" stopColor={color} stopOpacity={0.35} />
        <stop offset="95%" stopColor={color} stopOpacity={0} />
      </linearGradient>
    </defs>
  );
}

export default function Trends() {
  const [tags, setTags] = useState(null);
  const reportRef = useRef(null);
  const [exportingPdf, setExportingPdf] = useState(false);

  useEffect(() => {
    fetchProcessHistory().then((data) => setTags(data.tags || {}));
  }, []);

  function handleExportCsv() {
    const rows = [["tag_key", "timestamp", "value"]];
    Object.entries(tags || {}).forEach(([key, points]) => {
      (points || []).forEach((p) => rows.push([key, p.timestamp, p.value]));
    });
    const csv = rows.map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `trends_historian_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function handleExportPdf() {
    if (!reportRef.current) return;
    setExportingPdf(true);
    try {
      const canvas = await html2canvas(reportRef.current, { backgroundColor: "#030712", scale: 2 });
      const imgData = canvas.toDataURL("image/png");

      const pdf = new jsPDF({ orientation: "p", unit: "pt", format: "a4" });
      const pageWidth = pdf.internal.pageSize.getWidth();
      const pageHeight = pdf.internal.pageSize.getHeight();

      pdf.setFontSize(16);
      pdf.text("Trends & History — Bao cao lich su tag", 40, 50);
      pdf.setFontSize(10);
      pdf.text(`Thoi gian xuat: ${new Date().toLocaleString()}`, 40, 75);
      pdf.text(`Tong diem du lieu: ${totalPoints}`, 40, 90);
      pdf.text("Du lieu historian that (SQLite/Postgres) — khong noi suy so lieu gia.", 40, 110);

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

      pdf.save(`trends_report_${Date.now()}.pdf`);
    } finally {
      setExportingPdf(false);
    }
  }

  const timerData = useMemo(() => {
    if (!tags) return [];
    return mergeSeries({ cd1: tags.cd1 || [], cd2: tags.cd2 || [], cd3: tags.cd3 || [] });
  }, [tags]);

  const runData = useMemo(() => {
    if (!tags) return [];
    return mergeSeries({ bang_tai: tags.bang_tai || [] });
  }, [tags]);

  const productionData = useMemo(() => {
    if (!tags) return [];
    return mergeSeries({ nhap: tags.nhap || [], hien_thi: tags.hien_thi || [] });
  }, [tags]);

  const hasAnyData = timerData.length > 0 || runData.length > 0 || productionData.length > 0;

  // Chart-only, downsampled views — totalPoints/activityBuckets/uptimePct
  // below still use the full-resolution arrays. bang_tai is deliberately
  // NOT downsampled: it's a 2-value boolean, and a stride pick on a rapidly
  // alternating 1/0/1/0 series (exactly what RWRITE_BURST produces) can
  // alias into a flat line depending on the stride's parity — silently
  // hiding the one signal this chart exists to show. Numeric series (CD
  // timers, production counts) don't have that failure mode.
  const timerChartData = useMemo(() => downsampleForChart(timerData), [timerData]);
  const runChartData = runData;
  const productionChartData = useMemo(() => downsampleForChart(productionData), [productionData]);

  const totalPoints = timerData.length + runData.length + productionData.length;
  const activityBuckets = useMemo(() => bucketActivity(timerData), [timerData]);
  const uptimePct = useMemo(() => computeUptimePct(runData), [runData]);
  const uptimeColor = uptimePct >= 50 ? GOOD_GREEN : uptimePct > 0 ? "#c98500" : ATTACK_RED;

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        icon={TrendingUp}
        title="Xu hướng & Lịch sử"
        subtitle="Lịch sử tag thật (SQLite/Postgres historian) — chỉ ghi khi giá trị thay đổi, không nội suy số liệu giả."
        right={
          hasAnyData && (
            <div className="flex items-center gap-2">
              <button
                onClick={handleExportCsv}
                className="flex items-center gap-1.5 rounded border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-300 transition-colors hover:border-blue-600 hover:text-blue-300"
              >
                <Download size={13} />
                Xuất CSV
              </button>
              <button
                onClick={handleExportPdf}
                disabled={exportingPdf}
                className="flex items-center gap-1.5 rounded border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-300 transition-colors hover:border-blue-600 hover:text-blue-300 disabled:opacity-50"
              >
                {exportingPdf ? <Loader2 size={13} className="animate-spin" /> : <FileDown size={13} />}
                {exportingPdf ? "Đang xuất..." : "Xuất PDF"}
              </button>
            </div>
          )
        }
      />

      {!hasAnyData ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-gray-700 bg-gray-800 p-10 text-sm text-gray-500">
          <History size={28} className="text-gray-700" />
          Chưa có dữ liệu lịch sử — historian chỉ ghi khi tag đổi giá trị thật. Chờ băng chuyền hoạt động hoặc chạy kịch bản tấn công để có dữ liệu.
        </div>
      ) : (
        <div ref={reportRef} className="space-y-6 bg-slate-950 p-1">
          {/* Z-pattern hero row — the numbers that matter most, top-left to top-right */}
          <div className="grid gap-4 lg:grid-cols-[1fr_auto]">
            <div className="overflow-hidden rounded-lg border border-gray-700 bg-gray-800 shadow-sm shadow-black/20 transition-colors hover:border-gray-600">
              <div className="h-1" style={{ backgroundColor: AQUA }} />
              <div className="p-4">
                <div className="text-xs uppercase text-gray-500">Tổng điểm dữ liệu</div>
                <div className="mt-1 font-mono text-2xl font-bold" style={{ color: AQUA }}>{totalPoints}</div>
                <Sparkline data={activityBuckets} color={AQUA} />
              </div>
            </div>
            <div className="flex items-center justify-center rounded-lg border border-gray-700 bg-gray-800 p-4 shadow-sm shadow-black/20">
              <Gauge value={uptimePct} color={uptimeColor} label="Uptime băng chuyền" />
            </div>
          </div>

          {(timerChartData.length < timerData.length || runChartData.length < runData.length || productionChartData.length < productionData.length) && (
            <div className="text-[11px] text-gray-600">
              Biểu đồ dưới đây giảm mẫu để hiển thị mượt (dữ liệu quá lớn) — {totalPoints} điểm dữ liệu gốc vẫn đầy đủ trong "Xuất CSV".
            </div>
          )}

          <ChartPanel title="Timer công đoạn — CD1 / CD2 / CD3 (ms)" subtitle="Vùng an toàn 500–10000ms. SETPOINT_ATTACK sẽ đẩy giá trị vọt ra ngoài vùng này.">
            <AreaChart data={timerChartData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
              <GradientDefs id="gradCd1" color={BLUE} />
              <GradientDefs id="gradCd2" color={ORANGE} />
              <GradientDefs id="gradCd3" color={AQUA} />
              <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="t" type="number" domain={["dataMin", "dataMax"]} tickFormatter={formatTime} stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} />
              <YAxis stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} label={{ value: "ms", angle: -90, position: "insideLeft", fill: MUTED, fontSize: 11 }} />
              <Tooltip contentStyle={{ background: "#111827", border: "1px solid #374151", fontSize: 12 }} labelFormatter={formatTime} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <ReferenceLine y={500} stroke={MUTED} strokeDasharray="2 2" />
              <ReferenceLine y={10000} stroke={MUTED} strokeDasharray="2 2" />
              <Area type="stepAfter" dataKey="cd1" name="CD1" stroke={BLUE} strokeWidth={2} fill="url(#gradCd1)" dot={false} connectNulls />
              <Area type="stepAfter" dataKey="cd2" name="CD2" stroke={ORANGE} strokeWidth={2} fill="url(#gradCd2)" dot={false} connectNulls />
              <Area type="stepAfter" dataKey="cd3" name="CD3" stroke={AQUA} strokeWidth={2} fill="url(#gradCd3)" dot={false} connectNulls />
            </AreaChart>
          </ChartPanel>

          <div className="grid gap-4 lg:grid-cols-2">
            <ChartPanel title="Băng tải CHẠY/DỪNG (bang_tai)" subtitle="0 = DỪNG, 1 = CHẠY. RWRITE_BURST sẽ làm đường này giật liên tục.">
              <AreaChart data={runChartData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <GradientDefs id="gradRun" color={VIOLET} />
                <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="t" type="number" domain={["dataMin", "dataMax"]} tickFormatter={formatTime} stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} />
                <YAxis stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} domain={[0, 1]} ticks={[0, 1]} />
                <Tooltip contentStyle={{ background: "#111827", border: "1px solid #374151", fontSize: 12 }} labelFormatter={formatTime} />
                <Area type="stepAfter" dataKey="bang_tai" name="Băng tải (CHẠY=1)" stroke={VIOLET} strokeWidth={2} fill="url(#gradRun)" dot={false} connectNulls />
              </AreaChart>
            </ChartPanel>

            <ChartPanel title="Sản lượng — Mục tiêu và Hoàn thành (nhap / hien_thi)">
              <AreaChart data={productionChartData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <GradientDefs id="gradNhap" color={BLUE} />
                <GradientDefs id="gradHienThi" color={ORANGE} />
                <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="t" type="number" domain={["dataMin", "dataMax"]} tickFormatter={formatTime} stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} />
                <YAxis stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} />
                <Tooltip contentStyle={{ background: "#111827", border: "1px solid #374151", fontSize: 12 }} labelFormatter={formatTime} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <Area type="stepAfter" dataKey="nhap" name="Sản lượng mục tiêu" stroke={BLUE} strokeWidth={2} fill="url(#gradNhap)" dot={false} connectNulls />
                <Area type="stepAfter" dataKey="hien_thi" name="Sản lượng hoàn thành" stroke={ORANGE} strokeWidth={2} fill="url(#gradHienThi)" dot={false} connectNulls />
              </AreaChart>
            </ChartPanel>
          </div>
        </div>
      )}
    </div>
  );
}

function ChartPanel({ title, subtitle, children }) {
  return (
    <div className="rounded-lg border border-gray-700 bg-gray-800 p-4 shadow-sm shadow-black/20">
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
