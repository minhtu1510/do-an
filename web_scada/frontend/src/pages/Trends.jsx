import { useEffect, useMemo, useState } from "react";
import {
  CartesianGrid, Legend, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { fetchAttackEvents, fetchProcessHistory } from "../services/api";
import PageHeader from "../components/PageHeader";

// Validated categorical slots (dark mode) — fixed order, never cycled per series identity.
const BLUE = "#3987e5";
const ORANGE = "#d95926";
const AQUA = "#199e70";
const ATTACK_RED = "#e66767";
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
function mergeSeries(seriesMap) {
  const allTimestamps = new Set();
  Object.values(seriesMap).forEach((points) => points.forEach((p) => allTimestamps.add(p.timestamp)));
  const sorted = [...allTimestamps].sort();

  const last = {};
  return sorted.map((ts) => {
    const row = { timestamp: ts, t: toEpoch(ts) };
    for (const [key, points] of Object.entries(seriesMap)) {
      const match = points.find((p) => p.timestamp === ts);
      if (match) last[key] = match.value;
      row[key] = last[key] ?? null;
    }
    return row;
  });
}

function formatTime(t) {
  return new Date(t).toLocaleTimeString();
}

export default function Trends() {
  const [tags, setTags] = useState(null);
  const [attackEvents, setAttackEvents] = useState({ configured: false, events: [] });

  useEffect(() => {
    fetchProcessHistory().then((data) => setTags(data.tags || {}));
    fetchAttackEvents().then(setAttackEvents);
  }, []);

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

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        title="Trends & History"
        subtitle="Lịch sử tag thật (SQLite/Postgres historian) — chỉ ghi khi giá trị thay đổi, không nội suy số liệu giả."
      />

      {!attackEvents.configured && (
        <div className="rounded border border-yellow-900/50 bg-yellow-950/20 px-4 py-3 text-xs text-yellow-500">
          Chưa cấu hình <code className="rounded bg-gray-900 px-1">ATTACK_EVENT_FILE</code> — không có mốc tấn công nào được overlay lên biểu đồ. Copy file CSV từ máy attack (attack_event_logger.py) sang máy chạy backend này và set biến môi trường đó để bật overlay.
        </div>
      )}

      {!hasAnyData ? (
        <div className="rounded border border-gray-700 bg-gray-800 p-6 text-sm text-gray-500">
          Chưa có dữ liệu lịch sử — historian chỉ ghi khi tag đổi giá trị thật. Chờ băng chuyền hoạt động hoặc chạy kịch bản tấn công để có dữ liệu.
        </div>
      ) : (
        <>
          <ChartPanel title="Stage timers — CD1 / CD2 / CD3 (ms)" subtitle="Vùng an toàn 500–10000ms. SETPOINT_ATTACK sẽ đẩy giá trị vọt ra ngoài vùng này.">
            <LineChart data={timerData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
              <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="t" type="number" domain={["dataMin", "dataMax"]} tickFormatter={formatTime} stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} />
              <YAxis stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} label={{ value: "ms", angle: -90, position: "insideLeft", fill: MUTED, fontSize: 11 }} />
              <Tooltip contentStyle={{ background: "#111827", border: "1px solid #374151", fontSize: 12 }} labelFormatter={formatTime} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <ReferenceLine y={500} stroke={MUTED} strokeDasharray="2 2" />
              <ReferenceLine y={10000} stroke={MUTED} strokeDasharray="2 2" />
              {attackEvents.events.map((ev, i) => (
                <ReferenceLine key={i} x={toEpoch(ev.timestamp)} stroke={ATTACK_RED} strokeWidth={2}
                  label={{ value: ev.scenario_label, position: "top", fill: ATTACK_RED, fontSize: 10 }} />
              ))}
              <Line type="stepAfter" dataKey="cd1" name="CD1" stroke={BLUE} strokeWidth={2} dot={false} connectNulls />
              <Line type="stepAfter" dataKey="cd2" name="CD2" stroke={ORANGE} strokeWidth={2} dot={false} connectNulls />
              <Line type="stepAfter" dataKey="cd3" name="CD3" stroke={AQUA} strokeWidth={2} dot={false} connectNulls />
            </LineChart>
          </ChartPanel>

          <ChartPanel title="Conveyor RUN/STOP (bang_tai)" subtitle="0 = STOPPED, 1 = RUNNING. RWRITE_BURST sẽ làm đường này giật liên tục.">
            <LineChart data={runData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
              <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="t" type="number" domain={["dataMin", "dataMax"]} tickFormatter={formatTime} stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} />
              <YAxis stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} domain={[0, 1]} ticks={[0, 1]} />
              <Tooltip contentStyle={{ background: "#111827", border: "1px solid #374151", fontSize: 12 }} labelFormatter={formatTime} />
              {attackEvents.events.map((ev, i) => (
                <ReferenceLine key={i} x={toEpoch(ev.timestamp)} stroke={ATTACK_RED} strokeWidth={2}
                  label={{ value: ev.scenario_label, position: "top", fill: ATTACK_RED, fontSize: 10 }} />
              ))}
              <Line type="stepAfter" dataKey="bang_tai" name="Conveyor (RUN=1)" stroke={BLUE} strokeWidth={2} dot={false} connectNulls />
            </LineChart>
          </ChartPanel>

          <ChartPanel title="Production — Target vs Completed (nhap / hien_thi)">
            <LineChart data={productionData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
              <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="t" type="number" domain={["dataMin", "dataMax"]} tickFormatter={formatTime} stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} />
              <YAxis stroke={AXIS} tick={{ fill: MUTED, fontSize: 11 }} />
              <Tooltip contentStyle={{ background: "#111827", border: "1px solid #374151", fontSize: 12 }} labelFormatter={formatTime} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              {attackEvents.events.map((ev, i) => (
                <ReferenceLine key={i} x={toEpoch(ev.timestamp)} stroke={ATTACK_RED} strokeWidth={2}
                  label={{ value: ev.scenario_label, position: "top", fill: ATTACK_RED, fontSize: 10 }} />
              ))}
              <Line type="stepAfter" dataKey="nhap" name="Target quantity" stroke={BLUE} strokeWidth={2} dot={false} connectNulls />
              <Line type="stepAfter" dataKey="hien_thi" name="Completed quantity" stroke={ORANGE} strokeWidth={2} dot={false} connectNulls />
            </LineChart>
          </ChartPanel>
        </>
      )}
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
