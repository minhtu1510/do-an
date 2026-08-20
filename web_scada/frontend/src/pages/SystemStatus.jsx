import { useState, useEffect, useRef } from "react";
import { ServerCog, ArrowUp, ArrowDown, Radio, BellRing } from "lucide-react";
import { fetchAllTags, fetchEvents, fetchPlcStatus, fetchSystemResources } from "../services/api";
import { connectWebSocket } from "../services/websocket";
import PageHeader from "../components/PageHeader";
import Gauge from "../components/Gauge";
import Sparkline from "../components/Sparkline";

const GOOD_GREEN = "#0ca30c";
const WARN_AMBER = "#c98500";
const ATTACK_RED = "#e66767";
const BLUE = "#3987e5";
const AQUA = "#199e70";

function gaugeColor(pct) {
  if (pct >= 85) return ATTACK_RED;
  if (pct >= 60) return WARN_AMBER;
  return GOOD_GREEN;
}

const HISTORY_LEN = 40; // ~80s of history at the 2s broadcast interval

function pushHistory(history, value) {
  const next = [...history, { value }];
  return next.length > HISTORY_LEN ? next.slice(next.length - HISTORY_LEN) : next;
}

function formatBytesPerSec(bytesPerSec) {
  if (bytesPerSec == null) return "—";
  if (bytesPerSec < 1024) return `${bytesPerSec.toFixed(0)} B/s`;
  if (bytesPerSec < 1024 * 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  return `${(bytesPerSec / 1024 / 1024).toFixed(2)} MB/s`;
}

// Buckets recent events into per-minute counts — the same "rate over time"
// idea as a Prometheus/Grafana alert-rate panel, built from real event
// timestamps already stored by event_service (no synthetic data).
function bucketEventsPerMinute(events, bucketCount = 10) {
  const now = Date.now();
  const buckets = Array.from({ length: bucketCount }, (_, i) => ({
    label: `${bucketCount - i}m`,
    value: 0,
  }));
  events.forEach((e) => {
    const t = new Date(e.timestamp).getTime();
    const minutesAgo = Math.floor((now - t) / 60000);
    if (minutesAgo >= 0 && minutesAgo < bucketCount) {
      buckets[bucketCount - 1 - minutesAgo].value += 1;
    }
  });
  return buckets;
}

export default function SystemStatus() {
  const [status, setStatus] = useState(null);
  const [tags, setTags] = useState({});
  const [resources, setResources] = useState(null);
  const [eventRate, setEventRate] = useState([]);
  const historyRef = useRef({ cpu: [], mem: [], disk: [], netSent: [], netRecv: [] });
  const [, forceTick] = useState(0);

  useEffect(() => {
    fetchPlcStatus().then(setStatus);
    fetchSystemResources().then(setResources);
    fetchAllTags().then((data) => {
      if (data.tags) {
        const map = {};
        data.tags.forEach((t) => (map[t.key] = t));
        setTags(map);
      }
    });
    fetchEvents(200).then((data) => setEventRate(bucketEventsPerMinute(data.events || [])));

    const timer = setInterval(() => {
      fetchPlcStatus().then(setStatus);
      fetchAllTags().then((data) => {
        if (data.tags) {
          const map = {};
          data.tags.forEach((t) => (map[t.key] = t));
          setTags(map);
        }
      });
      fetchEvents(200).then((data) => setEventRate(bucketEventsPerMinute(data.events || [])));
    }, 30000);

    const unsub = connectWebSocket((data) => {
      if (data.type === "full_state" && data.status) setStatus(data.status);
      if (data.type === "full_state" && data.tags) {
        const map = {};
        data.tags.forEach((t) => (map[t.key] = t));
        setTags(map);
      }
      if (data.type === "tag_update") {
        setTags((prev) => ({ ...prev, [data.key]: data.data }));
      }
      if (data.type === "system_resources") {
        const r = {
          cpu_percent: data.cpu_percent,
          memory_percent: data.memory_percent,
          disk_percent: data.disk_percent,
          net_sent_bytes_per_sec: data.net_sent_bytes_per_sec,
          net_recv_bytes_per_sec: data.net_recv_bytes_per_sec,
          ws_connections: data.ws_connections,
        };
        setResources(r);
        const h = historyRef.current;
        h.cpu = pushHistory(h.cpu, r.cpu_percent ?? 0);
        h.mem = pushHistory(h.mem, r.memory_percent ?? 0);
        h.disk = pushHistory(h.disk, r.disk_percent ?? 0);
        h.netSent = pushHistory(h.netSent, r.net_sent_bytes_per_sec ?? 0);
        h.netRecv = pushHistory(h.netRecv, r.net_recv_bytes_per_sec ?? 0);
        forceTick((n) => n + 1);
      }
    });

    return () => {
      clearInterval(timer);
      unsub();
    };
  }, []);

  const staleTags = Object.values(tags).filter((t) => t.stale).length;
  const totalTags = Object.values(tags).length || status?.subscribed_tags || 9;
  const goodTags = Object.values(tags).length > 0 ? Object.values(tags).filter((t) => !t.stale).length : totalTags - staleTags;
  const history = historyRef.current;

  return (
    <div className="p-6 space-y-6">
      <PageHeader icon={ServerCog} title="System Status" subtitle="Backend, OPC UA gateway and websocket health at a glance." />

      <div className="grid gap-4 sm:grid-cols-3">
        <ResourcePanel
          label="CPU — máy backend"
          value={resources?.cpu_percent ?? 0}
          color={gaugeColor(resources?.cpu_percent ?? 0)}
          history={history.cpu}
          note="Tài nguyên máy chạy Web-SCADA gateway, không phải PLC (PLC không có hệ điều hành để đo)."
        />
        <ResourcePanel
          label="RAM — máy backend"
          value={resources?.memory_percent ?? 0}
          color={gaugeColor(resources?.memory_percent ?? 0)}
          history={history.mem}
          note="Tăng khi gateway phải xử lý khối lượng OPC UA lớn (vd: subscription flood)."
        />
        <ResourcePanel
          label="Disk — máy backend"
          value={resources?.disk_percent ?? 0}
          color={gaugeColor(resources?.disk_percent ?? 0)}
          history={history.disk}
          note="Dung lượng ổ đĩa hệ thống nơi chạy backend (historian DB, model AI...)."
        />
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <StatTile
          icon={ArrowUp}
          iconColor={BLUE}
          label="Network out"
          value={formatBytesPerSec(resources?.net_sent_bytes_per_sec)}
          history={history.netSent}
          sparkColor={BLUE}
        />
        <StatTile
          icon={ArrowDown}
          iconColor={AQUA}
          label="Network in"
          value={formatBytesPerSec(resources?.net_recv_bytes_per_sec)}
          history={history.netRecv}
          sparkColor={AQUA}
        />
        <StatTile
          icon={Radio}
          iconColor={GOOD_GREEN}
          label="WebSocket connections"
          value={resources?.ws_connections ?? "—"}
          note="Số client (tab trình duyệt) đang mở dashboard, nhận cập nhật real-time."
        />
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 shadow-sm shadow-black/20">
        <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-200">
          <BellRing size={14} className="text-amber-400" />
          Tần suất cảnh báo (10 phút gần nhất)
        </div>
        {eventRate.every((b) => b.value === 0) ? (
          <div className="py-6 text-center text-xs text-slate-600">Không có cảnh báo nào trong 10 phút qua.</div>
        ) : (
          <EventRateChart data={eventRate} />
        )}
      </div>

      <div className="grid grid-cols-2 gap-3">
        <InfoRow label="PLC IP" value="192.168.210.211" />
        <InfoRow label="OPC UA" value={status?.endpoint || "opc.tcp://192.168.210.211:4840"} />
        <InfoRow label="State" value={status?.connected ? "CONNECTED" : "DISCONNECTED"} color={status?.connected ? "text-green-400" : "text-red-400"} />
        <InfoRow label="Reconnect count" value={status?.reconnect_count ?? 0} />
        <InfoRow label="Tags Total" value={totalTags} />
        <InfoRow label="Tags Good" value={goodTags} color="text-green-400" />
        <InfoRow label="Tags Stale" value={staleTags} color={staleTags > 0 ? "text-red-400" : "text-gray-400"} />
        <InfoRow label="Backend uptime" value={formatUptime(status?.uptime_seconds)} />
        <InfoRow label="Backend started" value={status?.backend_started_at ? new Date(status.backend_started_at).toLocaleTimeString() : "—"} />
        <InfoRow label="WebSocket" value="ONLINE" color="text-green-400" />
        <InfoRow label="Last connected" value={status?.last_connected_at ? new Date(status.last_connected_at).toLocaleTimeString() : "—"} />
        <InfoRow label="Last data" value={status?.last_data_at ? new Date(status.last_data_at).toLocaleTimeString() : "—"} />
      </div>
    </div>
  );
}

function ResourcePanel({ label, value, color, history, note }) {
  return (
    <div className="flex flex-col items-center gap-2 rounded-lg border border-gray-700 bg-gray-800 p-4 shadow-sm shadow-black/20 transition-colors hover:border-gray-600">
      <Gauge value={value} color={color} label={label} />
      {history.length >= 2 && (
        <div className="w-full">
          <Sparkline data={history} color={color} height={28} />
        </div>
      )}
      <div className="text-center text-[10px] text-gray-600">{note}</div>
    </div>
  );
}

function StatTile({ icon: Icon, iconColor, label, value, history, sparkColor, note }) {
  return (
    <div className="flex flex-col gap-2 rounded-lg border border-gray-700 bg-gray-800 p-4 shadow-sm shadow-black/20 transition-colors hover:border-gray-600">
      <div className="flex items-center gap-2">
        <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg" style={{ backgroundColor: `${iconColor}1a`, color: iconColor }}>
          <Icon size={14} />
        </div>
        <div className="text-xs text-gray-500">{label}</div>
      </div>
      <div className="font-mono text-xl font-bold text-gray-100">{value}</div>
      {history && history.length >= 2 && <Sparkline data={history} color={sparkColor} height={24} />}
      {note && <div className="text-[10px] text-gray-600">{note}</div>}
    </div>
  );
}

function EventRateChart({ data }) {
  const max = Math.max(...data.map((b) => b.value), 1);
  return (
    <div className="flex h-16 items-end gap-1.5">
      {data.map((b, i) => (
        <div key={i} className="flex flex-1 flex-col items-center gap-1">
          <div
            className="w-full rounded-t"
            style={{
              height: `${Math.max((b.value / max) * 100, b.value > 0 ? 8 : 2)}%`,
              backgroundColor: b.value > 0 ? WARN_AMBER : "#334155",
              minHeight: 2,
            }}
            title={`${b.value} cảnh báo`}
          />
          <div className="text-[9px] text-slate-600">{b.label}</div>
        </div>
      ))}
    </div>
  );
}

function InfoRow({ label, value, color = "text-gray-300" }) {
  return (
    <div className="flex items-center justify-between rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 shadow-sm shadow-black/20 transition-colors hover:border-gray-600">
      <span className="text-xs text-gray-500">{label}</span>
      <span className={`font-mono text-sm font-bold ${color}`}>{value}</span>
    </div>
  );
}

function formatUptime(secs) {
  if (secs === null || secs === undefined) return "—";
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  return `${h}h ${m}m ${s}s`;
}
