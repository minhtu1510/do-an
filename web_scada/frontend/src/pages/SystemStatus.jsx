import { useState, useEffect } from "react";
import { ServerCog } from "lucide-react";
import { fetchAllTags, fetchPlcStatus, fetchSystemResources } from "../services/api";
import { connectWebSocket } from "../services/websocket";
import PageHeader from "../components/PageHeader";
import Gauge from "../components/Gauge";

const GOOD_GREEN = "#0ca30c";
const WARN_AMBER = "#c98500";
const ATTACK_RED = "#e66767";

function gaugeColor(pct) {
  if (pct >= 85) return ATTACK_RED;
  if (pct >= 60) return WARN_AMBER;
  return GOOD_GREEN;
}

export default function SystemStatus() {
  const [status, setStatus] = useState(null);
  const [tags, setTags] = useState({});
  const [resources, setResources] = useState(null);

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

    const timer = setInterval(() => {
      fetchPlcStatus().then(setStatus);
      fetchAllTags().then((data) => {
        if (data.tags) {
          const map = {};
          data.tags.forEach((t) => (map[t.key] = t));
          setTags(map);
        }
      });
    }, 5000);

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
        setResources({ cpu_percent: data.cpu_percent, memory_percent: data.memory_percent });
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

  return (
    <div className="p-6 space-y-6">
      <PageHeader icon={ServerCog} title="System Status" subtitle="Backend, OPC UA gateway and websocket health at a glance." />

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="flex flex-col items-center gap-2 rounded-lg border border-gray-700 bg-gray-800 p-4 shadow-sm shadow-black/20 transition-colors hover:border-gray-600">
          <Gauge value={resources?.cpu_percent ?? 0} color={gaugeColor(resources?.cpu_percent ?? 0)} label="CPU — máy backend" />
          <div className="text-center text-[10px] text-gray-600">Tài nguyên máy chạy Web-SCADA gateway, không phải PLC (PLC không có hệ điều hành để đo).</div>
        </div>
        <div className="flex flex-col items-center gap-2 rounded-lg border border-gray-700 bg-gray-800 p-4 shadow-sm shadow-black/20 transition-colors hover:border-gray-600">
          <Gauge value={resources?.memory_percent ?? 0} color={gaugeColor(resources?.memory_percent ?? 0)} label="RAM — máy backend" />
          <div className="text-center text-[10px] text-gray-600">Tăng khi gateway phải xử lý khối lượng OPC UA lớn (vd: subscription flood).</div>
        </div>
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
