import { useState, useEffect } from "react";
import { fetchPlcStatus } from "../services/api";
import { connectWebSocket } from "../services/websocket";

export default function SystemStatus() {
  const [status, setStatus] = useState(null);
  const [tags, setTags] = useState({});
  const [uptime, setUptime] = useState(0);

  useEffect(() => {
    fetchPlcStatus().then(setStatus);
    const timer = setInterval(() => fetchPlcStatus().then(setStatus), 5000);

    const unsub = connectWebSocket((data) => {
      if (data.type === "full_state" && data.status) setStatus(data.status);
    });

    const uptimeTimer = setInterval(() => setUptime((p) => p + 1), 1000);

    return () => {
      clearInterval(timer);
      clearInterval(uptimeTimer);
      unsub();
    };
  }, []);

  const goodTags = Object.values(tags).filter((t) => !t.stale).length;
  const staleTags = Object.values(tags).filter((t) => t.stale).length;
  const totalTags = Object.values(tags).length || status?.subscribed_tags || 9;

  return (
    <div className="p-6 space-y-4">
      <h2 className="text-lg font-bold">Trang thai he thong</h2>

      <div className="grid grid-cols-2 gap-3">
        <InfoRow label="PLC IP" value="192.168.210.211" />
        <InfoRow label="OPC UA" value="opc.tcp://192.168.210.211:4840" />
        <InfoRow label="State" value={status?.connected ? "CONNECTED" : "DISCONNECTED"} color={status?.connected ? "text-green-400" : "text-red-400"} />
        <InfoRow label="Reconnect count" value={status?.reconnect_count ?? 0} />
        <InfoRow label="Tags Total" value={totalTags} />
        <InfoRow label="Tags Good" value={totalTags - staleTags} color="text-green-400" />
        <InfoRow label="Tags Stale" value={staleTags} color={staleTags > 0 ? "text-red-400" : "text-gray-400"} />
        <InfoRow label="Backend uptime" value={formatUptime(uptime)} />
        <InfoRow label="WebSocket" value="ONLINE" color="text-green-400" />
        <InfoRow label="Last connected" value={status?.last_connected_at ? new Date(status.last_connected_at).toLocaleTimeString() : "—"} />
        <InfoRow label="Last data" value={status?.last_data_at ? new Date(status.last_data_at).toLocaleTimeString() : "—"} />
      </div>
    </div>
  );
}

function InfoRow({ label, value, color = "text-gray-300" }) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded px-4 py-3 flex justify-between items-center">
      <span className="text-xs text-gray-500">{label}</span>
      <span className={`font-mono text-sm font-bold ${color}`}>{value}</span>
    </div>
  );
}

function formatUptime(secs) {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  return `${h}h ${m}m ${s}s`;
}
