import { useEffect, useState } from "react";
import { Bell, Check, Database, Inbox } from "lucide-react";
import { ackEvent, fetchEvents } from "../services/api";
import { connectWebSocket } from "../services/websocket";
import PageHeader from "../components/PageHeader";
import ExportCsvButton from "../components/ExportCsvButton";
import { useAuth } from "../stores/authStore";
import { COMMAND_EVENT_TYPES } from "../constants/events";

export default function AlarmEvents() {
  const [events, setEvents] = useState([]);
  const [lastUpdate, setLastUpdate] = useState(null);
  // Derived from the events already on screen (not the backend's separate
  // alarm_engine counter) so it counts every ACTIVE event type shown below —
  // including ones alarm_engine itself never tracks, like ATTACK_PCAP_DETECTED
  // from an IDS Upload finding — instead of silently under-counting.
  const activeCount = events.filter((e) => e.status === "ACTIVE").length;

  useEffect(() => {
    fetchEvents().then((data) => {
      setEvents((data.events || []).filter((e) => !COMMAND_EVENT_TYPES.includes(e.event_type)));
      setLastUpdate(data.timestamp || null);
    });

    const unsub = connectWebSocket((data) => {
      if (data.type === "event" && data.event && !COMMAND_EVENT_TYPES.includes(data.event.event_type)) {
        setEvents((prev) => {
          const existingIndex = prev.findIndex((e) => e.id === data.event.id);
          if (existingIndex !== -1) {
            const next = [...prev];
            next[existingIndex] = data.event;
            return next;
          }
          return [data.event, ...prev].slice(0, 100);
        });
        setLastUpdate(data.event.timestamp);
      }
    });

    return unsub;
  }, []);

  async function handleAck(eventId) {
    try {
      const updated = await ackEvent(eventId);
      setEvents((prev) => prev.map((e) => (e.id === eventId ? updated : e)));
    } catch (err) {
      // best-effort UI action; server state remains source of truth on next refresh
    }
  }

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        icon={Bell}
        title="Cảnh báo & Sự kiện"
        subtitle="Cảnh báo hệ thống từ trạng thái tag/kết nối OPC UA thật — lệnh điều khiển PLC xem ở trang Nhật ký điều khiển riêng."
        right={<ExportCsvButton excludeEventTypes={COMMAND_EVENT_TYPES} />}
      />

      <div className="grid gap-4 sm:grid-cols-3">
        <SummaryCard label="Cảnh báo đang hoạt động" value={activeCount} color={activeCount > 0 ? "text-red-400" : "text-green-400"} icon={Bell} />
        <SummaryCard label="Sự kiện đã lưu" value={events.length} icon={Inbox} />
        <SummaryCard label="Lưu trữ" value="Cơ sở dữ liệu" color="text-green-400" icon={Database} />
      </div>

      <div className="overflow-hidden rounded-lg border border-gray-700 bg-gray-800 shadow-sm shadow-black/20">
        <div className="border-b border-gray-700 px-4 py-3 text-sm font-semibold text-gray-200">Recent events</div>
        {events.length === 0 ? (
          <div className="flex flex-col items-center gap-2 p-10 text-sm text-gray-500">
            <Inbox size={28} className="text-gray-700" />
            No events recorded yet.
          </div>
        ) : (
          <div className="divide-y divide-gray-700">
            {events.map((event) => (
              <EventRow key={event.id} event={event} onAck={handleAck} />
            ))}
          </div>
        )}
      </div>

      {lastUpdate && <div className="text-right text-xs text-gray-600">Last event update: {lastUpdate}</div>}
    </div>
  );
}

function SummaryCard({ label, value, color = "text-white", icon: Icon }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-gray-700 bg-gray-800 p-4 shadow-sm shadow-black/20 transition-colors hover:border-gray-600">
      {Icon && (
        <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-gray-900 ${color}`}>
          <Icon size={16} />
        </div>
      )}
      <div>
        <div className="text-xs uppercase tracking-wide text-gray-500">{label}</div>
        <div className={`font-mono text-2xl font-bold ${color}`}>{value}</div>
      </div>
    </div>
  );
}

function EventRow({ event, onAck }) {
  const { hasRole } = useAuth();
  const severityColor = {
    INFO: "text-blue-300 bg-blue-950/40",
    WARN: "text-yellow-300 bg-yellow-950/40",
    ERROR: "text-red-300 bg-red-950/40",
  }[event.severity] || "text-gray-300 bg-gray-900";
  const statusColor = event.status === "ACTIVE" ? "text-red-400" : "text-green-400";
  const needsAck = event.status === "ACTIVE" && !event.acked_by;

  return (
    <div className="grid gap-3 px-4 py-3 transition-colors hover:bg-gray-900/40 md:grid-cols-[140px_110px_1fr_100px_150px] md:items-center">
      <div className="text-xs text-gray-500">{formatTime(event.timestamp)}</div>
      <div>
        <span className={`rounded px-2 py-1 text-[10px] font-bold ${severityColor}`}>{event.severity}</span>
      </div>
      <div>
        <div className="text-sm font-semibold text-gray-200">{event.event_type}</div>
        <div className="text-xs text-gray-500">{event.message}</div>
        {event.tag_key && <div className="text-[10px] text-gray-600">Tag: {event.tag_key}</div>}
      </div>
      <div className={`text-xs font-bold ${statusColor}`}>{event.status}</div>
      <div className="text-xs">
        {event.acked_by ? (
          <div className="text-gray-500">
            <div className="text-green-400">Acked: {event.acked_by}</div>
            <div className="text-[10px] text-gray-600">{formatTime(event.acked_at)}</div>
          </div>
        ) : needsAck && hasRole("operator") ? (
          <button
            onClick={() => onAck(event.id)}
            className="flex items-center gap-1 rounded border border-gray-700 bg-gray-900 px-2 py-1 text-[10px] font-semibold text-gray-300 transition-colors hover:border-blue-600 hover:text-blue-300"
          >
            <Check size={11} />
            Ack
          </button>
        ) : needsAck ? (
          <span className="text-gray-600">Chưa ack</span>
        ) : null}
      </div>
    </div>
  );
}

function formatTime(value) {
  if (!value) return "N/A";
  return new Date(value).toLocaleString();
}
