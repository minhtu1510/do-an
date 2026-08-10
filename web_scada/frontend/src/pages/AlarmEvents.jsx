import { useEffect, useState } from "react";
import { ackEvent, fetchEvents } from "../services/api";
import { connectWebSocket } from "../services/websocket";
import PageHeader from "../components/PageHeader";
import ExportCsvButton from "../components/ExportCsvButton";
import { useAuth } from "../stores/authStore";

export default function AlarmEvents() {
  const [events, setEvents] = useState([]);
  const [activeCount, setActiveCount] = useState(0);
  const [lastUpdate, setLastUpdate] = useState(null);

  useEffect(() => {
    fetchEvents().then((data) => {
      setEvents(data.events || []);
      setActiveCount(data.active_count || 0);
      setLastUpdate(data.timestamp || null);
    });

    const unsub = connectWebSocket((data) => {
      if (data.type === "event" && data.event) {
        setEvents((prev) => {
          const existingIndex = prev.findIndex((e) => e.id === data.event.id);
          if (existingIndex !== -1) {
            const next = [...prev];
            next[existingIndex] = data.event;
            return next;
          }
          return [data.event, ...prev].slice(0, 100);
        });
        if (data.active_count !== null && data.active_count !== undefined) {
          setActiveCount(data.active_count);
        } else if (data.event.active_count !== null && data.event.active_count !== undefined) {
          setActiveCount(data.event.active_count);
        }
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
        title="Alarms & Events"
        subtitle="In-memory events generated from live OPC UA tag and connection changes."
        right={<ExportCsvButton />}
      />

      <div className="grid gap-4 sm:grid-cols-3">
        <SummaryCard label="Active alarms" value={activeCount} color={activeCount > 0 ? "text-red-400" : "text-green-400"} />
        <SummaryCard label="Stored events" value={events.length} />
        <SummaryCard label="Persistence" value="In memory" color="text-yellow-400" />
      </div>

      <div className="bg-gray-800 rounded border border-gray-700 overflow-hidden">
        <div className="border-b border-gray-700 px-4 py-3 text-sm font-semibold text-gray-200">Recent events</div>
        {events.length === 0 ? (
          <div className="p-6 text-sm text-gray-500">No events recorded yet.</div>
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

function SummaryCard({ label, value, color = "text-white" }) {
  return (
    <div className="bg-gray-800 rounded border border-gray-700 p-4 text-center">
      <div className="text-xs uppercase text-gray-500">{label}</div>
      <div className={`mt-1 text-2xl font-bold ${color}`}>{value}</div>
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
    <div className="grid gap-3 px-4 py-3 md:grid-cols-[140px_110px_1fr_100px_150px] md:items-center">
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
            className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-[10px] font-semibold text-gray-300 hover:border-blue-600 hover:text-blue-300"
          >
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
