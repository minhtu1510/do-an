import { useEffect, useState } from "react";
import { jsPDF } from "jspdf";
import { Bell, Check, ClipboardList, FileDown, Inbox, Lock, ShieldAlert, ShieldCheck, ShieldX, Unlock } from "lucide-react";
import { ackEvent, fetchEvents, fetchWriteLock, releaseWriteLock } from "../services/api";
import { connectWebSocket } from "../services/websocket";
import PageHeader from "../components/PageHeader";
import ExportCsvButton from "../components/ExportCsvButton";
import { useAuth } from "../stores/authStore";
import { useToast } from "../components/Toast";
import { COMMAND_EVENT_TYPES } from "../constants/events";
import { runbookFor } from "../lib/runbook";

const DISPOSITION_LABEL = {
  investigating: "Đang xử lý",
  false_positive: "Xác nhận false positive",
  confirmed_new_pattern: "Xác nhận mẫu mới thật (admin)",
};

// One-event incident PDF — plain pdf.text() calls, not a screenshot: a
// single event's fields don't need a rendered-page capture, and text is
// crisper and more reliable than html2canvas for this.
function exportEventPdf(event) {
  const pdf = new jsPDF({ orientation: "p", unit: "pt", format: "a4" });
  let y = 50;
  const line = (text, size = 10, gap = 18) => {
    pdf.setFontSize(size);
    const wrapped = pdf.splitTextToSize(text, 500);
    pdf.text(wrapped, 40, y);
    y += gap * wrapped.length;
  };
  line("Báo cáo sự cố — Web-SCADA IDS", 16, 26);
  line(`Xuất lúc: ${new Date().toLocaleString()}`, 9, 16);
  y += 8;
  line(`Thời điểm sự kiện: ${formatTime(event.timestamp)}`);
  line(`Loại: ${event.event_type}`);
  line(`Mức độ: ${event.severity}    Trạng thái: ${event.status}`);
  line(`Nội dung: ${event.message}`);
  if (event.tag_key) line(`Tag liên quan: ${event.tag_key}`);
  if (event.labels?.length) line(`Nhãn dự đoán liên quan: ${event.labels.join(", ")}`);
  y += 4;
  line(`Người xác nhận: ${event.acked_by || "chưa ai xác nhận"}`);
  if (event.acked_at) line(`Lúc xác nhận: ${formatTime(event.acked_at)}`);
  if (event.disposition) line(`Trạng thái xử lý: ${DISPOSITION_LABEL[event.disposition] || event.disposition}`);
  if (event.note) line(`Ghi chú: ${event.note}`);
  if (event.event_type === "ATTACK_PCAP_DETECTED") {
    line("Tra cứu chi tiết đầy đủ lần phân tích liên quan tại trang Lịch sử phân tích PCAP.", 9);
  }
  pdf.save(`incident_${event.id.slice(0, 8)}.pdf`);
}

// Cảnh báo hệ thống và nhật ký lệnh điều khiển PLC dùng chung 1 nguồn
// (GET /events) — tách thành 2 mảng ngay từ 1 lần fetch/1 WS stream thay vì
// gọi 2 lần, và gộp chung 1 trang thay vì 2 trang riêng vì cả hai đều chỉ là
// "chuyện gì vừa xảy ra" và cùng yêu cầu role operator+ để thấy phần nhật ký.
export default function AlarmEvents() {
  const { hasRole } = useAuth();
  const toast = useToast();
  const [events, setEvents] = useState([]);
  const [commandEvents, setCommandEvents] = useState([]);
  const [lastUpdate, setLastUpdate] = useState(null);
  const [lock, setLock] = useState(null);
  const [unlocking, setUnlocking] = useState(false);
  const activeCount = events.filter((e) => e.status === "ACTIVE").length;

  useEffect(() => {
    fetchEvents(500).then((data) => {
      const all = data.events || [];
      setEvents(all.filter((e) => !COMMAND_EVENT_TYPES.includes(e.event_type)));
      setCommandEvents(all.filter((e) => COMMAND_EVENT_TYPES.includes(e.event_type)));
      setLastUpdate(data.timestamp || null);
    });
    fetchWriteLock().then(setLock).catch(() => {});

    const unsub = connectWebSocket((data) => {
      if (data.type !== "event" || !data.event) return;
      const isCommand = COMMAND_EVENT_TYPES.includes(data.event.event_type);
      const setter = isCommand ? setCommandEvents : setEvents;
      setter((prev) => {
        const existingIndex = prev.findIndex((e) => e.id === data.event.id);
        if (existingIndex !== -1) {
          const next = [...prev];
          next[existingIndex] = data.event;
          return next;
        }
        return [data.event, ...prev].slice(0, 500);
      });
      setLastUpdate(data.event.timestamp);
      // Lock state changed elsewhere (auto-trigger or another admin) —
      // re-fetch instead of guessing the shape from the event payload.
      if (data.event.event_type === "WRITE_LOCK_ENGAGED" || data.event.event_type === "WRITE_LOCK_RELEASED") {
        fetchWriteLock().then(setLock).catch(() => {});
      }
    });

    return unsub;
  }, []);

  async function handleAck(eventId, { disposition, note } = {}) {
    try {
      const updated = await ackEvent(eventId, { disposition, note });
      setEvents((prev) => prev.map((e) => (e.id === eventId ? updated : e)));
    } catch (err) {
      toast(err.message, { tone: "error" });
    }
  }

  async function handleUnlock() {
    setUnlocking(true);
    try {
      const next = await releaseWriteLock();
      setLock(next);
      toast("Đã mở khóa lệnh ghi PLC.", { tone: "success" });
    } catch (err) {
      toast(err.message, { tone: "error" });
    } finally {
      setUnlocking(false);
    }
  }

  const writeCount = commandEvents.filter((e) => e.event_type === "COMMAND_WRITE").length;
  const rejectedCount = commandEvents.filter((e) => e.event_type === "COMMAND_REJECTED").length;
  const failedCount = commandEvents.filter((e) => e.event_type === "COMMAND_FAILED").length;
  const blockedCount = commandEvents.filter((e) =>
    ["COMMAND_RATE_LIMITED", "ACCESS_DENIED", "COMMAND_BLOCKED_LOCKED"].includes(e.event_type)
  ).length;

  return (
    <div className="p-6 space-y-8">
      <PageHeader
        icon={Bell}
        title="Cảnh báo & Sự kiện"
        subtitle="Cảnh báo hệ thống từ trạng thái tag/kết nối OPC UA thật, cùng nhật ký lệnh điều khiển PLC."
        right={<ExportCsvButton excludeEventTypes={COMMAND_EVENT_TYPES} />}
      />

      {lock?.locked && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-red-600 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          <div className="flex items-start gap-2">
            <Lock size={16} className="mt-0.5 shrink-0" />
            <div>
              <div className="font-semibold">Lệnh ghi PLC qua web đang bị khóa</div>
              <div className="text-xs text-red-400/90">{lock.reason}</div>
              <div className="text-[10px] text-red-400/70">
                Khóa lúc {formatTime(lock.locked_at)} bởi {lock.locked_by === "system" ? "hệ thống (tự động)" : lock.locked_by}
                {" — "}chỉ chặn ghi qua web app này, không khóa được phần mềm khác (TIA Portal...) nếu nối thẳng PLC.
              </div>
            </div>
          </div>
          {hasRole("admin") && (
            <button
              onClick={handleUnlock}
              disabled={unlocking}
              className="flex shrink-0 items-center gap-1.5 rounded border border-red-500 bg-red-900/40 px-3 py-1.5 text-xs font-semibold text-red-200 transition-colors hover:bg-red-900/70 disabled:opacity-50"
            >
              <Unlock size={13} />
              {unlocking ? "Đang mở..." : "Mở khóa"}
            </button>
          )}
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-2">
        <SummaryCard label="Cảnh báo đang hoạt động" value={activeCount} color={activeCount > 0 ? "text-red-400" : "text-green-400"} icon={Bell} />
        <SummaryCard label="Sự kiện đã lưu" value={events.length} icon={Inbox} />
      </div>

      <div className="overflow-hidden rounded-lg border border-gray-700 bg-gray-800 shadow-sm shadow-black/20">
        <div className="border-b border-gray-700 px-4 py-3 text-sm font-semibold text-gray-200">Sự kiện gần đây</div>
        {events.length === 0 ? (
          <div className="flex flex-col items-center gap-2 p-10 text-sm text-gray-500">
            <Inbox size={28} className="text-gray-700" />
            Chưa có sự kiện nào được ghi nhận.
          </div>
        ) : (
          <div className="max-h-[600px] divide-y divide-gray-700 overflow-y-auto">
            {events.map((event) => (
              <EventRow key={event.id} event={event} onAck={handleAck} />
            ))}
          </div>
        )}
      </div>

      {lastUpdate && <div className="text-right text-xs text-gray-600">Cập nhật sự kiện gần nhất: {lastUpdate}</div>}

      {hasRole("operator") && (
        <div className="space-y-4 border-t border-gray-800 pt-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-semibold text-gray-200">
              <ClipboardList size={16} className="text-gray-500" />
              Nhật ký điều khiển
            </div>
            <ExportCsvButton eventTypes={COMMAND_EVENT_TYPES} label="Xuất nhật ký CSV" />
          </div>
          <p className="text-xs text-gray-500">Mọi lệnh ghi xuống PLC thật — thành công, bị từ chối, hoặc lỗi.</p>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <SummaryCard label="Lệnh thành công" value={writeCount} color="text-green-400" icon={ShieldCheck} />
            <SummaryCard label="Bị từ chối (validate)" value={rejectedCount} color="text-yellow-400" icon={ShieldAlert} />
            <SummaryCard label="Lỗi (không kết nối...)" value={failedCount} color="text-red-400" icon={ShieldX} />
            <SummaryCard label="Bị chặn (rate-limit / quyền)" value={blockedCount} color="text-orange-400" icon={ShieldAlert} />
          </div>

          <div className="overflow-hidden rounded-lg border border-gray-700 bg-gray-800 shadow-sm shadow-black/20">
            {commandEvents.length === 0 ? (
              <div className="flex flex-col items-center gap-2 p-10 text-sm text-gray-500">
                <ClipboardList size={28} className="text-gray-700" />
                Chưa có lệnh điều khiển nào được ghi nhận — có dữ liệu sau khi ai đó (vai trò controller trở lên) gửi lệnh ở Giám sát tiến trình.
              </div>
            ) : (
              <div className="max-h-[500px] divide-y divide-gray-700 overflow-y-auto">
                {commandEvents.map((event) => (
                  <AuditRow key={event.id} event={event} />
                ))}
              </div>
            )}
          </div>
        </div>
      )}
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
  const [formOpen, setFormOpen] = useState(false);
  const [note, setNote] = useState("");
  const [disposition, setDisposition] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const severityColor = {
    INFO: "text-blue-300 bg-blue-950/40",
    WARN: "text-yellow-300 bg-yellow-950/40",
    ERROR: "text-red-300 bg-red-950/40",
  }[event.severity] || "text-gray-300 bg-gray-900";
  const statusColor = event.status === "ACTIVE" ? "text-red-400" : "text-green-400";
  const needsAck = event.status === "ACTIVE" && !event.acked_by;
  const suggestion = event.labels?.map((l) => [l, runbookFor(l)]).find(([, s]) => s);

  async function submitAck() {
    setSubmitting(true);
    try {
      await onAck(event.id, { disposition: disposition || null, note: note.trim() || null });
      setFormOpen(false);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="px-4 py-3 transition-colors hover:bg-gray-900/40">
      <div className="grid gap-3 md:grid-cols-[140px_110px_1fr_100px_150px_60px] md:items-center">
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
              <div className="text-green-400">Đã xác nhận: {event.acked_by}</div>
              <div className="text-[10px] text-gray-600">{formatTime(event.acked_at)}</div>
              {event.disposition && (
                <div className={`mt-0.5 text-[10px] font-semibold ${event.disposition === "false_positive" ? "text-gray-500" : "text-amber-400"}`}>
                  {DISPOSITION_LABEL[event.disposition]}
                </div>
              )}
            </div>
          ) : needsAck && hasRole("operator") ? (
            <button
              onClick={() => setFormOpen((v) => !v)}
              className="flex items-center gap-1 rounded border border-gray-700 bg-gray-900 px-2 py-1 text-[10px] font-semibold text-gray-300 transition-colors hover:border-blue-600 hover:text-blue-300"
            >
              <Check size={11} />
              Xác nhận
            </button>
          ) : needsAck ? (
            <span className="text-gray-600">Chưa xác nhận</span>
          ) : null}
        </div>
        <button
          onClick={() => exportEventPdf(event)}
          title="Xuất báo cáo sự cố PDF"
          className="flex items-center gap-1 rounded border border-gray-700 bg-gray-900 px-2 py-1 text-[10px] font-semibold text-gray-400 transition-colors hover:border-blue-600 hover:text-blue-300"
        >
          <FileDown size={11} />
          PDF
        </button>
      </div>

      {suggestion && (
        <div className="mt-2 rounded border border-gray-700 bg-gray-900/60 px-3 py-2 text-[11px] text-gray-400">
          <span className="font-semibold text-gray-300">Gợi ý xử lý ({suggestion[0]}): </span>
          {suggestion[1]}
        </div>
      )}

      {formOpen && (
        <div className="mt-2 space-y-2 rounded border border-gray-700 bg-gray-900/60 p-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[11px] text-gray-500">Trạng thái xử lý:</span>
            {[
              ["", "Đã xác nhận"],
              ["investigating", "Đang xử lý"],
              ["false_positive", "False positive"],
              ...(event.event_type === "IDS_ANOMALY_DETECTED" && hasRole("admin")
                ? [["confirmed_new_pattern", "Xác nhận mẫu mới thật"]]
                : []),
            ].map(([val, lbl]) => (
              <button
                key={val}
                onClick={() => setDisposition(val)}
                className={`rounded px-2 py-1 text-[10px] font-semibold transition-colors ${
                  disposition === val ? "bg-blue-600 text-white" : "bg-gray-800 text-gray-400 hover:text-gray-200"
                }`}
              >
                {lbl}
              </button>
            ))}
          </div>
          <textarea
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Ghi chú (tùy chọn) — vì sao, đã làm gì..."
            rows={2}
            className="w-full rounded border border-gray-700 bg-gray-950 px-2 py-1.5 text-xs text-gray-200 placeholder:text-gray-600 focus:border-blue-600 focus:outline-none"
          />
          <div className="flex items-center gap-2">
            <button
              onClick={submitAck}
              disabled={submitting}
              className="rounded bg-blue-600 px-3 py-1 text-[11px] font-semibold text-white transition-colors hover:bg-blue-500 disabled:opacity-50"
            >
              {submitting ? "Đang gửi..." : "Gửi xác nhận"}
            </button>
            <button onClick={() => setFormOpen(false)} className="text-[11px] text-gray-500 hover:text-gray-300">
              Hủy
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

const TYPE_STYLE = {
  COMMAND_WRITE: { label: "ĐÃ GHI", color: "text-green-300 bg-green-950/40" },
  COMMAND_REJECTED: { label: "TỪ CHỐI", color: "text-yellow-300 bg-yellow-950/40" },
  COMMAND_FAILED: { label: "LỖI", color: "text-red-300 bg-red-950/40" },
  COMMAND_RATE_LIMITED: { label: "BỊ CHẶN TỐC ĐỘ", color: "text-orange-300 bg-orange-950/40" },
  ACCESS_DENIED: { label: "TỪ CHỐI TRUY CẬP", color: "text-orange-300 bg-orange-950/40" },
  COMMAND_BLOCKED_LOCKED: { label: "BỊ KHÓA", color: "text-red-300 bg-red-950/40" },
};

function AuditRow({ event }) {
  const style = TYPE_STYLE[event.event_type] || { label: event.event_type, color: "text-gray-300 bg-gray-900" };
  return (
    <div className="grid gap-3 px-4 py-3 text-xs transition-colors hover:bg-gray-900/40 md:grid-cols-[140px_100px_100px_140px_1fr] md:items-center">
      <div className="text-gray-500">{formatTime(event.timestamp)}</div>
      <span className={`w-fit rounded px-2 py-1 text-[10px] font-bold ${style.color}`}>{style.label}</span>
      <div className="text-gray-400">{event.tag_key || "—"}</div>
      <div className="font-mono text-gray-400">
        {event.old_value !== null && event.old_value !== undefined ? String(event.old_value) : "—"}
        {" → "}
        {event.new_value !== null && event.new_value !== undefined ? String(event.new_value) : "—"}
      </div>
      <div className="text-gray-500">{event.message}</div>
    </div>
  );
}

function formatTime(value) {
  if (!value) return "N/A";
  return new Date(value).toLocaleString();
}
