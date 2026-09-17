import { useEffect, useState } from "react";
import { jsPDF } from "jspdf";
import { Bell, Check, CheckCircle2, ChevronRight, ClipboardList, FileDown, History, Inbox, LifeBuoy, Lock, RotateCcw, Search, ShieldAlert, ShieldCheck, ShieldX, Unlock, UserPlus, UserCheck } from "lucide-react";
import { ackEvent, ackEventsBulk, assignEvent, fetchAssignableUsers, fetchEvents, fetchWriteLock, releaseWriteLock, reopenEvent, requestSupport, resolveEvent, resolveEventsBulk } from "../services/api";
import { connectWebSocket } from "../services/websocket";
import PageHeader from "../components/PageHeader";
import ExportCsvButton from "../components/ExportCsvButton";
import { useAuth } from "../stores/authStore";
import { useToast } from "../components/Toast";
import { COMMAND_EVENT_TYPES } from "../constants/events";
import { runbookFor } from "../lib/runbook";

// Phải khớp CONDITION_BASED_EVENT_TYPES ở backend (events/service.py) — các
// loại cảnh báo có tín hiệu vật lý "đã phục hồi" thật (khác sự kiện pháp y
// một-lần như ATTACK_PCAP_DETECTED, không có gì tự chuyển CLEARED cho nó).
const CONDITION_BASED_EVENT_TYPES = new Set([
  "PLC_DISCONNECTED",
  "OPCUA_STALE",
  "STAGE_TIMER_OUT_OF_RANGE",
  "ATTACK_SENSOR_SPOOF_SUSPECTED",
  "WRITE_LOCK_ENGAGED",
]);

const DISPOSITION_LABEL = {
  investigating: "Đang điều tra",
  false_positive: "Xác nhận báo động giả",
  confirmed_new_pattern: "Xác nhận mẫu mới thật (admin)",
};

const AUDIT_ACTION_LABEL = {
  ack: "Xác nhận",
  disposition: "Đổi phân loại",
  note: "Cập nhật ghi chú",
  assign: "Giao vụ",
  resolve: "Đóng vụ",
  reopen: "Mở lại vụ",
  request_support: "Yêu cầu hỗ trợ",
  cancel_support: "Hủy yêu cầu hỗ trợ",
};

function dispositionText(value) {
  return value ? DISPOSITION_LABEL[value] || value : "Đã xác nhận";
}

// One-event incident PDF — plain pdf.text() calls, not a screenshot: a
// single event's fields don't need a rendered-page capture, and text is
// crisper and more reliable than html2canvas for this.
// jsPDF's built-in fonts (Helvetica etc.) only support WinAnsi encoding —
// no Vietnamese diacritics. Feeding them accented text silently renders
// garbled bytes ("Báo cáo sự cố" -> "Báo cáo sñ cÑ") instead of erroring,
// so this went unnoticed until someone actually opened the PDF. Stripping
// diacritics before every pdf.text() call is the same fix already used in
// IdsUpload.jsx's PDF export for this identical jsPDF limitation.
function stripDiacritics(text) {
  return String(text)
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/đ/g, "d")
    .replace(/Đ/g, "D");
}

function exportEventPdf(event) {
  const pdf = new jsPDF({ orientation: "p", unit: "pt", format: "a4" });
  let y = 50;
  const line = (text, size = 10, gap = 18) => {
    pdf.setFontSize(size);
    const wrapped = pdf.splitTextToSize(stripDiacritics(text), 500);
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
  if (event.assignee) line(`Người được giao xử lý: ${event.assignee}`);
  line(`Đóng vụ: ${event.resolved_by ? `${event.resolved_by} lúc ${formatTime(event.resolved_at)}` : "chưa đóng"}`);
  if (event.note) line(`Ghi chú: ${event.note}`);
  if (event.audit?.length) {
    y += 4;
    line("Nhật ký xử lý:", 11, 18);
    for (const a of event.audit) {
      const chg = a.from !== undefined || a.to !== undefined ? ` (${dispositionText(a.from)} -> ${dispositionText(a.to)})` : "";
      line(`- ${formatTime(a.at)} — ${AUDIT_ACTION_LABEL[a.action] || a.action} bởi ${a.by}${chg}${a.note ? ` — ${a.note}` : ""}`, 9, 14);
    }
  }
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
  const { hasRole, username } = useAuth();
  const toast = useToast();
  const [events, setEvents] = useState([]);
  const [commandEvents, setCommandEvents] = useState([]);
  const [lastUpdate, setLastUpdate] = useState(null);
  const [lock, setLock] = useState(null);
  const [unlocking, setUnlocking] = useState(false);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [mineOnly, setMineOnly] = useState(false);
  const [selectedIds, setSelectedIds] = useState(() => new Set());
  const [bulkAcking, setBulkAcking] = useState(false);
  const [users, setUsers] = useState([]);
  const activeCount = events.filter((e) => e.status === "ACTIVE").length;

  const filteredEvents = events.filter((e) => {
    if (severityFilter !== "ALL" && e.severity !== severityFilter) return false;
    if (statusFilter !== "ALL" && e.status !== statusFilter) return false;
    if (mineOnly && e.assignee !== username) return false;
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      if (!e.message?.toLowerCase().includes(q) && !e.event_type?.toLowerCase().includes(q)) return false;
    }
    return true;
  });

  // Only rows an operator could individually ACK are selectable — matches
  // EventRow's own needsAck check (ACTIVE + not yet acked).
  const pendingIds = filteredEvents.filter((e) => e.status === "ACTIVE" && !e.acked_by).map((e) => e.id);
  // Đã xác nhận nhưng chưa đóng vụ — mutually exclusive với pendingIds
  // (một sự kiện không thể vừa "chưa xác nhận" vừa "đã xác nhận"), nên dùng
  // chung 1 checkbox/selectedIds cho cả 2 nhóm là an toàn.
  const resolvableIds = filteredEvents.filter((e) => e.acked_by && !e.resolved_by).map((e) => e.id);

  useEffect(() => {
    fetchEvents(500).then((data) => {
      const all = data.events || [];
      setEvents(all.filter((e) => !COMMAND_EVENT_TYPES.includes(e.event_type)));
      setCommandEvents(all.filter((e) => COMMAND_EVENT_TYPES.includes(e.event_type)));
      setLastUpdate(data.timestamp || null);
    });
    fetchWriteLock().then(setLock).catch(() => {});
    // Danh sách người CÓ THỂ nhận giao xử lý (operator+). Endpoint riêng mở
    // cho operator+ (khác /auth/users admin-only), trả về [{username, role}].
    // Chỉ operator+ mới thấy/ dùng phần giao vụ.
    if (hasRole("operator")) {
      fetchAssignableUsers().then((data) => setUsers(data.users || [])).catch(() => {});
    }

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

  function applyUpdate(updated) {
    setEvents((prev) => prev.map((e) => (e.id === updated.id ? updated : e)));
  }

  async function handleAck(eventId, { disposition, note } = {}) {
    try {
      const updated = await ackEvent(eventId, { disposition, note });
      applyUpdate(updated);
    } catch (err) {
      toast(err.message, { tone: "error" });
    }
  }

  function toggleSelect(eventId) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(eventId)) next.delete(eventId);
      else next.add(eventId);
      return next;
    });
  }

  function selectAllPending() {
    setSelectedIds(new Set(pendingIds));
  }

  function selectAllResolvable() {
    setSelectedIds(new Set(resolvableIds));
  }

  async function handleAckBulk(disposition) {
    if (selectedIds.size === 0) return;
    setBulkAcking(true);
    try {
      const { acked, not_found } = await ackEventsBulk([...selectedIds], { disposition });
      const ackedById = new Map(acked.map((e) => [e.id, e]));
      setEvents((prev) => prev.map((e) => ackedById.get(e.id) || e));
      setSelectedIds(new Set());
      toast(`Đã xác nhận ${acked.length} sự kiện.${not_found.length ? ` (${not_found.length} không tìm thấy)` : ""}`, { tone: "success" });
    } catch (err) {
      toast(err.message, { tone: "error" });
    } finally {
      setBulkAcking(false);
    }
  }

  async function handleResolveBulk() {
    if (selectedIds.size === 0) return;
    setBulkAcking(true);
    try {
      const { resolved, not_found, blocked } = await resolveEventsBulk([...selectedIds]);
      const resolvedById = new Map(resolved.map((e) => [e.id, e]));
      setEvents((prev) => prev.map((e) => resolvedById.get(e.id) || e));
      setSelectedIds(new Set());
      const extra = [
        not_found.length ? `${not_found.length} không tìm thấy` : null,
        blocked.length ? `${blocked.length} chưa đóng được vì sự cố còn ACTIVE` : null,
      ].filter(Boolean).join(", ");
      toast(`Đã đóng vụ ${resolved.length} sự kiện.${extra ? ` (${extra})` : ""}`, { tone: resolved.length ? "success" : "error" });
    } catch (err) {
      toast(err.message, { tone: "error" });
    } finally {
      setBulkAcking(false);
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

      {hasRole("operator") && selectedIds.size > 0 && (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border border-cyan-700/60 bg-cyan-950/30 px-4 py-3 text-sm">
          <span className="font-semibold text-cyan-200">Đã chọn {selectedIds.size} sự kiện</span>
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => handleAckBulk(null)}
              disabled={bulkAcking}
              className="rounded bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-cyan-500 disabled:opacity-50"
            >
              Xác nhận tất cả
            </button>
            <button
              onClick={() => handleAckBulk("false_positive")}
              disabled={bulkAcking}
              className="rounded border border-gray-600 bg-gray-800 px-3 py-1.5 text-xs text-gray-200 transition-colors hover:border-gray-500 disabled:opacity-50"
            >
              Báo động giả
            </button>
            <button
              onClick={handleResolveBulk}
              disabled={bulkAcking}
              className="rounded bg-emerald-700 px-3 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-emerald-600 disabled:opacity-50"
            >
              Đóng vụ hàng loạt
            </button>
          </div>
          <button onClick={() => setSelectedIds(new Set())} className="ml-auto text-xs text-gray-500 hover:text-gray-300">
            Bỏ chọn
          </button>
        </div>
      )}

      <div className="overflow-hidden rounded-lg border border-gray-700 bg-gray-800 shadow-sm shadow-black/20">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-700 px-4 py-3">
          <div className="flex items-center gap-3">
            <div className="text-sm font-semibold text-gray-200">
              Sự kiện gần đây {filteredEvents.length !== events.length && <span className="text-gray-500">({filteredEvents.length}/{events.length})</span>}
            </div>
            {hasRole("operator") && pendingIds.length > 0 && (
              <button onClick={selectAllPending} className="text-xs text-cyan-400 hover:text-cyan-300">
                Chọn tất cả {pendingIds.length} sự kiện đang chờ xác nhận
              </button>
            )}
            {hasRole("operator") && resolvableIds.length > 0 && (
              <button onClick={selectAllResolvable} className="text-xs text-emerald-400 hover:text-emerald-300">
                Chọn tất cả {resolvableIds.length} sự kiện đang chờ đóng vụ
              </button>
            )}
          </div>
          {events.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative">
                <Search size={12} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-600" />
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Tìm theo nội dung / loại..."
                  className="w-56 rounded border border-gray-700 bg-gray-900 py-1.5 pl-7 pr-2 text-xs text-gray-200 outline-none focus:border-cyan-500"
                />
              </div>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="rounded border border-gray-700 bg-gray-900 px-2 py-1.5 text-xs text-gray-300"
              >
                <option value="ALL">Mọi mức độ</option>
                <option value="ERROR">ERROR</option>
                <option value="WARNING">WARNING</option>
                <option value="INFO">INFO</option>
              </select>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="rounded border border-gray-700 bg-gray-900 px-2 py-1.5 text-xs text-gray-300"
              >
                <option value="ALL">Mọi trạng thái</option>
                <option value="ACTIVE">ACTIVE</option>
                <option value="CLEARED">CLEARED</option>
              </select>
              {hasRole("operator") && (
                <button
                  onClick={() => setMineOnly((v) => !v)}
                  className={`flex items-center gap-1 rounded border px-2 py-1.5 text-xs transition-colors ${
                    mineOnly ? "border-cyan-500 bg-cyan-950/40 text-cyan-300" : "border-gray-700 bg-gray-900 text-gray-300 hover:border-gray-600"
                  }`}
                >
                  <UserCheck size={12} /> Việc của tôi
                </button>
              )}
            </div>
          )}
        </div>
        {events.length === 0 ? (
          <div className="flex flex-col items-center gap-2 p-10 text-sm text-gray-500">
            <Inbox size={28} className="text-gray-700" />
            Chưa có sự kiện nào được ghi nhận.
          </div>
        ) : filteredEvents.length === 0 ? (
          <div className="flex flex-col items-center gap-2 p-10 text-sm text-gray-500">
            <Search size={28} className="text-gray-700" />
            Không có sự kiện nào khớp bộ lọc.
          </div>
        ) : (
          <div className="max-h-[600px] divide-y divide-gray-700 overflow-y-auto">
            {filteredEvents.map((event) => (
              <EventRow
                key={event.id}
                event={event}
                onAck={handleAck}
                onUpdate={applyUpdate}
                users={users}
                selected={selectedIds.has(event.id)}
                onToggleSelect={toggleSelect}
              />
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

function EventRow({ event, onAck, onUpdate, users, selected, onToggleSelect }) {
  const { hasRole, username } = useAuth();
  const toast = useToast();
  const [panelOpen, setPanelOpen] = useState(false);
  const [suggestionOpen, setSuggestionOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [note, setNote] = useState("");
  const [disposition, setDisposition] = useState("");
  const [assignVal, setAssignVal] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [busy, setBusy] = useState(false);

  const severityColor = {
    INFO: "text-blue-300 bg-blue-950/40",
    WARN: "text-yellow-300 bg-yellow-950/40",
    ERROR: "text-red-300 bg-red-950/40",
  }[event.severity] || "text-gray-300 bg-gray-900";
  const statusColor = event.status === "ACTIVE" ? "text-red-400" : "text-green-400";
  const needsAck = event.status === "ACTIVE" && !event.acked_by;
  const acked = !!event.acked_by;
  const resolved = !!event.resolved_by;
  const needsClaim = acked && !resolved && !event.assignee;
  const selectable = needsAck || (acked && !resolved);
  const resolveBlocked = CONDITION_BASED_EVENT_TYPES.has(event.event_type) && event.status === "ACTIVE";
  const suggestion = event.labels?.map((l) => [l, runbookFor(l)]).find(([, s]) => s);
  const canOperate = hasRole("operator");

  function openPanel() {
    // Nạp sẵn phân loại/ghi chú hiện tại để re-classify hiển thị đúng giá trị cũ.
    setDisposition(event.disposition || "");
    setNote(event.note || "");
    setAssignVal(event.assignee || "");
    setPanelOpen((v) => !v);
  }

  async function submitAck() {
    setSubmitting(true);
    try {
      await onAck(event.id, { disposition: disposition || null, note: note.trim() || null });
      setPanelOpen(false);
    } finally {
      setSubmitting(false);
    }
  }

  async function runAction(fn, okMsg) {
    setBusy(true);
    try {
      const updated = await fn();
      onUpdate(updated);
      if (okMsg) toast(okMsg, { tone: "success" });
    } catch (err) {
      toast(err.message, { tone: "error" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="px-4 py-3 transition-colors hover:bg-gray-900/40">
      <div className="grid gap-3 md:grid-cols-[20px_140px_110px_1fr_100px_170px_60px] md:items-center">
        <div>
          {selectable && canOperate && (
            <input
              type="checkbox"
              checked={!!selected}
              onChange={() => onToggleSelect(event.id)}
              className="h-3.5 w-3.5 accent-cyan-500"
              title={needsAck ? "Chọn để xác nhận hàng loạt" : "Chọn để đóng vụ hàng loạt"}
            />
          )}
        </div>
        <div className="text-xs text-gray-500">{formatTime(event.timestamp)}</div>
        <div>
          <span className={`rounded px-2 py-1 text-[10px] font-bold ${severityColor}`}>{event.severity}</span>
        </div>
        <div>
          <div className="flex items-center gap-1.5">
            <div className="text-sm font-semibold text-gray-200">{event.event_type}</div>
            {event.support_requested_by && (
              <span title={`${event.support_requested_by} yêu cầu admin hỗ trợ`} className="flex items-center gap-0.5 rounded bg-rose-950/50 px-1 py-0.5 text-[9px] font-bold text-rose-300">
                <LifeBuoy size={9} /> HỖ TRỢ
              </span>
            )}
          </div>
          <div className="text-xs text-gray-500">{event.message}</div>
          {event.tag_key && <div className="text-[10px] text-gray-600">Tag: {event.tag_key}</div>}
        </div>
        <div className={`text-xs font-bold ${statusColor}`}>{event.status}</div>
        <div className="text-xs">
          {acked ? (
            <div className="text-gray-500">
              <div className="text-green-400">Đã xác nhận: {event.acked_by}</div>
              <div className="text-[10px] text-gray-600">{formatTime(event.acked_at)}</div>
              {event.disposition && (
                <div className={`mt-0.5 text-[10px] font-semibold ${event.disposition === "false_positive" ? "text-gray-500" : "text-amber-400"}`}>
                  {dispositionText(event.disposition)}
                </div>
              )}
              {event.assignee ? (
                <div className="mt-0.5 text-[10px] font-semibold text-amber-400">Đang xử lý: {event.assignee}</div>
              ) : needsClaim && canOperate ? (
                <button
                  onClick={() => runAction(() => assignEvent(event.id, username), "Đã tiếp nhận vụ này.")}
                  disabled={busy}
                  className="mt-0.5 flex items-center gap-1 rounded border border-cyan-700 bg-cyan-950/40 px-1.5 py-0.5 text-[10px] font-semibold text-cyan-300 hover:bg-cyan-900/40 disabled:opacity-50"
                >
                  <UserPlus size={10} /> Tiếp nhận vụ này
                </button>
              ) : null}
              {resolved ? (
                <div className="mt-0.5 flex items-center gap-1 text-[10px] font-semibold text-emerald-400">
                  <CheckCircle2 size={10} /> Đã đóng · {event.resolved_by}
                </div>
              ) : (
                <div className="text-[10px] text-orange-400/80">Chưa đóng vụ</div>
              )}
              {canOperate && (
                <button onClick={openPanel} className="mt-1 text-[10px] text-blue-400 hover:text-blue-300">
                  {panelOpen ? "Ẩn xử lý" : "Xử lý ▾"}
                </button>
              )}
            </div>
          ) : needsAck && canOperate ? (
            <button
              onClick={openPanel}
              className="flex items-center gap-1 rounded border border-gray-700 bg-gray-900 px-2 py-1 text-[10px] font-semibold text-gray-300 transition-colors hover:border-blue-600 hover:text-blue-300"
            >
              <Check size={11} />
              Xác nhận
            </button>
          ) : needsAck ? (
            <span className="text-gray-600">Chưa xác nhận</span>
          ) : null}
        </div>
        {/* Only WARNING/ERROR are actual "incidents" worth a report — a
        routine INFO event (PLC_CONNECTED, OPCUA_RECONNECTED...) has nothing
        incident-like to report on, the button was just noise there. */}
        {event.severity !== "INFO" ? (
          <button
            onClick={() => exportEventPdf(event)}
            title="Xuất báo cáo sự cố PDF"
            className="flex items-center gap-1 rounded border border-gray-700 bg-gray-900 px-2 py-1 text-[10px] font-semibold text-gray-400 transition-colors hover:border-blue-600 hover:text-blue-300"
          >
            <FileDown size={11} />
            PDF
          </button>
        ) : (
          <div />
        )}
      </div>

      {suggestion && (
        <div className="mt-2">
          <button
            onClick={() => setSuggestionOpen((v) => !v)}
            className="flex items-center gap-1 text-[11px] text-gray-500 transition-colors hover:text-gray-300"
          >
            <ChevronRight size={11} className={`transition-transform ${suggestionOpen ? "rotate-90" : ""}`} />
            Gợi ý xử lý ({suggestion[0]})
          </button>
          {suggestionOpen && (
            <div className="mt-1 rounded border border-gray-700 bg-gray-900/60 px-3 py-2 text-[11px] text-gray-400">
              {suggestion[1]}
            </div>
          )}
        </div>
      )}

      {panelOpen && canOperate && (
        <div className="mt-2 space-y-3 rounded border border-gray-700 bg-gray-900/60 p-3">
          {/* 1. Phân loại — chỉ 2 KẾT LUẬN có ý nghĩa khác nhau thật (không phải
          trạng thái trung gian): Báo động giả, hoặc Xác nhận mẫu mới thật
          (admin). "Đang xử lý" không còn là 1 lựa chọn tay ở đây nữa — nó tự
          suy ra từ việc có assignee hay chưa (xem "Đang xử lý: {assignee}"
          phía trên), tránh 2 field lệch nhau. */}
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[11px] text-gray-500">Phân loại:</span>
              {[
                ["", "Đã xác nhận"],
                ["false_positive", "Báo động giả"],
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
                {submitting ? "Đang gửi..." : acked ? "Cập nhật phân loại" : "Gửi xác nhận"}
              </button>
              <button onClick={() => setPanelOpen(false)} className="text-[11px] text-gray-500 hover:text-gray-300">
                Đóng
              </button>
            </div>
          </div>

          {/* 2 & 3 chỉ có nghĩa sau khi đã xác nhận */}
          {acked && (
            <div className="flex flex-wrap items-end gap-4 border-t border-gray-800 pt-3">
              {/* Giao xử lý */}
              <div className="space-y-1">
                <div className="flex items-center gap-1 text-[11px] text-gray-500"><UserPlus size={11} /> Giao cho</div>
                <div className="flex items-center gap-1">
                  {users.length > 0 ? (
                    <>
                      <select
                        value={assignVal}
                        onChange={(e) => setAssignVal(e.target.value)}
                        className="rounded border border-gray-700 bg-gray-950 px-2 py-1 text-[11px] text-gray-200"
                      >
                        <option value="">— chọn người —</option>
                        {users.map((u) => (
                          <option key={u.username} value={u.username}>{u.username} ({u.role})</option>
                        ))}
                      </select>
                      <button
                        onClick={() => runAction(() => assignEvent(event.id, assignVal || null), "Đã cập nhật người xử lý.")}
                        disabled={busy}
                        className="rounded bg-cyan-700 px-2 py-1 text-[10px] font-semibold text-white hover:bg-cyan-600 disabled:opacity-50"
                      >
                        Giao
                      </button>
                      {event.assignee && (
                        <button
                          onClick={() => { setAssignVal(""); runAction(() => assignEvent(event.id, null), "Đã bỏ giao."); }}
                          disabled={busy}
                          className="text-[10px] text-gray-500 hover:text-gray-300"
                        >
                          Bỏ giao
                        </button>
                      )}
                    </>
                  ) : (
                    <span className="text-[10px] text-gray-600">Chưa có người dùng operator+ nào để giao.</span>
                  )}
                </div>
              </div>

              {/* Yêu cầu hỗ trợ — khác "Giao cho": KHÔNG chuyển quyền sở hữu,
              chỉ đánh dấu để admin để ý (badge HỖ TRỢ + StatusBar). Không
              cần chuyển hẳn vụ cho admin (điều mà assign() giờ chặn theo
              cấp bậc) mới báo được là cần admin xem qua. */}
              {!resolved && (
                <div className="space-y-1">
                  <div className="flex items-center gap-1 text-[11px] text-gray-500"><LifeBuoy size={11} /> Hỗ trợ</div>
                  {event.support_requested_by ? (
                    <button
                      onClick={() => runAction(() => requestSupport(event.id, false), "Đã hủy yêu cầu hỗ trợ.")}
                      disabled={busy}
                      className="flex items-center gap-1 rounded border border-rose-700 bg-rose-950/40 px-2 py-1 text-[10px] font-semibold text-rose-300 hover:bg-rose-900/40 disabled:opacity-50"
                    >
                      <LifeBuoy size={11} /> Hủy yêu cầu ({event.support_requested_by})
                    </button>
                  ) : (
                    <button
                      onClick={() => runAction(() => requestSupport(event.id, true), "Đã gửi yêu cầu hỗ trợ tới admin.")}
                      disabled={busy}
                      className="flex items-center gap-1 rounded border border-gray-600 bg-gray-800 px-2 py-1 text-[10px] font-semibold text-gray-300 hover:border-rose-600 hover:text-rose-300 disabled:opacity-50"
                    >
                      <LifeBuoy size={11} /> Yêu cầu admin hỗ trợ
                    </button>
                  )}
                </div>
              )}

              {/* Đóng / mở lại vụ */}
              <div className="space-y-1">
                <div className="text-[11px] text-gray-500">Kết thúc</div>
                {resolved ? (
                  <button
                    onClick={() => runAction(() => reopenEvent(event.id), "Đã mở lại vụ.")}
                    disabled={busy}
                    className="flex items-center gap-1 rounded border border-orange-700 bg-orange-950/40 px-2 py-1 text-[10px] font-semibold text-orange-300 hover:bg-orange-900/40 disabled:opacity-50"
                  >
                    <RotateCcw size={11} /> Mở lại vụ
                  </button>
                ) : (
                  <div>
                    <button
                      onClick={() => runAction(() => resolveEvent(event.id, note.trim() || null), "Đã đóng vụ.")}
                      disabled={busy || resolveBlocked}
                      title={resolveBlocked ? "Không thể đóng vụ khi sự cố vẫn đang tiếp diễn (status=ACTIVE)." : undefined}
                      className="flex items-center gap-1 rounded bg-emerald-700 px-2 py-1 text-[10px] font-semibold text-white hover:bg-emerald-600 disabled:opacity-50 disabled:hover:bg-emerald-700"
                    >
                      <CheckCircle2 size={11} /> Đã xử lý xong
                    </button>
                    {resolveBlocked && (
                      <div className="mt-1 max-w-[220px] text-[10px] text-orange-400/80">
                        Sự cố vẫn đang tiếp diễn (ACTIVE) — chờ tự phục hồi rồi mới đóng được vụ.
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Nhật ký xử lý (audit trail) — luôn xem được nếu đã có thao tác */}
      {event.audit?.length > 0 && (
        <div className="mt-2">
          <button
            onClick={() => setHistoryOpen((v) => !v)}
            className="flex items-center gap-1 text-[11px] text-gray-500 transition-colors hover:text-gray-300"
          >
            <History size={11} className={`transition-transform ${historyOpen ? "rotate-0" : ""}`} />
            Nhật ký xử lý ({event.audit.length})
          </button>
          {historyOpen && (
            <ul className="mt-1 space-y-1 rounded border border-gray-700 bg-gray-900/60 px-3 py-2 text-[11px] text-gray-400">
              {event.audit.map((a, i) => (
                <li key={i} className="flex flex-wrap gap-x-2">
                  <span className="text-gray-600">{formatTime(a.at)}</span>
                  <span className="font-semibold text-gray-300">{AUDIT_ACTION_LABEL[a.action] || a.action}</span>
                  <span className="text-gray-500">bởi {a.by}</span>
                  {(a.from !== undefined || a.to !== undefined) && (
                    <span className="text-gray-500">({dispositionText(a.from)} → {dispositionText(a.to)})</span>
                  )}
                  {a.note && <span className="text-gray-400">— {a.note}</span>}
                </li>
              ))}
            </ul>
          )}
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
