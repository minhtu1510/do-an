import { useEffect, useState } from "react";
import { Users as UsersIcon, UserPlus, Trash2, AlertTriangle, ShieldCheck } from "lucide-react";
import PageHeader from "../components/PageHeader";
import { addIpAllowlist, changeUserRole, createUser, deleteUser, fetchIpAllowlist, fetchUsers, removeIpAllowlist } from "../services/api";
import { useAuth } from "../stores/authStore";
import { useConfirm } from "../components/ConfirmDialog";
import { useToast } from "../components/Toast";

const ROLES = ["viewer", "operator", "controller", "admin"];

export default function AdminUsers() {
  const { session } = useAuth();
  const confirm = useConfirm();
  const toast = useToast();
  const [users, setUsers] = useState([]);
  const [error, setError] = useState(null);
  const [form, setForm] = useState({ username: "", password: "", role: "viewer" });
  const [busy, setBusy] = useState(false);

  function load() {
    fetchUsers().then(setUsers).catch((e) => setError(e.message));
  }

  useEffect(load, []);

  async function handleCreate(e) {
    e.preventDefault();
    if (form.password.length < 8) {
      toast("Password cần tối thiểu 8 ký tự.", { tone: "error" });
      return;
    }
    setError(null);
    setBusy(true);
    try {
      await createUser(form.username, form.password, form.role);
      setForm({ username: "", password: "", role: "viewer" });
      load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleRoleChange(userId, role) {
    setError(null);
    try {
      await changeUserRole(userId, role);
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleDelete(userId) {
    if (!(await confirm({ title: "Xoá user", message: "Xoá user này? Không thể hoàn tác.", confirmLabel: "Xoá" }))) return;
    setError(null);
    try {
      await deleteUser(userId);
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="p-6 space-y-6">
      <PageHeader icon={UsersIcon} title="Người dùng" subtitle="Quản lý tài khoản và phân quyền (chỉ admin)." />

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-900/50 bg-red-950/30 px-3 py-2 text-sm text-red-400 animate-fade-in">
          <AlertTriangle size={14} className="shrink-0" />
          {error}
        </div>
      )}

      <form onSubmit={handleCreate} className="flex flex-wrap items-end gap-3 rounded-lg border border-gray-700 bg-gray-800 p-4 shadow-sm shadow-black/20">
        <label className="flex flex-col gap-1">
          <span className="text-xs uppercase text-gray-500">Username</span>
          <input
            value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
            className="rounded border border-gray-700 bg-gray-950 px-3 py-1.5 text-sm text-gray-200 outline-none transition-colors focus:border-blue-600"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-xs uppercase text-gray-500">Password</span>
          <input
            type="password"
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            className="rounded border border-gray-700 bg-gray-950 px-3 py-1.5 text-sm text-gray-200 outline-none transition-colors focus:border-blue-600"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-xs uppercase text-gray-500">Role</span>
          <select
            value={form.role}
            onChange={(e) => setForm({ ...form, role: e.target.value })}
            className="rounded border border-gray-700 bg-gray-950 px-3 py-1.5 text-sm text-gray-200 outline-none transition-colors focus:border-blue-600"
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>{r}</option>
            ))}
          </select>
        </label>
        <button
          type="submit"
          disabled={busy || !form.username || !form.password}
          className="flex items-center gap-1.5 rounded bg-blue-600 px-4 py-1.5 text-sm font-semibold text-white shadow-sm shadow-blue-950 transition-colors hover:bg-blue-500 disabled:opacity-50"
        >
          <UserPlus size={14} />
          Tạo user
        </button>
      </form>

      <div className="overflow-hidden rounded-lg border border-gray-700 bg-gray-800 shadow-sm shadow-black/20">
        <div className="grid grid-cols-[1fr_140px_180px_100px] gap-3 border-b border-gray-700 px-4 py-2 text-xs uppercase text-gray-500">
          <div>Username</div>
          <div>Role</div>
          <div>Created</div>
          <div></div>
        </div>
        <div className="divide-y divide-gray-700">
          {users.map((u) => (
            <div key={u.id} className="grid grid-cols-[1fr_140px_180px_100px] items-center gap-3 px-4 py-3 transition-colors hover:bg-gray-900/40">
              <div className="text-sm text-gray-200">{u.username}</div>
              <select
                value={u.role}
                disabled={u.id === session?.id}
                onChange={(e) => handleRoleChange(u.id, e.target.value)}
                className="rounded border border-gray-700 bg-gray-950 px-2 py-1 text-xs text-gray-300 outline-none transition-colors disabled:opacity-40"
              >
                {ROLES.map((r) => (
                  <option key={r} value={r}>{r}</option>
                ))}
              </select>
              <div className="text-xs text-gray-500">{u.created_at ? new Date(u.created_at).toLocaleString() : "—"}</div>
              <button
                onClick={() => handleDelete(u.id)}
                disabled={u.id === session?.id}
                className="flex items-center gap-1 text-xs text-red-400 transition-colors hover:text-red-300 disabled:opacity-30"
              >
                <Trash2 size={12} />
                Xoá
              </button>
            </div>
          ))}
        </div>
      </div>

      <IpAllowlistSection />
    </div>
  );
}

// Real ICS security practice (CISA/NIST recommend IP allowlisting for OT
// networks) — a list of IPs considered legitimate on the PLC network
// (engineering workstations, the PLC itself). Currently used to flag
// unexpected source IPs in the packet detail view on Phân tích lưu lượng
// mạng (an IP outside this list showing up in attack-flagged traffic is a
// stronger signal than one already known).
function IpAllowlistSection() {
  const toast = useToast();
  const confirm = useConfirm();
  const [entries, setEntries] = useState([]);
  const [form, setForm] = useState({ ip: "", label: "" });
  const [busy, setBusy] = useState(false);

  function load() {
    fetchIpAllowlist().then((d) => setEntries(d.entries || [])).catch(() => {});
  }

  useEffect(load, []);

  async function handleAdd(e) {
    e.preventDefault();
    setBusy(true);
    try {
      await addIpAllowlist(form.ip.trim(), form.label.trim());
      setForm({ ip: "", label: "" });
      load();
    } catch (err) {
      toast(err.message, { tone: "error" });
    } finally {
      setBusy(false);
    }
  }

  async function handleRemove(ip) {
    if (!(await confirm({ title: "Xoá IP hợp lệ", message: `Xoá "${ip}" khỏi danh sách IP hợp lệ?`, confirmLabel: "Xoá" }))) return;
    try {
      await removeIpAllowlist(ip);
      load();
    } catch (err) {
      toast(err.message, { tone: "error" });
    }
  }

  return (
    <div className="space-y-4 border-t border-gray-800 pt-8">
      <div className="flex items-center gap-2 text-sm font-semibold text-gray-200">
        <ShieldCheck size={16} className="text-gray-500" />
        IP hợp lệ trên mạng PLC
      </div>
      <p className="text-xs text-gray-500">
        Máy trạm kỹ sư / thiết bị được coi là hợp lệ trên mạng PLC — dùng để đánh dấu IP lạ trong chi tiết gói tin ở trang "Phân tích lưu lượng mạng".
      </p>

      <form onSubmit={handleAdd} className="flex flex-wrap items-end gap-3 rounded-lg border border-gray-700 bg-gray-800 p-4 shadow-sm shadow-black/20">
        <label className="flex flex-col gap-1">
          <span className="text-xs uppercase text-gray-500">IP</span>
          <input
            value={form.ip}
            onChange={(e) => setForm({ ...form, ip: e.target.value })}
            placeholder="192.168.210.31"
            className="rounded border border-gray-700 bg-gray-950 px-3 py-1.5 text-sm text-gray-200 outline-none transition-colors focus:border-blue-600"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-xs uppercase text-gray-500">Ghi chú</span>
          <input
            value={form.label}
            onChange={(e) => setForm({ ...form, label: e.target.value })}
            placeholder="Máy kỹ sư 1"
            className="rounded border border-gray-700 bg-gray-950 px-3 py-1.5 text-sm text-gray-200 outline-none transition-colors focus:border-blue-600"
          />
        </label>
        <button
          type="submit"
          disabled={busy || !form.ip}
          className="flex items-center gap-1.5 rounded bg-blue-600 px-4 py-1.5 text-sm font-semibold text-white shadow-sm shadow-blue-950 transition-colors hover:bg-blue-500 disabled:opacity-50"
        >
          <UserPlus size={14} />
          Thêm IP
        </button>
      </form>

      <div className="overflow-hidden rounded-lg border border-gray-700 bg-gray-800 shadow-sm shadow-black/20">
        <div className="grid grid-cols-[160px_1fr_140px_100px] gap-3 border-b border-gray-700 px-4 py-2 text-xs uppercase text-gray-500">
          <div>IP</div>
          <div>Ghi chú</div>
          <div>Thêm bởi</div>
          <div></div>
        </div>
        {entries.length === 0 ? (
          <div className="p-6 text-center text-xs text-gray-500">Chưa có IP nào — mọi IP hiện đều được coi là "chưa xác định" trong chi tiết gói tin.</div>
        ) : (
          <div className="divide-y divide-gray-700">
            {entries.map((e) => (
              <div key={e.ip} className="grid grid-cols-[160px_1fr_140px_100px] items-center gap-3 px-4 py-3 text-sm text-gray-200">
                <div className="font-mono">{e.ip}</div>
                <div className="text-gray-400">{e.label || "—"}</div>
                <div className="text-xs text-gray-500">{e.added_by}</div>
                <button onClick={() => handleRemove(e.ip)} className="flex items-center gap-1 text-xs text-red-400 transition-colors hover:text-red-300">
                  <Trash2 size={12} />
                  Xoá
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
