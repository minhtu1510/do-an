import { Routes, Route, Navigate, NavLink, useLocation } from "react-router-dom";
import {
  LayoutDashboard, Workflow, Bell, TrendingUp, ShieldCheck,
  UploadCloud, ServerCog, Users as UsersIcon, ChevronRight, FileClock,
  Database, Settings2,
} from "lucide-react";
import StatusBar from "./components/StatusBar";
import Overview from "./pages/Overview";
import ProcessMonitor from "./pages/ProcessMonitor";
import AlarmEvents from "./pages/AlarmEvents";
import Trends from "./pages/Trends";
import SystemStatus from "./pages/SystemStatus";
import IdsUpload from "./pages/IdsUpload";
import PcapHistory from "./pages/PcapHistory";
import Login from "./pages/Login";
import AdminUsers from "./pages/AdminUsers";
import { AuthProvider, useAuth } from "./stores/authStore";
import { ConfirmProvider } from "./components/ConfirmDialog";
import { ToastProvider } from "./components/Toast";

const NAV_GROUPS = [
  {
    label: "Tổng quan",
    icon: LayoutDashboard,
    items: [
      { to: "/", label: "Tổng quan", icon: LayoutDashboard, end: true, minRole: "viewer" },
    ],
  },
  {
    label: "Giám sát & điều khiển PLC",
    icon: Workflow,
    items: [
      { to: "/process", label: "Giám sát tiến trình", icon: Workflow, end: false, minRole: "viewer" },
    ],
  },
  {
    label: "Cảnh báo bất thường",
    icon: Bell,
    items: [
      { to: "/alarms", label: "Cảnh báo & Sự kiện", icon: Bell, end: false, minRole: "viewer" },
    ],
  },
  {
    label: "Phân tích PCAP",
    icon: UploadCloud,
    items: [
      { to: "/ids-upload", label: "Tải PCAP phân tích", icon: UploadCloud, end: false, minRole: "operator" },
    ],
  },
  {
    label: "Lịch sử & báo cáo",
    icon: TrendingUp,
    items: [
      { to: "/trends", label: "Xu hướng & Lịch sử", icon: TrendingUp, end: false, minRole: "viewer" },
      { to: "/pcap-history", label: "Lịch sử phân tích PCAP", icon: FileClock, end: false, minRole: "operator" },
    ],
  },
  {
    label: "Quản trị hệ thống",
    icon: Settings2,
    items: [
      { to: "/system", label: "Trạng thái hệ thống", icon: ServerCog, end: false, minRole: "viewer" },
      { to: "/admin/users", label: "Người dùng", icon: UsersIcon, end: false, minRole: "admin" },
    ],
  },
];

function RequireRole({ minRole, children }) {
  const { isAuthenticated, hasRole } = useAuth();
  const location = useLocation();

  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  if (!hasRole(minRole)) {
    return (
      <div className="flex min-h-[70vh] flex-col items-center justify-center gap-3 p-10 text-center animate-fade-in">
        <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-red-500/20 bg-red-500/10 text-red-300">
          <ShieldCheck size={22} />
        </div>
        <div className="text-lg font-semibold text-slate-100">403 — Không đủ quyền truy cập</div>
        <div className="max-w-md text-sm text-slate-500">
          Trang này yêu cầu role <span className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 font-mono text-slate-300">{minRole}</span> trở lên.
        </div>
      </div>
    );
  }
  return children;
}

function Sidebar() {
  const { hasRole } = useAuth();

  return (
    <aside className="hidden w-[248px] shrink-0 border-r border-slate-800/80 bg-slate-950/70 lg:block">
      <div className="sticky top-[49px] h-[calc(100vh-49px)] overflow-y-auto px-3 py-5">
        <div className="mb-5 rounded-2xl border border-cyan-500/10 bg-gradient-to-br from-cyan-500/[0.08] to-blue-500/[0.03] p-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300">
              <ShieldCheck size={20} />
            </div>
            <div>
              <div className="text-sm font-semibold text-slate-100">ICS Security Console</div>
              <div className="mt-0.5 text-[11px] text-slate-500">SCADA · IDS · OPC UA</div>
            </div>
          </div>
          <div className="mt-3 flex items-center gap-2 text-[10px] uppercase tracking-[0.18em] text-emerald-400/80">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,.7)]" />
            Monitoring active
          </div>
        </div>

        <div className="space-y-6">
          {NAV_GROUPS.map((group) => {
            const visible = group.items.filter((item) => hasRole(item.minRole));
            if (!visible.length) return null;
            return (
              <div key={group.label}>
                <div className="mb-2 flex items-center gap-2 px-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-600">
                  <group.icon size={11} />
                  {group.label}
                </div>
                <div className="space-y-1">
                  {visible.map((item) => (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      end={item.end}
                      className={({ isActive }) =>
                        `group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition-all ${
                          isActive
                            ? "bg-cyan-400/[0.10] text-cyan-200 ring-1 ring-inset ring-cyan-400/10"
                            : "text-slate-500 hover:bg-slate-900/80 hover:text-slate-200"
                        }`
                      }
                    >
                      {({ isActive }) => (
                        <>
                          <item.icon size={16} strokeWidth={isActive ? 2.3 : 1.9} className={isActive ? "text-cyan-300" : "text-slate-600 group-hover:text-slate-400"} />
                          <span className="flex-1">{item.label}</span>
                          <ChevronRight size={13} className={`transition-transform ${isActive ? "translate-x-0 text-cyan-500" : "-translate-x-1 text-transparent group-hover:translate-x-0 group-hover:text-slate-600"}`} />
                        </>
                      )}
                    </NavLink>
                  ))}
                </div>
              </div>
            );
          })}
        </div>

        <div className="mt-8 border-t border-slate-800/70 pt-4">
          <div className="flex items-center gap-2 px-2 text-[11px] text-slate-600">
            <Database size={12} />
            Event-backed monitoring
          </div>
          <div className="mt-1 px-2 text-[10px] leading-relaxed text-slate-700">
            Live PLC/OPC UA telemetry with scenario evidence and IDS analysis.
          </div>
        </div>
      </div>
    </aside>
  );
}

function MobileNav() {
  const { hasRole } = useAuth();
  const items = NAV_GROUPS.flatMap((g) => g.items).filter((item) => hasRole(item.minRole));
  return (
    <nav className="flex gap-1 overflow-x-auto border-b border-slate-800 bg-slate-950/90 px-3 lg:hidden">
      {items.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.end}
          className={({ isActive }) => `flex shrink-0 items-center gap-1.5 border-b-2 px-3 py-3 text-xs ${isActive ? "border-cyan-400 text-cyan-300" : "border-transparent text-slate-500"}`}
        >
          <item.icon size={14} />
          {item.label}
        </NavLink>
      ))}
    </nav>
  );
}

function Shell() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <StatusBar />
      <MobileNav />
      <div className="flex min-h-[calc(100vh-49px)]">
        <Sidebar />
        <main className="min-w-0 flex-1 bg-[radial-gradient(circle_at_top_right,rgba(34,211,238,0.035),transparent_28%)]">
          <div className="mx-auto max-w-[1680px] animate-fade-in">
            <Routes>
              <Route path="/" element={<RequireRole minRole="viewer"><Overview /></RequireRole>} />
              <Route path="/process" element={<RequireRole minRole="viewer"><ProcessMonitor /></RequireRole>} />
              <Route path="/alarms" element={<RequireRole minRole="viewer"><AlarmEvents /></RequireRole>} />
              <Route path="/pcap-history" element={<RequireRole minRole="operator"><PcapHistory /></RequireRole>} />
              <Route path="/trends" element={<RequireRole minRole="viewer"><Trends /></RequireRole>} />
              <Route path="/ids-upload" element={<RequireRole minRole="operator"><IdsUpload /></RequireRole>} />
              <Route path="/system" element={<RequireRole minRole="viewer"><SystemStatus /></RequireRole>} />
              <Route path="/admin/users" element={<RequireRole minRole="admin"><AdminUsers /></RequireRole>} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </div>
        </main>
      </div>
    </div>
  );
}

function Routed() {
  const { isAuthenticated } = useAuth();
  return (
    <Routes>
      <Route path="/login" element={isAuthenticated ? <Navigate to="/" replace /> : <Login />} />
      <Route path="/*" element={<Shell />} />
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <ConfirmProvider>
        <ToastProvider>
          <Routed />
        </ToastProvider>
      </ConfirmProvider>
    </AuthProvider>
  );
}
