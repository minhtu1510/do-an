import { Routes, Route, Navigate, NavLink, useLocation } from "react-router-dom";
import StatusBar from "./components/StatusBar";
import Overview from "./pages/Overview";
import ProcessMonitor from "./pages/ProcessMonitor";
import AlarmEvents from "./pages/AlarmEvents";
import Trends from "./pages/Trends";
import SecurityView from "./pages/SecurityView";
import SystemStatus from "./pages/SystemStatus";
import DatasetStats from "./pages/DatasetStats";
import Login from "./pages/Login";
import AdminUsers from "./pages/AdminUsers";
import { AuthProvider, useAuth } from "./stores/authStore";

const NAV = [
  { to: "/", label: "Overview", end: true, minRole: "viewer" },
  { to: "/process", label: "Process Monitor", end: false, minRole: "viewer" },
  { to: "/alarms", label: "Alarms & Events", end: false, minRole: "viewer" },
  { to: "/trends", label: "Trends & History", end: false, minRole: "viewer" },
  { to: "/security", label: "Security / IDS", end: false, minRole: "operator" },
  { to: "/dataset", label: "Dataset & Model Stats", end: false, minRole: "operator" },
  { to: "/system", label: "System Status", end: false, minRole: "viewer" },
  { to: "/admin/users", label: "Users", end: false, minRole: "admin" },
];

function RequireRole({ minRole, children }) {
  const { isAuthenticated, hasRole } = useAuth();
  const location = useLocation();

  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  if (!hasRole(minRole)) {
    return (
      <div className="p-10 text-center text-sm text-gray-500">
        <div className="text-lg font-bold text-red-400">403 — Không đủ quyền</div>
        <div className="mt-2">Trang này yêu cầu role <span className="font-mono text-gray-300">{minRole}</span> trở lên.</div>
      </div>
    );
  }
  return children;
}

function Shell() {
  const { hasRole } = useAuth();

  return (
    <div className="min-h-screen bg-gray-950">
      <StatusBar />
      <nav className="flex flex-wrap gap-1 bg-gray-900 border-b border-gray-800 px-4">
        {NAV.filter((n) => hasRole(n.minRole)).map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            end={n.end}
            className={({ isActive }) =>
              `px-4 py-2 text-sm border-b-2 transition-colors ${
                isActive
                  ? "border-blue-500 text-blue-400"
                  : "border-transparent text-gray-500 hover:text-gray-300"
              }`
            }
          >
            {n.label}
          </NavLink>
        ))}
      </nav>
      <div className="mx-auto max-w-[1600px]">
        <Routes>
          <Route path="/" element={<RequireRole minRole="viewer"><Overview /></RequireRole>} />
          <Route path="/process" element={<RequireRole minRole="viewer"><ProcessMonitor /></RequireRole>} />
          <Route path="/alarms" element={<RequireRole minRole="viewer"><AlarmEvents /></RequireRole>} />
          <Route path="/trends" element={<RequireRole minRole="viewer"><Trends /></RequireRole>} />
          <Route path="/security" element={<RequireRole minRole="operator"><SecurityView /></RequireRole>} />
          <Route path="/dataset" element={<RequireRole minRole="operator"><DatasetStats /></RequireRole>} />
          <Route path="/system" element={<RequireRole minRole="viewer"><SystemStatus /></RequireRole>} />
          <Route path="/admin/users" element={<RequireRole minRole="admin"><AdminUsers /></RequireRole>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
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
      <Routed />
    </AuthProvider>
  );
}
