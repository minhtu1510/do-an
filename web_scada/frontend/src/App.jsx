import { Routes, Route, NavLink } from "react-router-dom";
import StatusBar from "./components/StatusBar";
import Overview from "./pages/Overview";
import ProcessMonitor from "./pages/ProcessMonitor";
import SystemStatus from "./pages/SystemStatus";

const NAV = [
  { to: "/", label: "Tong quan", end: true },
  { to: "/process", label: "Giam sat", end: false },
  { to: "/system", label: "He thong", end: false },
];

export default function App() {
  return (
    <div className="min-h-screen bg-gray-950">
      <StatusBar />
      {/* Nav */}
      <nav className="flex gap-1 bg-gray-900 border-b border-gray-800 px-4">
        {NAV.map((n) => (
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
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/process" element={<ProcessMonitor />} />
        <Route path="/system" element={<SystemStatus />} />
      </Routes>
    </div>
  );
}
