import { Routes, Route, NavLink } from "react-router-dom";
import StatusBar from "./components/StatusBar";
import Overview from "./pages/Overview";
import ProcessMonitor from "./pages/ProcessMonitor";
import AlarmEvents from "./pages/AlarmEvents";
import Trends from "./pages/Trends";
import SecurityView from "./pages/SecurityView";
import SystemStatus from "./pages/SystemStatus";
import DatasetStats from "./pages/DatasetStats";

const NAV = [
  { to: "/", label: "Overview", end: true },
  { to: "/process", label: "Process Monitor", end: false },
  { to: "/alarms", label: "Alarms & Events", end: false },
  { to: "/trends", label: "Trends & History", end: false },
  { to: "/security", label: "Security / IDS", end: false },
  { to: "/dataset", label: "Dataset & Model Stats", end: false },
  { to: "/system", label: "System Status", end: false },
];

export default function App() {
  return (
    <div className="min-h-screen bg-gray-950">
      <StatusBar />
      {/* Nav */}
      <nav className="flex flex-wrap gap-1 bg-gray-900 border-b border-gray-800 px-4">
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
      <div className="mx-auto max-w-[1600px]">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/process" element={<ProcessMonitor />} />
          <Route path="/alarms" element={<AlarmEvents />} />
          <Route path="/trends" element={<Trends />} />
          <Route path="/security" element={<SecurityView />} />
          <Route path="/dataset" element={<DatasetStats />} />
          <Route path="/system" element={<SystemStatus />} />
        </Routes>
      </div>
    </div>
  );
}
