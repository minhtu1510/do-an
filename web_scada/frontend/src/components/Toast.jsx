import { createContext, useCallback, useContext, useRef, useState } from "react";
import { AlertTriangle, CheckCircle2, Info } from "lucide-react";

const ToastContext = createContext(null);

const TONE = {
  error: { icon: AlertTriangle, cls: "border-red-400/25 bg-red-400/[0.08] text-red-300" },
  success: { icon: CheckCircle2, cls: "border-emerald-400/25 bg-emerald-400/[0.08] text-emerald-300" },
  info: { icon: Info, cls: "border-cyan-400/25 bg-cyan-400/[0.08] text-cyan-300" },
};

// Lightweight auto-dismissing notification — replaces ad-hoc inline
// validation hints / native alerts with one small styled popup. Usage:
//   const toast = useToast();
//   toast("Password cần tối thiểu 8 ký tự", { tone: "error" });
export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const idRef = useRef(0);

  const show = useCallback((message, opts = {}) => {
    const id = ++idRef.current;
    const tone = opts.tone || "info";
    const duration = opts.duration ?? 3200;
    setToasts((prev) => [...prev, { id, message, tone }]);
    if (duration > 0) {
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, duration);
    }
    return id;
  }, []);

  return (
    <ToastContext.Provider value={show}>
      {children}
      <div className="pointer-events-none fixed right-5 top-16 z-[60] flex flex-col gap-2">
        {toasts.map((t) => {
          const { icon: Icon, cls } = TONE[t.tone] || TONE.info;
          return (
            <div
              key={t.id}
              className={`pointer-events-auto flex items-start gap-2.5 rounded-xl border px-4 py-3 text-sm shadow-[0_12px_40px_rgba(0,0,0,.4)] backdrop-blur-md animate-fade-in ${cls}`}
            >
              <Icon size={15} className="mt-0.5 shrink-0" />
              <span className="max-w-xs leading-relaxed">{t.message}</span>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used inside ToastProvider");
  return ctx;
}
