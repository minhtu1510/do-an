import { createContext, useCallback, useContext, useRef, useState } from "react";
import { AlertTriangle } from "lucide-react";

const ConfirmContext = createContext(null);

// Replaces window.confirm() with a modal styled to match the app instead of
// the browser's native (unstyled, theme-breaking) confirm dialog. Usage:
//   const confirm = useConfirm();
//   if (!(await confirm({ message: "..." }))) return;
export function ConfirmProvider({ children }) {
  const [state, setState] = useState(null); // { title, message, tone, confirmLabel }
  const resolverRef = useRef(null);

  const confirm = useCallback((opts) => {
    const options = typeof opts === "string" ? { message: opts } : opts;
    setState(options);
    return new Promise((resolve) => {
      resolverRef.current = resolve;
    });
  }, []);

  function settle(result) {
    setState(null);
    if (resolverRef.current) {
      resolverRef.current(result);
      resolverRef.current = null;
    }
  }

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      {state && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 backdrop-blur-sm animate-fade-in" onClick={() => settle(false)}>
          <div
            className="mx-4 w-full max-w-sm rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-[0_30px_80px_rgba(0,0,0,.5)]"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start gap-3">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-amber-400/25 bg-amber-400/10 text-amber-300">
                <AlertTriangle size={17} />
              </div>
              <div className="min-w-0 pt-0.5">
                {state.title && <div className="text-sm font-semibold text-slate-100">{state.title}</div>}
                <div className="mt-1 text-sm leading-relaxed text-slate-400">{state.message}</div>
              </div>
            </div>
            <div className="mt-5 flex justify-end gap-2">
              <button
                onClick={() => settle(false)}
                className="rounded-lg border border-slate-700 px-3.5 py-1.5 text-xs font-semibold text-slate-400 transition-colors hover:border-slate-600 hover:text-slate-200"
              >
                Huỷ
              </button>
              <button
                onClick={() => settle(true)}
                className="rounded-lg bg-amber-400 px-3.5 py-1.5 text-xs font-semibold text-slate-950 shadow-sm transition-colors hover:bg-amber-300"
              >
                {state.confirmLabel || "Xác nhận"}
              </button>
            </div>
          </div>
        </div>
      )}
    </ConfirmContext.Provider>
  );
}

export function useConfirm() {
  const ctx = useContext(ConfirmContext);
  if (!ctx) throw new Error("useConfirm must be used inside ConfirmProvider");
  return ctx;
}
