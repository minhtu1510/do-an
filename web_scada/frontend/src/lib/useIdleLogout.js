import { useEffect, useRef } from "react";

// 2h — real feedback on the first cut (30 min) was that it fired while
// someone was actively watching a live dashboard, just not touching mouse/
// keyboard (this only tracks input events, not WebSocket data arriving —
// watching numbers update on screen isn't "activity" a browser can see).
// 2h covers a full monitoring shift without interaction while still
// bounding how long a forgotten, unlocked control-room terminal stays
// authenticated. JWT itself only expires after 12h (JWT_EXPIRES_HOURS),
// which was never a substitute for this — a stolen or shared terminal is
// the threat model here, not token lifetime.
const IDLE_TIMEOUT_MS = 2 * 60 * 60 * 1000;
const ACTIVITY_EVENTS = ["mousedown", "mousemove", "keydown", "touchstart", "scroll", "wheel"];

export function useIdleLogout(active, onIdle) {
  const timerRef = useRef(null);

  useEffect(() => {
    if (!active) return undefined;

    function reset() {
      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = setTimeout(onIdle, IDLE_TIMEOUT_MS);
    }

    reset();
    ACTIVITY_EVENTS.forEach((evt) => window.addEventListener(evt, reset, { passive: true }));
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
      ACTIVITY_EVENTS.forEach((evt) => window.removeEventListener(evt, reset));
    };
  }, [active, onIdle]);
}
