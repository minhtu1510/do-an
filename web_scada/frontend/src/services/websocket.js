let ws = null;
let reconnectTimer = null;
let reconnectAttempts = 0;
const listeners = new Set();

export function connectWebSocket(onMessage) {
  if (listeners.size === 0 && !ws) {
    _open();
  }
  if (onMessage) {
    listeners.add(onMessage);
    return () => {
      listeners.delete(onMessage);
      if (listeners.size === 0 && ws) {
        clearTimeout(reconnectTimer);
        reconnectAttempts = 0;
        ws.close();
        ws = null;
      }
    };
  }
}

function _open() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${protocol}//${window.location.host}/ws/process`;
  ws = new WebSocket(url);

  ws.onopen = () => {
    reconnectAttempts = 0;
    listeners.forEach((fn) => fn({ type: "ws_open" }));
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      listeners.forEach((fn) => fn(data));
    } catch (e) { /* ignore */ }
  };

  ws.onclose = () => {
    listeners.forEach((fn) => fn({ type: "ws_close" }));
    ws = null;
    const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 15000);
    reconnectAttempts++;
    reconnectTimer = setTimeout(() => {
      if (listeners.size > 0) _open();
    }, delay);
  };

  ws.onerror = () => {
    ws?.close();
  };
}
