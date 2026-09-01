// Plain module-level object — not React state — so it survives IdsUpload
// unmounting when the user navigates to another page and back. A File object
// and the analysis result would otherwise be lost on every route change,
// forcing a re-pick + re-analyze for no reason. Cleared only by a fresh
// upload/reset, not by navigation.
export const idsUploadStore = {
  protocol: "s7comm", // "s7comm" | "opcua" — picks which model/extractor analyzes the upload
  file: null,
  plcIp: "192.168.210.211",
  windowS: 2.0,
  result: null,
  historian: null,
  status: null,
};

// The OPC UA backend returns lowercase "benign" (that's literally what's in
// the training CSV) and no layer_used (model_opcua/ is a single classifier,
// not the S7comm 3-layer pipeline) — everywhere else in the app checks
// `!== "BENIGN"` uppercase, so this must run on every OPC UA result exactly
// once: right after a fresh analyze call (IdsUpload.jsx) AND right after
// reopening a saved one from history (PcapHistory.jsx), since the stored
// result_json is the raw pre-normalization payload. Shared here so both
// call sites can't drift out of sync with each other.
export function normalizeOpcuaResult(raw) {
  const upper = (p) => (p === "benign" ? "BENIGN" : p);
  return {
    ...raw,
    protocol: "opcua",
    prediction_counts: Object.fromEntries(Object.entries(raw.prediction_counts).map(([k, v]) => [upper(k), v])),
    timeline: raw.timeline.map((p) => ({ ...p, prediction: upper(p.prediction), layer_used: null })),
    flow_table: raw.flow_table.map((r) => ({ ...r, prediction: upper(r.prediction), layer_used: null })),
  };
}
