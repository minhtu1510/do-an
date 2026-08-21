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
