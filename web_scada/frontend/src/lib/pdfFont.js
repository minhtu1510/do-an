import { DEJAVU_SANS_BASE64 } from "./dejavuSansFont";

// Registers DejaVu Sans (full Vietnamese Unicode coverage) into a jsPDF
// instance and switches to it — call once right after `new jsPDF(...)`.
// Without this, jsPDF's built-in fonts (Helvetica etc.) only support WinAnsi
// and silently garble Vietnamese text, which is why report PDFs used to
// strip all diacritics before rendering (reads like txt-speak, not a formal
// report). addFileToVFS/addFont only need to run once per jsPDF instance;
// re-registering on every export call is cheap enough not to bother caching.
export function useVietnameseFont(pdf) {
  pdf.addFileToVFS("DejaVuSans.ttf", DEJAVU_SANS_BASE64);
  pdf.addFont("DejaVuSans.ttf", "DejaVuSans", "normal");
  pdf.setFont("DejaVuSans");
}
