const pptxgen = require('/mnt/c/Users/Asus/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/pptxgenjs');

const pptx = new pptxgen();
pptx.layout = 'LAYOUT_WIDE';
pptx.author = 'Codex';
pptx.subject = 'Kết quả đánh giá và rà soát nhãn OOD2';
pptx.title = 'OOD2 — kết quả mô hình và rà soát nhãn';
pptx.company = 'OT Security';
pptx.lang = 'vi-VN';
pptx.theme = {
  headFontFace: 'Times New Roman',
  bodyFontFace: 'Times New Roman',
  lang: 'vi-VN'
};
pptx.defineSlideMaster({
  title: 'MASTER',
  background: { color: 'F7F9FB' },
  objects: [
    { rect: { x: 0, y: 0, w: 13.333, h: 0.13, line: { color: '156082', transparency: 100 }, fill: { color: '156082' } } },
    { text: { text: 'NGHIÊN CỨU BẢO MẬT MẠNG ĐIỀU KHIỂN CÔNG NGHIỆP', options: { x: 0.62, y: 7.12, w: 8.9, h: 0.18, fontFace: 'Times New Roman', fontSize: 9, color: '607786', margin: 0, breakLine: false } } },
  ],
  slideNumber: { x: 12.2, y: 7.09, color: '607786', fontFace: 'Times New Roman', fontSize: 9 }
});

const C = {
  navy: '0E2841', teal: '156082', blue: '0F9ED5', orange: 'E97132', green: '196B24',
  ink: '17324A', muted: '5C7180', line: 'D7E2E9', white: 'FFFFFF',
  paleBlue: 'E9F3F7', paleOrange: 'FFF1E8', paleGreen: 'EAF4ED', paleGray: 'EEF2F5'
};
const FONT = 'Times New Roman';

function addHeader(slide, kicker, title, subtitle) {
  slide.addText(kicker.toUpperCase(), { x: 0.65, y: 0.38, w: 11.9, h: 0.24, fontFace: FONT, fontSize: 11, bold: true, charSpacing: 1.5, color: C.teal, margin: 0 });
  slide.addText(title, { x: 0.62, y: 0.72, w: 12.1, h: 0.55, fontFace: FONT, fontSize: 25, bold: true, color: C.navy, margin: 0, fit: 'shrink' });
  slide.addText(subtitle, { x: 0.65, y: 1.37, w: 12.0, h: 0.36, fontFace: FONT, fontSize: 14, color: C.muted, margin: 0, fit: 'shrink' });
}

function addMetricCard(slide, x, label, metric, descriptor, color) {
  const y = 2.03, w = 3.86, h = 2.10;
  slide.addShape(pptx.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.08, fill: { color: C.white }, line: { color: C.line, width: 1 } });
  slide.addShape(pptx.ShapeType.rect, { x, y, w, h: 0.09, fill: { color }, line: { color, transparency: 100 } });
  slide.addText(label.toUpperCase(), { x: x + 0.24, y: y + 0.27, w: w - 0.48, h: 0.27, fontFace: FONT, fontSize: 11, bold: true, charSpacing: 0.8, color: C.muted, margin: 0, fit: 'shrink' });
  slide.addText(metric, { x: x + 0.24, y: y + 0.69, w: w - 0.48, h: 0.68, fontFace: FONT, fontSize: 34, bold: true, color, margin: 0, fit: 'shrink' });
  slide.addText(descriptor, { x: x + 0.24, y: y + 1.47, w: w - 0.48, h: 0.43, fontFace: FONT, fontSize: 14, color: C.ink, margin: 0, breakLine: false, fit: 'shrink', valign: 'mid' });
}

// Slide 1: baseline model results under the original labeling rule.
{
  const slide = pptx.addSlide('MASTER');
  addHeader(slide, 'OOD2 · phiên thu sau khoảng một tháng', 'Phát hiện tốt hơn phân loại chi tiết', '605 cửa sổ · 480 BENIGN và 125 attack theo nhãn pipeline hiện tại');

  addMetricCard(slide, 0.65, 'Phát hiện nhị phân', '0,943', 'Macro-F1 · recall attack 99,2% (124/125)', C.teal);
  addMetricCard(slide, 4.74, 'Theo họ hành vi', '0,656', 'Macro-F1 · accuracy 95,7%', C.blue);
  addMetricCard(slide, 8.83, 'Theo từng hành vi', '0,518', 'Macro-F1 · accuracy 94,7%', C.orange);

  slide.addShape(pptx.ShapeType.roundRect, { x: 0.65, y: 4.46, w: 12.04, h: 1.25, rectRadius: 0.08, fill: { color: C.paleBlue }, line: { color: C.paleBlue, transparency: 100 } });
  slide.addText('THEO NHÃN PIPELINE HIỆN TẠI', { x: 0.92, y: 4.70, w: 3.1, h: 0.23, fontFace: FONT, fontSize: 10, bold: true, charSpacing: 0.8, color: C.teal, margin: 0 });
  slide.addText('23 / 480', { x: 0.92, y: 5.00, w: 2.3, h: 0.46, fontFace: FONT, fontSize: 25, bold: true, color: C.navy, margin: 0 });
  slide.addText('cửa sổ BENIGN bị báo attack', { x: 3.08, y: 5.09, w: 3.6, h: 0.28, fontFace: FONT, fontSize: 13, color: C.ink, margin: 0, fit: 'shrink' });
  slide.addShape(pptx.ShapeType.line, { x: 7.18, y: 4.72, w: 0, h: 0.72, line: { color: 'B9CDD8', width: 1 } });
  slide.addText('0 / 444', { x: 7.55, y: 5.00, w: 2.2, h: 0.46, fontFace: FONT, fontSize: 25, bold: true, color: C.green, margin: 0 });
  slide.addText('cửa sổ vận hành ổn định bị báo nhầm', { x: 9.55, y: 5.09, w: 2.75, h: 0.3, fontFace: FONT, fontSize: 12, color: C.ink, margin: 0, fit: 'shrink' });

  slide.addText('Các mức Macro-F1 trả lời những bài toán khác nhau; OOD2 đã tham gia so sánh và lựa chọn mô hình.', { x: 0.70, y: 6.05, w: 11.95, h: 0.48, fontFace: FONT, fontSize: 13, color: C.muted, margin: 0, fit: 'shrink', valign: 'mid' });
  slide.addNotes(`Sau khi đánh giá trong cùng phiên Day 8, nhóm kiểm tra mô hình trên OOD2, một phiên thu cách khoảng một tháng. Bộ này có 605 cửa sổ, gồm 480 BENIGN và 125 attack theo nhãn pipeline hiện tại.\n\nBa điểm Macro-F1 ứng với ba nhiệm vụ khác nhau: phân biệt BENIGN với attack, xác định họ hành vi, và xác định từng hành vi cụ thể. Vì vậy không nên đọc chúng như một chỉ số giảm dần trên cùng một bài toán. Ở mức nhị phân, mô hình phát hiện 124 trên 125 cửa sổ attack, recall 99,2%.\n\nTheo nhãn hiện tại, 23 trên 480 cửa sổ BENIGN bị báo attack; 444 cửa sổ vận hành ổn định không có cảnh báo nhầm. Câu hỏi tiếp theo là: các cửa sổ bị tính là báo nhầm có thật sự không có hoạt động kiểm thử không? Nhóm đã rà PCAP cùng timeline để trả lời.\n\nLưu ý: OOD2 đã tham gia so sánh và lựa chọn mô hình, nên đây là đánh giá chuyển phiên trong quá trình phát triển, chưa phải kiểm định cuối độc lập.`);
}

// Slide 2: label sensitivity audit; predictions remain frozen.
{
  const slide = pptx.addSlide('MASTER');
  addHeader(slide, 'RÀ SOÁT PCAP · TIMELINE · NHÃN', '22/23 cảnh báo bị tính là FP có traffic trong khoảng attack', 'Cùng một mô hình và cùng dự đoán · chỉ thay đổi cách đối chiếu nhãn');

  const y = 2.03, h = 2.92, w = 5.62;
  function panel(x, title, fill, line, color) {
    slide.addShape(pptx.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.08, fill: { color: C.white }, line: { color: line, width: 1.2 } });
    slide.addShape(pptx.ShapeType.rect, { x, y, w, h: 0.1, fill: { color }, line: { color, transparency: 100 } });
    slide.addText(title, { x: x + 0.25, y: y + 0.27, w: w - 0.5, h: 0.28, fontFace: FONT, fontSize: 11, bold: true, charSpacing: 0.7, color, margin: 0, fit: 'shrink' });
    slide.addText(fill, { x: x + 0.25, y: y + 0.67, w: w - 0.5, h: 0.24, fontFace: FONT, fontSize: 12, color: C.muted, margin: 0 });
  }
  panel(0.65, 'NHÃN PIPELINE BAN ĐẦU', '125 attack · 480 BENIGN', C.line, C.teal);
  panel(7.06, 'CHẤM ĐỘ NHẠY THEO BẰNG CHỨNG SỰ KIỆN', '147 attack · 458 BENIGN (+22 cửa sổ)', 'F1D1BC', C.orange);

  slide.addText('TP', { x: 0.98, y: 3.03, w: 1.0, h: 0.22, fontFace: FONT, fontSize: 10, bold: true, color: C.muted, margin: 0 });
  slide.addText('124', { x: 0.98, y: 3.30, w: 1.3, h: 0.52, fontFace: FONT, fontSize: 28, bold: true, color: C.teal, margin: 0 });
  slide.addText('FP', { x: 2.78, y: 3.03, w: 1.0, h: 0.22, fontFace: FONT, fontSize: 10, bold: true, color: C.muted, margin: 0 });
  slide.addText('23', { x: 2.78, y: 3.30, w: 1.3, h: 0.52, fontFace: FONT, fontSize: 28, bold: true, color: C.orange, margin: 0 });
  slide.addText('TN  457     ·     FN  1', { x: 0.98, y: 4.09, w: 3.95, h: 0.25, fontFace: FONT, fontSize: 12, color: C.ink, margin: 0 });
  slide.addText('F1 attack  0,912', { x: 0.98, y: 4.50, w: 3.95, h: 0.27, fontFace: FONT, fontSize: 15, bold: true, color: C.navy, margin: 0 });

  slide.addText('TP', { x: 7.39, y: 3.03, w: 1.0, h: 0.22, fontFace: FONT, fontSize: 10, bold: true, color: C.muted, margin: 0 });
  slide.addText('146', { x: 7.39, y: 3.30, w: 1.3, h: 0.52, fontFace: FONT, fontSize: 28, bold: true, color: C.green, margin: 0 });
  slide.addText('FP', { x: 9.19, y: 3.03, w: 1.0, h: 0.22, fontFace: FONT, fontSize: 10, bold: true, color: C.muted, margin: 0 });
  slide.addText('1', { x: 9.19, y: 3.30, w: 1.3, h: 0.52, fontFace: FONT, fontSize: 28, bold: true, color: C.orange, margin: 0 });
  slide.addText('TN  457     ·     FN  1', { x: 7.39, y: 4.09, w: 3.95, h: 0.25, fontFace: FONT, fontSize: 12, color: C.ink, margin: 0 });
  slide.addText('F1 attack  0,993', { x: 7.39, y: 4.50, w: 3.95, h: 0.27, fontFace: FONT, fontSize: 15, bold: true, color: C.navy, margin: 0 });

  slide.addShape(pptx.ShapeType.chevron, { x: 6.37, y: 3.35, w: 0.46, h: 0.55, fill: { color: C.orange }, line: { color: C.orange, transparency: 100 } });

  slide.addShape(pptx.ShapeType.roundRect, { x: 0.65, y: 5.30, w: 12.03, h: 1.10, rectRadius: 0.06, fill: { color: C.paleOrange }, line: { color: C.paleOrange, transparency: 100 } });
  slide.addText('ĐIỀU CẦN KẾT LUẬN', { x: 0.92, y: 5.52, w: 2.25, h: 0.22, fontFace: FONT, fontSize: 10, bold: true, charSpacing: 0.8, color: C.orange, margin: 0 });
  slide.addText('Điểm tăng do đổi nhãn đối chiếu, không phải mô hình tốt lên. Tiêu chí bổ sung được xác lập sau khi xem OOD2; đây là phân tích độ nhạy, chưa phải kiểm định độc lập.', { x: 3.10, y: 5.49, w: 9.20, h: 0.54, fontFace: FONT, fontSize: 13, color: C.ink, margin: 0, fit: 'shrink', valign: 'mid' });
  slide.addText('Packet chứng minh có traffic trong khoảng kịch bản, không chứng minh PLC đã bị thay đổi.', { x: 0.70, y: 6.60, w: 11.95, h: 0.25, fontFace: FONT, fontSize: 11, italic: true, color: C.muted, margin: 0, fit: 'shrink' });

  slide.addNotes(`Ở slide trước, 23 cửa sổ được tính là false positive vì nhãn pipeline ban đầu ghi chúng là BENIGN. Nhóm kiểm tra lại bằng cách ghép thời điểm từng packet trong PCAP với khoảng chạy kịch bản trên timeline. Kết quả cho thấy 22 trong 23 cửa sổ có packet từ máy kiểm thử tới PLC qua TCP/4840 trong đúng khoảng episode attack. Một cửa sổ chưa có bằng chứng theo tiêu chí này. Vì cửa sổ dài 5 giây, một cửa sổ có thể chứa cả traffic nền lẫn hoạt động kiểm thử ngắn.\n\nĐể xem quy tắc nhãn ảnh hưởng kết quả ra sao, nhóm giữ nguyên model và toàn bộ dự đoán, rồi chấm lại 22 cửa sổ theo nhãn sự kiện bổ sung. Theo nhãn ban đầu, TP/FP/TN/FN là 124/23/457/1 và F1 attack là 0,912. Theo đối chiếu bổ sung, các giá trị là 146/1/457/1 và F1 attack là 0,993. Mô hình không thay đổi; chỉ nhãn dùng để chấm thay đổi.\n\nVì tiêu chí bổ sung được xác lập sau khi xem OOD2 và chưa được áp dụng thống nhất cho tập huấn luyện, không dùng 0,993 để thay kết quả chính hoặc khẳng định mô hình tốt hơn. Đây là phân tích độ nhạy, cho thấy kết quả phụ thuộc vào cách định nghĩa ground truth. Packet trong khoảng timeline cho thấy hoạt động mạng khi kịch bản chạy, nhưng chưa tự chứng minh thao tác đã làm thay đổi trạng thái PLC. OOD2 cũng đã tham gia lựa chọn mô hình, nên chưa phải kiểm định cuối độc lập.`);
}

 pptx.writeFile({ fileName: '/home/sus/do-an/OOD2_2_slides_with_notes.pptx' })
  .then(() => console.log('Wrote /home/sus/do-an/OOD2_2_slides_with_notes.pptx'))
  .catch((err) => { console.error(err); process.exitCode = 1; });
