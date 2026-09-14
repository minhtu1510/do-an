# Hướng dẫn bật Basic256Sha256 + so sánh A/B (Q2 — Day 7)

Mục tiêu: chứng minh **bằng thực nghiệm** rằng lỗ hổng của testbed là **cấu hình OPC UA
Anonymous**, không phải giao thức. Bằng cách chạy cùng một tấn công dưới 2 cấu hình
server và so sánh kết quả.

| Cấu hình | Trạng thái server | Kết quả tấn công mong đợi |
|---|---|---|
| **INSECURE** (hiện tại) | Anonymous / No-Security | Che giấu ~17%, ghi được (ĐÃ CÓ DATA) |
| **SECURE** (mới) | Basic256Sha256 + user auth | Kết nối attacker bị từ chối → **0%** |

Phần code Web-SCADA đã sẵn sàng (gateway đọc `OPCUA_SECURITY`/`OPCUA_USER`/
`OPCUA_PASSWORD` từ `.env`). Việc còn lại chia 5 phần dưới đây.

---

## Phần 1 — Cấu hình S7-1500 OPC UA server (TIA Portal — bạn tự làm trên PLC)

1. TIA Portal → thiết bị PLC → **OPC UA → Server**: đảm bảo "Activate OPC UA server" đã bật.
2. **Security policies**: tick **Basic256Sha256**.
   - Muốn giữ khả năng A/B linh hoạt: tick cả "No security" *và* Basic256Sha256.
   - Muốn ép buộc bảo mật (chứng minh chặn mạnh nhất): **bỏ** "No security", chỉ để Basic256Sha256.
3. **User authentication**: **bỏ tick** "Enable guest authentication" (tắt Anonymous),
   thêm một user + mật khẩu (vd `scada` / `<mật khẩu mạnh>`).
4. **Certificate**: server tự sinh cert của nó. Sẽ cần thêm cert của client (gateway) vào
   danh sách tin cậy ở Phần 3.
5. **Compile + Download** vào PLC.

> Chính cấu hình này (bỏ Anonymous, bỏ No-Security) là thứ làm attacker kết nối
> ẩn danh bị **từ chối ngay ở bước handshake** — đó là bằng chứng "0%".

## Phần 2 — Sinh certificate cho client Web-SCADA gateway

OPC UA yêu cầu cert client có **URI ứng dụng** trong SubjectAltName (không chỉ CN
thường). Sinh cặp self-signed (đủ cho lab):

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout client_key.pem -out client_cert.der -outform DER \
  -subj "/CN=web-scada-gateway" \
  -addext "subjectAltName=URI:urn:web-scada:gateway,IP:<IP-máy-chạy-gateway>"
```

Đặt 2 file `client_cert.der` + `client_key.pem` vào thư mục chạy backend
(`web_scada/backend/`), hoặc dùng đường dẫn tuyệt đối trong `.env`.

> **Gotcha hay gặp:** URI trong cert (`urn:web-scada:gateway`) phải khớp application
> URI mà asyncua khai báo khi kết nối. Nếu server báo `BadCertificateUriInvalid`,
> chỉnh URI cho khớp (hoặc để asyncua tự sinh cert — xem tài liệu asyncua
> `set_security_string` + `application_uri`).

## Phần 3 — Trao đổi certificate 2 chiều

- **Client → Server:** import `client_cert.der` vào TIA Portal → OPC UA → Security →
  danh sách **Trusted client certificates** của PLC. Download lại.
- **Server → Client:** export cert server từ TIA Portal; đặt để gateway tin cậy, hoặc
  trong môi trường lab có thể để asyncua auto-accept cert server (chấp nhận rủi ro lab).

## Phần 4 — Bật security cho Web-SCADA gateway (chỉ điền .env — code đã sẵn)

Trong `web_scada/backend/.env`:

```
OPCUA_SECURITY=Basic256Sha256,SignAndEncrypt,client_cert.der,client_key.pem
OPCUA_USER=scada
OPCUA_PASSWORD=<mật khẩu đã tạo ở Phần 1>
```

Restart backend. Nếu cấu hình đúng, log gateway in `OPC UA security enabled:
Basic256Sha256` và **giám sát vẫn chạy bình thường** (gateway có cred hợp lệ). Nếu
để trống 3 biến này → gateway quay lại Anonymous như cũ.

## Phần 5 — Chạy so sánh A/B (trên máy attacker)

Attacker **không có** cred/cert hợp lệ — nên khi server ở chế độ SECURE, mọi kết nối
tấn công ẩn danh sẽ bị từ chối. Chạy cùng bộ kịch bản dưới 2 nhãn mode để comparator
trong Web-SCADA hiện cả hai:

```bash
# 1) Server đang INSECURE (hoặc còn cho phép Anonymous) — baseline
OPCUA_SECURITY_MODE=Anonymous python tests/day8/run_day8.py --group opcua --execute --allow-gated

# 2) Chuyển server sang SECURE (Phần 1), rồi chạy lại CHÍNH bộ đó
OPCUA_SECURITY_MODE=Basic256Sha256 python tests/day8/run_day8.py --group opcua --execute --allow-gated
```

Kết quả:
- Bảng **OPC UA Security-Mode Comparator** (trang Security/IDS) tự điền 2 cột
  Anonymous vs Basic256Sha256 — đây là slide A/B đắt giá nhất.
- Các scenario `OPCUA_UNAUTHORIZED_SESSION`, `OPCUA_CERTIFICATE_REJECTED` (trước trả
  `NOT_CONFIGURED`) giờ **có nghĩa** — test thật việc từ chối auth/cert.
- Nếu muốn tái hiện đúng tấn công che giấu dưới 2 mode: chạy
  `attacks_ext/concealed_stop_attack.py` khi server INSECURE (được ~17%) và khi
  SECURE (kết nối OPC UA bị từ chối → concealment = 0, dù STOP qua S7 vẫn chạy).

---

## Lưu ý an toàn (đọc trước khi làm)

1. **Backup cấu hình Anonymous.** Lỡ bật security hỏng thì còn quay về demo được ngay.
   Đừng làm sát ngày thi.
2. **Test lại toàn bộ luồng** sau khi đổi: gateway connect lại được không, các trang
   web còn dữ liệu không, upload pcap còn chạy không.
3. Sự cố hay gặp khi gateway KHÔNG connect được sau khi bật secure:
   - `BadCertificateUriInvalid` → URI trong cert không khớp (Phần 2 gotcha).
   - `BadUserAccessDenied` → sai user/password.
   - `BadCertificateUntrusted` → chưa import client cert vào trusted list của PLC (Phần 3).
4. Giá trị lớn nhất của Q2: biến câu "khuyến nghị bật Basic256Sha256" ở mục 10 báo cáo
   **từ lời khuyên thành bằng chứng đo được** — nên chỉ làm khi có thời gian làm cho chuẩn.
