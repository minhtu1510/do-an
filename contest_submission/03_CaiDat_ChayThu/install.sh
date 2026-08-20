#!/usr/bin/env bash
# Cài đặt Web-SCADA (backend Python + frontend Node) cho Linux/macOS.
# Chạy 1 lần: bash install.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/../02_MaNguon_ThuVien/MaNguon"
BACKEND="$ROOT/web_scada/backend"
FRONTEND="$ROOT/web_scada/frontend"

echo "== [1/4] Kiểm tra công cụ =="
command -v python3 >/dev/null || { echo "Thiếu python3."; exit 1; }
command -v npm >/dev/null || { echo "Thiếu Node.js/npm."; exit 1; }

echo "== [2/4] Cài đặt backend (Python venv) =="
python3 -m venv "$BACKEND/.venv"
# shellcheck disable=SC1091
source "$BACKEND/.venv/bin/activate"
pip install --upgrade pip >/dev/null
pip install -r "$BACKEND/requirements.txt"
deactivate

echo "== [3/4] Tạo file cấu hình .env (nếu chưa có) =="
if [ ! -f "$BACKEND/.env" ]; then
  cp "$BACKEND/.env.example" "$BACKEND/.env"
  SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  TMP="$(mktemp)"
  sed "s|^JWT_SECRET=.*|JWT_SECRET=$SECRET|" "$BACKEND/.env" > "$TMP" && mv "$TMP" "$BACKEND/.env"
  echo "Đã tạo $BACKEND/.env với JWT_SECRET mới sinh."
  echo "  -> Mở file này, sửa OPCUA_ENDPOINT trỏ đúng PLC/OPC UA server của bạn trước khi demo thật."
else
  echo "$BACKEND/.env đã tồn tại, bỏ qua."
fi

echo "== [4/4] Cài đặt frontend (npm) =="
( cd "$FRONTEND" && npm install )

echo ""
echo "Cài đặt xong. Chạy demo bằng:"
echo "  1) bash run_backend.sh   (terminal 1)"
echo "  2) bash run_frontend.sh  (terminal 2)"
echo "  3) Mở http://localhost:5173 — đăng nhập bằng ADMIN_USERNAME/ADMIN_PASSWORD trong .env"
