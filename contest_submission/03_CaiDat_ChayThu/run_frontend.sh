#!/usr/bin/env bash
# Chạy frontend Vite dev server (mở cổng 5173). Chạy sau khi đã install.sh
# và trong lúc run_backend.sh đang chạy ở cửa sổ khác.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND="$SCRIPT_DIR/../02_MaNguon_ThuVien/MaNguon/web_scada/frontend"

cd "$FRONTEND"
npm run dev
