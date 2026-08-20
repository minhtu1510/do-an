#!/usr/bin/env bash
# Chạy backend FastAPI (mở cổng 8000). Chạy sau khi đã install.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$SCRIPT_DIR/../02_MaNguon_ThuVien/MaNguon/web_scada/backend"

# shellcheck disable=SC1091
source "$BACKEND/.venv/bin/activate"
cd "$BACKEND"
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
