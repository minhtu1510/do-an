@echo off
REM Chay frontend Vite dev server (mo cong 5173). Chay sau khi da install.bat
REM va trong luc run_backend.bat dang chay o cua so khac.
set "SCRIPT_DIR=%~dp0"
set "FRONTEND=%SCRIPT_DIR%..\02_MaNguon_ThuVien\MaNguon\web_scada\frontend"

cd /d "%FRONTEND%"
call npm run dev
