@echo off
REM Chay backend FastAPI (mo cong 8000). Chay sau khi da install.bat.
set "SCRIPT_DIR=%~dp0"
set "BACKEND=%SCRIPT_DIR%..\02_MaNguon_ThuVien\MaNguon\web_scada\backend"

call "%BACKEND%\.venv\Scripts\activate.bat"
cd /d "%BACKEND%"
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
