@echo off
REM Cai dat Web-SCADA (backend Python + frontend Node) cho Windows.
REM Chay 1 lan: install.bat
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "ROOT=%SCRIPT_DIR%..\02_MaNguon_ThuVien\MaNguon"
set "BACKEND=%ROOT%\web_scada\backend"
set "FRONTEND=%ROOT%\web_scada\frontend"

echo == [1/4] Kiem tra cong cu ==
where python >nul 2>nul || (echo Thieu Python. & exit /b 1)
where npm >nul 2>nul || (echo Thieu Node.js/npm. & exit /b 1)

echo == [2/4] Cai dat backend (Python venv) ==
python -m venv "%BACKEND%\.venv"
call "%BACKEND%\.venv\Scripts\activate.bat"
pip install --upgrade pip
pip install -r "%BACKEND%\requirements.txt"
call deactivate

echo == [3/4] Tao file cau hinh .env (neu chua co) ==
if not exist "%BACKEND%\.env" (
  copy "%BACKEND%\.env.example" "%BACKEND%\.env" >nul
  echo Da tao %BACKEND%\.env
  echo   -^> Mo file nay: dien JWT_SECRET ^(sinh bang: python -c "import secrets;print(secrets.token_hex(32))"^)
  echo      va sua OPCUA_ENDPOINT truoc khi demo that.
) else (
  echo %BACKEND%\.env da ton tai, bo qua.
)

echo == [4/4] Cai dat frontend (npm) ==
cd /d "%FRONTEND%"
call npm install

echo.
echo Cai dat xong. Chay demo bang:
echo   1) run_backend.bat   (cua so 1)
echo   2) run_frontend.bat  (cua so 2)
echo   3) Mo http://localhost:5173 - dang nhap bang ADMIN_USERNAME/ADMIN_PASSWORD trong .env
pause
