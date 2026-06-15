@echo off
title ICSScout - OT Security Assessment Tool
echo ============================================================
echo ICSScout - OT/ICS Security Assessment Tool
echo ============================================================
echo.
echo Starting web server...
echo Open browser and navigate to: http://localhost:5000
echo.
echo Press Ctrl+C to stop the server
echo ============================================================
echo.

REM Check for admin rights (needed for network scanning)
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running with Administrator privileges
) else (
    echo [WARNING] Not running as Administrator
    echo Some network scanning features may not work properly
    echo Please run as Administrator for full functionality
    echo.
)

REM Start ICSScout
ICSScout.exe --host 127.0.0.1 --port 5000

pause
