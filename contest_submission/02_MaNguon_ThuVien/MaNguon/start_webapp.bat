@echo off
REM ICSScout Web Application Launcher for Windows
REM Run this batch file as Administrator!

echo ============================================================
echo ICSScout Web Application v2.0
echo ============================================================
echo.
echo Checking Administrator privileges...
echo.

REM Check for admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script requires Administrator privileges!
    echo.
    echo Please right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo [OK] Running with Administrator privileges
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH!
    echo.
    echo Please install Python 3.8+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    echo.
    pause
    exit /b 1
)

echo [OK] Python is installed
python --version
echo.

REM Check if requirements are installed
python -c "import flask" >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] Dependencies not installed. Installing now...
    echo.
    pip install -r requirements.txt
    echo.
)

echo Starting ICSScout Web Application...
echo.
echo Server will start at: http://localhost:5000
echo Press Ctrl+C to stop the server
echo.
echo ============================================================
echo.

REM Start the web application
python start_webapp.py

pause
