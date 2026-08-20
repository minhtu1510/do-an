@echo off
REM ICSScout Windows Installation Script
REM Run this batch file as Administrator!

echo ============================================================
echo ICSScout v2.0 - Windows Installation
echo ============================================================
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
    echo [ERROR] Python is not installed!
    echo.
    echo Please install Python 3.8 or later from:
    echo https://www.python.org/downloads/
    echo.
    echo IMPORTANT: Check "Add Python to PATH" during installation!
    echo.
    pause
    exit /b 1
)

echo [OK] Python is installed:
python --version
echo.

REM Check if Npcap is installed
echo Checking for Npcap...
if exist "C:\Windows\System32\Npcap\wpcap.dll" (
    echo [OK] Npcap is installed
) else (
    echo [WARNING] Npcap is not detected!
    echo.
    echo Npcap is REQUIRED for packet capture on Windows.
    echo.
    echo Please download and install Npcap from:
    echo https://npcap.com/#download
    echo.
    echo IMPORTANT: When installing Npcap, make sure to check:
    echo - "Install Npcap in WinPcap API-compatible Mode"
    echo.
    echo After installing Npcap, reboot your computer and run this script again.
    echo.
    pause
    exit /b 1
)
echo.

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip
echo.

REM Install requirements
echo Installing ICSScout dependencies...
echo This may take a few minutes...
echo.
pip install -r requirements.txt

if %errorLevel% neq 0 (
    echo.
    echo [ERROR] Installation failed!
    echo.
    echo Common issues:
    echo 1. Missing Visual C++ Redistributable
    echo    Download from: https://aka.ms/vs/17/release/vc_redist.x64.exe
    echo.
    echo 2. Python 32-bit on Windows 64-bit
    echo    Install Python 64-bit version
    echo.
    echo 3. Firewall or antivirus blocking installation
    echo    Temporarily disable and try again
    echo.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo Installation Complete!
echo ============================================================
echo.
echo To start ICSScout Web Application:
echo 1. Right-click "start_webapp.bat"
echo 2. Select "Run as administrator"
echo 3. Open browser to http://localhost:5000
echo.
echo For detailed instructions, read WINDOWS_SETUP.md
echo.
pause
