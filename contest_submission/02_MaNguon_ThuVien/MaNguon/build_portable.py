#!/usr/bin/env python3
"""
Build script for ICSScout Portable Application

This script:
1. Checks dependencies
2. Builds executable with PyInstaller
3. Creates portable package structure
4. Copies necessary files
5. Creates launcher scripts
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

def check_pyinstaller():
    """Check if PyInstaller is installed"""
    try:
        import PyInstaller
        print("✓ PyInstaller found")
        return True
    except ImportError:
        print("✗ PyInstaller not found")
        print("  Installing PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        return True

def clean_build_dirs():
    """Clean previous build directories"""
    print("\n[1/6] Cleaning previous builds...")
    dirs_to_clean = ['build', 'dist']
    for d in dirs_to_clean:
        if Path(d).exists():
            print(f"  Removing {d}/")
            shutil.rmtree(d)
    print("  ✓ Clean complete")

def build_executable():
    """Build executable with PyInstaller"""
    print("\n[2/6] Building executable...")
    print("  This may take several minutes...")

    cmd = [sys.executable, "-m", "PyInstaller", "icsscout_app.spec", "--clean"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print("  ✗ Build failed!")
        print(result.stderr)
        return False

    print("  ✓ Executable built successfully")
    return True

def create_portable_structure():
    """Create portable package structure"""
    print("\n[3/6] Creating portable package...")

    portable_dir = Path("ICSScout_Portable")
    if portable_dir.exists():
        shutil.rmtree(portable_dir)

    # Copy dist directory
    dist_dir = Path("dist/ICSScout")
    if not dist_dir.exists():
        print("  ✗ Dist directory not found!")
        return False

    print(f"  Copying {dist_dir} to {portable_dir}/")
    shutil.copytree(dist_dir, portable_dir)

    # Create data directories
    (portable_dir / "data").mkdir(exist_ok=True)
    (portable_dir / "reports").mkdir(exist_ok=True)
    (portable_dir / "sessions").mkdir(exist_ok=True)

    print("  ✓ Package structure created")
    return True

def create_launchers():
    """Create launcher scripts"""
    print("\n[4/6] Creating launcher scripts...")

    portable_dir = Path("ICSScout_Portable")

    # Windows launcher
    windows_launcher = portable_dir / "Start_ICSScout.bat"
    windows_launcher.write_text("""@echo off
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
""", encoding='utf-8')
    print("  ✓ Created Start_ICSScout.bat")

    # Linux/Mac launcher
    linux_launcher = portable_dir / "start_icsscout.sh"
    linux_launcher.write_text("""#!/bin/bash

echo "============================================================"
echo "ICSScout - OT/ICS Security Assessment Tool"
echo "============================================================"
echo ""
echo "Starting web server..."
echo "Open browser and navigate to: http://localhost:5000"
echo ""
echo "Press Ctrl+C to stop the server"
echo "============================================================"
echo ""

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo "[WARNING] Not running as root"
    echo "Some network scanning features may not work properly"
    echo "Please run with sudo for full functionality"
    echo ""
fi

# Start ICSScout
./ICSScout --host 127.0.0.1 --port 5000
""", encoding='utf-8')
    linux_launcher.chmod(0o755)
    print("  ✓ Created start_icsscout.sh")

    return True

def create_readme():
    """Create README file"""
    print("\n[5/6] Creating documentation...")

    portable_dir = Path("ICSScout_Portable")

    readme = portable_dir / "README.txt"
    readme.write_text("""================================================================
ICSScout Portable - OT/ICS Security Assessment Tool
================================================================

QUICK START:
------------

Windows:
  1. Right-click "Start_ICSScout.bat"
  2. Select "Run as Administrator"
  3. Open browser: http://localhost:5000

Linux/Mac:
  1. Open terminal in this directory
  2. Run: sudo ./start_icsscout.sh
  3. Open browser: http://localhost:5000


REQUIREMENTS:
-------------

Windows:
  - Windows 10/11 (64-bit)
  - Npcap driver (for packet capture)
    Download from: https://npcap.com/
  - Administrator privileges (for network scanning)

Linux:
  - Python 3.8+ or standalone executable
  - libpcap (usually pre-installed)
  - Root privileges (for network scanning)


FEATURES:
---------

✓ Network Scanner - Discover OT/ICS devices
✓ OT Protocol Scanner - Deep scan (S7, Modbus, Profinet, etc.)
✓ Vulnerability Scanner - Check for known CVEs
✓ Risk Assessment - Comprehensive security analysis
✓ PLC Monitoring - Real-time monitoring and anomaly detection
✓ Session Management - Save and restore assessment sessions
✓ Report Generation - PDF/DOCX/JSON export


DIRECTORY STRUCTURE:
--------------------

ICSScout_Portable/
├── ICSScout.exe          # Main application
├── Start_ICSScout.bat    # Windows launcher
├── start_icsscout.sh     # Linux/Mac launcher
├── data/                 # Session data (created automatically)
├── reports/              # Generated reports
├── sessions/             # Saved sessions
└── README.txt            # This file


USAGE TIPS:
-----------

1. Network Scanning:
   - Requires Administrator/root privileges
   - Install Npcap on Windows first
   - For Layer 2 scanning, select correct network interface

2. Session Management:
   - Sessions auto-save to data/ directory
   - Load previous sessions from Sessions page
   - Export sessions before moving to another machine

3. Risk Assessment:
   - Run Network Scan first to discover devices
   - Run OT Protocol Scan for detailed device info
   - Then run Risk Assessment for full analysis

4. Portable Usage:
   - Copy entire folder to USB drive
   - Run directly from USB (no installation needed)
   - All data stored in local directories


TROUBLESHOOTING:
----------------

Issue: "Permission denied" errors
Fix: Run as Administrator (Windows) or with sudo (Linux)

Issue: No devices found in network scan
Fix:
  - Check network interface selection
  - Ensure you're on same network as OT devices
  - Verify firewall settings

Issue: "Npcap not found" on Windows
Fix: Download and install from https://npcap.com/

Issue: Cannot access http://localhost:5000
Fix:
  - Check if port 5000 is available
  - Try different port: ICSScout.exe --port 8080
  - Check firewall settings


SUPPORT:
--------

GitHub: https://github.com/trangjackie/S7.Pwn
Documentation: See docs/ directory
Issues: Report bugs on GitHub Issues


LICENSE:
--------

See LICENSE file for details.


================================================================
© 2025 ICSScout - OT/ICS Security Assessment Tool
================================================================
""", encoding='utf-8')
    print("  ✓ Created README.txt")

    return True

def create_requirements_file():
    """Create requirements.txt for reference"""
    print("\n[6/6] Creating requirements.txt...")

    portable_dir = Path("ICSScout_Portable")

    # Get current requirements
    requirements = portable_dir / "requirements.txt"

    # Copy from project root if exists
    if Path("requirements.txt").exists():
        shutil.copy("requirements.txt", requirements)
        print("  ✓ Copied requirements.txt")
    else:
        # Create minimal requirements
        requirements.write_text("""# ICSScout Dependencies
flask>=2.3.0
flask-socketio>=5.3.0
flask-cors>=4.0.0
python-socketio>=5.9.0
scapy>=2.5.0
snap7-plus>=1.3.1
pymodbus>=3.5.0
opcua>=0.98.13
reportlab>=4.0.0
python-docx>=1.1.0
jinja2>=3.1.2
""", encoding='utf-8')
        print("  ✓ Created requirements.txt")

    return True

def main():
    """Main build process"""
    print("=" * 60)
    print("ICSScout Portable - Build Script")
    print("=" * 60)

    # Check PyInstaller
    if not check_pyinstaller():
        return 1

    # Build steps
    clean_build_dirs()

    if not build_executable():
        print("\n✗ Build failed!")
        return 1

    if not create_portable_structure():
        print("\n✗ Package creation failed!")
        return 1

    if not create_launchers():
        print("\n✗ Launcher creation failed!")
        return 1

    if not create_readme():
        print("\n✗ Documentation creation failed!")
        return 1

    if not create_requirements_file():
        print("\n✗ Requirements file creation failed!")
        return 1

    # Success
    print("\n" + "=" * 60)
    print("✓ BUILD SUCCESSFUL!")
    print("=" * 60)
    print("\nPortable package created: ICSScout_Portable/")
    print("\nTo use:")
    print("  1. Copy 'ICSScout_Portable' folder to USB drive")
    print("  2. Run 'Start_ICSScout.bat' (Windows) or './start_icsscout.sh' (Linux)")
    print("  3. Open browser: http://localhost:5000")
    print("\nNote: Administrator/root privileges required for network scanning")
    print("=" * 60)

    return 0

if __name__ == '__main__':
    sys.exit(main())
