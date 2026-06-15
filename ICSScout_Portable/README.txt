================================================================
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
