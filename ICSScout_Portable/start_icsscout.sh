#!/bin/bash

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
