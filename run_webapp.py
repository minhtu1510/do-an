#!/usr/bin/env python3
"""
ICSScout Portable Application Entry Point

This script starts the ICSScout web application.
Can be run directly or built into standalone executable.
"""

import sys
import os
from pathlib import Path

# Add project root to path
if getattr(sys, 'frozen', False):
    # Running as compiled executable
    application_path = Path(sys._MEIPASS)
else:
    # Running as script
    application_path = Path(__file__).parent

sys.path.insert(0, str(application_path))

# Set working directory for data files
os.chdir(application_path)

# Import and start app
from icsscout.interfaces.web.app import start_web_app

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='ICSScout OT Security Assessment Tool')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to (default: 5000)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    args = parser.parse_args()

    print("=" * 60)
    print("ICSScout - OT/ICS Security Assessment Tool")
    print("=" * 60)
    print(f"Starting web server on http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    print()

    try:
        start_web_app(host=args.host, port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        sys.exit(0)
