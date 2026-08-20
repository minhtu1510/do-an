#!/usr/bin/env python3
"""
Standalone launcher for S7Pwn Web GUI
Run this script to start the web interface directly without CLI
"""
from __future__ import annotations
import sys
import argparse
from s7pwn.web_gui import start_web_gui
from s7pwn.version import __version__


def main():
    parser = argparse.ArgumentParser(
        description=f'S7Pwn Web GUI v{__version__}',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Host to bind (default: 127.0.0.1)'
    )

    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Port to bind (default: 5000)'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )

    parser.add_argument(
        '--no-browser',
        action='store_true',
        help='Do not automatically open browser'
    )

    args = parser.parse_args()

    print(f"""
╔═══════════════════════════════════════╗
║        S7Pwn Web GUI v{__version__}         ║
║  Siemens S7 PLC Security Tool         ║
╚═══════════════════════════════════════╝
    """)

    start_web_gui(
        host=args.host,
        port=args.port,
        debug=args.debug,
        open_browser=not args.no_browser
    )


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)
