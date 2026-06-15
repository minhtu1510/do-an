#!/usr/bin/env python3
"""
ICSScout Web Application Launcher

Start the ICSScout Web GUI with real-time packet analyzer.
"""

import sys
import argparse
from pathlib import Path

# Add icsscout to path
sys.path.insert(0, str(Path(__file__).parent))

from icsscout.interfaces.web.app import start_web_app
from icsscout.utils.logger import setup_logging


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='ICSScout Web Application - OT/ICS Security Assessment Platform'
    )
    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Host to bind to (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Port to bind to (default: 5000)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging()

    # Start web app
    start_web_app(
        host=args.host,
        port=args.port,
        debug=args.debug
    )


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
