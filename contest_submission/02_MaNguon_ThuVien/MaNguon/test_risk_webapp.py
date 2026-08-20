#!/usr/bin/env python3
"""
Simple test to start webapp and check routes
"""
import sys
sys.path.insert(0, '/home/user/S7.Pwn')

print("Starting webapp test...")

try:
    # Start webapp with minimal dependencies
    from s7pwn import runtime
    from flask import Flask, render_template

    # Create minimal Flask app
    app = Flask(__name__,
                template_folder='/home/user/S7.Pwn/s7pwn/templates',
                static_folder='/home/user/S7.Pwn/s7pwn/static')

    # Add routes
    @app.route('/')
    def index():
        return render_template('index.html', version='1.0')

    @app.route('/risk-assessment')
    def risk_assessment_page():
        return render_template('risk_assessment.html', version='1.0')

    # Try to setup risk assessment routes
    try:
        from icsscout.interfaces.web.routes import setup_risk_assessment_routes
        setup_risk_assessment_routes(app, runtime)
        print("[✓] Risk Assessment routes loaded")
    except Exception as e:
        print(f"[!] Risk Assessment routes failed: {e}")

    # List routes
    print("\nRegistered routes:")
    for rule in app.url_map.iter_rules():
        if not str(rule).startswith('/static'):
            print(f"  - {rule}")

    # Start server
    print(f"\n{'='*60}")
    print("Starting server on http://0.0.0.0:5000")
    print(f"{'='*60}\n")

    print("Access:")
    print("  Main: http://localhost:5000/")
    print("  Risk Assessment: http://localhost:5000/risk-assessment")
    print("\nPress Ctrl+C to stop\n")

    app.run(host='0.0.0.0', port=5000, debug=False)

except KeyboardInterrupt:
    print("\n\nShutting down...")
    sys.exit(0)
except Exception as e:
    print(f"\nError: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
