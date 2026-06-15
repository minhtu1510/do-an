# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for ICSScout Portable Application

Build command:
    pyinstaller icsscout_app.spec

This creates a standalone executable that can run from USB drive.
"""

import sys
from pathlib import Path

block_cipher = None

# Get project root
project_root = Path(SPECPATH)

# Collect all template files
template_files = []
templates_dir = project_root / 'icsscout' / 'interfaces' / 'web' / 'templates'
if templates_dir.exists():
    for tmpl in templates_dir.rglob('*.html'):
        rel_path = tmpl.relative_to(project_root)
        template_files.append((str(tmpl), str(rel_path.parent)))

# Collect all static files
static_files = []
static_dir = project_root / 'icsscout' / 'interfaces' / 'web' / 'static'
if static_dir.exists():
    for static in static_dir.rglob('*'):
        if static.is_file():
            rel_path = static.relative_to(project_root)
            static_files.append((str(static), str(rel_path.parent)))

# Collect s7pwn templates (for Risk Assessment)
s7pwn_templates = []
s7pwn_dir = project_root / 's7pwn' / 'templates'
if s7pwn_dir.exists():
    for tmpl in s7pwn_dir.rglob('*.html'):
        rel_path = tmpl.relative_to(project_root)
        s7pwn_templates.append((str(tmpl), str(rel_path.parent)))

# Collect s7pwn device_map (JSON data files)
device_map_files = []
device_map_dir = project_root / 's7pwn' / 'device_map'
if device_map_dir.exists():
    for data in device_map_dir.rglob('*.json'):
        rel_path = data.relative_to(project_root)
        device_map_files.append((str(data), str(rel_path.parent)))

# Collect data files (CVE database, etc.)
data_files = []
data_dir = project_root / 'icsscout' / 'data'
if data_dir.exists():
    for data in data_dir.rglob('*'):
        if data.is_file():
            rel_path = data.relative_to(project_root)
            data_files.append((str(data), str(rel_path.parent)))

# Hidden imports for dynamic loading
hidden_imports = [
    'flask',
    'flask_socketio',
    'flask_cors',
    'engineio.async_drivers.threading',
    'socketio',
    'scapy.all',
    'scapy.layers.inet',
    'scapy.layers.l2',
    'snap7',
    'pymodbus',
    'opcua',
    'chart',
    'reportlab',
    'docx',
    'jinja2',
    'sqlalchemy',
    'icsscout.core',
    'icsscout.domain',
    'icsscout.services',
    'icsscout.interfaces',
    'icsscout.core.capture',
    'icsscout.core.scanner',
    'icsscout.core.protocols',
    'icsscout.core.vulnerability',
    'icsscout.core.risk_assessment',
    's7pwn.ext.ot_protocol_scanner',
    's7pwn.ext.scan_module',
]

a = Analysis(
    ['run_webapp.py'],
    pathex=[str(project_root)],
    binaries=[],
    datas=template_files + static_files + s7pwn_templates + device_map_files + data_files,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',  # Large, not needed
        'tkinter',     # GUI toolkit, not needed
        'PyQt5',       # Not needed
        'test',        # Test packages
        'unittest',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='ICSScout',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,  # Show console for logs
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # Add icon file if available
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='ICSScout',
)
