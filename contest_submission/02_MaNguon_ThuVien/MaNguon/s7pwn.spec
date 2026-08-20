
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

# CLI Application
cli_a = Analysis(
    ['s7pwn/cli.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('s7pwn/device_map/*.json', 'device_map'),
        ('s7pwn/templates', 'templates'),
        ('s7pwn/static', 'static'),
    ],
    hiddenimports=[
        's7pwn.commands.scan',
        's7pwn.commands.listing',
        's7pwn.commands.target',
        's7pwn.commands.probe',
        's7pwn.commands.read',
        's7pwn.commands.write',
        's7pwn.commands.rwrite',
        's7pwn.commands.flood',
        's7pwn.commands.monitor',
        's7pwn.commands.export',
        's7pwn.commands.help',
        's7pwn.ext.scan_module',
        's7pwn.report_exporter',
        's7pwn.web_gui',
        'flask',
        'jinja2',
        'werkzeug',
        'click',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

cli_pyz = PYZ(cli_a.pure, cli_a.zipped_data, cipher=block_cipher)

cli_exe = EXE(
    cli_pyz,
    cli_a.scripts,
    [],
    exclude_binaries=True,
    name='s7pwn',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# Web GUI Application
webgui_a = Analysis(
    ['start_webgui.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('s7pwn/device_map/*.json', 'device_map'),
        ('s7pwn/templates', 'templates'),
        ('s7pwn/static', 'static'),
    ],
    hiddenimports=[
        's7pwn.web_gui',
        's7pwn.report_exporter',
        's7pwn.runtime',
        's7pwn.ext.scan_module',
        's7pwn.utils',
        'flask',
        'jinja2',
        'werkzeug',
        'click',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

webgui_pyz = PYZ(webgui_a.pure, webgui_a.zipped_data, cipher=block_cipher)

webgui_exe = EXE(
    webgui_pyz,
    webgui_a.scripts,
    [],
    exclude_binaries=True,
    name='s7pwn-webgui',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# Collect everything
coll = COLLECT(
    cli_exe,
    cli_a.binaries,
    cli_a.zipfiles,
    cli_a.datas,
    webgui_exe,
    webgui_a.binaries,
    webgui_a.zipfiles,
    webgui_a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='s7pwn',
)
