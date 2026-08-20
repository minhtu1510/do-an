"""
Build script for creating S7Pwn standalone executable using PyInstaller
Run: python build_exe.py
"""
import os
import sys
import shutil
import subprocess
from pathlib import Path


def build_executable():
    """Build standalone executable with PyInstaller"""

    print("=" * 60)
    print("S7Pwn Executable Builder")
    print("=" * 60)

    # Check if PyInstaller is installed
    try:
        import PyInstaller
        print("✓ PyInstaller found")
    except ImportError:
        print("✗ PyInstaller not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        print("✓ PyInstaller installed")

    # Get project root
    project_root = Path(__file__).parent
    dist_dir = project_root / "dist"
    build_dir = project_root / "build"

    # Clean previous builds
    print("\nCleaning previous builds...")
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    if build_dir.exists():
        shutil.rmtree(build_dir)
    print("✓ Clean complete")

    # Create spec file content
    spec_content = """
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
"""

    # Write spec file
    spec_file = project_root / "s7pwn.spec"
    with open(spec_file, 'w') as f:
        f.write(spec_content)
    print(f"✓ Created spec file: {spec_file}")

    # Run PyInstaller
    print("\nBuilding executable...")
    print("This may take a few minutes...\n")

    cmd = [
        "pyinstaller",
        "--clean",
        "--noconfirm",
        str(spec_file)
    ]

    try:
        subprocess.check_call(cmd, cwd=project_root)
        print("\n✓ Build successful!")
    except subprocess.CalledProcessError as e:
        print(f"\n✗ Build failed with error: {e}")
        return False

    # Create reports directory in dist
    reports_dir = dist_dir / "s7pwn" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    print(f"✓ Created reports directory: {reports_dir}")

    # Copy documentation
    docs = ["README.md", "FEATURES.md", "QUICK_START.md", "BUILD.md"]
    for doc in docs:
        src = project_root / doc
        if src.exists():
            dst = dist_dir / "s7pwn" / doc
            shutil.copy2(src, dst)
            print(f"✓ Copied {doc}")

    # Create run scripts
    print("\nCreating launcher scripts...")

    # Windows batch file for CLI
    cli_bat = dist_dir / "s7pwn" / "s7pwn-cli.bat"
    with open(cli_bat, 'w') as f:
        f.write("@echo off\n")
        f.write('cd /d "%~dp0"\n')
        f.write("s7pwn.exe\n")
        f.write("pause\n")
    print(f"✓ Created {cli_bat.name}")

    # Windows batch file for Web GUI
    webgui_bat = dist_dir / "s7pwn" / "s7pwn-webgui.bat"
    with open(webgui_bat, 'w') as f:
        f.write("@echo off\n")
        f.write('cd /d "%~dp0"\n')
        f.write("s7pwn-webgui.exe\n")
        f.write("pause\n")
    print(f"✓ Created {webgui_bat.name}")

    # Create README for dist
    readme_dist = dist_dir / "s7pwn" / "README_DIST.txt"
    with open(readme_dist, 'w', encoding='utf-8') as f:
        f.write("""
S7Pwn - Portable Distribution
==============================

This is a standalone version of S7Pwn that doesn't require Python installation.

Contents:
---------
- s7pwn.exe           : CLI version
- s7pwn-webgui.exe    : Web GUI version
- s7pwn-cli.bat       : Easy launcher for CLI
- s7pwn-webgui.bat    : Easy launcher for Web GUI
- reports/            : Export reports directory
- device_map/         : Device mapping data
- templates/          : Web templates
- Documentation files

Quick Start:
------------
1. Double-click 's7pwn-cli.bat' to start CLI
   OR
   Double-click 's7pwn-webgui.bat' to start Web GUI

2. For CLI usage, type 'help' for commands
3. For Web GUI, browser will open automatically at http://127.0.0.1:5000

4. Scan network: scan
5. List PLCs: list
6. Select target: select 0
7. Export reports: export scan json

Requirements:
-------------
- Windows 10/11 (64-bit)
- Administrator privileges (for network scanning)
- Network access to target PLCs

Security Notice:
---------------
Only use this tool on networks you have permission to test.
This tool is for authorized security testing only.

For more information, see FEATURES.md and QUICK_START.md

Support:
--------
https://github.com/your-repo/S7.Pwn
""")
    print(f"✓ Created {readme_dist.name}")

    print("\n" + "=" * 60)
    print("BUILD COMPLETE!")
    print("=" * 60)
    print(f"\nExecutables location: {dist_dir / 's7pwn'}")
    print("\nTo distribute:")
    print(f"  1. Compress the folder: {dist_dir / 's7pwn'}")
    print("  2. Copy to target machine")
    print("  3. Extract and run s7pwn-cli.bat or s7pwn-webgui.bat")
    print("\nNote: First run may be slow due to unpacking")

    return True


def create_installer():
    """Create NSIS installer script (optional)"""
    project_root = Path(__file__).parent

    nsis_script = """
; S7Pwn Installer Script for NSIS
; Install NSIS from https://nsis.sourceforge.io/

!define APPNAME "S7Pwn"
!define COMPANYNAME "Security Research"
!define DESCRIPTION "Siemens S7 PLC Security Testing Tool"
!define VERSIONMAJOR 1
!define VERSIONMINOR 0
!define VERSIONBUILD 0

RequestExecutionLevel admin
InstallDir "$PROGRAMFILES64\\${APPNAME}"

Name "${APPNAME}"
OutFile "S7Pwn-Setup.exe"

Page directory
Page instfiles

Section "Install"
    SetOutPath $INSTDIR
    File /r "dist\\s7pwn\\*.*"

    CreateDirectory "$SMPROGRAMS\\${APPNAME}"
    CreateShortCut "$SMPROGRAMS\\${APPNAME}\\S7Pwn CLI.lnk" "$INSTDIR\\s7pwn.exe"
    CreateShortCut "$SMPROGRAMS\\${APPNAME}\\S7Pwn Web GUI.lnk" "$INSTDIR\\s7pwn-webgui.exe"
    CreateShortCut "$SMPROGRAMS\\${APPNAME}\\Uninstall.lnk" "$INSTDIR\\uninstall.exe"

    CreateShortCut "$DESKTOP\\S7Pwn Web GUI.lnk" "$INSTDIR\\s7pwn-webgui.exe"

    WriteUninstaller "$INSTDIR\\uninstall.exe"
SectionEnd

Section "Uninstall"
    Delete "$SMPROGRAMS\\${APPNAME}\\*.*"
    RMDir "$SMPROGRAMS\\${APPNAME}"
    Delete "$DESKTOP\\S7Pwn Web GUI.lnk"
    RMDir /r "$INSTDIR"
SectionEnd
"""

    nsis_file = project_root / "installer.nsi"
    with open(nsis_file, 'w') as f:
        f.write(nsis_script)

    print(f"\n✓ NSIS installer script created: {nsis_file}")
    print("  To create installer, install NSIS and run:")
    print(f"  makensis {nsis_file}")


if __name__ == "__main__":
    try:
        success = build_executable()

        if success:
            print("\nDo you want to create an NSIS installer script? (y/n): ", end='')
            choice = input().strip().lower()
            if choice == 'y':
                create_installer()

        sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        print("\n\nBuild cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
