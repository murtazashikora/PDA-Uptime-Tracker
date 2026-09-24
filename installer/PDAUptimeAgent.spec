# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec for freezing agent_service_frozen.py into PDAUptimeAgent.exe.
#
# Usage:  pyinstaller PDAUptimeAgent.spec
# Output: dist\PDAUptimeAgent.exe  (single-file, ~12-15 MB)

import sys
from pathlib import Path

block_cipher = None

a = Analysis(
    ['agent_service_frozen.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'win32timezone',          # pywin32 pulls this at runtime
        'win32serviceutil',
        'win32service',
        'win32event',
        'servicemanager',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter', '_tkinter',    # not needed, saves ~5 MB
        'matplotlib',
        'numpy',
        'PIL',
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='PDAUptimeAgent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,                 # no console window (runs as a service)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,                     # add an .ico path here if you want a branded icon
)
