# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['bi_app.py'],
    pathex=[],
    binaries=[],
    datas=[('bacnet_inspector.ico', '.'), ('version.txt', '.'), ('update_url.txt', '.')],
    hiddenimports=['serial.tools.list_ports', 'serial.tools.list_ports_windows', 'serial.win32'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['webview', 'PySide6.QtWebEngineCore', 'PySide6.QtWebEngineWidgets', 'PySide6.QtQml', 'PySide6.QtQuick', 'tkinter'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='BACnet Inspector',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['bacnet_inspector.ico'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='BACnet Inspector',
)
