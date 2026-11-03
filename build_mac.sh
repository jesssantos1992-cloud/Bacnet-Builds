#!/bin/bash
# Builds "BACnet Inspector.app" and zips it. Run on a Mac; GitHub does this for every release (.github/workflows/build-mac.yml).
set -e
cd "$(dirname "$0")"
VERSION=$(tr -d '[:space:]' < version.txt)
python3 -m pip install --upgrade pyinstaller PySide6-Essentials pyserial pillow
python3 -m PyInstaller --noconfirm --clean --windowed \
  --name "BACnet Inspector" \
  --icon bacnet_inspector.ico \
  --osx-bundle-identifier com.jessesantos.bacnetinspector \
  --add-data "bacnet_inspector.ico:." \
  --add-data "accs_logo.png:." \
  --add-data "version.txt:." \
  --add-data "update_url.txt:." \
  --add-data "release_notes.txt:." \
  --exclude-module webview \
  --exclude-module PySide6.QtWebEngineCore \
  --exclude-module PySide6.QtWebEngineWidgets \
  --exclude-module PySide6.QtQml \
  --exclude-module PySide6.QtQuick \
  --exclude-module tkinter \
  --hidden-import serial.tools.list_ports \
  --hidden-import serial.tools.list_ports_osx \
  bi_app.py
cd dist
ditto -c -k --keepParent "BACnet Inspector.app" "BACnet-Inspector-Mac-$VERSION.zip"
