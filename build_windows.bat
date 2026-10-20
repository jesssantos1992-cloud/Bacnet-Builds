@echo off
REM Builds the native BACnet Inspector app (a folder with "BACnet Inspector.exe" inside).
REM Needs the bi_*.py files, bacnet_live.py and bacnet_inspector.ico in this folder.
REM (build_windows_web.bat builds the older web-page version.)
setlocal
cd /d "%~dp0"
if not exist version.txt (echo version.txt is missing. & pause & exit /b 1)
if not exist update_url.txt (echo update_url.txt is missing. & pause & exit /b 1)
findstr /i "YOUR-NAME YOUR-REPO" update_url.txt >nul && (echo Put your GitHub name and repository in update_url.txt first. See RELEASING.txt. & pause & exit /b 1)
set "PY="
where py >nul 2>nul && set "PY=py"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY for /d %%D in ("%LocalAppData%\Python\pythoncore-*") do if exist "%%D\python.exe" set "PY=%%D\python.exe"
if not defined PY (echo Python is not installed. Get it from https://www.python.org/downloads/ and tick "Add python.exe to PATH". & pause & exit /b 1)

echo Installing build tools...
"%PY%" -m pip install --upgrade pyinstaller PySide6-Essentials pyserial || (echo pip failed & pause & exit /b 1)

echo Building the application...
"%PY%" -m PyInstaller --noconfirm --clean --onedir --noconsole ^
  --name "BACnet Inspector" ^
  --icon "bacnet_inspector.ico" ^
  --add-data "bacnet_inspector.ico;." ^
  --add-data "version.txt;." ^
  --add-data "update_url.txt;." ^
  --add-data "release_notes.txt;." ^
  --add-binary "tools\putty\putty.exe;putty" ^
  --add-data "tools\putty\LICENCE;putty" ^
  --add-data "tools\putty\putty.chm;putty" ^
  --exclude-module webview ^
  --exclude-module PySide6.QtWebEngineCore ^
  --exclude-module PySide6.QtWebEngineWidgets ^
  --exclude-module PySide6.QtQml ^
  --exclude-module PySide6.QtQuick ^
  --exclude-module tkinter ^
  --hidden-import serial.tools.list_ports ^
  --hidden-import serial.tools.list_ports_windows ^
  --hidden-import serial.win32 ^
  bi_app.py || (echo Build failed & pause & exit /b 1)

echo Removing parts of Qt the app does not use (smaller download)...
set "QT=dist\BACnet Inspector\_internal\PySide6"
for %%F in (opengl32sw.dll Qt6Quick.dll Qt6Qml.dll Qt6QmlMeta.dll Qt6QmlModels.dll Qt6QmlWorkerScript.dll Qt6Pdf.dll Qt6VirtualKeyboard.dll) do if exist "%QT%\%%F" del /q "%QT%\%%F"
for %%F in (qdirect2d.dll qminimal.dll qoffscreen.dll) do if exist "%QT%\plugins\platforms\%%F" del /q "%QT%\plugins\platforms\%%F"
for %%F in (qpdf.dll qgif.dll qicns.dll qjpeg.dll qtga.dll qtiff.dll qwbmp.dll qwebp.dll) do if exist "%QT%\plugins\imageformats\%%F" del /q "%QT%\plugins\imageformats\%%F"
if exist "%QT%\plugins\platforminputcontexts" rmdir /s /q "%QT%\plugins\platforminputcontexts"
if exist "%QT%\translations" rmdir /s /q "%QT%\translations"

call "%~dp0sign.bat" "dist\BACnet Inspector\BACnet Inspector.exe" || (echo Signing failed & pause & exit /b 1)

echo.
echo Done:  dist\BACnet Inspector\BACnet Inspector.exe
echo Keep the whole "BACnet Inspector" folder together, or use build_installer.bat to make a Setup file.
echo (Add --uac-admin to the PyInstaller line if you want it to always ask for Administrator,
echo  which the built-in "raw" capture option needs. Not needed when using Wireshark/Npcap.)
pause
