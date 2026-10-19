@echo off
REM Builds the BACnet Inspector app (a folder with "BACnet Inspector.exe" inside; starts instantly).
REM Put this file, bacnet_live.py, bacnet_inspector.html and bacnet_inspector.ico in one folder, then run this file.
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
"%PY%" -m pip install --upgrade pyinstaller pywebview pyserial || (echo pip failed & pause & exit /b 1)

echo Building the application...
"%PY%" -m PyInstaller --noconfirm --clean --onedir --noconsole ^
  --name "BACnet Inspector" ^
  --icon "bacnet_inspector.ico" ^
  --add-data "bacnet_inspector.html;." ^
  --add-data "version.txt;." ^
  --add-data "update_url.txt;." ^
  --collect-all webview ^
  --hidden-import serial.tools.list_ports ^
  --hidden-import serial.tools.list_ports_windows ^
  --hidden-import serial.win32 ^
  bacnet_live.py || (echo Build failed & pause & exit /b 1)

call "%~dp0sign.bat" "dist\BACnet Inspector\BACnet Inspector.exe" || (echo Signing failed & pause & exit /b 1)

echo.
echo Done:  dist\BACnet Inspector\BACnet Inspector.exe
echo Keep the whole "BACnet Inspector" folder together, or use build_installer.bat to make a Setup file.
echo (Add --uac-admin to the PyInstaller line if you want it to always ask for Administrator,
echo  which the built-in "raw" capture option needs. Not needed when using Wireshark/Npcap.)
pause
