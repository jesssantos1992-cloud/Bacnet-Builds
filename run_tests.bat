@echo off
REM Runs all regression tests (see tests\run_tests.py). Put a BACnet/IP and an MS/TP capture in tests\captures first.
setlocal
cd /d "%~dp0"
set "PY="
where py >nul 2>nul && set "PY=py"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY for /d %%D in ("%LocalAppData%\Python\pythoncore-*") do if exist "%%D\python.exe" set "PY=%%D\python.exe"
if not defined PY (echo Python is not installed. & pause & exit /b 1)
"%PY%" -m pip install --quiet pyflakes PySide6-Essentials pyserial
"%PY%" tests\run_tests.py
set RC=%errorlevel%
if "%~1"=="" pause
exit /b %RC%
