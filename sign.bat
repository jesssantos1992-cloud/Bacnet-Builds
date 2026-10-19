@echo off
REM Optional code signing. Does nothing unless the SIGN_PFX environment variable is set.
REM Usage: sign.bat "path\to\file.exe"          (build_windows.bat and build_installer.bat call this for you)
REM See SIGNING.txt for how to get a certificate and set the variables.
if not defined SIGN_PFX exit /b 0
set "ST="
for /f "delims=" %%S in ('where signtool 2^>nul') do set "ST=%%S"
if defined ST goto go
for /f "delims=" %%S in ('dir /b /s "%ProgramFiles(x86)%\Windows Kits\10\bin\*signtool.exe" 2^>nul ^| findstr /i "\\x64\\"') do set "ST=%%S"
if defined ST goto go
echo signtool.exe was not found. Install the Windows 10/11 SDK ^(tick "Signing Tools for Desktop Apps"^).
exit /b 1
:go
if not defined SIGN_TS set "SIGN_TS=http://timestamp.digicert.com"
echo Signing %~1
"%ST%" sign /fd SHA256 /f "%SIGN_PFX%" /p "%SIGN_PASSWORD%" /tr "%SIGN_TS%" /td SHA256 /d "BACnet Inspector" "%~1"
exit /b %errorlevel%
