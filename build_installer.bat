@echo off
REM Compiles installer.iss into a Setup .exe and writes installer\update.json. Run build_windows.bat first.
setlocal
cd /d "%~dp0"
if not exist "dist\BACnet Inspector\BACnet Inspector.exe" (echo Run build_windows.bat first - dist\BACnet Inspector\BACnet Inspector.exe was not found. & pause & exit /b 1)
set /p VER=<version.txt
if not defined VER (echo version.txt is empty. & pause & exit /b 1)
set "ISCC="
for %%P in ("%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" "%ProgramFiles%\Inno Setup 6\ISCC.exe" "%LocalAppData%\Programs\Inno Setup 6\ISCC.exe") do if exist %%P set "ISCC=%%~P"
if not defined ISCC (echo Inno Setup 6 is not installed. Get it from https://jrsoftware.org/isdl.php & pause & exit /b 1)
if defined SIGN_PFX goto signed
"%ISCC%" "/DAppVersion=%VER%" installer.iss || (echo Installer build failed & pause & exit /b 1)
goto built
:signed
"%ISCC%" "/DAppVersion=%VER%" /DSIGN "/Ssigntool=$q%~dp0sign.bat$q $q$f$q" installer.iss || (echo Installer build failed & pause & exit /b 1)
:built
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0make_update_json.ps1" -Version %VER% || (echo Could not write update.json & pause & exit /b 1)
echo.
echo Done:  installer\BACnet-Inspector-Setup-%VER%.exe  and  installer\update.json
echo To publish: on GitHub make a new release with tag v%VER% and attach BOTH files. See RELEASING.txt.
pause
