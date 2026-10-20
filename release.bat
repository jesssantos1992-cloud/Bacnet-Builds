@echo off
REM Tests, builds and (with GITHUB_TOKEN set) publishes a release. See RELEASING.txt.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0release.ps1" %*
pause
