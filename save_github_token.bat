@echo off
REM Saves the GitHub token that is on the clipboard, so release.bat can publish releases.
REM 1. On GitHub, click the copy button next to your new token.  2. Double-click this file.
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$t = ((Get-Clipboard -Raw) + '').Trim();" ^
  "if ($t -notmatch '^(github_pat_|ghp_)[A-Za-z0-9_]{20,}$' -or $t -like '*ABCDEFG*' -or $t -like '*paste_yours*') {" ^
  "  Write-Host 'The clipboard does not hold a GitHub token.' -ForegroundColor Red;" ^
  "  Write-Host 'On the GitHub page, click the copy icon next to the token (it starts with github_pat_), then run this again.'; exit 1 };" ^
  "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;" ^
  "try { $u = Invoke-RestMethod 'https://api.github.com/user' -Headers @{ Authorization = 'Bearer ' + $t } }" ^
  "catch { Write-Host 'GitHub did not accept this token. Make a new one and copy it again.' -ForegroundColor Red; exit 1 };" ^
  "[Environment]::SetEnvironmentVariable('GITHUB_TOKEN', $t, 'User');" ^
  "Set-Clipboard -Value ' ';" ^
  "Write-Host ('Saved. The token works for GitHub user ' + $u.login + '. release.bat can now publish.') -ForegroundColor Green"
pause
