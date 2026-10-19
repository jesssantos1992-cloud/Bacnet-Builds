# Writes installer\update.json for the Setup file that build_installer.bat just made.
# Usage: make_update_json.ps1 -Version 1.2.1      (build_installer.bat calls this for you)
param([Parameter(Mandatory)][string]$Version)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$feed = (Get-Content update_url.txt -Raw).Trim()
if ($feed -notmatch '^https://github\.com/([^/]+)/([^/]+)/releases/latest/download/update\.json$') {
  throw "update_url.txt must look like https://github.com/NAME/REPO/releases/latest/download/update.json"
}
$repo = "https://github.com/$($Matches[1])/$($Matches[2])"
$setup = "installer\BACnet-Inspector-Setup-$Version.exe"
$notes = ''
if (Test-Path release_notes.txt) { $notes = (Get-Content release_notes.txt -Raw -Encoding UTF8).Trim() }

$m = [ordered]@{
  version = $Version
  date    = (Get-Date -Format 'yyyy-MM-dd')
  notes   = $notes
  url     = "$repo/releases/download/v$Version/BACnet-Inspector-Setup-$Version.exe"
  sha256  = (Get-FileHash $setup -Algorithm SHA256).Hash.ToLower()
  page    = "$repo/releases/latest"
}
# UTF-8 without a BOM: the app's JSON reader rejects a BOM.
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'installer\update.json'), ($m | ConvertTo-Json), (New-Object Text.UTF8Encoding $false))
Write-Host "Wrote installer\update.json for version $Version"
