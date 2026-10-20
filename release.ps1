# One-step release: tests, build, installer, update.json and (with a token) the GitHub release.
# Usage (or double-click release.bat):
#   release.ps1                 build everything; publish to GitHub if GITHUB_TOKEN is set
#   release.ps1 -SkipTests      skip the regression tests
#   release.ps1 -NoPublish      build only, even if GITHUB_TOKEN is set
# Before running: raise version.txt, write release_notes.txt, commit and push. See RELEASING.txt.
param([switch]$SkipTests, [switch]$NoPublish)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Step($t) { Write-Host "`n=== $t" -ForegroundColor Cyan }
function Fail($t) { Write-Host "`n$t" -ForegroundColor Red; exit 1 }
function RunBat($name, $arg) {
  # stdin from NUL so the "pause" at the end of each .bat returns straight away
  cmd /c "`"$PSScriptRoot\$name`" $arg < NUL"
  if ($LASTEXITCODE -ne 0) { Fail "$name failed (exit code $LASTEXITCODE)." }
}

$ver = (Get-Content version.txt -Raw).Trim()
if ($ver -notmatch '^\d+\.\d+\.\d+$') { Fail "version.txt should hold a version like 1.3.1 (it has '$ver')." }
if (-not (Get-Content release_notes.txt -Raw -ErrorAction SilentlyContinue)) { Fail 'release_notes.txt is empty - write what changed first.' }
$feed = (Get-Content update_url.txt -Raw).Trim()
if ($feed -notmatch '^https://github\.com/([^/]+)/([^/]+)/releases/latest/download/update\.json$') { Fail 'update_url.txt is not a GitHub releases address.' }
$owner, $repo = $Matches[1], $Matches[2]
$publish = $env:GITHUB_TOKEN -and -not $NoPublish
$api = "https://api.github.com/repos/$owner/$repo"
$hdr = @{ Authorization = "Bearer $env:GITHUB_TOKEN"; Accept = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28' }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Step "Releasing BACnet Inspector $ver"
if ($publish) {
  if (git status --porcelain --untracked-files=no) { Fail 'There are uncommitted changes. Commit and push them first.' }
  git fetch --quiet origin
  if ((git rev-parse HEAD) -ne (git rev-parse '@{u}')) { Fail 'This branch is not the same as GitHub. Push (or pull) first.' }
  try { Invoke-RestMethod "$api/releases/tags/v$ver" -Headers $hdr | Out-Null; Fail "Release v$ver already exists on GitHub. Raise version.txt." } catch {
    if ($_.Exception.Response.StatusCode.value__ -ne 404) { throw }
  }
}

if (-not $SkipTests) { Step 'Running the regression tests'; RunBat 'run_tests.bat' 'nopause' }
Step 'Building the application'; RunBat 'build_windows.bat' ''
Step 'Building the installer and update.json'; RunBat 'build_installer.bat' ''

$setup = "installer\BACnet-Inspector-Setup-$ver.exe"
$json = 'installer\update.json'
foreach ($f in $setup, $json) { if (-not (Test-Path $f)) { Fail "$f was not made." } }

if (-not $publish) {
  Step 'Built (not published)'
  Write-Host "  $setup`n  $json"
  Write-Host "To publish: GitHub -> Releases -> Draft a new release, tag v$ver, attach BOTH files."
  Write-Host '(Set the GITHUB_TOKEN environment variable to let this script publish for you. See RELEASING.txt.)'
  if (-not $NoPublish) { Start-Process "https://github.com/$owner/$repo/releases/new?tag=v$ver&title=BACnet%20Inspector%20$ver" }
  exit 0
}

Step 'Publishing on GitHub'
$body = @{ tag_name = "v$ver"; target_commitish = (git rev-parse HEAD); name = "BACnet Inspector $ver"
           body = (Get-Content release_notes.txt -Raw -Encoding UTF8).Trim(); make_latest = 'true' } | ConvertTo-Json
$rel = Invoke-RestMethod "$api/releases" -Method Post -Headers $hdr -ContentType 'application/json; charset=utf-8' `
  -Body ([Text.Encoding]::UTF8.GetBytes($body))
foreach ($f in $setup, $json) {
  $name = Split-Path $f -Leaf
  Write-Host "  uploading $name"
  Invoke-RestMethod "https://uploads.github.com/repos/$owner/$repo/releases/$($rel.id)/assets?name=$name" -Method Post `
    -Headers $hdr -ContentType 'application/octet-stream' -InFile $f | Out-Null
}
git fetch --quiet --tags origin
Write-Host "`nPublished: $($rel.html_url)" -ForegroundColor Green
Write-Host 'Installed copies will offer the update the next time they check.'
