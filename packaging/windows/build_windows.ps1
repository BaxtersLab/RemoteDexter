<#
.SYNOPSIS
    Build RemoteDexter for Windows and stage a folder a person can actually run.

.DESCRIPTION
    The gap this closes, recorded in the `windows-host` gate row:

        no build step stages host_app.exe into windows/, so on a clean checkout
        the shortcut -> run.bat -> exe chain ends at a missing file

    Cargo writes to target\release\. `windows\run.bat` looks next to itself.
    Nothing connected the two, so the supported launch path worked only on a
    machine where somebody had already copied the file by hand -- which is the
    machine it was written on, and no other.

    Block 13 produced a Linux .deb. This is the Windows counterpart. It is a
    PORTABLE package, not an MSI, and deliberately so:

      * no admin rights, no registry, no service, nothing to uninstall wrongly;
      * the shortcut bootstrap that already exists in windows\bootstrap\ is a
        per-user shortcut creator, which is the same shape;
      * an installer that must be signed is an installer that cannot be built
        here -- release signing reads RDX_KEYSTORE and companions, the key is
        the operator's, and it must not come near this tree.

    Unsigned is stated rather than hidden: SmartScreen will warn on first run,
    and PACKAGE-README.txt in the output says so.

.PARAMETER Configuration
    release (default) or debug.

.PARAMETER OutDir
    Where to write the staged folder. Default: dist\ at the repository root.

.PARAMETER Zip
    Also produce a .zip beside the folder.

.PARAMETER SkipBuild
    Stage from an existing build instead of running cargo. For packaging a
    binary that was already produced and verified.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File packaging\windows\build_windows.ps1 -Zip
#>
[CmdletBinding()]
param(
    [ValidateSet('release', 'debug')]
    [string]$Configuration = 'release',
    [string]$OutDir,
    [switch]$Zip,
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Repository root is two levels up from packaging\windows\.
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$WindowsDir = Join-Path $RepoRoot 'windows'
if (-not $OutDir) { $OutDir = Join-Path $RepoRoot 'dist' }

Write-Host "RemoteDexter Windows packaging" -ForegroundColor Cyan
Write-Host "  repository : $RepoRoot"
Write-Host "  config     : $Configuration"
Write-Host "  output     : $OutDir"
Write-Host ''

# ── 1. Build ────────────────────────────────────────────────────────────────
if ($SkipBuild) {
    Write-Host '  [1/5] build SKIPPED (-SkipBuild)' -ForegroundColor Yellow
} else {
    Write-Host '  [1/5] cargo build' -ForegroundColor Green
    Push-Location $RepoRoot
    try {
        $cargoArgs = @('build', '-p', 'host_app')
        if ($Configuration -eq 'release') { $cargoArgs += '--release' }
        & cargo @cargoArgs
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
}

# CARGO_TARGET_DIR is honoured if set, because a machine that redirects its
# build output would otherwise have this script stage a stale binary from a
# target\ directory cargo is no longer writing to.
$targetRoot = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $RepoRoot 'target' }
$exe = Join-Path $targetRoot (Join-Path $Configuration 'host_app.exe')
if (-not (Test-Path $exe)) {
    throw "host_app.exe was not found at '$exe'. Build first, or point -Configuration at one that exists."
}
$built = Get-Item $exe
Write-Host ("        host_app.exe  {0:n0} bytes  {1}" -f $built.Length, $built.LastWriteTime)

# ── 2. Stage into windows\ so the supported launch path works in-tree ───────
# This is the actual defect being fixed. Copying into dist\ alone would leave
# the shortcut -> run.bat -> exe chain broken for anyone launching from the
# checkout, which is how the operator launches it.
Write-Host '  [2/5] stage host_app.exe into windows\' -ForegroundColor Green
Copy-Item -Path $exe -Destination (Join-Path $WindowsDir 'host_app.exe') -Force
Write-Host ("        -> {0}" -f (Join-Path $WindowsDir 'host_app.exe'))

# ── 3. Assemble the portable package ────────────────────────────────────────
Write-Host '  [3/5] assemble portable package' -ForegroundColor Green
$pkgName = 'RemoteDexter-windows'
$pkgDir = Join-Path $OutDir $pkgName
if (Test-Path $pkgDir) { Remove-Item -Recurse -Force $pkgDir }
New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $pkgDir 'bootstrap') -Force | Out-Null

Copy-Item $exe (Join-Path $pkgDir 'host_app.exe') -Force
Copy-Item (Join-Path $WindowsDir 'run.bat') $pkgDir -Force
foreach ($f in @('bootstrap.ico', 'create_shortcut.vbs', 'install_shortcut.bat', 'README.md')) {
    $src = Join-Path (Join-Path $WindowsDir 'bootstrap') $f
    if (Test-Path $src) { Copy-Item $src (Join-Path $pkgDir 'bootstrap') -Force }
}
$licence = Join-Path $RepoRoot 'LICENSE'
if (Test-Path $licence) { Copy-Item $licence $pkgDir -Force }

# ── 4. A readme that tells the truth about what this is ─────────────────────
Write-Host '  [4/5] write PACKAGE-README.txt' -ForegroundColor Green
$stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
$readme = @"
RemoteDexter - Windows portable package
=======================================

Built    : $stamp
Config   : $Configuration
Licence  : AGPL-3.0-only (see LICENSE)

WHAT THIS IS
------------
A folder you can copy anywhere and run. No installer, no admin rights, no
registry entries, no service. Deleting the folder removes it completely.

TO RUN
------
  1. Double-click run.bat  (or bootstrap\install_shortcut.bat first, to get
     Desktop and Start Menu shortcuts with an icon)
  2. In the host window, choose a network interface, then Start host
  3. Create a pairing QR and scan it with the RemoteDexter phone app

VIEWING vs CONTROL
------------------
run.bat enables VIEWING only. Input (mouse and keyboard) is deny-by-default
and stays that way: being able to see a machine and being able to drive it are
different grants, and a launcher should not decide the second one for you.

To allow the phone to drive this desktop for ONE launch, from a cmd window:

    set "RD_CAP_INPUT=1" && run.bat

The quotes matter. Written as `set RD_CAP_INPUT=1 && run.bat`, cmd stores the
value as "1 " with a trailing space, the host's exact-match check rejects it,
and you get picture-without-control with no explanation.

CODE SIGNING
------------
This package is NOT signed. Windows SmartScreen will warn the first time you
run it ("Windows protected your PC" -> More info -> Run anyway). That warning
is accurate: nothing here carries a publisher signature.

"@
Set-Content -Path (Join-Path $pkgDir 'PACKAGE-README.txt') -Value $readme -Encoding ascii

# ── 5. Manifest, and optionally a zip ───────────────────────────────────────
Write-Host '  [5/5] manifest' -ForegroundColor Green
$manifest = Join-Path $pkgDir 'SHA256SUMS.txt'
Get-ChildItem -Path $pkgDir -Recurse -File |
    Where-Object { $_.Name -ne 'SHA256SUMS.txt' } |
    ForEach-Object {
        $rel = $_.FullName.Substring($pkgDir.Length + 1)
        "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $rel
    } | Set-Content -Path $manifest -Encoding ascii

if ($Zip) {
    $zipPath = Join-Path $OutDir "$pkgName.zip"
    if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
    Compress-Archive -Path $pkgDir -DestinationPath $zipPath
    Write-Host ("        zip: {0} ({1:n0} bytes)" -f $zipPath, (Get-Item $zipPath).Length)
}

$count = (Get-ChildItem -Path $pkgDir -Recurse -File).Count
Write-Host ''
Write-Host "DONE. $count files in $pkgDir" -ForegroundColor Cyan
Write-Host "windows\host_app.exe is staged, so run.bat works from the checkout too." -ForegroundColor Cyan
