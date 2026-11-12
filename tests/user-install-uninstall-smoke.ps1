# Windows integration: per-user install/uninstall must preserve user data.
$ErrorActionPreference = 'Stop'
$originalLocalAppData = $env:LOCALAPPDATA
$tempRoot = Join-Path $env:RUNNER_TEMP ('AntiOS-User-Uninstall-' + [guid]::NewGuid().ToString('N'))
$env:LOCALAPPDATA = Join-Path $tempRoot 'profile'
$source = Join-Path $tempRoot 'source'
$installDir = Join-Path $env:LOCALAPPDATA 'Programs\AntiOS'
$startMenuDir = Join-Path ([Environment]::GetFolderPath('Programs')) 'AntiOS'
$installScript = Join-Path $PSScriptRoot '..\scripts\install.ps1'
$uninstallScript = Join-Path $PSScriptRoot '..\scripts\uninstall.ps1'
try {
    New-Item -ItemType Directory -Path $source -Force | Out-Null
    foreach ($name in @('AntiOS.exe', 'AntiOS-GUI.exe', 'AntiOS-Guard.exe')) {
        Set-Content -LiteralPath (Join-Path $source $name) -Value 'inert fixture' -Encoding ascii
    }
    foreach ($name in @('guard-startup.ps1', 'dashboard-startup.ps1')) {
        Set-Content -LiteralPath (Join-Path $source $name) -Value 'param([switch]$Uninstall,[switch]$Apply)' -Encoding utf8
    }
    foreach ($directory in @('_cli', '_gui', '_guard')) {
        $folder = Join-Path $source $directory
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $folder 'owned.txt') -Value 'owned' -Encoding utf8
    }

    & $installScript -SourceDirectory $source
    $manifestFile = Join-Path $installDir 'install-manifest.json'
    $manifest = Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
    if ($manifest.schema -ne 1 -or @($manifest.files).Count -ne 8) {
        throw 'Per-user installer did not generate a complete ownership manifest.'
    }

    # Manifest traversal must be rejected before any installed file is touched.
    $originalManifest = Get-Content -LiteralPath $manifestFile -Raw
    $manifest.files += '..\..\outside.txt'
    [IO.File]::WriteAllText($manifestFile, ($manifest | ConvertTo-Json -Depth 4))
    $rejected = $false
    try { & $uninstallScript } catch { $rejected = $true }
    if (-not $rejected -or -not (Test-Path -LiteralPath (Join-Path $installDir 'AntiOS.exe'))) {
        throw 'Unsafe manifest traversal was not rejected before uninstall.'
    }
    [IO.File]::WriteAllText($manifestFile, $originalManifest)

    Set-Content -LiteralPath (Join-Path $installDir 'Keep-me.txt') -Value 'user data'
    Set-Content -LiteralPath (Join-Path $installDir '_cli\Keep-me-too.txt') -Value 'user data'
    Set-Content -LiteralPath (Join-Path $startMenuDir 'Keep-custom-shortcut.txt') -Value 'user data'
    # Inert fixture must not be executed as Guard.
    Remove-Item -LiteralPath (Join-Path $installDir 'AntiOS-Guard.exe') -Force

    & $uninstallScript
    foreach ($path in @(
        (Join-Path $installDir 'Keep-me.txt'),
        (Join-Path $installDir '_cli\Keep-me-too.txt'),
        (Join-Path $startMenuDir 'Keep-custom-shortcut.txt')
    )) {
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Uninstaller erased a foreign file: $path"
        }
    }
    foreach ($path in @(
        (Join-Path $installDir 'AntiOS.exe'),
        (Join-Path $installDir '_cli\owned.txt'),
        $manifestFile
    )) {
        if (Test-Path -LiteralPath $path) {
            throw "Uninstaller did not remove an owned path: $path"
        }
    }
    Write-Host 'PASS: per-user uninstall rejects traversal, preserves unknown files and removes owned payload.'
}
finally {
    $env:LOCALAPPDATA = $originalLocalAppData
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
    $fixture = Join-Path $startMenuDir 'Keep-custom-shortcut.txt'
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Force }
    if (Test-Path -LiteralPath $startMenuDir) {
        Remove-Item -LiteralPath $startMenuDir -ErrorAction SilentlyContinue
    }
}
