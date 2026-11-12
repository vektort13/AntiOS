param(
    [switch]$RemoveFromPath
)

$ErrorActionPreference = 'Stop'

$InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\AntiOS'
$Programs = [Environment]::GetFolderPath('Programs')
$StartMenuDir = Join-Path $Programs 'AntiOS'
$Desktop = [Environment]::GetFolderPath('Desktop')
$DesktopLink = Join-Path $Desktop 'AntiOS.lnk'
$ManifestFile = Join-Path $InstallDir 'install-manifest.json'

# Refuse legacy installs without a manifest. Guessing what is owned by AntiOS
# and recursively deleting a user-writable directory could erase user data.
if (-not (Test-Path -LiteralPath $InstallDir -PathType Container)) {
    Write-Host "AntiOS is not installed at $InstallDir"
    return
}
if (-not (Test-Path -LiteralPath $ManifestFile -PathType Leaf)) {
    throw 'Safe uninstall requires install-manifest.json. Reinstall the current version over this installation before uninstalling, or remove owned files manually.'
}

function Assert-NoReparsePoint([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Refusing a reparse point in AntiOS uninstall: $Path"
    }
}

$root = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
Assert-NoReparsePoint $root
Assert-NoReparsePoint $ManifestFile
$manifest = Get-Content -LiteralPath $ManifestFile -Raw | ConvertFrom-Json
if ($manifest.schema -ne 1 -or -not $manifest.files -or
    $manifest.files -is [string] -or @($manifest.files).Count -gt 250000) {
    throw 'Missing or unsupported AntiOS file ownership manifest.'
}

$topFiles = @(
    'AntiOS.exe', 'AntiOS-GUI.exe', 'AntiOS-Guard.exe',
    'guard-startup.ps1', 'dashboard-startup.ps1'
)
$ownedFiles = [Collections.Generic.List[string]]::new()
$ownedDirs = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($runtime in @('_cli', '_gui', '_guard')) { [void]$ownedDirs.Add((Join-Path $root $runtime)) }

# Validate the *entire* manifest before invoking any executable or deleting any
# file, and refuse path traversal, alternate streams, links and unexpected roots.
foreach ($entry in @($manifest.files)) {
    if ($entry -isnot [string] -or -not $entry -or $entry.Length -gt 2048 -or
        [IO.Path]::IsPathRooted($entry) -or $entry -match '[:*?"<>|]' -or
        $entry -match '[\/]' -or $entry -match '(^|\\)\.\.?(\\|$)') {
        throw "Unsafe AntiOS uninstall manifest path: $entry"
    }
    $segments = @($entry -split '\\')
    if ($segments.Count -lt 1 -or @($segments | Where-Object { -not $_ }).Count -gt 0) {
        throw "Malformed AntiOS uninstall manifest path: $entry"
    }
    if ($segments.Count -eq 1 -and $entry -cnotin $topFiles) {
        throw "Unknown top-level AntiOS uninstall file: $entry"
    }
    if ($segments.Count -gt 1 -and $segments[0] -cnotin @('_cli', '_gui', '_guard')) {
        throw "Unexpected AntiOS runtime payload location: $entry"
    }
    $candidate = [IO.Path]::GetFullPath((Join-Path $root $entry))
    if (-not $candidate.StartsWith(($root + '\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw "AntiOS uninstall path escapes installation root: $entry"
    }
    $ownedFiles.Add($candidate)
    for ($depth = 1; $depth -lt $segments.Count; $depth++) {
        $relativeDir = ($segments[0..($depth - 1)] -join '\')
        [void]$ownedDirs.Add((Join-Path $root $relativeDir))
    }
}

# A junction or symlink anywhere in a stored path can redirect deletion outside
# the installation root. Check all known directories and files before actions.
foreach ($directory in $ownedDirs) { Assert-NoReparsePoint $directory }
foreach ($path in $ownedFiles) { Assert-NoReparsePoint $path }

$Guard = Join-Path $root 'AntiOS-Guard.exe'
if (Test-Path -LiteralPath $Guard -PathType Leaf) {
    & $Guard stop | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not request Guard shutdown; installation was preserved.' }
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        $state = (& $Guard status | ConvertFrom-Json)
        if ($LASTEXITCODE -ne 0) { throw 'Could not verify Guard shutdown; installation was preserved.' }
        if (-not $state.running) { break }
        if ($state.pid -and -not (Get-Process -Id $state.pid -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($state.running -and (Get-Process -Id $state.pid -ErrorAction SilentlyContinue)) {
        throw 'Guard has not stopped. Review its status before uninstalling; installation was preserved.'
    }
}

$StartupManager = Join-Path $root 'guard-startup.ps1'
if (Test-Path -LiteralPath $StartupManager -PathType Leaf) {
    & $StartupManager -Uninstall -Apply
}
$DashboardStartupManager = Join-Path $root 'dashboard-startup.ps1'
if (Test-Path -LiteralPath $DashboardStartupManager -PathType Leaf) {
    & $DashboardStartupManager -Uninstall -Apply
}

# Remove only the shortcut created by AntiOS, never a complete Start Menu
# directory that may contain other applications or custom user shortcuts.
function Remove-OwnShortcut([string]$Path, [string]$ExpectedTarget) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    Assert-NoReparsePoint $Path
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($Path)
    $target = [string]$shortcut.TargetPath
    if ($target -and [IO.Path]::GetFullPath($target) -ieq [IO.Path]::GetFullPath($ExpectedTarget)) {
        Remove-Item -LiteralPath $Path -Force
    }
}

$GuiTarget = Join-Path $root 'AntiOS-GUI.exe'
if (Test-Path -LiteralPath $StartMenuDir) {
    Assert-NoReparsePoint $StartMenuDir
}
Remove-OwnShortcut (Join-Path $StartMenuDir 'AntiOS.lnk') $GuiTarget
Remove-OwnShortcut $DesktopLink $GuiTarget
function Remove-EmptyDirectory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    Assert-NoReparsePoint $Path
    # Windows PowerShell can raise an internal provider error when attempting
    # non-recursive Remove-Item on a nonempty folder. Never attempt it.
    if ($null -eq (Get-ChildItem -LiteralPath $Path -Force | Select-Object -First 1)) {
        try { [IO.Directory]::Delete($Path, $false) }
        catch [IO.IOException] { } # concurrent user-created file: keep it
    }
}
Remove-EmptyDirectory $StartMenuDir

# Remove only payload files listed during installation, deepest directories
# first and always non-recursively. Preserve unknown content on disk.
foreach ($path in $ownedFiles) {
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        Remove-Item -LiteralPath $path -Force
    }
}
Remove-Item -LiteralPath $ManifestFile -Force
foreach ($directory in @($ownedDirs | Sort-Object { ($_.TrimEnd('\') -split '\\').Count } -Descending)) {
    Remove-EmptyDirectory $directory
}
Remove-EmptyDirectory $root
Write-Host 'AntiOS owned payload removed. Unknown files and folders were preserved.'

if ($RemoveFromPath) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @(
        $userPath -split ';' |
        Where-Object { $_ -and $_.TrimEnd('\') -ne $root }
    )
    [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User')
    Write-Host 'Removed AntiOS install directory from the current user PATH.'
    Write-Host 'Open a new terminal for PATH changes to take effect.'
}
