param(
    [string]$SourceDirectory = $PSScriptRoot,
    [switch]$AddToPath,
    [switch]$DesktopShortcut
)

$ErrorActionPreference = "Stop"

$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\AntiOS"
$CliSource = Join-Path $SourceDirectory "AntiOS.exe"
$GuiSource = Join-Path $SourceDirectory "AntiOS-GUI.exe"
$CliTarget = Join-Path $InstallDir "AntiOS.exe"
$GuiTarget = Join-Path $InstallDir "AntiOS-GUI.exe"
$GuardSource = Join-Path $SourceDirectory "AntiOS-Guard.exe"
$GuardTarget = Join-Path $InstallDir "AntiOS-Guard.exe"
$StartupSource = Join-Path $SourceDirectory "guard-startup.ps1"
$DashboardStartupSource = Join-Path $SourceDirectory "dashboard-startup.ps1"

foreach ($required in @($CliSource, $GuiSource, $GuardSource, $StartupSource, $DashboardStartupSource, (Join-Path $SourceDirectory "_cli"), (Join-Path $SourceDirectory "_gui"), (Join-Path $SourceDirectory "_guard"))) {
    if (-not (Test-Path $required)) {
        throw "Required AntiOS file not found: $required"
    }
}

# Inventory only files coming from the trusted source payload, never the
# contents of an existing install directory (which may include user data).
$owned = [Collections.Generic.List[string]]::new()
foreach ($relative in @('AntiOS.exe', 'AntiOS-GUI.exe', 'AntiOS-Guard.exe',
                        'guard-startup.ps1', 'dashboard-startup.ps1')) {
    $source = Join-Path $SourceDirectory $relative
    $item = Get-Item -LiteralPath $source -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Unsafe AntiOS source file: $source"
    }
    $owned.Add($relative)
}
foreach ($runtime in @('_cli', '_gui', '_guard')) {
    $folder = Join-Path $SourceDirectory $runtime
    $directory = Get-Item -LiteralPath $folder -Force
    if (-not $directory.PSIsContainer -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Unsafe runtime payload directory: $folder"
    }
    foreach ($item in (Get-ChildItem -LiteralPath $folder -Recurse -Force)) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Source runtime contains a reparse point: $($item.FullName)"
        }
        if (-not $item.PSIsContainer) {
            $suffix = $item.FullName.Substring($folder.Length).TrimStart('\')
            $owned.Add((Join-Path $runtime $suffix))
        }
    }
}
if (Test-Path -LiteralPath $InstallDir) {
    $existing = Get-Item -LiteralPath $InstallDir -Force
    if (-not $existing.PSIsContainer -or
        ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Unsafe existing AntiOS install directory: $InstallDir"
    }
}
$manifestFile = Join-Path $InstallDir 'install-manifest.json'
if ((Test-Path -LiteralPath $manifestFile) -and
    ((Get-Item -LiteralPath $manifestFile -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Refusing to overwrite a reparse-point install manifest.'
}

if (Test-Path -LiteralPath $GuardTarget) {
    $guardState = (& $GuardTarget status | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0 -or $guardState.running) {
        throw 'Stop AntiOS Guard and verify its status before updating this installation.'
    }
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Force $CliSource $CliTarget
Copy-Item -Force $GuiSource $GuiTarget
Copy-Item -Force $GuardSource $InstallDir
Copy-Item -Force $StartupSource $InstallDir
Copy-Item -Force $DashboardStartupSource $InstallDir
foreach ($runtime in @("_cli", "_gui", "_guard")) {
    Copy-Item -Recurse -Force (Join-Path $SourceDirectory $runtime) $InstallDir
}

# The manifest is written only after the payload copy succeeded. Uninstall
# removes these exact relative paths, leaving unknown files untouched.
$manifest = @{
    schema = 1
    files = @($owned | Sort-Object -Unique)
}
[IO.File]::WriteAllText(
    $manifestFile,
    ($manifest | ConvertTo-Json -Depth 4),
    [Text.UTF8Encoding]::new($false)
)

$Programs = [Environment]::GetFolderPath("Programs")
$StartMenuDir = Join-Path $Programs "AntiOS"
New-Item -ItemType Directory -Force -Path $StartMenuDir | Out-Null

$Shell = New-Object -ComObject WScript.Shell
$StartShortcut = $Shell.CreateShortcut((Join-Path $StartMenuDir "AntiOS.lnk"))
$StartShortcut.TargetPath = $GuiTarget
$StartShortcut.WorkingDirectory = $InstallDir
$StartShortcut.Description = "AntiOS Windows Health & Privacy"
$StartShortcut.IconLocation = $GuiTarget
$StartShortcut.Save()

if ($DesktopShortcut) {
    $Desktop = [Environment]::GetFolderPath("Desktop")
    $DesktopLink = $Shell.CreateShortcut((Join-Path $Desktop "AntiOS.lnk"))
    $DesktopLink.TargetPath = $GuiTarget
    $DesktopLink.WorkingDirectory = $InstallDir
    $DesktopLink.Description = "AntiOS Windows Health & Privacy"
    $DesktopLink.IconLocation = $GuiTarget
    $DesktopLink.Save()
}

if ($AddToPath) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @($userPath -split ";" | Where-Object { $_ })
    if ($parts -notcontains $InstallDir) {
        $newPath = (($parts + $InstallDir) -join ";")
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        Write-Host "Added $InstallDir to the current user's PATH."
        Write-Host "Open a new terminal before using 'antios' from PATH."
    } else {
        Write-Host "AntiOS install directory is already in the current user's PATH."
    }
}

Write-Host "Installed AntiOS to $InstallDir"
Write-Host "A Start Menu shortcut was created."
if ($DesktopShortcut) {
    Write-Host "A desktop shortcut was created."
}
Write-Host "GUI: $GuiTarget"
Write-Host "CLI: $CliTarget"
