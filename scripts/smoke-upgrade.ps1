param(
    [string]$CurrentSetup = ".\installer-output\AntiOS-Setup.exe",
    [string]$PreviousTag = "",
    [string]$ExpectedPreviousVersion = "",
    [string]$ExpectedCurrentVersion = ""
)

$ErrorActionPreference = "Stop"
if (-not $ExpectedCurrentVersion) {
    $ExpectedCurrentVersion = (Get-Content ".\release\VERSION" -Raw).Trim()
}
if ($ExpectedCurrentVersion -notmatch '^\d+\.\d+\.\d+a\d+$') {
    throw "Unexpected current alpha version: $ExpectedCurrentVersion"
}
if (-not $PreviousTag) { $PreviousTag = "v2.0.0-alpha.37" }
if (-not $ExpectedPreviousVersion) {
    if ($PreviousTag -notmatch '^v(\d+\.\d+\.\d+)-alpha\.(\d+)$') {
        throw "Unexpected previous alpha tag: $PreviousTag"
    }
    $ExpectedPreviousVersion = "$($Matches[1])a$($Matches[2])"
}

# Previous alpha installers are not Authenticode-signed. Never execute a
# mutable release asset as administrator without independently pinned bytes.
$trustedPreviousInstallers = @{
    "v2.0.0-alpha.36" = "4b8781d630cb10d5418c8ffe335e27d61183266e536f69e6f88faf4fc5cdabe4"
    "v2.0.0-alpha.37" = "b9cff406e68dd1f4831ab7de292f2f5582aff5970d23eef916015f334b4fe05f"
}
if (-not $trustedPreviousInstallers.ContainsKey($PreviousTag)) {
    throw "Unpinned legacy installer $PreviousTag; review and pin the release asset SHA-256 first."
}

function Invoke-Installer([string]$Setup, [string]$InstallDir, [string]$Option) {
    $argsList = @("/S", $Option, "/D=$InstallDir")
    $process = Start-Process -FilePath $Setup -ArgumentList $argsList -Wait -PassThru
    return [int]$process.ExitCode
}

function Assert-Version([string]$Executable, [string]$Expected) {
    $output = (& $Executable --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $output -notmatch [regex]::Escape($Expected)) {
        throw "Version mismatch for $Executable. Expected $Expected, received $output"
    }
}

function Assert-RegisteredVersion([string]$Expected) {
    $actual = (Get-ItemProperty "HKLM:\Software\DargonITP\AntiOS" -Name Version).Version
    if ($actual -ne $Expected) { throw "Registered version changed: $actual; expected $Expected" }
}

function Assert-NoRollbackDirectories([string]$InstallDir) {
    foreach ($name in @("_antios_next", "_antios_previous")) {
        if (Test-Path -LiteralPath (Join-Path $InstallDir $name)) {
            throw "Installer left pending transaction directory: $name"
        }
    }
}

$installDir = Join-Path $env:RUNNER_TEMP "AntiOS-Upgrade-Smoke"
$previousSetup = Join-Path $env:RUNNER_TEMP "AntiOS-Previous-Setup.exe"
$configDir = Join-Path $env:APPDATA "AntiOS"
$configPath = Join-Path $configDir "antios.toml"
$configBackup = Join-Path $env:RUNNER_TEMP "AntiOS-Upgrade-Smoke-antios.toml.backup"
$hadConfig = Test-Path -LiteralPath $configPath
$currentSetup = (Resolve-Path $CurrentSetup).Path

try {
    # Dedicated disposable path only; never clean arbitrary installations.
    if (Test-Path -LiteralPath $installDir) {
        $attributes = (Get-Item -LiteralPath $installDir -Force).Attributes
        if ($attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Refusing to clean reparse-point smoke directory."
        }
        Remove-Item -LiteralPath $installDir -Recurse -Force
    }
    Remove-Item -LiteralPath $previousSetup -Force -ErrorAction SilentlyContinue
    if ($hadConfig) {
        Copy-Item -LiteralPath $configPath -Destination $configBackup -Force
    }

    # The retired switch must be refused without ever extracting the new app.
    $oldSwitch = Invoke-Installer $currentSetup $installDir "/NOENGINE=1"
    if ($oldSwitch -ne 31 -or (Test-Path -LiteralPath (Join-Path $installDir "AntiOS.exe"))) {
        throw "Old /NOENGINE installer switch was not rejected before installation (exit $oldSwitch)."
    }

    $downloadUrl = "https://github.com/Dargon777/AntiOS/releases/download/$PreviousTag/AntiOS-Setup.exe"
    Write-Host "Downloading previous AntiOS Setup from $downloadUrl"
    Invoke-WebRequest -Uri $downloadUrl -OutFile $previousSetup -UseBasicParsing
    if (-not (Test-Path -LiteralPath $previousSetup -PathType Leaf)) {
        throw "Previous installer was not downloaded."
    }
    $actualHash = (Get-FileHash -LiteralPath $previousSetup -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $trustedPreviousInstallers[$PreviousTag]) {
        throw "Refusing to execute a legacy installer with untrusted SHA-256 ($PreviousTag)."
    }

    Write-Host "Installing previous release $PreviousTag without its old engine service"
    if ((Invoke-Installer $previousSetup $installDir "/NOENGINE=1") -ne 0) {
        throw "Previous release could not be installed."
    }
    $cli = Join-Path $installDir "AntiOS.exe"
    $gui = Join-Path $installDir "AntiOS-GUI.exe"
    $uninstaller = Join-Path $installDir "Uninstall.exe"
    foreach ($required in @($cli, $gui, $uninstaller, (Join-Path $installDir "Install-AmsiProvider.ps1"))) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Previous setup missing required legacy fixture: $required"
        }
    }
    Assert-Version $cli $ExpectedPreviousVersion
    Assert-RegisteredVersion $ExpectedPreviousVersion

    # The new installer MUST refuse to mix the old sidecar and new engine.
    # This verifies the real legacy fixture, with no fake registry ownership.
    Write-Host "Verifying fail-closed upgrade of the previous engine"
    $blocked = Invoke-Installer $currentSetup $installDir "/NOGUARD=1"
    if ($blocked -ne 30) { throw "Legacy engine upgrade returned $blocked, expected 30." }
    Assert-Version $cli $ExpectedPreviousVersion
    Assert-RegisteredVersion $ExpectedPreviousVersion
    Assert-NoRollbackDirectories $installDir

    # The owner-specific old uninstaller, not our new installer, cleans its own
    # files. Never delete arbitrary legacy services, drivers or AMSI registry keys.
    Write-Host "Uninstalling previous release through its own uninstaller"
    $oldUninstall = Start-Process -FilePath $uninstaller -ArgumentList "/S" -Wait -PassThru
    if ($oldUninstall.ExitCode -ne 0) {
        throw "Original release uninstaller failed with $($oldUninstall.ExitCode)."
    }
    if (Test-Path -LiteralPath (Join-Path $installDir "Install-AmsiProvider.ps1")) {
        throw "Legacy provider script still installed; clean upgrade is intentionally blocked."
    }

    New-Item -ItemType Directory -Force $configDir | Out-Null
    $configLines = @(
        '[general]',
        'computer_name_prefix = "LAB"',
        'backup_path = "antios-backup.json"',
        'color = "auto"',
        '',
        '[logging]',
        'level = "INFO"',
        'file = ""',
        '',
        '[ui]',
        'language = "pl"',
        'theme = "light"',
        '',
        '[cleanup]',
        'old_days = 91',
        'large_mb = 321',
        'duplicate_min_mb = 7',
        'remember_folder = false',
        'last_path = ""',
        '',
        '[protection]',
        'resident_enabled = false',
        '',
        '[updates]',
        'auto_update = false'
    )
    [string]::Join([Environment]::NewLine, $configLines) |
        Set-Content -LiteralPath $configPath -Encoding utf8NoBOM
    $configHashBefore = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash

    Write-Host "Installing independent AntiOS Engine after legacy uninstall"
    if ((Invoke-Installer $currentSetup $installDir "/NOGUARD=1") -ne 0) {
        throw "Clean native AntiOS setup failed after legacy uninstall."
    }
    Assert-Version $cli $ExpectedCurrentVersion
    Assert-RegisteredVersion $ExpectedCurrentVersion
    Assert-NoRollbackDirectories $installDir

    # A pre-existing staging tree must cause refusal WITHOUT stopping Guard.
    $stageDir = Join-Path $installDir "_antios_next"
    $backupDir = Join-Path $installDir "_antios_previous"
    New-Item -ItemType Directory -Force $stageDir | Out-Null
    "do-not-overwrite" | Set-Content -LiteralPath (Join-Path $stageDir "sentinel") -Encoding utf8
    try {
        if ((Invoke-Installer $currentSetup $installDir "/NOGUARD=1") -eq 0) {
            throw "Installer reused a pre-existing staging directory."
        }
        Assert-Version $cli $ExpectedCurrentVersion
        Assert-RegisteredVersion $ExpectedCurrentVersion
        if ((Get-Content -LiteralPath (Join-Path $stageDir "sentinel") -Raw).Trim() -ne "do-not-overwrite") {
            throw "Installer modified an existing staging directory."
        }
    }
    finally {
        Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Lock the NOTICE file so application-item rotation fails after staging.
    # A correct rollback must restore the old bytes without losing user data.
    $notice = Join-Path $installDir "NOTICE"
    if (-not (Test-Path -LiteralPath $notice -PathType Leaf)) {
        throw "Native installation is missing NOTICE for rollback test."
    }
    $oldNoticeHash = (Get-FileHash -LiteralPath $notice -Algorithm SHA256).Hash
    $lock = [IO.File]::Open($notice, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ((Invoke-Installer $currentSetup $installDir "/NOGUARD=1") -eq 0) {
            throw "Installer incorrectly succeeded with a locked NOTICE."
        }
    }
    finally {
        $lock.Dispose()
    }
    Assert-Version $cli $ExpectedCurrentVersion
    Assert-RegisteredVersion $ExpectedCurrentVersion
    Assert-NoRollbackDirectories $installDir
    if ((Get-FileHash -LiteralPath $notice -Algorithm SHA256).Hash -ne $oldNoticeHash) {
        throw "Failed activation changed NOTICE contents."
    }

    # A foreign test marker simulates a leftover engine without installing
    # or stopping any real service.
    $engineRoot = Join-Path $installDir "ClamAV"
    New-Item -ItemType Directory -Force $engineRoot | Out-Null
    $marker = Join-Path $engineRoot "owned-by-upgrade-smoke.txt"
    "must-preserve" | Set-Content -LiteralPath $marker -Encoding utf8
    try {
        $blocked = Invoke-Installer $currentSetup $installDir "/NOGUARD=1"
        if ($blocked -ne 30) { throw "Legacy file marker did not block upgrade (exit $blocked)." }
        if ((Get-Content -LiteralPath $marker -Raw).Trim() -ne "must-preserve") {
            throw "Legacy marker was modified by a rejected upgrade."
        }
        Assert-RegisteredVersion $ExpectedCurrentVersion
    }
    finally {
        # Only remove files deliberately created by this disposable smoke.
        Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $engineRoot -ErrorAction SilentlyContinue
    }

    if ((Invoke-Installer $currentSetup $installDir "/NOGUARD=1") -ne 0) {
        throw "Native same-version reinstall failed."
    }
    Assert-Version $cli $ExpectedCurrentVersion
    Assert-RegisteredVersion $ExpectedCurrentVersion
    Assert-NoRollbackDirectories $installDir
    if ((Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash -ne $configHashBefore) {
        throw "Installer changed antios.toml during upgrade."
    }
    $env:ANTIOS_UPGRADE_SMOKE_CONFIG = $configPath
    python -c "import os; from antios.config import load_config; c=load_config(os.environ['ANTIOS_UPGRADE_SMOKE_CONFIG']); assert c.ui.language == 'pl'; assert c.ui.theme == 'light'; assert c.cleanup.old_days == 91; assert c.cleanup.large_mb == 321; assert c.cleanup.duplicate_min_mb == 7; assert c.protection.resident_enabled is False; assert c.updates.auto_update is False"
    if ($LASTEXITCODE -ne 0) { throw "Current AntiOS failed to load preserved config." }
    & $gui --self-test
    if ($LASTEXITCODE -ne 0) { throw "Native GUI self-test failed." }
    & $gui --ui-self-test
    if ($LASTEXITCODE -ne 0) { throw "Native GUI UI self-test failed." }
    Write-Host "Legacy refusal, clean native install, rollback and config preservation: PASS"
}
finally {
    $uninstaller = Join-Path $installDir "Uninstall.exe"
    if (Test-Path -LiteralPath $uninstaller -PathType Leaf) {
        $process = Start-Process -FilePath $uninstaller -ArgumentList "/S" -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            Write-Warning "Smoke uninstaller exited $($process.ExitCode)"
        }
    }
    if ($hadConfig -and (Test-Path -LiteralPath $configBackup)) {
        New-Item -ItemType Directory -Force $configDir | Out-Null
        Copy-Item -LiteralPath $configBackup -Destination $configPath -Force
    }
    elseif (-not $hadConfig) {
        Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $configDir) {
            $remaining = Get-ChildItem -LiteralPath $configDir -Force -ErrorAction SilentlyContinue
            if (-not $remaining) { Remove-Item -LiteralPath $configDir -Force }
        }
    }
    Remove-Item -LiteralPath $previousSetup -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $configBackup -Force -ErrorAction SilentlyContinue
}
