# Configure current-user Guard after application installation.
# Runs only when the elevated identity is also the active interactive user.
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$current = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$interactive = (Get-CimInstance Win32_ComputerSystem).UserName
$guardScript = Join-Path $PSScriptRoot 'guard-startup.ps1'
$guardExe = Join-Path $PSScriptRoot 'AntiOS-Guard.exe'

$result = [ordered]@{
    schema = 1
    kind = 'antios-protection-first-run'
    dry_run = -not [bool]$Apply
    current_user = $current
    interactive_user = $interactive
    configured = $false
    deferred_reason = $null
    roots = @()
}

if (-not $interactive) {
    $result.deferred_reason = 'no-interactive-user'
} elseif ($interactive -ne $current) {
    $result.deferred_reason = 'uac-identity-differs-from-interactive-user'
} elseif (-not (Test-Path -LiteralPath $guardScript -PathType Leaf) -or
        -not (Test-Path -LiteralPath $guardExe -PathType Leaf)) {
    $result.deferred_reason = 'guard-files-missing'
} else {
    $profile = [Environment]::GetFolderPath('UserProfile')
    $localAppData = [Environment]::GetFolderPath('LocalApplicationData')
    $roamingAppData = [Environment]::GetFolderPath('ApplicationData')
    $candidates = @(
        (Join-Path $profile 'Downloads'),
        (Join-Path $profile 'Desktop'),
        (Join-Path $profile 'Documents'),
        (Join-Path $localAppData 'Temp'),
        (Join-Path $roamingAppData 'Microsoft\Windows\Start Menu\Programs\Startup')
    )
    $roots = @($candidates | Where-Object {
        $_ -and (Test-Path -LiteralPath $_ -PathType Container)
    } | ForEach-Object {
        (Resolve-Path -LiteralPath $_).Path
    } | Select-Object -Unique)
    if ($roots.Count -eq 0 -and (Test-Path -LiteralPath $profile -PathType Container)) {
        $roots = @((Resolve-Path -LiteralPath $profile).Path)
    }
    $result.roots = $roots

    if (-not $Apply) {
        $result.deferred_reason = 'preview'
    } elseif ($roots.Count -eq 0) {
        $result.deferred_reason = 'no-monitorable-user-roots'
    } else {
        & $guardScript -Executable $guardExe -Roots $roots -Mode notify -AllowManagedUnsigned -Apply
        if ($LASTEXITCODE -ne 0) {
            throw "Guard startup configuration failed with exit code $LASTEXITCODE"
        }
        $result.configured = $true
    }
}

if ($Json) {
    $result | ConvertTo-Json -Depth 5
} else {
    [pscustomobject]$result | Format-List
}
