# AntiOS Control Center logon startup. Separate from Resident Guard protection.
[CmdletBinding()]
param(
    [string]$Executable,
    [switch]$AllowManagedUnsigned,
    [switch]$Uninstall,
    [switch]$Status,
    [switch]$Json,
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
$ScriptDirectory = if ($PSScriptRoot) {
    $PSScriptRoot
} else {
    Split-Path -Parent $MyInvocation.MyCommand.Path
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.Value -eq 'S-1-5-18') {
    throw 'Control Center autostart must be configured for an interactive user, not LocalSystem.'
}
$taskName = "AntiOS Control Center ($($identity.User.Value))"

function Assert-ControlCenterTaskOwned($Task, [string]$ExpectedExecutable) {
    if (-not $Task) { return }
    $account = [string]$Task.Principal.UserId
    if ($account -notin @($identity.Name, $identity.User.Value)) {
        throw 'Existing Control Center task belongs to a different Windows user; refusing modification.'
    }
    $actions = @($Task.Actions)
    if ($actions.Count -ne 1 -or -not $actions[0].Execute) {
        throw 'Existing Control Center task contains unexpected actions.'
    }
    try {
        $actual = [IO.Path]::GetFullPath([string]$actions[0].Execute)
        $expected = [IO.Path]::GetFullPath($ExpectedExecutable)
    } catch {
        throw 'Existing Control Center task executable is invalid.'
    }
    if ($actual -ine $expected) {
        throw 'Existing Control Center task points to another executable; refusing modification.'
    }
}

function Get-ControlCenterTask {
    Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue
}

function Assert-ManagedUnsignedDashboard([string]$Path) {
    $installKey = 'HKLM:\SOFTWARE\DargonITP\AntiOS'
    $installDir = Get-ItemPropertyValue -Path $installKey -Name InstallDir -ErrorAction Stop
    $expected = [IO.Path]::GetFullPath((Join-Path $installDir 'AntiOS-GUI.exe'))
    if ([IO.Path]::GetFullPath($Path) -ne $expected) {
        throw 'Unsigned dashboard startup is allowed only for the machine-installed AntiOS-GUI.exe.'
    }

    . (Join-Path $ScriptDirectory 'clamav-trust.ps1')
    Assert-AntiOSProtectedInstallPath $expected
}

if ($Status) {
    $task = Get-ControlCenterTask
    $payload = [ordered]@{
        enabled = ($null -ne $task)
        task = $taskName
        state = if ($task) { [string]$task.State } else { 'Absent' }
        run_level = if ($task) { [string]$task.Principal.RunLevel } else { 'Absent' }
        user = $identity.Name
    }
    if ($Json) {
        $payload | ConvertTo-Json -Compress
    } else {
        [pscustomobject]$payload | Format-List
    }
    return
}

if ($Uninstall) {
    if (-not $Apply) {
        Write-Output "Preview: unregister task '$taskName'. Resident Guard is not changed."
        return
    }
    $task = Get-ControlCenterTask
    if ($task) {
        $ownedExe = if ($Executable) { $Executable } else { Join-Path $ScriptDirectory 'AntiOS-GUI.exe' }
        Assert-ControlCenterTaskOwned -Task $task -ExpectedExecutable $ownedExe
        Stop-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskPath '\' -TaskName $taskName -Confirm:$false
    }
    return
}

if (-not $Executable) {
    $Executable = Join-Path $ScriptDirectory 'AntiOS-GUI.exe'
}
$exe = (Resolve-Path -LiteralPath $Executable).Path
if ([IO.Path]::GetFileName($exe) -ne 'AntiOS-GUI.exe') {
    throw 'Control Center startup requires AntiOS-GUI.exe.'
}

$signature = Get-AuthenticodeSignature -LiteralPath $exe

[pscustomobject]@{
    Task = $taskName
    User = $identity.Name
    Executable = $exe
    Arguments = '--background'
    Signature = $signature.Status
    Signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '(none)' }
    Privilege = 'Limited'
    Trigger = 'Current user logon'
} | Format-List

if (-not $Apply) {
    Write-Output 'Preview only. Use -Apply to enable AntiOS Control Center startup.'
    return
}

# Unlike a same-user UAC approval, elevation through a different admin account
# must not register background software for the administrator instead of the
# interactive desktop user.
$interactiveUser = (Get-CimInstance Win32_ComputerSystem).UserName
if (-not $interactiveUser -or $interactiveUser -ine $identity.Name) {
    throw 'Control Center startup deferred: current elevated identity differs from the interactive user.'
}

if ($signature.Status -ne 'Valid') {
    if (-not $AllowManagedUnsigned) {
        throw 'Automatic Control Center startup requires a valid Authenticode signature.'
    }
    Assert-ManagedUnsignedDashboard $exe
}

$action = New-ScheduledTaskAction -Execute $exe -Argument '--background' -WorkingDirectory ([IO.Path]::GetDirectoryName($exe))
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
$principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

# A task with the same SID/name is not automatically ours. Check both the
# configured principal and exact executable before overwriting any task.
$existing = Get-ControlCenterTask
if ($existing) { Assert-ControlCenterTaskOwned -Task $existing -ExpectedExecutable $exe }

Register-ScheduledTask -TaskPath '\' -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Starts the AntiOS Control Center in the notification area at user logon. Resident Guard protection is managed separately.' -Force | Out-Null

Write-Output "Enabled '$taskName'. AntiOS will start in the notification area at the next logon."
