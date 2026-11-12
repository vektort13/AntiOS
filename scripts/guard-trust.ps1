# Trust policy for the installed AntiOS Guard executable.
# This module is intentionally independent of ClamAV and never touches Defender.
Set-StrictMode -Version Latest

function Assert-AntiOSProtectedInstallPath([string]$Path) {
    $programFiles = [IO.Path]::GetFullPath(
        [Environment]::GetFolderPath('ProgramFiles')).TrimEnd('\')
    $actual = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if (-not $actual.StartsWith($programFiles + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Guard executable must be installed under Program Files.'
    }
    $allowedOwners = @('S-1-5-18', 'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $writeRights = [int64](
        [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    )
    $writeRights = $writeRights -bor [int64]0x40000000 -bor [int64]0x10000000
    $current = $actual
    while ($true) {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Guard executable path contains a reparse point.'
        }
        $acl = Get-Acl -LiteralPath $current -ErrorAction Stop
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin $allowedOwners) { throw 'Guard executable path has an untrusted owner.' }
        $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
        foreach ($rule in $rules) {
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
            if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
            if (([int64]$rule.FileSystemRights -band $writeRights) -eq 0) { continue }
            if ($rule.IdentityReference.Value -notin $allowedOwners) {
                throw 'Guard executable path grants write access to an untrusted SID.'
            }
        }
        if ($current -ieq $programFiles) { break }
        $parent = [IO.Path]::GetDirectoryName($current)
        if (-not $parent -or $parent -eq $current) {
            throw 'Guard install path has no trusted ancestor.'
        }
        $current = $parent
    }
}
