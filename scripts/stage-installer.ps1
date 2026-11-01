param(
    [string]$OutputDirectory = ".\installer-stage"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
# Restrict recursive cleanup to the dedicated generated staging folder.
$stageName = $OutputDirectory -replace '^[.][\\/]', ''
if ($stageName -cnotmatch '^installer-stage(?:-[A-Za-z0-9_-]{1,40})?$') {
    throw 'Installer staging must be installer-stage or installer-stage-SUFFIX under the repository.'
}
$stage = [IO.Path]::GetFullPath((Join-Path $repoRoot $stageName))
if (Test-Path -LiteralPath $stage) {
    $tree = @(Get-Item -LiteralPath $stage -Force) +
            @(Get-ChildItem -LiteralPath $stage -Force -Recurse)
    if (@($tree | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) {
        throw 'Installer stage contains a junction/symlink; refusing recursive cleanup.'
    }
}
Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $stage | Out-Null

foreach ($source in @(
    @{ Path = "dist\AntiOS"; Name = "CLI" },
    @{ Path = "dist\AntiOS-GUI"; Name = "GUI" },
    @{ Path = "dist\AntiOS-Guard"; Name = "Guard" }
)) {
    $full = Join-Path $repoRoot $source.Path
    if (-not (Test-Path -LiteralPath $full)) {
        throw "$($source.Name) build directory not found: $full"
    }
    Copy-Item (Join-Path $full "*") $stage -Recurse -Force
}

$amsiProvider = Join-Path $repoRoot "build\native\windows\AntiOS-AmsiProvider.dll"
if (-not (Test-Path -LiteralPath $amsiProvider -PathType Leaf)) {
    throw "AMSI provider build not found: $amsiProvider"
}
Copy-Item -LiteralPath $amsiProvider -Destination (Join-Path $stage "AntiOS-AmsiProvider.dll") -Force

python (Join-Path $PSScriptRoot "release-payload.py") stage-runtime $stage
if ($LASTEXITCODE -ne 0) { throw "Windows runtime resource staging failed." }

foreach ($path in @(
    "docs\COEXISTENCE.md",
    "README.md",
    "README.ru.md",
    "README.es.md",
    "README.zh-CN.md",
    "README.fi.md",
    "README.pl.md",
    "README.mn.md",
    "PRIVACY.md",
    "SUPPORT.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "LICENSE",
    "NOTICE"
)) {
    $source = Join-Path $repoRoot $path
    if (-not (Test-Path -LiteralPath $source)) {
        throw "Installer payload file not found: $source"
    }
    Copy-Item -LiteralPath $source -Destination $stage -Force
}

$clamConfig = Join-Path $repoRoot "config\clamav"
if (Test-Path -LiteralPath $clamConfig) {
    Copy-Item -LiteralPath $clamConfig -Destination (Join-Path $stage "clamav-config") -Recurse -Force
}

$required = @(
    "AntiOS.exe",
    "AntiOS-GUI.exe",
    "AntiOS-Guard.exe",
    "_cli",
    "_gui",
    "_guard",
    "guard-startup.ps1",
    "dashboard-startup.ps1",
    "protection-engine.ps1",
    "clamav-trust.ps1",
    "clamav-repair-validation.ps1",
    "protection-bootstrap.ps1",
    "protection-repair.ps1",
    "protection-first-run.ps1",
    "AntiOS-AmsiProvider.dll",
    "Install-AmsiProvider.ps1",
    "LICENSE.microsoft",
    "COEXISTENCE.md",
    "clamav-windows.json",
    "LICENSE"
)
foreach ($name in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $stage $name))) {
        throw "Installer staging is incomplete: $name"
    }
}

# Build an exact uninstall manifest from the packaged files, not a recursive
# delete of the destination directory. This preserves unrelated user files.
function Convert-ToNsisRelativePath {
    param([string]$FullName)
    $relative = $FullName.Substring($stage.Length).TrimStart('\')
    if (-not $relative -or $relative -match '[\x00-\x1F"$]') {
        throw "Unsafe AntiOS staged path: $relative"
    }
    return $relative.Replace('/', '\')
}

$items = @(Get-ChildItem -LiteralPath $stage -Recurse -Force)
if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) {
    throw "Refusing a reparse point in the AntiOS installer stage."
}
$files = @($items | Where-Object { -not $_.PSIsContainer } |
    ForEach-Object { Convert-ToNsisRelativePath $_.FullName })
$dirs = @($items | Where-Object { $_.PSIsContainer } |
    ForEach-Object { Convert-ToNsisRelativePath $_.FullName } |
    Sort-Object { ($_ -split '\\').Count } -Descending)
$lines = [Collections.Generic.List[string]]::new()
$lines.Add('!macro ANTIOS_UNINSTALL_CHECK_PATHS')
foreach ($relative in @('') + @($dirs)) {
    $target = if ($relative) { '$INSTDIR\' + $relative } else { '$INSTDIR' }
    $lines.Add('  ${If} ${FileExists} "' + $target + '"')
    $lines.Add('    System::Call ' + "'kernel32::GetFileAttributesW(w " + '"' + $target + '"' + ") i .r0'")
    $lines.Add('    IntOp $1 $0 & 0x400')
    $lines.Add('    ${If} $1 != 0')
    $lines.Add('      SetErrorLevel 31')
    $lines.Add('      MessageBox MB_ICONSTOP|MB_OK "Unsafe AntiOS uninstall path (reparse point)." /SD IDOK')
    $lines.Add('      Abort')
    $lines.Add('    ${EndIf}')
    $lines.Add('  ${EndIf}')
}
$lines.Add('!macroend')
$lines.Add('')
$lines.Add('!macro ANTIOS_UNINSTALL_OWNED_PAYLOAD')
foreach ($relative in $files) {
    $lines.Add('  Delete "$INSTDIR\' + $relative + '"')
}
$lines.Add('  Delete "$INSTDIR\uninstall-manifest.nsh"')
foreach ($relative in $dirs) {
    $lines.Add('  RMDir "$INSTDIR\' + $relative + '"')
}
$lines.Add('!macroend')
[IO.File]::WriteAllLines(
    (Join-Path $stage 'uninstall-manifest.nsh'), $lines,
    [Text.UTF8Encoding]::new($false)
)
Write-Host "Prepared AntiOS installer payload at $stage with an exact uninstall manifest."
