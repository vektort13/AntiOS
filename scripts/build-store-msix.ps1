param(
    [string]$IdentityName = "DargonsITP.AntiOS",
    [string]$Publisher = "CN=D0D34602-FED2-4FE0-B705-18B9041C45F3",
    [string]$PublisherDisplayName = "DargonITP",
    [string]$PackageVersion = "3.0.2.0",
    [string]$GuiPath = ".\dist\AntiOS-GUI\AntiOS-GUI.exe",
    [string]$OutputPath = ".\store-output\AntiOS.msix"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $GuiPath)) {
    throw "GUI executable not found: $GuiPath"
}

if ($PackageVersion -notmatch '^\d+\.\d+\.\d+\.0$') {
    throw "Store package version must be Major.Minor.Build.0"
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$templatePath = Join-Path $repoRoot "store\AppxManifest.xml.template"
$stage = Join-Path $repoRoot "store-build"
$assets = Join-Path $stage "Assets"
$output = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $OutputPath))

Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $assets | Out-Null
New-Item -ItemType Directory -Force (Split-Path -Parent $output) | Out-Null

Copy-Item $GuiPath (Join-Path $stage "AntiOS-GUI.exe")
$runtime = Join-Path (Split-Path -Parent $GuiPath) "_gui"
if (-not (Test-Path $runtime)) { throw "GUI runtime folder not found: $runtime" }
Copy-Item $runtime (Join-Path $stage "_gui") -Recurse
foreach ($doc in @("README.md", "PRIVACY.md", "LICENSE", "NOTICE")) {
    Copy-Item (Join-Path $repoRoot $doc) (Join-Path $stage $doc)
}

Add-Type -AssemblyName System.Drawing

$brandSource = Join-Path $repoRoot "antios\assets\icons\app_main.png"
if (-not (Test-Path -LiteralPath $brandSource)) {
    throw "Primary AntiOS artwork not found: $brandSource"
}

function New-AntiOSAsset {
    param(
        [string]$Path,
        [int]$Width,
        [int]$Height
    )

    $source = [System.Drawing.Image]::FromFile($brandSource)
    $bitmap = New-Object System.Drawing.Bitmap($Width, $Height, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
    $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $graphics.Clear([System.Drawing.Color]::Transparent)

    $margin = [Math]::Max(1, [Math]::Floor([Math]::Min($Width, $Height) * 0.07))
    $availableWidth = $Width - (2 * $margin)
    $availableHeight = $Height - (2 * $margin)
    $scale = [Math]::Min($availableWidth / $source.Width, $availableHeight / $source.Height)
    $drawWidth = [Math]::Max(1, [Math]::Round($source.Width * $scale))
    $drawHeight = [Math]::Max(1, [Math]::Round($source.Height * $scale))
    $x = [Math]::Floor(($Width - $drawWidth) / 2)
    $y = [Math]::Floor(($Height - $drawHeight) / 2)

    $graphics.DrawImage($source, $x, $y, $drawWidth, $drawHeight)
    $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)

    $graphics.Dispose()
    $bitmap.Dispose()
    $source.Dispose()
}

New-AntiOSAsset (Join-Path $assets "StoreLogo.png") 50 50
New-AntiOSAsset (Join-Path $assets "Square44x44Logo.png") 44 44
New-AntiOSAsset (Join-Path $assets "Square71x71Logo.png") 71 71
New-AntiOSAsset (Join-Path $assets "Square150x150Logo.png") 150 150
New-AntiOSAsset (Join-Path $assets "Wide310x150Logo.png") 310 150
New-AntiOSAsset (Join-Path $assets "Square310x310Logo.png") 310 310

function Escape-XmlAttribute([string]$Value) {
    return [System.Security.SecurityElement]::Escape($Value)
}

$manifest = Get-Content $templatePath -Raw
$manifest = $manifest.Replace("__IDENTITY_NAME__", (Escape-XmlAttribute $IdentityName))
$manifest = $manifest.Replace("__PUBLISHER__", (Escape-XmlAttribute $Publisher))
$manifest = $manifest.Replace("__PUBLISHER_DISPLAY_NAME__", (Escape-XmlAttribute $PublisherDisplayName))
$manifest = $manifest.Replace("__PACKAGE_VERSION__", $PackageVersion)
Set-Content -Path (Join-Path $stage "AppxManifest.xml") -Value $manifest -Encoding UTF8

$kitsRoot = Join-Path ([Environment]::GetFolderPath("ProgramFilesX86")) "Windows Kits\10\bin"
$makeAppx = Get-ChildItem $kitsRoot -Recurse -Filter MakeAppx.exe -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending |
    Select-Object -First 1

if (-not $makeAppx) {
    throw "MakeAppx.exe was not found. Install the Windows SDK."
}

if (Test-Path $output) {
    Remove-Item -Force $output
}

& $makeAppx.FullName pack /d $stage /p $output /o
if ($LASTEXITCODE -ne 0) {
    throw "MakeAppx failed with exit code $LASTEXITCODE"
}

Write-Host "Built Store MSIX: $output"
Write-Host "Identity: $IdentityName"
Write-Host "Publisher: $Publisher"
Write-Host "Version: $PackageVersion"
Write-Host "Package is unsigned; Microsoft Store signs accepted submissions."
