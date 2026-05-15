param(
    [string]$Version,
    [string]$ReleaseRoot = "github-release"
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$AppName = "GreyNOC-Slop-Detection"

function Resolve-InRepo {
    param([Parameter(Mandatory = $true)][string]$Path)

    $FullPath = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
    $RepoRootWithSeparator = $RepoRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (
        $FullPath -ne $RepoRoot -and
        -not $FullPath.StartsWith($RepoRootWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)
    ) {
        throw "Path escaped repository root: $FullPath"
    }
    return $FullPath
}

Set-Location $RepoRoot

if (-not $Version) {
    $Version = (Get-Content -Raw -Path "package.json" | ConvertFrom-Json).version
}

$ReleaseRootPath = Resolve-InRepo $ReleaseRoot
$ReleaseDir = Join-Path $ReleaseRootPath "$AppName-v$Version-windows"

if (Test-Path $ReleaseDir) {
    Remove-Item -LiteralPath $ReleaseDir -Recurse -Force
}
New-Item -ItemType Directory -Path $ReleaseDir | Out-Null

$Artifacts = @(
    "release\$AppName-Setup-$Version.exe",
    "release\$AppName-Setup-$Version.exe.blockmap",
    "release\$AppName-Portable-$Version.exe",
    "release\latest.yml"
)

foreach ($Artifact in $Artifacts) {
    if (-not (Test-Path $Artifact)) {
        throw "Missing release artifact: $Artifact"
    }
    Copy-Item -LiteralPath $Artifact -Destination $ReleaseDir -Force
}

$UnpackedDir = "release\win-unpacked"
if (-not (Test-Path $UnpackedDir)) {
    throw "Missing unpacked release directory: $UnpackedDir"
}

$UnpackedZip = Join-Path $ReleaseDir "$AppName-v$Version-win-unpacked.zip"
Compress-Archive -Path "$UnpackedDir\*" -DestinationPath $UnpackedZip -Force

$Notes = @(
    "# GreyNOC Slop Detection v$Version",
    "",
    "Windows desktop release artifacts for GitHub Releases.",
    "",
    "## Install",
    "",
    "- Use ``$AppName-Setup-$Version.exe`` for a normal desktop install.",
    "- Use ``$AppName-Portable-$Version.exe`` for a no-install launch.",
    "- Use ``$AppName-v$Version-win-unpacked.zip`` for a raw unpacked app archive.",
    "",
    "## Verify",
    "",
    "Compare downloaded files against ``SHA256SUMS.txt``."
)
Set-Content -Path (Join-Path $ReleaseDir "RELEASE-NOTES.md") -Value $Notes -Encoding ascii

Get-ChildItem -File $ReleaseDir |
    Where-Object { $_.Name -ne "SHA256SUMS.txt" } |
    Sort-Object Name |
    ForEach-Object {
        "{0}  {1}" -f (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower(), $_.Name
    } |
    Set-Content -Path (Join-Path $ReleaseDir "SHA256SUMS.txt") -Encoding ascii

Write-Host "GitHub release folder:"
Write-Host $ReleaseDir
Get-ChildItem -File $ReleaseDir | Sort-Object Name | Format-Table Length, Name
