$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE"
    }
}

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

$InnoCompiler = $env:INNO_COMPILER
if (-not $InnoCompiler) {
    $DefaultCompiler = Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"
    if (Test-Path $DefaultCompiler) {
        $InnoCompiler = $DefaultCompiler
    } else {
        $InnoCompiler = "ISCC.exe"
    }
}

$WinUnpacked = Join-Path $RepoRoot "release\win-unpacked"
if (-not (Test-Path $WinUnpacked)) {
    Write-Host "Windows unpacked app was not found. Building Windows app first..."
    Invoke-Checked "powershell" @("-ExecutionPolicy", "Bypass", "-File", "scripts\compile-windows.ps1")
}

if ($env:GN_SIGNTOOL) {
    Write-Host "Using custom Inno SignTool from GN_SIGNTOOL."
    $env:INNO_SIGNTOOL_CUSTOM = $env:GN_SIGNTOOL
}

Write-Host "Building Inno Setup installer..."
Invoke-Checked $InnoCompiler @("installer\windows\greynoc-slop-detection.iss")

Write-Host "Done. Inno installer output is in release\inno."
