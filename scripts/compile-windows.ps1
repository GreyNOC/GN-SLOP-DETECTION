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
$env:electron_config_cache = Join-Path $RepoRoot ".electron-cache"
$env:ELECTRON_CACHE = Join-Path $RepoRoot ".electron-cache"
$env:ELECTRON_BUILDER_CACHE = Join-Path $RepoRoot ".electron-builder-cache"

if (
    -not $env:CSC_LINK -and
    -not $env:WIN_CSC_LINK -and
    -not $env:CSC_NAME -and
    -not $env:WIN_CSC_NAME -and
    -not $env:AZURE_TENANT_ID
) {
    $env:CSC_IDENTITY_AUTO_DISCOVERY = "false"
}

$BuildArgs = @("run", "build:win")
if ($env:CSC_IDENTITY_AUTO_DISCOVERY -eq "false") {
    $BuildArgs += @("--", "-c.win.signAndEditExecutable=false")
}

if ($env:PYTHON) {
    $Python = $env:PYTHON
} elseif (Test-Path ".venv\Scripts\python.exe") {
    $Python = ".venv\Scripts\python.exe"
} else {
    $Python = "python"
}

Write-Host "Installing Python build dependencies..."
Invoke-Checked $Python @("-m", "pip", "install", "-r", "requirements.txt", "-r", "requirements-build.txt")

Write-Host "Building Python backend executable..."
Invoke-Checked $Python @(
    "-m",
    "PyInstaller",
    "--clean",
    "--noconfirm",
    "--onefile",
    "--name",
    "gn-slop-backend",
    "--add-data",
    "app\static;app\static",
    "app\desktop_server.py"
)

$DesktopBackend = Join-Path $RepoRoot "dist\desktop-backend"
if (Test-Path $DesktopBackend) {
    Remove-Item -LiteralPath $DesktopBackend -Recurse -Force
}
New-Item -ItemType Directory -Path $DesktopBackend | Out-Null
Copy-Item -LiteralPath "dist\gn-slop-backend.exe" -Destination (Join-Path $DesktopBackend "gn-slop-backend.exe")

Write-Host "Installing Electron dependencies..."
Invoke-Checked "npm" @("install")

Write-Host "Packaging Windows app..."
Invoke-Checked "npm" $BuildArgs

Write-Host "Done. Output is in the release directory."
