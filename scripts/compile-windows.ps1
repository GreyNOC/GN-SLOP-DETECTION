param(
    [ValidateSet("never", "onTag", "onTagOrDraft", "always")]
    [string]$PublishMode = "never"
)

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

$ElectronBuilderArgs = @("--publish", $PublishMode)

if ($env:CSC_IDENTITY_AUTO_DISCOVERY -eq "false") {
    $ElectronBuilderArgs += "-c.win.signAndEditExecutable=false"
}

$BuildArgs = @("run", "build:win", "--") + $ElectronBuilderArgs

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
$BackendBuildFile = Join-Path $RepoRoot "dist\gn-slop-backend.exe"
$BackendBuildDir = Join-Path $RepoRoot "dist\gn-slop-backend"
if (Test-Path $BackendBuildFile) {
    Remove-Item -LiteralPath $BackendBuildFile -Force
}
if (Test-Path $BackendBuildDir) {
    Remove-Item -LiteralPath $BackendBuildDir -Recurse -Force
}
Invoke-Checked $Python @(
    "-m",
    "PyInstaller",
    "--clean",
    "--noconfirm",
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
if (-not (Test-Path (Join-Path $BackendBuildDir "gn-slop-backend.exe"))) {
    throw "Missing backend executable: $BackendBuildDir\gn-slop-backend.exe"
}
Get-ChildItem -LiteralPath $BackendBuildDir | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $DesktopBackend -Recurse -Force
}

Write-Host "Building portable CLI executable..."
$CliBuildFile = Join-Path $RepoRoot "dist\gn-slop.exe"
if (Test-Path $CliBuildFile) {
    Remove-Item -LiteralPath $CliBuildFile -Force
}
# Onefile so the result is a single, no-install, no-Python-required executable.
# The CLI's engine imports are all static (the scanner rules are imported
# explicitly in rules/__init__.py), so PyInstaller's analysis follows them
# without --collect-submodules. The heavy, optional ML backends (torch /
# transformers, only reachable via the model-detector seam, which the CLI never
# touches) are excluded so the build stays ~25 MB and deterministic even when
# they happen to be installed in the build environment (otherwise the onefile
# balloons to multiple GB).
Invoke-Checked $Python @(
    "-m",
    "PyInstaller",
    "--clean",
    "--noconfirm",
    "--onefile",
    "--name",
    "gn-slop",
    "--console",
    "--exclude-module", "torch",
    "--exclude-module", "transformers",
    "--exclude-module", "numpy",
    "--exclude-module", "scipy",
    "--exclude-module", "pandas",
    "app\cli.py"
)
if (-not (Test-Path $CliBuildFile)) {
    throw "Missing CLI executable: $CliBuildFile"
}

Write-Host "Installing Electron dependencies..."
Invoke-Checked "npm" @("install")

Write-Host "Packaging Windows app..."
Invoke-Checked "npm" $BuildArgs

Write-Host "Done. Output is in the release directory."
