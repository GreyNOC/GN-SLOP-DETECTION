@echo off
setlocal EnableExtensions EnableDelayedExpansion

cd /d "%~dp0" || goto fail

set "APP_NAME=GreyNOC-Slop-Detection"
set "VERSION=0.1.0"
set "RELEASE_ROOT=github-release"
set "RELEASE_DIR=%RELEASE_ROOT%\%APP_NAME%-v%VERSION%-windows"
set "VENV_PYTHON=.venv\Scripts\python.exe"

echo.
echo ============================================================
echo  GreyNOC Slop Detection - GitHub Release Builder
echo ============================================================
echo.
echo Version: %VERSION%
echo Output:  %CD%\%RELEASE_DIR%
echo.

where node >nul 2>nul
if errorlevel 1 (
    echo Node.js was not found. Install Node.js, then run this file again.
    goto fail
)

where npm >nul 2>nul
if errorlevel 1 (
    echo npm was not found. Install Node.js with npm, then run this file again.
    goto fail
)

if not exist "%VENV_PYTHON%" (
    echo Creating Python virtual environment...
    py -3 -m venv .venv
    if errorlevel 1 (
        python -m venv .venv
        if errorlevel 1 goto fail
    )
)

echo Cleaning previous build folders...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
if exist "release" rmdir /s /q "release"
if exist "%RELEASE_DIR%" rmdir /s /q "%RELEASE_DIR%"
mkdir "%RELEASE_DIR%" || goto fail

echo.
echo Installing Python build dependencies...
"%VENV_PYTHON%" -m pip install --upgrade pip
if errorlevel 1 goto fail
"%VENV_PYTHON%" -m pip install -r requirements.txt -r requirements-build.txt
if errorlevel 1 goto fail

echo.
echo Installing Electron dependencies...
call npm install
if errorlevel 1 goto fail

echo.
echo Building Windows release artifacts...
powershell -ExecutionPolicy Bypass -File scripts\compile-windows.ps1
if errorlevel 1 goto fail

echo.
echo Copying release artifacts into clean GitHub release folder...
for %%F in (release\*.exe release\*.msi release\*.zip release\*.7z release\*.blockmap release\*.yml release\*.yaml release\*.json) do (
    if exist "%%~F" copy /y "%%~F" "%RELEASE_DIR%\" >nul
)

if exist "release\win-unpacked" (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Compress-Archive -Path 'release\win-unpacked\*' -DestinationPath '%RELEASE_DIR%\%APP_NAME%-v%VERSION%-win-unpacked.zip' -Force"
    if errorlevel 1 goto fail
)

echo Writing release notes...
(
    echo # GreyNOC Slop Detection v%VERSION%
    echo.
    echo Windows desktop release artifacts for GitHub Releases.
    echo.
    echo ## Install
    echo.
    echo - Use the installer `.exe` if present.
    echo - Use the portable `.exe` if present.
    echo - Use `%APP_NAME%-v%VERSION%-win-unpacked.zip` for a raw unpacked app archive.
    echo.
    echo ## Verify
    echo.
    echo Compare downloaded files against `SHA256SUMS.txt`.
) > "%RELEASE_DIR%\RELEASE-NOTES.md"

echo Generating SHA256 checksums...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -File '%RELEASE_DIR%' | Where-Object { $_.Name -ne 'SHA256SUMS.txt' } | ForEach-Object { '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower(), $_.Name } | Set-Content -Encoding ascii '%RELEASE_DIR%\SHA256SUMS.txt'"
if errorlevel 1 goto fail

echo.
echo ============================================================
echo  Build complete.
echo ============================================================
echo.
echo GitHub release folder:
echo %CD%\%RELEASE_DIR%
echo.
dir "%RELEASE_DIR%"
echo.
goto done

:fail
echo.
echo Build failed. Check the message above for the cause.
echo.
pause
exit /b 1

:done
endlocal
