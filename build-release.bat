@echo off
setlocal EnableExtensions EnableDelayedExpansion

cd /d "%~dp0" || goto fail

set "APP_NAME=GreyNOC-Slop-Detection"
set "VERSION=0.3.2"
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
echo Packaging GitHub release folder...
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\package-github-release.ps1 -Version "%VERSION%" -ReleaseRoot "%RELEASE_ROOT%"
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
