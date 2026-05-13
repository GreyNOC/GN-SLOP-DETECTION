@echo off
setlocal EnableExtensions

cd /d "%~dp0" || goto fail

set "VENV_PYTHON=.venv\Scripts\python.exe"
set "PYTHONDONTWRITEBYTECODE=1"

echo.
echo GreyNOC Slop Detection desktop launcher
echo Working directory: %CD%
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
    echo Creating virtual environment...
    py -3 -m venv .venv
    if errorlevel 1 (
        python -m venv .venv
        if errorlevel 1 goto fail
    )
)

echo Installing Python dependencies...
"%VENV_PYTHON%" -m pip install -r requirements.txt
if errorlevel 1 goto fail

echo Installing Electron dependencies...
npm install
if errorlevel 1 goto fail

set "GN_SLOP_PYTHON=%CD%\%VENV_PYTHON%"

echo.
echo Starting GreyNOC Slop Detection desktop app...
echo The Electron front end will open and launch the local analysis engine automatically.
echo Leave this window open while using the app.
echo.

npm start
if errorlevel 1 goto fail

goto done

:fail
echo.
echo Something went wrong. The message above should show the cause.
echo.
pause
exit /b 1

:done
endlocal
