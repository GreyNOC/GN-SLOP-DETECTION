@echo off
setlocal EnableExtensions

cd /d "%~dp0" || goto fail

if "%APP_HOST%"=="" set "APP_HOST=127.0.0.1"
if "%APP_PORT%"=="" set "APP_PORT=8000"
set "START_PORT=%APP_PORT%"
set "VENV_PYTHON=.venv\Scripts\python.exe"
set "PYTHONDONTWRITEBYTECODE=1"

echo.
echo GreyNOC Slop Detection launcher
echo Working directory: %CD%
echo.

if not exist "%VENV_PYTHON%" (
    echo Creating virtual environment...
    py -3 -m venv .venv
    if errorlevel 1 (
        python -m venv .venv
        if errorlevel 1 goto fail
    )
)

echo Installing dependencies...
"%VENV_PYTHON%" -m pip install -r requirements.txt
if errorlevel 1 goto fail

call :find_port
if errorlevel 1 goto fail

if not "%APP_PORT%"=="%START_PORT%" (
    echo Port %START_PORT% is already in use. Using %APP_PORT% instead.
)

echo.
echo GUI:  http://%APP_HOST%:%APP_PORT%/
echo Docs: http://%APP_HOST%:%APP_PORT%/docs
echo.
echo Leave this window open while using the app.
echo Press Ctrl+C to stop the server.
echo.

"%VENV_PYTHON%" -B -m uvicorn app.main:app --reload --host %APP_HOST% --port %APP_PORT%
if errorlevel 1 goto fail

goto done

:find_port
for /l %%P in (%START_PORT%,1,8020) do (
    netstat -ano | findstr /R /C:":%%P .*LISTENING" >nul
    if errorlevel 1 (
        set "APP_PORT=%%P"
        exit /b 0
    )
)
echo No free port found between %START_PORT% and 8020.
exit /b 1

:fail
echo.
echo Something went wrong. The message above should show the cause.
echo.
pause
exit /b 1

:done
endlocal
