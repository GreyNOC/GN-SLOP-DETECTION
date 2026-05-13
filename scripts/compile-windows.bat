@echo off
setlocal
powershell -ExecutionPolicy Bypass -File "%~dp0compile-windows.ps1"
exit /b %ERRORLEVEL%
