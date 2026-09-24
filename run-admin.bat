@echo off
title LogSentinel - Real-Time Security Log Analyzer
cd /d "%~dp0"

echo ========================================================
echo  LogSentinel - Real-Time Cybersecurity Log Analyzer
echo ========================================================
echo.

:: Check for Administrator rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] NOT RUNNING AS ADMINISTRATOR
    echo.
    echo Windows requires Administrator rights to read the Security Event Log.
    echo.
    echo To run with Administrator rights:
    echo   1. Right-click on this file (run-admin.bat)
    echo   2. Click "Run as administrator"
    echo   3. Click "Yes" when Windows asks for permission
    echo.
    echo Press any key to exit...
    pause >nul
    exit /b 1
)

echo [*] Administrator rights verified!
echo [*] Terminating previous non-admin instances on port 8080...

for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8080 " ^| findstr "LISTENING"') do (
    echo Releasing port 8080 from PID %%a...
    taskkill /PID %%a /F >nul 2>&1
)

timeout /t 1 /nobreak >nul

set "JAVA_CMD=java"
if exist "C:\Program Files\Java\jdk-17\bin\java.exe" (
    set "JAVA_CMD=C:\Program Files\Java\jdk-17\bin\java.exe"
)

echo.
echo [*] Starting LogSentinel server...
echo [*] Dashboard: http://localhost:8080
echo [*] Live Windows Security event logs will be captured.
echo.
echo Press Ctrl+C in this window to stop the server at any time.
echo --------------------------------------------------------

"%JAVA_CMD%" -jar target\log-analyzer-1.0.0.jar

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Server exited with code %errorlevel%.
    echo Press any key to close this window.
    pause >nul
)