@echo off
title IoT Honeypot Simulator
color 0B

echo ===========================================
echo   IoT Honeypot Simulator - Starting...
echo ===========================================
echo.

cd /d "%~dp0"

where node >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js not found. Please install Node.js.
    pause
    exit /b 1
)

if not exist "node_modules" (
    echo Installing dependencies...
    npm install
    if errorlevel 1 (
        echo ERROR: npm install failed.
        pause
        exit /b 1
    )
    echo.
)

echo Starting simulator... (Edit config.json to change burst rate)
echo.

cmd /k node index.js
