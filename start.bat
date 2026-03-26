@echo off
title IoT Honeypot Log System
color 0A

echo ============================================
echo   IoT Honeypot Log System - Starting...
echo ============================================
echo.

cd /d "%~dp0"

:: Check Node.js
where node >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js not found. Please install Node.js first.
    echo Download: https://nodejs.org/
    pause
    exit /b 1
)

:: Install dependencies if needed
if not exist "node_modules" (
    echo [1/3] Installing dependencies...
    npm install
    if errorlevel 1 (
        echo ERROR: npm install failed.
        pause
        exit /b 1
    )
) else (
    echo [1/3] Dependencies already installed.
)

echo.

:: Start Mosquitto from PATH
echo [2/3] Starting MQTT broker (Mosquitto)...
where mosquitto >nul 2>&1
if not errorlevel 1 (
    start "MQTT Broker" /min mosquitto -v
    echo       Mosquitto started.
) else (
    echo       Mosquitto not found in PATH.
    echo       Please install Mosquitto and add it to Windows PATH.
    echo       Download: https://mosquitto.org/download/
)

echo.

:: Start server
echo [3/3] Starting Node.js server...
echo.
echo ============================================
echo   Frontend : http://localhost:3000
echo   API      : http://localhost:3000/api/logs
echo   WebSocket: ws://localhost:3001
echo ============================================
echo.

start "" cmd /c "timeout /t 2 >nul && start http://localhost:3000"

cmd /k node backend/index.js
