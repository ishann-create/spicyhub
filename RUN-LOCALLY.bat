@echo off
title Spicyhub Restaurant OS & B2B SaaS Platform
color 0A
cls
echo ======================================================================
echo    SPICYHUB RESTAURANT OS - LOCAL PRODUCTION SERVER
echo ======================================================================
echo.

:: 1. Check if Node.js is installed
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not found in PATH!
    echo Please download and install Node.js from https://nodejs.org
    echo.
    pause
    exit /b 1
)

:: 2. Check and free port 3000 if occupied by another node process
echo [*] Checking port 3000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :3000 ^| findstr LISTENING') do (
    echo [*] Port 3000 is occupied by PID %%a. Freeing port...
    taskkill /F /PID %%a >nul 2>nul
)

:: 3. Give 1 second for port release
timeout /t 1 /nobreak >nul

:: 4. Launch Spicyhub server
echo [*] Starting Spicyhub Server on http://localhost:3000...
start "Spicyhub Server Daemon" cmd /k "node server/index.js"

:: 5. Wait for server boot
timeout /t 2 /nobreak >nul

:: 6. Open Restaurant OS and Superadmin Console in default browser
echo [*] Launching Spicyhub portals in your default browser...
start http://localhost:3000/dashboard
start http://localhost:3000/admin

echo.
echo ======================================================================
echo [OK] SPICYHUB IS LIVE AND RUNNING LOCALLY!
echo.
echo  ⚡ Restaurant OS Portal  : http://localhost:3000/dashboard
echo  🔒 Superadmin Console    : http://localhost:3000/admin
echo  🌐 Landing Page          : http://localhost:3000
echo.
echo  MASTER LOGIN CREDENTIALS:
echo  - Restaurant OS Email    : work.ishann@gmail.com
echo  - Restaurant OS Password : ishan104
echo  - (You can also click the green '1-Click Founder Master Login' button)
echo ======================================================================
echo.
echo Keep this window or the server window open while using the app.
pause
