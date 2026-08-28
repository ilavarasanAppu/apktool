@echo off
title APK Security Studio
echo ============================================================
echo   APK Security Studio - Web Server
echo ============================================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found in PATH. Please install Python 3.8+
    pause
    exit /b 1
)

REM Install dependencies
echo [*] Checking dependencies...
pip install flask flask-socketio flask-cors werkzeug eventlet >nul 2>&1
if errorlevel 1 (
    echo [WARN] Some packages may have failed to install. Trying alternative...
    pip install flask flask-socketio flask-cors werkzeug >nul 2>&1
)

echo [+] Dependencies ready.
echo.
echo [*] Starting server at http://localhost:5000
echo [*] Press Ctrl+C to stop.
echo.

REM Open browser after 2 seconds
start /b cmd /c "timeout /t 2 >nul && start http://localhost:5000"

REM Start server
python server.py

pause
