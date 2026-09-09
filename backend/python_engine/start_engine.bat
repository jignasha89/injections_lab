@echo off
echo ============================================
echo   Injection Lab - Python Engine Launcher
echo ============================================
echo.

cd /d "%~dp0"

if not exist venv (
    echo [INFO] Creating virtual environment...
    python -m venv venv
)

echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat

echo [INFO] Installing requirements...
pip install -r requirements.txt -q

echo [INFO] Starting FastAPI Engine on port 8000...
python -m uvicorn backend.main:socket_app --host 0.0.0.0 --port 8000
