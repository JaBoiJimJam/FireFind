@echo off
REM Install dependencies with python -m pip to avoid PATH issues on Windows/Wine
python -m pip install -r backend\requirements.txt

setlocal
set "PYTHONPATH=%~dp0backend\src;%PYTHONPATH%"

if not defined FIRE_FIND_API_TOKEN (
    set "FIRE_FIND_API_TOKEN=dev-admin-token"
    echo [run_firefind.bat] FIRE_FIND_API_TOKEN not set; using development default 'dev-admin-token'.
)

if not defined FIRE_FIND_PORT (
    set "FIRE_FIND_PORT=8000"
)

echo [run_firefind.bat] Scheduling browser launch after server startup...
start "" powershell -NoLogo -NoProfile -Command "Start-Sleep -Seconds 5; Start-Process 'http://localhost:%FIRE_FIND_PORT%/'"

echo [run_firefind.bat] Launching FastAPI dev server on port %FIRE_FIND_PORT%...
cd /d "%~dp0"
python -m uvicorn backend.dev_server:app --host localhost --port %FIRE_FIND_PORT%
