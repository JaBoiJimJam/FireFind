@echo off
REM Install dependencies with python -m pip to avoid PATH issues on Windows/Wine
python -m pip install -r backend\requirements.txt

setlocal
set "PYTHONPATH=%~dp0backend\src;%PYTHONPATH%"

if not defined FIRE_FIND_API_TOKEN (
    set "FIRE_FIND_API_TOKEN=dev-admin-token"
    echo [run_firefind.bat] FIRE_FIND_API_TOKEN not set; using development default 'dev-admin-token'.
)

echo [run_firefind.bat] Launching FastAPI dev server in a new window...
start "" cmd /c "cd /d \"%~dp0\" && python -m uvicorn backend.dev_server:app --reload --host localhost --port 8000"

echo [run_firefind.bat] Waiting for server to start...
timeout /t 5 /nobreak > nul

echo [run_firefind.bat] Opening FireFind in default browser...
start "" http://localhost:8000/
