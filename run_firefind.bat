@echo off
REM Install dependencies with python -m pip to avoid PATH issues on Windows/Wine
python -m pip install -r backend\requirements.txt

setlocal
set "PYTHONPATH=%~dp0backend\src;%PYTHONPATH%"

if not defined FIRE_FIND_API_TOKEN (
    set "FIRE_FIND_API_TOKEN=dev-admin-token"
    echo [run_firefind.bat] FIRE_FIND_API_TOKEN not set; using development default 'dev-admin-token'.
)

REM Launch FastAPI dev server and open default browser
python -m uvicorn backend.dev_server:app --reload --host localhost --port 8000
timeout /t 3 > nul
start "" http://localhost:8000/
