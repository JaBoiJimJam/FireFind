@echo off
REM Install dependencies with python -m pip to avoid PATH issues on Windows/Wine
python -m pip install -r backend\requirements.txt

REM Ensure backend source is on PYTHONPATH
set "PYTHONPATH=%~dp0backend\src;%PYTHONPATH%"

REM Launch FastAPI dev server and open default browser
start "" /b python -m uvicorn backend.dev_server:app --reload --host 0.0.0.0 --port 8000
timeout /t 3 > nul
start "" http://localhost:8000/
