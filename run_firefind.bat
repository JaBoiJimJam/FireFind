@echo off
pip install -r backend\requirements.txt
start "" bash start_dev.sh
timeout /t 3 >nul
start http://localhost:8000/
