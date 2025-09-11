#!/usr/bin/env bash
set -e

pip install -r backend/requirements.txt
./start_dev.sh &
sleep 3
if command -v xdg-open >/dev/null; then
  xdg-open http://localhost:8000/ >/dev/null &
elif command -v open >/dev/null; then
  open http://localhost:8000/ >/dev/null &
fi
wait
