#!/usr/bin/env bash
set -e

# Name of the virtual environment folder
VENV_DIR="venv"

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Upgrade pip in the virtual environment
pip install --upgrade pip

# Install backend dependencies
echo "Installing backend dependencies..."
pip install -r backend/requirements.txt

# Start backend server
echo "Starting backend server..."
./start_dev.sh &

# Wait until server is listening on port 8000
echo "Waiting for server to start on port 8000..."
while ! nc -z localhost 8000; do
    sleep 1
done

# Open browser if possible
URL="http://localhost:8000"
if command -v xdg-open >/dev/null; then
    xdg-open "$URL" >/dev/null &
elif command -v open >/dev/null; then
    open "$URL" >/dev/null &
else
    echo "Open a browser and navigate to $URL"
fi

# Wait for background server process
wait

