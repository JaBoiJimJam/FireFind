#!/usr/bin/env bash
set -e

# Determine project root
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ensure backend source is on PYTHONPATH for imports
export PYTHONPATH="$DIR/backend/src:$PYTHONPATH"

# Launch FastAPI dev server serving API and static frontend assets
exec python -m uvicorn backend.dev_server:app --reload --host 0.0.0.0 --port 8000

