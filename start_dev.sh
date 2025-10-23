#!/usr/bin/env bash
set -e

# Determine project root
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ensure backend source is on PYTHONPATH for imports
export PYTHONPATH="$DIR/backend/src:$PYTHONPATH"

# Provide a predictable admin token for local development if one is not set.
if [ -z "${FIRE_FIND_API_TOKEN:-}" ]; then
    export FIRE_FIND_API_TOKEN="dev-admin-token"
    echo "[start_dev] FIRE_FIND_API_TOKEN not set; using development default 'dev-admin-token'."
fi

# Launch FastAPI dev server serving API and static frontend assets
exec python -m uvicorn backend.dev_server:app --reload --host 0.0.0.0 --port 8000
