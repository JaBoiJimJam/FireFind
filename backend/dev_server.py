from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from firefind.api import app as api_app

app = FastAPI()


@app.get("/health")
async def health() -> dict[str, str]:
    """Simple health check endpoint."""
    return {"status": "ok"}


app.mount("/api", api_app)

# Serve the frontend directory if it exists
FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
