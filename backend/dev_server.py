from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from firefind.api import app as api_app

app = FastAPI()


@app.get("/health")
async def health() -> dict[str, str]:
    """Simple health check endpoint."""
    return {"status": "ok"}


@app.get("/.well-known/appspecific/com.chrome.devtools.json", include_in_schema=False)
async def chrome_devtools_config() -> dict[str, str]:
    """Return empty JSON for Chrome devtools config."""
    return {}


REPORTS_DIR = Path(__file__).resolve().parents[1] / "out"
REPORTS_DIR.mkdir(exist_ok=True)
app.mount("/downloads", StaticFiles(directory=str(REPORTS_DIR)), name="downloads")

app.mount("/api", api_app)

# Serve the frontend directory if it exists
FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
