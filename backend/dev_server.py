from __future__ import annotations

from pathlib import Path
from typing import Any, Final

from fastapi import HTTPException
from fastapi.staticfiles import StaticFiles
from firefind.api import app


@app.get("/health", include_in_schema=False)
async def health() -> dict[str, str]:
    """Simple health check endpoint."""
    return {"status": "ok"}


@app.get("/.well-known/appspecific/com.chrome.devtools.json", include_in_schema=False)
async def chrome_devtools_config() -> dict[str, str]:
    """Return empty JSON for Chrome devtools config."""
    return {}


ALLOWED_REPORT_SUFFIXES: Final[set[str]] = {".pdf", ".csv", ".xlsx", ".xls"}
REPORTS_DIR = Path(__file__).resolve().parents[1] / "out"
REPORTS_DIR.mkdir(exist_ok=True)
app.mount("/downloads", StaticFiles(directory=str(REPORTS_DIR)), name="downloads")


def _is_allowed_report(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in ALLOWED_REPORT_SUFFIXES


def _serialize_report(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "name": path.name,
        "size": stat.st_size,
        "modified": stat.st_mtime,
        "type": path.suffix[1:].lower(),
    }


@app.get("/api/reports")
async def get_reports() -> list[dict[str, Any]]:
    """Return metadata about generated report files."""

    if not REPORTS_DIR.exists():
        return []

    reports = [_serialize_report(path) for path in REPORTS_DIR.iterdir() if _is_allowed_report(path)]
    reports.sort(key=lambda item: item["modified"], reverse=True)
    return reports


@app.delete("/api/reports/{filename}")
async def delete_report(filename: str) -> dict[str, str]:
    """Delete a generated report from disk."""

    candidate = REPORTS_DIR / filename

    if not candidate.exists():
        raise HTTPException(status_code=404, detail="File not found")

    if not _is_allowed_report(candidate):
        raise HTTPException(status_code=400, detail="File type not allowed for deletion")

    candidate.unlink()
    return {"message": f"File {filename} deleted successfully"}

# Serve the frontend directory if it exists
FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
