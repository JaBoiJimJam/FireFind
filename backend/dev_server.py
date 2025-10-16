"""Development convenience server for FireFind."""

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from firefind.api import app as firefind_api_app

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount the real API routes so the frontend can call them during development.
# ``include_router`` keeps the paths exactly as defined in ``firefind.api``
# (for example ``/api/config/rules``) without introducing double prefixes,
# while still allowing us to serve static frontend assets below.
app.include_router(firefind_api_app.router)

# Serve generated report artifacts so the frontend can download CSV/PDF
# exports produced by ``/api/scan``.  The development server previously only
# mounted the static route if the ``out`` directory already existed.  When the
# application is freshly started the directory is created lazily during the
# first scan request, which meant the mount never occurred and the frontend saw
# 404 errors for the download URLs.  Ensuring the directory exists up front lets
# FastAPI mount the static files handler every time.
out_path = Path("out")
out_path.mkdir(parents=True, exist_ok=True)
downloads_mount = StaticFiles(directory=out_path)
app.mount("/downloads", downloads_mount, name="downloads")
app.mount("/out", downloads_mount, name="out")

# API endpoint to get list of files in out folder
@app.get("/api/reports")
async def get_reports():
    """Get list of report files from the out directory"""
    out_dir = Path("out")
    
    if not out_dir.exists():
        return []
    
    reports = []
    try:
        for file_path in out_dir.iterdir():
            if file_path.is_file() and file_path.suffix.lower() in ['.pdf', '.csv', '.xlsx', '.xls']:
                stat = file_path.stat()
                reports.append({
                    "name": file_path.name,
                    "size": stat.st_size,
                    "modified": stat.st_mtime,
                    "type": file_path.suffix[1:].lower()  # Remove the dot
                })
        
        # Sort by modification time (newest first)
        reports.sort(key=lambda x: x["modified"], reverse=True)
        
    except Exception as e:
        print(f"Error reading out directory: {e}")
        return []
    
    return reports

# API endpoint to delete a specific report file
@app.delete("/api/reports/{filename}")
async def delete_report(filename: str):
    """Delete a specific report file from the out directory"""
    out_dir = Path("out")
    file_path = out_dir / filename
    
    try:
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        if not file_path.is_file():
            raise HTTPException(status_code=400, detail="Path is not a file")
        
        # Only allow deletion of report files
        if file_path.suffix.lower() not in ['.pdf', '.csv', '.xlsx', '.xls']:
            raise HTTPException(status_code=400, detail="File type not allowed for deletion")
        
        file_path.unlink()  # Delete the file
        return {"message": f"File {filename} deleted successfully"}
        
    except Exception as e:
        print(f"Error deleting file: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete file")

# Add route handlers for clean URLs before the catch-all static files mount
from fastapi.responses import FileResponse

@app.get("/about")
@app.get("/")
async def serve_index():
    """Serve index.html for root and /about routes"""
    return FileResponse("frontend/index.html")

@app.get("/scan")
async def serve_scan():
    """Serve scan.html for /scan route"""
    return FileResponse("frontend/scan.html")

@app.get("/reports")
async def serve_reports():
    """Serve reports.html for /reports route"""
    return FileResponse("frontend/reports.html")

@app.get("/admin")
async def serve_admin():
    """Serve admin.html for /admin route"""
    return FileResponse("frontend/admin.html")

# Serve static files from frontend directory (this should be last)
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
