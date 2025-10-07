from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os
import json
from pathlib import Path

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve files from out directory if it exists
out_path = Path("out")
if out_path.exists():
    app.mount("/out", StaticFiles(directory="out"), name="out")

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

# Serve static files from frontend directory (this should be last)
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
