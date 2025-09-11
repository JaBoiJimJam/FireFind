from __future__ import annotations

"""FastAPI application exposing FireFind analysis as an HTTP service."""

from pathlib import Path
import os
import tempfile
from dataclasses import asdict
from typing import List

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

from .service import run_analysis
from .reporters.csv_report import write_findings_csv
from .reporters.pdf_report import generate_pdf

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Development convenience
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/scan")
async def scan(
    files: List[UploadFile] = File(...),
    vendor: str = "fortinet",
    save_csv: bool = False,
    save_pdf: bool = False,
):
    """Analyze uploaded CSV/XLSX files and return findings as JSON."""
    # Persist uploads to a temporary directory so our loader can read them
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        for uploaded in files:
            dest = tmp_path / Path(uploaded.filename).name
            contents = await uploaded.read()
            dest.write_bytes(contents)

        findings = run_analysis(tmp_path, vendor=vendor)

        # Optional report generation
        if save_csv or save_pdf:
            os.makedirs("out", exist_ok=True)
            if save_csv:
                write_findings_csv("out/findings.csv", findings)
            if save_pdf:
                generate_pdf("out/report.pdf", findings, client_name="FireFind Analysis")

    return {"findings": [asdict(f) for f in findings]}
