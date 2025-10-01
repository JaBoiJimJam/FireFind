from __future__ import annotations

"""FastAPI application exposing FireFind analysis as an HTTP service."""

from pathlib import Path
import os
import tempfile
from collections import Counter
from dataclasses import asdict
from typing import List, Dict, Any

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

from .service import run_analysis
from .reporters.csv_report import write_findings_csv
from .reporters.pdf_report import generate_pdf

app = FastAPI()

# Configure allowed CORS origins via environment variable. Multiple origins can
# be provided as a comma-separated list. Defaults to "*" for development
# convenience.
origins_env = os.getenv("FIRE_FIND_ALLOW_ORIGINS", "*")
if origins_env == "*":
    allowed_origins = ["*"]
else:
    allowed_origins = [origin.strip() for origin in origins_env.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


_SEVERITY_KEYS = ("critical", "high", "medium", "low", "info")


def _calculate_score(metrics: Dict[str, int]) -> int:
    """Return a 0-100 security score based on severity metrics."""

    weights = {
        "critical": 30,
        "high": 15,
        "medium": 5,
        "low": 2,
    }
    penalty = sum(metrics.get(level, 0) * weight for level, weight in weights.items())
    score = max(0, 100 - penalty)
    return int(score)


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

        # Resolve configuration file locations relative to the backend package
        base_dir = Path(__file__).resolve().parents[2]
        rules_dir = base_dir / "rules"
        findings = run_analysis(
            tmp_path,
            vendor=vendor,
            rules_path=rules_dir / "rules.yaml",
            mappings_path=rules_dir / "vendor_mappings.yaml",
        )
        # Build metrics by severity
        severity_counts = Counter(f.severity.lower() for f in findings)
        metrics: Dict[str, Any] = dict(severity_counts)
        metrics["total"] = len(findings)

        pdf_path: Path | None = None
        csv_path: Path | None = None

        # Optional report generation
        if save_csv or save_pdf:
            os.makedirs("out", exist_ok=True)
            if save_csv:
                csv_path = Path("out/findings.csv")
                write_findings_csv(csv_path, findings)
            if save_pdf:
                pdf_path = Path("out/report.pdf")
                generate_pdf(
                    pdf_path, findings, client_name="FireFind Analysis"
                )

    response: Dict[str, Any] = {
        "findings": [asdict(f) for f in findings],
        "metrics": metrics,
    }
    if csv_path:
        response["csv"] = f"/downloads/{csv_path.name}"
    if pdf_path:
        response["pdf"] = pdf_path.as_posix()

    return response
