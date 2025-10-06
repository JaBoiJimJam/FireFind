from __future__ import annotations

"""FastAPI application exposing FireFind analysis as an HTTP service."""

import os
from pathlib import Path
import tempfile
from collections import Counter
from dataclasses import asdict
from typing import Any, Dict, List
from uuid import uuid4

from fastapi import (
    Body,
    Depends,
    FastAPI,
    File,
    Header,
    HTTPException,
    UploadFile,
)
from fastapi import status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .service import run_analysis
from .reporters.csv_report import write_findings_csv
from .reporters.pdf_report import generate_pdf
from .config import RulesConfigStore

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


def require_api_token(authorization: str = Header(default="")) -> None:
    token = os.getenv("FIRE_FIND_API_TOKEN")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API token is not configured",
        )

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scheme, _, credentials = authorization.partition(" ")
    if scheme.lower() != "bearer" or credentials != token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_actor(
    x_firefind_actor: str | None = Header(default=None, alias="X-Firefind-Actor")
) -> str:
    return (x_firefind_actor or "unknown").strip() or "unknown"


def get_rules_config_store() -> RulesConfigStore:
    return RulesConfigStore()


class RulesConfigPatch(BaseModel):
    """Incoming payload for partial rules configuration updates."""

    changes: Dict[str, Any] = Field(default_factory=dict)
    message: str | None = Field(default=None, max_length=500)


@app.get("/api/config/rules")
def get_rules_config(
    _: None = Depends(require_api_token),
    store: RulesConfigStore = Depends(get_rules_config_store),
):
    config = store.load_active().to_dict()
    revision = store.latest_revision()
    metadata = {
        "version": revision.version if revision else 0,
        "updated_at": revision.timestamp if revision else None,
        "updated_by": revision.actor if revision else None,
        "summary": revision.summary if revision else None,
    }
    return {"config": config, "metadata": metadata}


@app.get("/api/config/rules/history")
def get_rules_config_history(
    limit: int = 20,
    _: None = Depends(require_api_token),
    store: RulesConfigStore = Depends(get_rules_config_store),
):
    history = store.get_history(limit if limit > 0 else None)
    return {"history": history}


@app.patch("/api/config/rules")
def patch_rules_config(
    payload: RulesConfigPatch = Body(...),
    _: None = Depends(require_api_token),
    store: RulesConfigStore = Depends(get_rules_config_store),
    actor: str = Depends(get_actor),
):
    if not payload.changes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No configuration changes supplied",
        )

    try:
        config, revision = store.update(
            payload.changes,
            actor=actor,
            summary=payload.message,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    metadata = {
        "version": revision.version,
        "updated_at": revision.timestamp,
        "updated_by": revision.actor,
        "summary": revision.summary,
    }
    return {"config": config.to_dict(), "metadata": metadata}


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
        metrics: Dict[str, Any] = {
            key: int(severity_counts.get(key, 0)) for key in _SEVERITY_KEYS
        }
        metrics["total"] = len(findings)
        metrics["score"] = _calculate_score(metrics)

        pdf_path: Path | None = None
        csv_path: Path | None = None

        # Optional report generation
        if save_csv or save_pdf:
            reports_dir = Path.cwd() / "out"
            reports_dir.mkdir(parents=True, exist_ok=True)
            token = uuid4().hex
            if save_csv:
                csv_path = reports_dir / f"firefind_findings_{token}.csv"
                write_findings_csv(csv_path, findings)
            if save_pdf:
                pdf_path = reports_dir / f"firefind_report_{token}.pdf"
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
        response["pdf"] = f"/downloads/{pdf_path.name}"

    return response
