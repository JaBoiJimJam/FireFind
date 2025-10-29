from __future__ import annotations

"""FastAPI application exposing FireFind analysis as an HTTP service."""

import os
from pathlib import Path
import tempfile
from collections import Counter
from dataclasses import asdict
from typing import Any, Dict, List, Literal, Mapping, Optional, Set
from uuid import uuid4
from datetime import datetime

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
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)

from .service import run_analysis
from .reporters.csv_report import write_findings_csv
from .reporters.pdf_report import generate_pdf
from .config import (
    RulesConfigStore,
    build_rules_update_patch,
    extract_rule_logic,
    extract_thresholds,
)

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
    """Incoming payload for legacy partial rules configuration updates."""

    changes: Dict[str, Any] = Field(default_factory=dict)
    message: Optional[str] = Field(default=None, max_length=500)


class ConditionNodeModel(BaseModel):
    """Recursive representation of a rule condition tree."""

    type: Literal["all", "any", "comparison"]
    conditions: List["ConditionNodeModel"] = Field(default_factory=list)
    field: Optional[str] = None
    operator: Optional[str] = None
    value: Any = None
    model_config = ConfigDict(str_strip_whitespace=True)

    @field_validator("conditions")
    def validate_children(
        cls, value: List["ConditionNodeModel"], info: ValidationInfo
    ) -> List["ConditionNodeModel"]:
        node_type = info.data.get("type") if info.data else None
        if node_type in {"all", "any"}:
            if not value:
                raise ValueError("'conditions' must contain at least one child for group nodes")
        else:
            if value:
                raise ValueError("Comparison nodes cannot define nested conditions")
        return value

    @model_validator(mode="after")
    def validate_node(self) -> "ConditionNodeModel":
        node_type = self.type
        if node_type == "comparison":
            field = (self.field or "").strip()
            operator = (self.operator or "").strip()
            if not field:
                raise ValueError("Comparison nodes require a 'field'")
            if not operator:
                raise ValueError("Comparison nodes require an 'operator'")
        else:
            if self.field is not None:
                raise ValueError("Group nodes cannot define 'field'")
            if self.operator is not None:
                raise ValueError("Group nodes cannot define 'operator'")
            if self.value not in (None, "", [], {}):
                raise ValueError("Group nodes cannot define 'value'")
        return self

class RuleDefinitionModel(BaseModel):
    """API payload describing a configurable rule."""

    id: str = Field(..., min_length=1)
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    tags: Optional[List[str]] = None
    conditions: ConditionNodeModel
    metadata: Optional[Dict[str, Any]] = None
    model_config = ConfigDict(str_strip_whitespace=True)

    @field_validator("id")
    def validate_id(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("Rule id cannot be blank")
        return trimmed

class ThresholdUpdateModel(BaseModel):
    """Threshold deltas for an individual risk level."""

    min_score: Optional[int] = Field(default=None, ge=0, le=100)
    max_score: Optional[int] = Field(default=None, ge=0, le=100)
    min_findings: Optional[int] = Field(default=None, ge=0)
    max_findings: Optional[int] = Field(default=None, ge=0)
    model_config = ConfigDict()

    @model_validator(mode="after")
    def validate_ranges(self) -> "ThresholdUpdateModel":
        if (
            self.min_score is not None
            and self.max_score is not None
            and self.min_score > self.max_score
        ):
            raise ValueError("min_score cannot exceed max_score")
        if (
            self.min_findings is not None
            and self.max_findings is not None
            and self.min_findings > self.max_findings
        ):
            raise ValueError("min_findings cannot exceed max_findings")
        return self


class RulesConfigUpdatePayload(BaseModel):
    """Incoming payload for replacing rules configuration content."""

    rules: Optional[List[RuleDefinitionModel]] = None
    thresholds: Optional[Dict[str, ThresholdUpdateModel]] = None
    message: Optional[str] = Field(default=None, max_length=500)
    model_config = ConfigDict(str_strip_whitespace=True)

    @model_validator(mode="after")
    def validate_payload(self) -> "RulesConfigUpdatePayload":
        if self.rules is None and self.thresholds is None:
            raise ValueError("At least one of 'rules' or 'thresholds' must be provided")
        return self

ConditionNodeModel.model_rebuild()
RuleDefinitionModel.model_rebuild()


def _iter_condition_nodes(node: ConditionNodeModel):
    yield node
    for child in node.conditions:
        yield from _iter_condition_nodes(child)


def _validate_rule_ports(rule: RuleDefinitionModel) -> None:
    for node in _iter_condition_nodes(rule.conditions):
        if node.type != "comparison":
            continue
        field = (node.field or "").lower()
        if "port" not in field:
            continue
        raw_value = node.value
        if raw_value is None:
            raise ValueError(f"Rule '{rule.id}' comparison against port requires a value")

        if isinstance(raw_value, (list, tuple, set)):
            values = list(raw_value)
        elif isinstance(raw_value, str):
            values = [part.strip() for part in raw_value.split(",") if part.strip()]
        else:
            values = [raw_value]

        if not values:
            raise ValueError(f"Rule '{rule.id}' comparison against port requires a value")

        for entry in values:
            try:
                port = int(entry)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Rule '{rule.id}' contains non-numeric port value '{entry}'"
                ) from exc
            if not (1 <= port <= 65535):
                raise ValueError(
                    f"Rule '{rule.id}' contains invalid port '{port}' (must be 1-65535)"
                )


@app.get("/api/config/rules")
def get_rules_config(
    _: None = Depends(require_api_token),
    store: RulesConfigStore = Depends(get_rules_config_store),
):
    active_config = store.load_active()
    config = active_config.to_dict()
    raw_config = store.load_raw()
    revision = store.latest_revision()
    metadata = {
        "version": revision.version if revision else 0,
        "updated_at": revision.timestamp if revision else None,
        "updated_by": revision.actor if revision else None,
        "summary": revision.summary if revision else None,
    }
    rule_logic = extract_rule_logic(raw_config)
    thresholds = extract_thresholds(active_config)
    return {
        "config": config,
        "rules": rule_logic,
        "thresholds": thresholds,
        "metadata": metadata,
    }


@app.put("/api/config/rules")
def put_rules_config(
    payload: RulesConfigUpdatePayload = Body(...),
    _: None = Depends(require_api_token),
    store: RulesConfigStore = Depends(get_rules_config_store),
    actor: str = Depends(get_actor),
):
    rules = payload.rules or []
    seen_ids: Set[str] = set()
    for rule in rules:
        if rule.id in seen_ids:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Duplicate rule id '{rule.id}' detected",
            )
        seen_ids.add(rule.id)
        try:
            _validate_rule_ports(rule)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc

    current_raw = store.load_raw()
    current_config = store.load_active()
    thresholds_payload: Mapping[str, Mapping[str, Any]] | None = None
    if payload.thresholds is not None:
        thresholds_payload = {
            name: update.model_dump(exclude_none=True)
            for name, update in payload.thresholds.items()
        }

    patch = build_rules_update_patch(
        current_raw=current_raw,
        current_config=current_config,
        rules=[rule.model_dump(exclude_none=True) for rule in payload.rules]
        if payload.rules is not None
        else None,
        thresholds=thresholds_payload,
    )

    if not patch:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No configuration changes supplied",
        )

    try:
        config, revision = store.update(
            patch,
            actor=actor,
            summary=payload.message,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    metadata = {
        "version": revision.version,
        "updated_at": revision.timestamp,
        "updated_by": revision.actor,
        "summary": revision.summary,
    }

    raw_config = store.load_raw()
    return {
        "config": config.to_dict(),
        "rules": extract_rule_logic(raw_config),
        "thresholds": extract_thresholds(config),
        "metadata": metadata,
    }


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
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    metadata = {
        "version": revision.version,
        "updated_at": revision.timestamp,
        "updated_by": revision.actor,
        "summary": revision.summary,
    }
    return {"config": config.to_dict(), "metadata": metadata}


_SEVERITY_KEYS = ("critical", "high", "medium", "cautionary", "low", "info")


def _calculate_score(metrics: Dict[str, int]) -> int:
    """Return a 0-100 security score based on severity metrics."""

    weights = {
        "critical": 30,
        "high": 15,
        "medium": 5,
        "cautionary": 3,
        "low": 2,
    }
    penalty = sum(metrics.get(level, 0) * weight for level, weight in weights.items())
    score = max(0, 100 - penalty)
    return int(score)


from fastapi import Form

@app.post("/scan")
@app.post("/api/scan")
async def scan(
    files: List[UploadFile] = File(...),
    vendor: str = "generic",
    save_csv: bool = False,
    save_pdf: bool = False,
    client_name: Optional[str] = Form(None),
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
        severity_counts: Counter[str] = Counter()
        for finding in findings:
            severities = (
                finding.contributing_severities
                if getattr(finding, "contributing_severities", None)
                else (finding.severity,)
            )
            for severity in severities:
                if not severity:
                    continue
                severity_counts[severity.lower()] += 1
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
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            # Sanitize client name for filename (use '-' for spaces)
            client_name_for_file = (client_name.strip().replace(' ', '-') if client_name else "FireFind-Analysis")
            if save_csv:
                csv_path = reports_dir / f"findings_{client_name_for_file}_{timestamp}.csv"
                write_findings_csv(csv_path, findings)
            if save_pdf:
                pdf_path = reports_dir / f"report_{client_name_for_file}_{timestamp}.pdf"
                # Use provided client_name or fallback
                name_for_pdf = client_name if client_name else "FireFind Analysis"
                generate_pdf(
                    pdf_path, findings, client_name=name_for_pdf
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


# Maintain backward compatibility with front-end clients expecting the API
# under an "/api" prefix. This registers a second path that reuses the same
# handler logic without duplicating implementation details.
app.add_api_route(
    "/api/scan",
    scan,
    methods=["POST"],
    name="scan_with_prefix",
)
