from __future__ import annotations

"""Core analysis service for FireFind.

This module exposes :func:`run_analysis` which mirrors the logic of the
CLI ``parse`` command but returns findings in-memory instead of writing
reports directly to disk.  It can be used by other interfaces (e.g.
APIs) that need programmatic access to the analysis results.
"""

from pathlib import Path
from typing import Dict, List, Tuple

from .loaders.csv_xlsx_loader import load_table
from .model import Rule, Finding
from .rules_engine import run_checks, generate_risk_code
from .config import load_rules_config
from .utils import load_yaml, pick_mapping, to_rule


# ------------------------
# Public service function
# ------------------------

# Severity ranking used to compare and retain the most critical finding when
# duplicates are encountered. Higher numbers represent higher risk.
_SEVERITY_PRIORITY: Dict[str, int] = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
}


def _severity_rank(severity: str) -> int:
    """Return a numeric priority for a severity label."""

    return _SEVERITY_PRIORITY.get(severity or "", -1)


def _resequence_risk_codes(findings: List[Finding]) -> None:
    """Ensure risk codes are sequential after de-duplication."""

    counters: Dict[str, int] = {}

    for finding in findings:
        # Only specific finding types receive risk codes for now. For any other
        # finding we keep the field empty to avoid implying a tracked risk.
        if finding.finding_type != "admin_port_exposed":
            finding.risk_code = finding.risk_code or ""
            continue

        counter = counters.get(finding.finding_type, 0) + 1
        counters[finding.finding_type] = counter
        finding.risk_code = generate_risk_code(
            finding.finding_type, finding.severity, counter
        )


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """De-duplicate findings keeping the highest severity entry for each key."""

    # We intentionally omit the severity from the key so that we can compare and
    # retain the highest severity when the same underlying issue is reported
    # more than once.
    key_fields: Tuple[str, ...]
    index_map: Dict[Tuple[str, ...], int] = {}
    findings_unique: List[Finding] = []

    for finding in findings:
        key_fields = (
            finding.vendor,
            finding.rule_id,
            finding.src,
            finding.dst,
            finding.proto,
            finding.port,
            finding.action,
            finding.finding_type,
            finding.rationale,
            finding.source_file,
        )

        existing_index = index_map.get(key_fields)
        if existing_index is None:
            index_map[key_fields] = len(findings_unique)
            findings_unique.append(finding)
            continue

        existing = findings_unique[existing_index]
        if _severity_rank(finding.severity) > _severity_rank(existing.severity):
            findings_unique[existing_index] = finding

    _resequence_risk_codes(findings_unique)

    return findings_unique


def run_analysis(
    input_path: Path,
    vendor: str = "fortinet",
    rules_path: Path = Path("rules/rules.yaml"),
    mappings_path: Path = Path("rules/vendor_mappings.yaml"),
) -> List[Finding]:
    """Run the FireFind analysis and return a list of findings.

    Parameters
    ----------
    input_path:
        Path to a CSV/XLSX file or a directory containing such files.
    vendor:
        Vendor name used for column mappings.
    rules_path:
        Path to the YAML rules configuration.
    mappings_path:
        Path to the vendor mappings YAML file.
    """

    # Load configs
    rules_cfg = load_rules_config(Path(rules_path))
    vendor_mappings = load_yaml(Path(mappings_path))
    mapping = pick_mapping(vendor_mappings, vendor)

    # Collect rows from one or many files
    raw_rows = []
    p = Path(input_path)
    if p.is_dir():
        files = list(sorted(p.glob("*.csv"))) + list(sorted(p.glob("*.xlsx")))
        for f in files:
            for row in load_table(f):
                row["_source_file"] = f.name
                raw_rows.append(row)
    else:
        for row in load_table(p):
            row["_source_file"] = p.name
            raw_rows.append(row)

    # Normalize rules with de-duplication
    rules_norm: List[Rule] = []
    seen_rules = set()
    for row in raw_rows:
        r = to_rule(row, mapping)
        if not r:
            continue
        key = (r.rule_id, r.src, r.dst, r.proto, r.port, r.action)
        if key in seen_rules:
            continue
        seen_rules.add(key)
        rules_norm.append(r)

    # Analyze
    findings = run_checks(vendor, rules_norm, rules_cfg)

    return deduplicate_findings(findings)
