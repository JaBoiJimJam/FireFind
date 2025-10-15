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
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Cautionary": 2,
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
    """Collapse duplicate findings and aggregate rule level issues.

    The previous de-duplication logic compared the entire ``Finding`` payload
    (rule identifiers, addressing, protocol details, etc.) and retained the
    highest severity match.  That approach still surfaced multiple entries for
    the same rule when different analyzers flagged related issues (e.g. an
    administrative port exposure *and* an all-ports service warning).  Users
    reported inflated risk counts as a result.

    This implementation first removes exact duplicates and then groups findings
    by vendor/source file/rule identifier.  For each rule we:

    * retain the highest severity finding as the "primary" record; and
    * merge rationales from all contributing analyzers into a single narrative
      so that additional context is not lost.

    Returning a single consolidated finding per rule produces counts that match
    expectations while still communicating every detected issue.
    """

    # Step 1 – coalesce identical findings keeping the highest severity entry.
    detailed_index: Dict[Tuple[str, ...], Finding] = {}

    for finding in findings:
        detail_key = (
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

        existing = detailed_index.get(detail_key)
        if existing is None or _severity_rank(finding.severity) > _severity_rank(
            existing.severity
        ):
            detailed_index[detail_key] = finding

    # Step 2 – group by rule identifier and aggregate related rationales.
    grouped: Dict[Tuple[str, str, str], Dict[str, object]] = {}

    for finding in detailed_index.values():
        rule_key = (finding.vendor, finding.source_file, finding.rule_id)
        entry = grouped.setdefault(
            rule_key,
            {
                "primary": None,
                "details": [],
            },
        )

        entry["details"].append(finding)

        primary = entry["primary"]
        if primary is None or _severity_rank(finding.severity) > _severity_rank(
            primary.severity
        ):
            entry["primary"] = finding
            continue

        # Prefer admin_port_exposed as the representative issue when severities
        # match so that risk codes remain visible for the most critical cases.
        if (
            _severity_rank(finding.severity) == _severity_rank(primary.severity)
            and primary.finding_type != "admin_port_exposed"
            and finding.finding_type == "admin_port_exposed"
        ):
            entry["primary"] = finding

    findings_unique: List[Finding] = []

    for entry in grouped.values():
        primary = entry["primary"]
        assert isinstance(primary, Finding)  # for type-checkers

        # Build a combined rationale that preserves all contributing messages.
        rationale_parts: List[str] = []
        seen_pairs = set()
        contributing_severities: List[str] = []
        for detail in entry["details"]:
            pair = (detail.finding_type, detail.rationale)
            contributing_severities.append(detail.severity)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            if detail is primary:
                continue
            label = detail.finding_type.replace("_", " ")
            rationale_parts.append(f"{label}: {detail.rationale}")

        combined_rationale = primary.rationale
        if rationale_parts:
            combined_rationale = (
                f"{combined_rationale} | Additional issues: "
                + " | ".join(rationale_parts)
            )

        findings_unique.append(
            Finding(
                vendor=primary.vendor,
                rule_id=primary.rule_id,
                src=primary.src,
                dst=primary.dst,
                proto=primary.proto,
                port=primary.port,
                action=primary.action,
                finding_type=primary.finding_type,
                severity=primary.severity,
                rationale=combined_rationale,
                risk_code=primary.risk_code,
                source_file=primary.source_file,
                contributing_severities=tuple(contributing_severities),
            )
        )

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
        r = to_rule(row, mapping, vendor=vendor)
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
