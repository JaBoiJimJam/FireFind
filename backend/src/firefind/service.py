from __future__ import annotations

"""Core analysis service for FireFind.

This module exposes :func:`run_analysis` which mirrors the logic of the
CLI ``parse`` command but returns findings in-memory instead of writing
reports directly to disk.  It can be used by other interfaces (e.g.
APIs) that need programmatic access to the analysis results.
"""

from pathlib import Path
from typing import List

from .loaders.csv_xlsx_loader import load_table
from .model import Rule, Finding
from .rules_engine import run_checks
from .utils import load_yaml, pick_mapping, to_rule


# ------------------------
# Public service function
# ------------------------

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
    rules_cfg = load_yaml(Path(rules_path))
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

    # De-duplicate findings across files
    dedup = set()
    findings_unique: List[Finding] = []
    for f in findings:
        fkey = (
            f.vendor,
            f.rule_id,
            f.src,
            f.dst,
            f.proto,
            f.port,
            f.action,
            f.finding_type,
            f.severity,
            f.rationale,
            f.source_file,
        )
        if fkey in dedup:
            continue
        dedup.add(fkey)
        findings_unique.append(f)

    return findings_unique
