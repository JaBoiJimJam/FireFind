# backend/src/firefind/cli.py

import os
from pathlib import Path
from typing import List, Tuple

import typer
import yaml

from .loaders.csv_xlsx_loader import load_table
from .model import Rule, Finding
from .rules_engine import run_checks
from .reporters.csv_report import write_findings_csv
from .reporters.pdf_report import generate_pdf
from .vendors.utils import pick_first_present  # we reuse this helper

app = typer.Typer(help="Ingest, normalize, analyze, and output reports.")

# ------------------------
# Small helpers (local)
# ------------------------

def load_yaml(path: Path) -> dict:
    with Path(path).open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def pick_mapping(vendor_mappings: dict, vendor: str) -> dict:
    if not vendor_mappings:
        return {}
    v = vendor.lower()
    for k, val in vendor_mappings.items():
        if k.lower() == v:
            return val
    return vendor_mappings.get(vendor, {})

def save_csv(findings: List[Finding], path: Path) -> None:
    p = Path(path)
    os.makedirs(p.parent, exist_ok=True)
    write_findings_csv(str(p), findings)

def save_pdf(findings: List[Finding], path: Path) -> None:
    p = Path(path)
    os.makedirs(p.parent, exist_ok=True)
    # Change from title= to client_name= to match your PDF function
    generate_pdf(str(p), findings, client_name="FireFind Analysis")
    
# --- Service/Port sniffing improvements ---

def sniff_proto_port(row: dict) -> Tuple[str, str]:
    """
    Prefer an explicit TCP/nnn or UDP/nnn column (e.g., 'Service.1').
    If missing, sniff any cell that contains TCP/nnn or UDP/nnn (line-separated allowed).
    Fall back to service NAME (ignored by rules_engine) or 'any'.
    Returns (proto, port_string). We leave proto='any' and put concrete values in port_string.
    """
    # Typical places for concrete ports
    svc_port = pick_first_present(row, ["Service.1", "Service Port", "Port", "DPort"])
    if svc_port.strip():
        parts = [p.strip() for p in str(svc_port).splitlines() if p.strip()]
        return ("any", ",".join(parts))

    # Sniff anywhere for TCP/nnn or UDP/nnn
    for _, v in row.items():
        s = str(v or "").strip().upper()
        if (s.startswith("TCP/") or s.startswith("UDP/")) and any(ch.isdigit() for ch in s):
            parts = [p.strip() for p in s.splitlines() if p.strip()]
            return ("any", ",".join(parts))

    # Fall back to friendly service name if present (rules engine will ignore)
    svc_name = pick_first_present(row, ["Service"])
    if svc_name.strip():
        parts = [p.strip() for p in str(svc_name).splitlines() if p.strip()]
        return ("any", ",".join(parts))

    return ("any", "any")

def to_rule(row: dict, mapping: dict) -> Rule | None:
    """
    Map a raw row into our normalized Rule. Skip obvious non-data rows.
    """
    rid = pick_first_present(row, mapping.get("rule_id", [])) or "(unknown)"
    action = pick_first_present(row, mapping.get("action", [])) or "allow"
    src = pick_first_present(row, mapping.get("src", [])) or "any"
    dst = pick_first_present(row, mapping.get("dst", [])) or "any"
    proto, port = sniff_proto_port(row)
    comment = pick_first_present(row, mapping.get("comment", [])) or ""

    # Skip banner/section/noise rows that have nothing useful
    if rid == "(unknown)" and src == "any" and dst == "any" and port == "any":
        return None

    return Rule(
        rule_id=rid,
        src=src,
        dst=dst,
        proto=proto,
        port=port,
        action=action,
        comment=comment,
    )

# ------------------------
# CLI command
# ------------------------

@app.command()
def parse(
    input: str = typer.Option(..., "--input", help="Path to input CSV/XLSX file or folder of files"),
    vendor: str = typer.Option("fortinet", "--vendor", help="Vendor name (e.g., 'fortinet')"),
    out_csv: str = typer.Option("out/findings.csv", "--out-csv", help="Output CSV path"),
    out_pdf: str = typer.Option("out/report.pdf", "--out-pdf", help="Output PDF path"),
    rules: str = typer.Option("rules/rules.yaml", "--rules", help="Rules YAML path"),
    mappings: str = typer.Option("rules/vendor_mappings.yaml", "--mappings", help="Vendor mappings YAML"),
):
    """Main entrypoint for FireFind CLI."""

    input_path = Path(input)

    # Load configs
    rules_cfg = load_yaml(Path(rules))
    vendor_mappings = load_yaml(Path(mappings))
    mapping = pick_mapping(vendor_mappings, vendor)

    # Collect rows from one or many files
    raw_rows = []
    if input_path.is_dir():
        typer.echo(f"Input is a directory → scanning for CSV/XLSX in {input_path}")
        files = list(sorted(input_path.glob("*.csv"))) + list(sorted(input_path.glob("*.xlsx")))
        for f in files:
            typer.echo(f"  Loading {f}")
            raw_rows.extend(load_table(f))
    else:
        typer.echo(f"Input is a file → {input_path}")
        raw_rows = list(load_table(input_path))

    typer.echo(f"Loaded {len(raw_rows)} rows")

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
        fkey = (f.vendor, f.rule_id, f.src, f.dst, f.proto, f.port, f.action, f.finding_type, f.severity, f.rationale)
        if fkey in dedup:
            continue
        dedup.add(fkey)
        findings_unique.append(f)

    # Save reports
    save_csv(findings_unique, Path(out_csv))
    typer.echo(f"Saved CSV → {out_csv}")
    save_pdf(findings_unique, Path(out_pdf))
    typer.echo(f"Saved PDF → {out_pdf}")

if __name__ == "__main__":
    app()
