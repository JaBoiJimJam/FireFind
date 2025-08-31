import typer, os, yaml
from typing import List, Dict
from .loaders.csv_xlsx_loader import load_table
from .vendors.fortinet import map_row_fortinet
from .model import Rule
from .rules_engine import run_checks
from .reporters.csv_report import write_findings_csv
from .reporters.pdf_report import generate_pdf
import sys
import os

# Add the `src` directory to the Python module search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

app = typer.Typer(add_completion=False)

def pick_mapping(mappings: Dict[str, Dict[str, list]], vendor: str) -> Dict[str, list]:
    v = vendor.lower()
    if v not in mappings:
        raise typer.BadParameter(f"Vendor '{vendor}' not found in mappings file.")
    return mappings[v]

@app.command()
def parse(
    input: str = typer.Option(..., help="Path to input CSV/XLSX"),
    vendor: str = typer.Option("fortinet", help="Vendor name (Sprint 1: 'fortinet')"),
    out_csv: str = typer.Option("out/findings.csv", help="Output CSV path"),
    out_pdf: str = typer.Option("out/report.pdf", help="Output PDF path"),
    rules: str = typer.Option("rules/rules.yaml", help="Rules YAML path"),
    mappings: str = typer.Option("rules/vendor_mappings.yaml", help="Vendor mappings YAML"),
):
    """Ingest, normalize, analyze, and output reports."""
    # Load config
    with open(rules, "r", encoding="utf-8") as f:
        rules_cfg = yaml.safe_load(f) or {}
    with open(mappings, "r", encoding="utf-8") as f:
        vendor_mappings = yaml.safe_load(f) or {}
    mapping = pick_mapping(vendor_mappings, vendor)

    # Load rows
    raw_rows = list(load_table(input))
    typer.echo(f"Loaded {len(raw_rows)} rows from {input}")

    # Map → normalized Rules
    rules_norm: List[Rule] = []
    for row in raw_rows:
        if vendor.lower() == "fortinet":
            nr = map_row_fortinet(row, mapping)
        else:
            raise typer.BadParameter("Only 'fortinet' supported in Sprint 1 starter.")
        rules_norm.append(Rule(**nr))

    typer.echo(f"Normalized {len(rules_norm)} rules.")

    # Analyze
    findings = run_checks(vendor, rules_norm, rules_cfg or {})
    typer.echo(f"Findings: {len(findings)} total.")

    # Outputs
    write_findings_csv(out_csv, findings)
    typer.echo(f"Wrote CSV: {out_csv}")
    generate_pdf(out_pdf, findings)
    typer.echo(f"Wrote PDF: {out_pdf}")

if __name__ == "__main__":
    app()
