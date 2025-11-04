# backend/src/firefind/cli.py

import os
from pathlib import Path
from typing import List

import typer

from . import __version__

from .loaders.csv_xlsx_loader import load_table
from .model import Finding
from .reporters.csv_report import write_findings_csv
from .reporters.pdf_report import generate_pdf
from .service import run_analysis

app = typer.Typer(help="Ingest, normalize, analyze, and output reports.")


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"FireFind {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    input: str = typer.Option(
        ...,
        "--input",
        help="Path to input CSV/XLSX file or folder of files",
    ),
    vendor: str = typer.Option(
        "generic",
        "--vendor",
        help="Vendor name (e.g., 'generic')",
    ),
    out_csv: str = typer.Option(
        "out/findings.csv",
        "--out-csv",
        help="Output CSV path",
    ),
    out_pdf: str = typer.Option(
        "out/report.pdf",
        "--out-pdf",
        help="Output PDF path",
    ),
    rules: str = typer.Option(
        "rules/rules.yaml",
        "--rules",
        help="Rules YAML path",
    ),
    mappings: str = typer.Option(
        "rules/vendor_mappings.yaml",
        "--mappings",
        help="Vendor mappings YAML",
    ),
    version: bool = typer.Option(
        False,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show the application's version and exit",
    ),
):
    """FireFind command line interface."""
    parse(input, vendor, out_csv, out_pdf, rules, mappings)

def save_csv(findings: List[Finding], path: Path) -> None:
    p = Path(path)
    os.makedirs(p.parent, exist_ok=True)
    write_findings_csv(str(p), findings)

def save_pdf(findings: List[Finding], path: Path) -> None:
    p = Path(path)
    os.makedirs(p.parent, exist_ok=True)
    generate_pdf(str(p), findings, client_name="FireFind Analysis")
    
def parse(
    input: str,
    vendor: str,
    out_csv: str,
    out_pdf: str,
    rules: str,
    mappings: str,
):
    """Main entrypoint for FireFind CLI."""

    input_path = Path(input)
    if not input_path.exists():
        raise typer.BadParameter(f"{input_path} does not exist")

    raw_rows = []
    if input_path.is_dir():
        typer.echo(f"Input is a directory → scanning for CSV/XLSX in {input_path}")
        files = [
            f
            for f in sorted(input_path.iterdir())
            if f.is_file() and f.suffix.lower() in {".csv", ".xlsx"}
        ]

        files = [f for f in files if not f.name.startswith("~$")]
        
        if not files:
            raise typer.BadParameter("No CSV or XLSX files found")
        for f in files:
            typer.echo(f"  Loading {f}")
            for row in load_table(f):
                row["_source_file"] = f.name
                raw_rows.append(row)
    else:
        typer.echo(f"Input is a file → {input_path}")
        for row in load_table(input_path):
            row["_source_file"] = input_path.name
            raw_rows.append(row)

    typer.echo(f"Loaded {len(raw_rows)} rows")
    analysis = run_analysis(
        input_path,
        vendor=vendor,
        rules_path=Path(rules),
        mappings_path=Path(mappings),
    )
    findings_unique = analysis.findings

    tag_set = {tag for finding in findings_unique for tag in getattr(finding, "tags", ()) if tag}
    if tag_set:
        typer.echo(f"Observed tags → {', '.join(sorted(tag_set))}")
    else:
        typer.echo("Observed tags → (none)")

    save_csv(findings_unique, Path(out_csv))
    typer.echo(f"Saved CSV → {out_csv}")
    save_pdf(findings_unique, Path(out_pdf))
    typer.echo(f"Saved PDF → {out_pdf}")

if __name__ == "__main__":
    app()
