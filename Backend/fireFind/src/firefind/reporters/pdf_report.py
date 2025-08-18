from fpdf import FPDF
import os
from collections import Counter
from typing import List
from ..model import Finding

def generate_pdf(path: str, findings: List[Finding], title: str = "FireFind - Sprint 1 Report") -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)  # <-- add this
    pdf.add_page()
    pdf.set_font("Helvetica", size=16)
    pdf.cell(0, 10, title, ln=True)

    pdf.set_font("Helvetica", size=12)
    pdf.cell(0, 8, f"Total findings: {len(findings)}", ln=True)

    # Severity counts
    sev_counts = Counter([f.severity for f in findings])
    for sev in ("Critical","High","Medium","Low"):
        if sev in sev_counts:
            pdf.cell(0, 8, f"{sev}: {sev_counts[sev]}", ln=True)

    # Top 5 table
    pdf.ln(4)
    pdf.set_font("Helvetica", size=12)
    pdf.cell(0, 8, "Top 5 Findings:", ln=True)
    pdf.set_font("Helvetica", size=10)
    for f in findings[:5]:
        line = f"- {f.rule_id} [{f.finding_type}] {f.rationale} (src={f.src}, dst={f.dst}, port={f.port})"
        pdf.multi_cell(0, 6, line, new_x="LMARGIN", new_y="NEXT")  # <-- changed: reset X each line

    pdf.output(path)
