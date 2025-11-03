import csv
from typing import List
from ..model import Finding


def write_findings_csv(path: str, findings: List[Finding]) -> None:
    """Write findings to a CSV file."""
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'vendor', 'rule_id', 'src', 'dst', 'proto', 'port', 'action',
            'finding_type', 'severity', 'risk_code', 'rationale'
        ])
        
        for finding in findings:
            writer.writerow([
                finding.vendor,
                finding.rule_id,
                finding.src,
                finding.dst,
                finding.proto,
                finding.port,
                finding.action,
                finding.finding_type,
                finding.severity,
                finding.risk_code,
                finding.rationale
            ])
