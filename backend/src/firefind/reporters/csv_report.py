import csv
from typing import List
from ..model import Finding


def write_findings_csv(path: str, findings: List[Finding]) -> None:
    """Write findings to a CSV file."""
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'vendor', 'rule_id', 'src', 'dst', 'proto', 'port', 'action',
            'finding_type', 'severity', 'risk_code', 'hit_count', 'byte_count',
            'rule_enabled', 'rationale', 'tags'
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
                "" if finding.hit_count is None else finding.hit_count,
                "" if finding.byte_count is None else finding.byte_count,
                "" if finding.rule_enabled is None else str(finding.rule_enabled).lower(),
                finding.rationale,
                ";".join(finding.tags)
            ])
