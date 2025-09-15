import csv, os
from typing import List
from ..model import Finding


def write_findings_csv(path: str, findings: List[Finding]) -> None:
    dir_name = os.path.dirname(path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["vendor","rule_id","src","dst","proto","port","action","finding_type","severity","rationale"])
        for x in findings:
            w.writerow([x.vendor,x.rule_id,x.src,x.dst,x.proto,x.port,x.action,x.finding_type,x.severity,x.rationale])
