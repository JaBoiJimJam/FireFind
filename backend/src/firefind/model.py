from dataclasses import dataclass
from typing import Optional

@dataclass
class Rule:
    rule_id: str
    src: str
    dst: str
    proto: str
    port: str
    action: str
    comment: Optional[str] = None

@dataclass
class Finding:
    vendor: str
    rule_id: str
    src: str
    dst: str
    proto: str
    port: str
    action: str
    finding_type: str
    severity: str
    rationale: str
    risk_code: str = ""  # Add this field
