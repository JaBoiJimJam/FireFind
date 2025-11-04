from dataclasses import dataclass, field
from typing import Optional, Tuple

@dataclass
class Rule:
    rule_id: str
    src: str
    dst: str
    proto: str
    port: str
    action: str
    comment: Optional[str] = None
    src_interface: str = ""
    dst_interface: str = ""
    service: str = ""
    source_file: str = ""
    risk_rating: str = ""
    tags: Tuple[str, ...] = field(default_factory=tuple)

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
    source_file: str = ""
    contributing_severities: Tuple[str, ...] = field(default_factory=tuple)
    risk_rating: str = ""
    tags: Tuple[str, ...] = field(default_factory=tuple)
