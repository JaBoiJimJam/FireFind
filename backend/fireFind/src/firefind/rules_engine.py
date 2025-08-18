import ipaddress
from typing import Dict, Iterable, List, Tuple
from .model import Rule, Finding

def parse_ports(port_str: str) -> List[int]:
    s = (port_str or "").lower().replace("tcp/", "").replace("udp/", "").strip()
    if s in ("", "any", "*"):
        return list(range(1,65536))
    parts = [p.strip() for p in s.split(",") if p.strip()]
    out: List[int] = []
    for p in parts:
        if "-" in p:
            a,b = p.split("-",1)
            try:
                a_i, b_i = int(a), int(b)
                out.extend(list(range(a_i, b_i+1)))
            except ValueError:
                continue
        else:
            try:
                out.append(int(p))
            except ValueError:
                continue
    return sorted(set([x for x in out if 1 <= x <= 65535]))

def is_any(value: str) -> bool:
    v = (value or "").strip().lower()
    return v in {"any","*","0.0.0.0/0","::/0"}

def is_broad_cidr(value: str, max_prefixlen: int) -> bool:
    v = (value or "").strip()
    try:
        net = ipaddress.ip_network(v, strict=False)
        return net.prefixlen <= max_prefixlen
    except Exception:
        return False

def run_checks(vendor: str, rules: Iterable[Rule], cfg: Dict) -> List[Finding]:
    admin_ports = set(cfg.get("admin_ports", [22,23,3389,5900,445,389,636]))
    broad_prefix = int(cfg.get("broad_cidr_prefix_max", 8))  # e.g., flag /0..../8 as "broad"
    findings: List[Finding] = []

    for r in rules:
        # Allow-any
        if r.action.lower().startswith("allow") and (is_any(r.src) or is_broad_cidr(r.src, 0)) and (is_any(r.dst) or is_broad_cidr(r.dst, 0)):
            findings.append(Finding(vendor, r.rule_id, r.src, r.dst, r.proto, r.port, r.action,
                                    finding_type="allow_any", severity="High",
                                    rationale="Rule allows any-to-any access"))

        # Admin ports exposure
        ports = set(parse_ports(r.port))
        if any(p in admin_ports for p in ports):
            findings.append(Finding(vendor, r.rule_id, r.src, r.dst, r.proto, r.port, r.action,
                                    finding_type="admin_port_exposed", severity="High",
                                    rationale=f"Rule permits administrative port(s): {sorted(admin_ports.intersection(ports))}"))

        # Broad CIDR (src or dst)
        if is_broad_cidr(r.src, broad_prefix) or is_broad_cidr(r.dst, broad_prefix):
            findings.append(Finding(vendor, r.rule_id, r.src, r.dst, r.proto, r.port, r.action,
                                    finding_type="broad_cidr", severity="Medium",
                                    rationale=f"Network prefix is very broad (/{broad_prefix} or larger)"))

    return findings
