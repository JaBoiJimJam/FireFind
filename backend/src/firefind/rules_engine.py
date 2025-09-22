import ipaddress
from typing import Dict, Iterable, List
from .model import Rule, Finding


def parse_ports(port_str: str) -> List[int]:
    s = (port_str or "").lower().replace("tcp/", "").replace("udp/", "").strip()
    # treat "any" as "unspecified" (empty list), not all ports
    if s in ("", "any", "*"):
        return []
    parts = [p.strip() for p in s.split(",") if p.strip()]
    out: List[int] = []
    for p in parts:
        if "-" in p:
            a, b = p.split("-", 1)
            try:
                a_i, b_i = int(a), int(b)
                out.extend(range(a_i, b_i + 1))
            except ValueError:
                continue
        else:
            try:
                out.append(int(p))
            except ValueError:
                continue
    return sorted({x for x in out if 1 <= x <= 65535})


def is_any(value: str) -> bool:
    v = (value or "").strip().lower()
    return v in {"any", "all", "*", "0.0.0.0/0", "::/0"}


def is_all_ports(value: str) -> bool:
    v = (value or "").strip().lower()
    return v in {"all", "all_services", "all_tcp", "all_udp"}


def is_broad_cidr(value: str, max_prefixlen: int) -> bool:
    v = (value or "").strip()
    try:
        net = ipaddress.ip_network(v, strict=False)
        return net.prefixlen <= max_prefixlen
    except Exception:
        return False


def generate_risk_code(finding_type: str, severity: str, index: int) -> str:
    """Generate a risk code in the format FR-[SEVERITY]-[NUMBER]"""
    severity_short = {
        'High': 'HIGEN',
        'Medium': 'MEDGEN',
        'Low': 'LOWGEN'
    }.get(severity, 'GEN')
    
    return f"FR-{severity_short}-{index:03d}"


def action_allows_traffic(action: str) -> bool:
    v = (action or "").strip().lower()
    return v.startswith("allow") or v.startswith("accept")


def looks_internet_facing(value: str) -> bool:
    v = (value or "").strip().lower()
    if not v:
        return False
    candidates = {"wan", "internet", "virtual-wan-link", "public"}
    return any(token in v for token in candidates)


def run_checks(vendor: str, rules: Iterable[Rule], cfg: Dict) -> List[Finding]:
    admin_ports = set(cfg.get("admin_ports", [22, 23, 3389, 5900, 445, 389, 636]))
    broad_prefix = int(
        cfg.get("broad_cidr_prefix_max", 8)
    )  # e.g., flag /0..../8 as "broad"
    findings: List[Finding] = []
    risk_code_counter = 1

    for r in rules:
        # Allow-any
        if (
            action_allows_traffic(r.action)
            and (is_any(r.src) or is_broad_cidr(r.src, 0))
            and (is_any(r.dst) or is_broad_cidr(r.dst, 0))
        ):
            findings.append(
                Finding(
                    vendor,
                    r.rule_id,
                    r.src,
                    r.dst,
                    r.proto,
                    r.port,
                    r.action,
                    finding_type="allow_any",
                    severity="High",
                    rationale="Rule allows any-to-any access",
                )
            )

        # Admin ports exposure
        ports = set(parse_ports(r.port))
        if is_all_ports(r.port):
            ports.update(admin_ports)

        if ports and any(p in admin_ports for p in ports):
            risk_code = generate_risk_code('admin_port_exposed', 'High', risk_code_counter)
            risk_code_counter += 1

            findings.append(
                Finding(
                    vendor,
                    r.rule_id,
                    r.src,
                    r.dst,
                    r.proto,
                    r.port,
                    r.action,
                    finding_type="admin_port_exposed",
                    severity="High",
                    rationale=f"Rule permits administrative port(s): {sorted(admin_ports.intersection(ports))}",
                    risk_code=risk_code
                )
            )

        # Broad CIDR (src or dst)
        if is_broad_cidr(r.src, broad_prefix) or is_broad_cidr(r.dst, broad_prefix):
            findings.append(
                Finding(
                    vendor,
                    r.rule_id,
                    r.src,
                    r.dst,
                    r.proto,
                    r.port,
                    r.action,
                    finding_type="broad_cidr",
                    severity="Medium",
                    rationale=f"Network prefix is very broad (/{broad_prefix} or larger)",
                )
            )

        if action_allows_traffic(r.action) and is_all_ports(r.port):
            severity = "High" if looks_internet_facing(r.dst_interface) else "Medium"
            rationale_bits = [
                "Service column permits all ports",
            ]
            if looks_internet_facing(r.dst_interface):
                rationale_bits.append("destination interface appears internet-facing")
            if is_any(r.src) and is_any(r.dst):
                rationale_bits.append("rule is scoped to all sources and destinations")

            findings.append(
                Finding(
                    vendor,
                    r.rule_id,
                    r.src,
                    r.dst,
                    r.proto,
                    r.port,
                    r.action,
                    finding_type="all_ports_service",
                    severity=severity,
                    rationale="; ".join(rationale_bits),
                )
            )

    return findings


def check_admin_ports(rule: Rule, admin_ports: List[int]) -> List[int]:
    """Check if rule exposes administrative ports."""
    if not action_allows_traffic(rule.action):
        return []

    exposed = []
    port_str = rule.port.lower()

    # Parse different port formats
    if 'any' in port_str or is_all_ports(rule.port):
        return admin_ports  # If any port is allowed, all admin ports are exposed
    
    # Handle comma-separated ports
    for port_part in port_str.split(','):
        port_part = port_part.strip()
        
        # Handle TCP/UDP prefixes
        if '/' in port_part:
            port_part = port_part.split('/', 1)[1]
        
        # Handle port ranges
        if '-' in port_part:
            try:
                start, end = port_part.split('-')
                start_port = int(start)
                end_port = int(end)
                for admin_port in admin_ports:
                    if start_port <= admin_port <= end_port:
                        exposed.append(admin_port)
            except ValueError:
                continue
        else:
            # Single port
            try:
                port_num = int(port_part)
                if port_num in admin_ports:
                    exposed.append(port_num)
            except ValueError:
                continue
    
    return list(set(exposed))  # Remove duplicates
