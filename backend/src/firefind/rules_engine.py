import ipaddress
import logging
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import (
    Dict,
    Iterable,
    List,
    MutableMapping,
    Optional,
    Set,
    Tuple,
    Union,
)

from .config import DEFAULT_RULES_CONFIG, RulesConfig, CIDRLimitPolicy
from .model import Rule, Finding


logger = logging.getLogger(__name__)


DEFAULT_CRITICAL_RISK_ADMIN_PORTS: Set[int] = set(
    DEFAULT_RULES_CONFIG.critical_risk_admin_ports
)
DEFAULT_HIGH_RISK_ADMIN_PORTS: Set[int] = set(
    DEFAULT_RULES_CONFIG.high_risk_admin_ports
)
DEFAULT_MEDIUM_RISK_ADMIN_PORTS: Set[int] = set(
    DEFAULT_RULES_CONFIG.medium_risk_admin_ports
)
DEFAULT_LOW_RISK_ADMIN_PORTS: Set[int] = set(
    DEFAULT_RULES_CONFIG.low_risk_admin_ports
)
DEFAULT_ADMIN_PORTS = sorted(DEFAULT_RULES_CONFIG.admin_ports)

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


@dataclass(frozen=True)
class ResolvedCIDRPolicy:
    """Policy ready for evaluation with parsed CIDR metadata."""

    name: str
    policy: CIDRLimitPolicy
    blocked: Tuple[Network, ...]
    exempt: Tuple[Network, ...]


def _parse_cidr_list(values: Iterable[str]) -> Tuple[Network, ...]:
    """Return parsed networks, ignoring entries that fail validation."""

    networks: list[Network] = []
    for value in values or []:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except Exception:  # pragma: no cover - defensive guard
            continue
    return tuple(networks)


def _resolve_cidr_policies(
    cfg: RulesConfig,
    *,
    vendor: str,
    analyzer: str = "broad_cidr",
) -> List[ResolvedCIDRPolicy]:
    """Expand CIDR limit sets into concrete policies with parsed metadata."""

    resolved: List[ResolvedCIDRPolicy] = []
    for name, limit_set in cfg.cidr_limits.items():
        policy = limit_set.resolve(analyzer=analyzer, vendor=vendor)
        resolved.append(
            ResolvedCIDRPolicy(
                name=name,
                policy=policy,
                blocked=_parse_cidr_list(policy.blocked),
                exempt=_parse_cidr_list(policy.exempt),
            )
        )
    return resolved


def _parse_network_value(value: str) -> Optional[Network]:
    """Attempt to normalise a rule value into a network instance."""

    if is_any(value):
        return ipaddress.ip_network("0.0.0.0/0")
    try:
        return ipaddress.ip_network(value, strict=False)
    except Exception:
        return None


def _format_policy_message(
    *,
    field: str,
    original_value: str,
    policy: ResolvedCIDRPolicy,
    detail: str,
) -> str:
    description = (policy.policy.description or "").strip()
    message = f"{field} {original_value} {detail} ({policy.name})"
    if description:
        message += f" – {description}"
    return message


def _evaluate_value_against_policy(
    *,
    value: str,
    field: str,
    policy: ResolvedCIDRPolicy,
    fallback_max_prefix: int,
) -> Optional[Tuple[str, str]]:
    network = _parse_network_value(value)
    if network is None:
        return None

    for exempt in policy.exempt:
        if network.subnet_of(exempt):
            return None

    for blocked in policy.blocked:
        if network.version != blocked.version:
            continue
        if network == blocked or blocked.subnet_of(network):
            detail = f"matches blocked CIDR {blocked.with_prefixlen}"
            return "High", _format_policy_message(
                field=field,
                original_value=value,
                policy=policy,
                detail=detail,
            )

    max_prefix = policy.policy.max_prefix
    if max_prefix is None:
        max_prefix = fallback_max_prefix
    if max_prefix is not None and network.prefixlen <= int(max_prefix):
        detail = f"is broader than /{int(max_prefix)} limit"
        return "Medium", _format_policy_message(
            field=field,
            original_value=value,
            policy=policy,
            detail=detail,
        )

    min_prefix = policy.policy.min_prefix
    if min_prefix is not None and network.prefixlen < int(min_prefix):
        detail = f"is broader than minimum /{int(min_prefix)} allowed"
        return "Medium", _format_policy_message(
            field=field,
            original_value=value,
            policy=policy,
            detail=detail,
        )

    return None


def _evaluate_policy_for_rule(
    policy: ResolvedCIDRPolicy,
    rule: Rule,
    fallback_max_prefix: int,
) -> Optional[Tuple[str, str]]:
    messages: List[str] = []
    severity_rank = 0
    for field, value in (("source", rule.src), ("destination", rule.dst)):
        result = _evaluate_value_against_policy(
            value=value,
            field=field,
            policy=policy,
            fallback_max_prefix=fallback_max_prefix,
        )
        if not result:
            continue
        severity, message = result
        messages.append(message)
        if severity == "High":
            severity_rank = max(severity_rank, 2)
        else:
            severity_rank = max(severity_rank, 1)

    if not messages:
        return None

    severity = "High" if severity_rank == 2 else "Medium"
    return severity, "; ".join(messages)


def _fallback_broad_messages(rule: Rule, max_prefix: int) -> List[str]:
    messages: List[str] = []
    for field, value in (("source", rule.src), ("destination", rule.dst)):
        if is_broad_cidr(value, max_prefix):
            messages.append(f"{field} {value} is broader than /{max_prefix}")
    return messages


ANALYZER_INVENTORY: Dict[str, Dict[str, List[str]]] = {
    "allow_any": {
        "risk_levels": [],
        "network_scope": [],
        "port_lists": [],
    },
    "admin_port_exposed": {
        "risk_levels": ["critical", "high", "medium", "low"],
        "network_scope": [],
        "port_lists": [
            "admin_ports",
            "critical_risk_admin_ports",
            "high_risk_admin_ports",
            "medium_risk_admin_ports",
            "low_risk_admin_ports",
        ],
    },
    "broad_cidr": {
        "risk_levels": [],
        "network_scope": ["broad_cidr_prefix_max", "cidr_limits"],
        "port_lists": [],
    },
    "all_ports_service": {
        "risk_levels": [],
        "network_scope": [],
        "port_lists": ["admin_ports"],
    },
}


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
        'Critical': 'CRGEN',
        'High': 'HIGEN',
        'Medium': 'MEDGEN',
        'Low': 'LOWGEN'
    }.get(severity, 'GEN')

    return f"FR-{severity_short}-{index:03d}"


def _deep_merge_dicts(
    base: MutableMapping[str, object], override: Mapping[str, object]
) -> MutableMapping[str, object]:
    """Recursively merge ``override`` into ``base`` returning a copy."""

    result: MutableMapping[str, object] = deepcopy(base)
    for key, value in (override or {}).items():
        if key in result and isinstance(result[key], Mapping) and isinstance(value, Mapping):
            result[key] = _deep_merge_dicts(
                result[key], value  # type: ignore[arg-type]
            )
        else:
            result[key] = deepcopy(value)
    return result


def _coerce_rules_config(cfg) -> RulesConfig:
    """Return a :class:`RulesConfig` instance for legacy callers."""

    if isinstance(cfg, RulesConfig):
        return cfg

    if isinstance(cfg, Mapping):
        merged = _deep_merge_dicts(
            DEFAULT_RULES_CONFIG.to_dict(), cfg  # type: ignore[arg-type]
        )
        return RulesConfig.from_dict(merged)

    return DEFAULT_RULES_CONFIG


def _log_active_thresholds(cfg: RulesConfig, *, vendor: str) -> None:
    """Emit structured logging describing the analyzer thresholds in use."""

    risk_levels_payload = {
        name: {
            "label": definition.label,
            "severity": definition.severity.value,
            "thresholds": definition.thresholds.to_dict(),
        }
        for name, definition in sorted(cfg.risk_levels.items())
    }

    analyzer_thresholds = {
        "admin_port_exposed": {
            "admin_ports": sorted(cfg.admin_ports) or sorted(DEFAULT_ADMIN_PORTS),
            "critical_ports": sorted(cfg.critical_risk_admin_ports)
            or sorted(DEFAULT_CRITICAL_RISK_ADMIN_PORTS),
            "high_ports": sorted(cfg.high_risk_admin_ports)
            or sorted(DEFAULT_HIGH_RISK_ADMIN_PORTS),
            "medium_ports": sorted(cfg.medium_risk_admin_ports)
            or sorted(DEFAULT_MEDIUM_RISK_ADMIN_PORTS),
            "low_ports": sorted(cfg.low_risk_admin_ports)
            or sorted(DEFAULT_LOW_RISK_ADMIN_PORTS),
        },
        "broad_cidr": {
            "broad_cidr_prefix_max": int(cfg.broad_cidr_prefix_max),
        },
    }

    logger.info(
        "Analyzer thresholds resolved",
        extra={
            "vendor": vendor,
            "analyzers": analyzer_thresholds,
            "risk_levels": risk_levels_payload,
            "inventory": ANALYZER_INVENTORY,
        },
    )


def classify_admin_port_severity(
    exposed_ports: Set[int],
    critical_risk_ports: Set[int],
    high_risk_ports: Set[int],
    medium_risk_ports: Set[int],
) -> str:
    """Return a qualitative severity based on the exposed admin ports."""

    if not exposed_ports:
        return "Low"

    if exposed_ports & critical_risk_ports:
        return "Critical"

    if exposed_ports & high_risk_ports:
        return "High"

    if exposed_ports & medium_risk_ports:
        return "Medium"

    if len(exposed_ports) >= 8:
        return "Critical"

    if len(exposed_ports) >= 4:
        return "High"

    if len(exposed_ports) >= 2:
        return "Medium"

    return "Low"


def action_allows_traffic(action: str) -> bool:
    v = (action or "").strip().lower()
    return v.startswith("allow") or v.startswith("accept")


def looks_internet_facing(value: str) -> bool:
    v = (value or "").strip().lower()
    if not v:
        return False
    candidates = {"wan", "internet", "virtual-wan-link", "public"}
    return any(token in v for token in candidates)


def run_checks(vendor: str, rules: Iterable[Rule], cfg) -> List[Finding]:
    rules_cfg = _coerce_rules_config(cfg)

    critical_risk_admin_ports = set(rules_cfg.critical_risk_admin_ports)
    if not critical_risk_admin_ports:
        critical_risk_admin_ports = set(DEFAULT_CRITICAL_RISK_ADMIN_PORTS)

    high_risk_admin_ports = set(rules_cfg.high_risk_admin_ports)
    if not high_risk_admin_ports:
        high_risk_admin_ports = set(DEFAULT_HIGH_RISK_ADMIN_PORTS)

    medium_risk_admin_ports = set(rules_cfg.medium_risk_admin_ports)
    if not medium_risk_admin_ports:
        medium_risk_admin_ports = set(DEFAULT_MEDIUM_RISK_ADMIN_PORTS)

    low_risk_admin_ports = set(rules_cfg.low_risk_admin_ports)
    if not low_risk_admin_ports:
        low_risk_admin_ports = set(DEFAULT_LOW_RISK_ADMIN_PORTS)

    admin_ports = set(rules_cfg.admin_ports)
    if not admin_ports:
        admin_ports = (
            set(DEFAULT_ADMIN_PORTS)
            | critical_risk_admin_ports
            | high_risk_admin_ports
            | medium_risk_admin_ports
            | low_risk_admin_ports
        )
    else:
        admin_ports.update(critical_risk_admin_ports)
        admin_ports.update(high_risk_admin_ports)
        admin_ports.update(medium_risk_admin_ports)
        admin_ports.update(low_risk_admin_ports)

    broad_prefix = int(rules_cfg.broad_cidr_prefix_max or 8)
    if broad_prefix <= 0:
        broad_prefix = 8
    cidr_policies = _resolve_cidr_policies(rules_cfg, vendor=vendor)
    use_fallback_cidr = not cidr_policies

    _log_active_thresholds(rules_cfg, vendor=vendor)

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
                    source_file=r.source_file,
                )
            )

        # Admin ports exposure
        ports = set(parse_ports(r.port))
        if is_all_ports(r.port):
            ports.update(admin_ports)

        exposed_admin_ports = admin_ports.intersection(ports)
        if exposed_admin_ports:
            severity = classify_admin_port_severity(
                exposed_admin_ports,
                critical_risk_admin_ports,
                high_risk_admin_ports,
                medium_risk_admin_ports,
            )
            risk_code = generate_risk_code('admin_port_exposed', severity, risk_code_counter)
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
                    severity=severity,
                    rationale=f"Rule permits administrative port(s): {sorted(exposed_admin_ports)}",
                    risk_code=risk_code,
                    source_file=r.source_file,
                )
            )

        # Broad CIDR (src or dst)
        cidr_messages: List[str] = []
        cidr_severity_rank = 0
        for policy in cidr_policies:
            result = _evaluate_policy_for_rule(
                policy,
                r,
                broad_prefix,
            )
            if not result:
                continue
            severity, message = result
            cidr_messages.append(message)
            if severity == "High":
                cidr_severity_rank = max(cidr_severity_rank, 2)
            else:
                cidr_severity_rank = max(cidr_severity_rank, 1)

        if not cidr_messages and use_fallback_cidr:
            fallback_messages = _fallback_broad_messages(r, broad_prefix)
            if fallback_messages:
                cidr_messages.extend(fallback_messages)
                cidr_severity_rank = max(cidr_severity_rank, 1)

        if cidr_messages:
            cidr_severity = "High" if cidr_severity_rank == 2 else "Medium"
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
                    severity=cidr_severity,
                    rationale="; ".join(cidr_messages),
                    source_file=r.source_file,
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
                    source_file=r.source_file,
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
