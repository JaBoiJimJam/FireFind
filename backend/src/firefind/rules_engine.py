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
from .utils import merge_tags, normalize_risk_rating


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

_SEVERITY_LADDER = ["Critical", "High", "Medium", "Cautionary", "Low", "Info"]
_SEVERITY_INDEX = {label: idx for idx, label in enumerate(_SEVERITY_LADDER)}
_LOWEST_ADMIN_SEVERITY = _SEVERITY_INDEX["Low"]


def _canonical_severity_label(value: str) -> str:
    """Normalise a severity string to the engine's display vocabulary."""

    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "cautionary": "Cautionary",
        "low": "Low",
        "info": "Info",
        "informational": "Info",
    }
    lowered = (value or "").strip().lower()
    if not lowered:
        return "Info"
    return mapping.get(lowered, value.title() or "Info")


def override_with_risk_rating(rule: Rule, severity: str) -> str:
    """Prefer a rule's explicit risk rating when present."""
    
    rating_raw = getattr(rule, "risk_rating", "")
    if not rating_raw:
        return severity

    rating = normalize_risk_rating(rating_raw)
    if not rating:
        return severity

    return _canonical_severity_label(rating)


_WEB_PORTS = {80, 443}
_SSH_PORTS = {22}
_RDP_PORTS = {3389}

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
        "risk_levels": ["critical", "high", "medium", "cautionary", "low"],
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
    "rule_overlap": {
        "risk_levels": [],
        "network_scope": ["rule_overlap"],
        "port_lists": [],
    },
    "unused_rule": {
        "risk_levels": [],
        "network_scope": [],
        "port_lists": [],
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


def _normalize_protocol(proto: str) -> str:
    return (proto or "").strip().lower()


def _protocol_covers(covering: str, target: str) -> bool:
    covering_norm = _normalize_protocol(covering)
    target_norm = _normalize_protocol(target)
    if covering_norm in {"", "any", "*", "all"}:
        return True
    if target_norm in {"", "any", "*", "all"}:
        return covering_norm in {"", "any", "*", "all"}
    return covering_norm == target_norm


def _normalize_port_text(value: str) -> str:
    return (value or "").strip().lower()


def _ports_cover(covering: str, target: str) -> bool:
    covering_norm = _normalize_port_text(covering)
    target_norm = _normalize_port_text(target)

    if is_all_ports(covering) or covering_norm in {"", "any", "*"}:
        return True

    if is_all_ports(target) or target_norm in {"", "any", "*"}:
        return is_all_ports(covering) or covering_norm in {"", "any", "*"}

    covering_ports = set(parse_ports(covering))
    target_ports = set(parse_ports(target))

    if covering_ports and target_ports:
        return target_ports.issubset(covering_ports)

    if covering_ports or target_ports:
        return False

    return covering_norm == target_norm


def _network_covers(covering: str, target: str) -> bool:
    if is_any(covering):
        return True
    if is_any(target):
        return is_any(covering)

    covering_net = _parse_network_value(covering)
    target_net = _parse_network_value(target)

    if covering_net and target_net and covering_net.version == target_net.version:
        return target_net.subnet_of(covering_net)

    covering_norm = (covering or "").strip().lower()
    target_norm = (target or "").strip().lower()
    return covering_norm == target_norm


def _describe_network_overlap(covering: str, target: str, field: str) -> Optional[str]:
    covering_norm = (covering or "").strip().lower()
    target_norm = (target or "").strip().lower()
    if covering_norm == target_norm:
        return None
    return f"{field} {target or 'any'} is covered by {covering or 'any'}"


def _describe_protocol_overlap(covering: str, target: str) -> Optional[str]:
    covering_norm = _normalize_protocol(covering)
    target_norm = _normalize_protocol(target)
    if covering_norm == target_norm or target_norm in {"", "any", "*", "all"}:
        return None
    return f"protocol {target or 'any'} is treated as {covering or 'any'}"


def _describe_port_overlap(covering: str, target: str) -> Optional[str]:
    covering_norm = _normalize_port_text(covering)
    target_norm = _normalize_port_text(target)
    if covering_norm == target_norm or target_norm in {"", "any", "*"}:
        return None
    if is_all_ports(covering) and not is_all_ports(target):
        return f"ports {target or 'any'} are included in all-ports rule"
    covering_ports = set(parse_ports(covering))
    target_ports = set(parse_ports(target))
    if covering_ports and target_ports and covering_ports != target_ports:
        return f"ports {sorted(target_ports)} are covered by {sorted(covering_ports)}"
    return None


def _rule_scope_covers(covering: Rule, target: Rule) -> Tuple[bool, List[str]]:
    notes: List[str] = []

    if not _network_covers(covering.src, target.src):
        return False, []
    network_note = _describe_network_overlap(covering.src, target.src, "source")
    if network_note:
        notes.append(network_note)

    if not _network_covers(covering.dst, target.dst):
        return False, []
    destination_note = _describe_network_overlap(covering.dst, target.dst, "destination")
    if destination_note:
        notes.append(destination_note)

    if not _protocol_covers(covering.proto, target.proto):
        return False, []
    protocol_note = _describe_protocol_overlap(covering.proto, target.proto)
    if protocol_note:
        notes.append(protocol_note)

    if not _ports_cover(covering.port, target.port):
        return False, []
    port_note = _describe_port_overlap(covering.port, target.port)
    if port_note:
        notes.append(port_note)

    return True, notes


def _normalize_action(action: str) -> str:
    value = (action or "").strip().lower()
    if not value:
        return "other"
    if action_allows_traffic(action):
        return "allow"
    if value.startswith(("deny", "block", "drop", "reject")):
        return "deny"
    return value


def _actions_conflict(first: str, second: str) -> bool:
    first_norm = _normalize_action(first)
    second_norm = _normalize_action(second)
    if first_norm == second_norm:
        return False
    allowish = {"allow"}
    denyish = {"deny"}
    return (first_norm in allowish and second_norm in denyish) or (
        first_norm in denyish and second_norm in allowish
    )


def _resolve_overlap_severity(value: object, fallback: str) -> str:
    raw = getattr(value, "value", value)
    text = str(raw or fallback).strip()
    if not text:
        return fallback
    return text[0].upper() + text[1:]


def _analyze_rule_overlap(rules: List[Rule], cfg: RulesConfig, vendor: str) -> List[Finding]:
    settings = getattr(cfg, "rule_overlap", None)
    if settings is None:
        return []

    max_rules = int(getattr(settings, "max_rules_evaluated", 0) or 0)
    max_pairs = int(getattr(settings, "max_rule_pairs", 0) or 0)

    if max_rules > 0:
        evaluated_rules = rules[:max_rules]
    else:
        evaluated_rules = list(rules)

    findings: List[Finding] = []
    comparisons = 0
    limit_reached = False

    for index, candidate in enumerate(evaluated_rules):
        for covering in evaluated_rules[:index]:
            comparisons += 1
            if max_pairs > 0 and comparisons > max_pairs:
                limit_reached = True
                break

            covers, notes = _rule_scope_covers(covering, candidate)
            if not covers:
                continue

            if _actions_conflict(covering.action, candidate.action):
                severity = _resolve_overlap_severity(settings.shadowed_severity, "Medium")
                severity = override_with_risk_rating(candidate, severity)
                rationale_bits = [
                    (
                        f"Rule {candidate.rule_id} is shadowed by earlier rule "
                        f"{covering.rule_id} ({covering.action} vs {candidate.action})."
                    )
                ]
                if notes:
                    rationale_bits.append("Overlap details: " + "; ".join(notes))
                findings.append(
                    Finding(
                        vendor,
                        candidate.rule_id,
                        candidate.src,
                        candidate.dst,
                        candidate.proto,
                        candidate.port,
                        candidate.action,
                        finding_type="shadowed_rule",
                        severity=severity,
                        rationale=" ".join(rationale_bits),
                        source_file=candidate.source_file,
                        risk_rating=candidate.risk_rating,
                        tags=merge_tags(candidate.tags, ["rule-overlap", "shadowed"]),
                    )
                )
                break

            covering_action = _normalize_action(covering.action)
            candidate_action = _normalize_action(candidate.action)
            if covering_action != candidate_action:
                continue

            severity = _resolve_overlap_severity(settings.redundant_severity, "Low")
            severity = override_with_risk_rating(candidate, severity)
            rationale_bits = [
                f"Rule {candidate.rule_id} is redundant because earlier rule {covering.rule_id} already applies."
            ]
            if notes:
                rationale_bits.append("Overlap details: " + "; ".join(notes))
            findings.append(
                Finding(
                    vendor,
                    candidate.rule_id,
                    candidate.src,
                    candidate.dst,
                    candidate.proto,
                    candidate.port,
                    candidate.action,
                    finding_type="redundant_rule",
                    severity=severity,
                    rationale=" ".join(rationale_bits),
                    source_file=candidate.source_file,
                    risk_rating=candidate.risk_rating,
                    tags=merge_tags(candidate.tags, ["rule-overlap", "redundant"]),
                )
            )
            break

        if limit_reached:
            break

    return findings


def generate_risk_code(finding_type: str, severity: str, index: int) -> str:
    """Generate a risk code in the format FR-[SEVERITY]-[NUMBER]"""
    severity_short = {
        'Critical': 'CRGEN',
        'High': 'HIGEN',
        'Medium': 'MEDGEN',
        'Cautionary': 'CAUGEN',
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
        "rule_overlap": {
            "max_rules_evaluated": int(cfg.rule_overlap.max_rules_evaluated),
            "max_rule_pairs": int(cfg.rule_overlap.max_rule_pairs),
            "redundant_severity": cfg.rule_overlap.redundant_severity.value,
            "shadowed_severity": cfg.rule_overlap.shadowed_severity.value,
        },
        "unused_rule": {
            "hit_count_threshold": int(cfg.unused_rule.hit_count_threshold),
            "include_disabled": bool(cfg.unused_rule.include_disabled),
            "hit_count_severity": cfg.unused_rule.hit_count_severity.value,
            "disabled_severity": cfg.unused_rule.disabled_severity.value,
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

    return "Cautionary"


def action_allows_traffic(action: str) -> bool:
    v = (action or "").strip().lower()
    return v.startswith("allow") or v.startswith("accept")


def looks_internet_facing(value: str) -> bool:
    v = (value or "").strip().lower()
    if not v:
        return False
    candidates = {"wan", "internet", "virtual-wan-link", "public"}
    return any(token in v for token in candidates)


def _downgrade_severity(severity: str, steps: int) -> str:
    if steps <= 0:
        return severity
    start = _SEVERITY_INDEX.get(severity, 0)
    target = min(start + steps, _LOWEST_ADMIN_SEVERITY)
    return _SEVERITY_LADDER[target]


def _is_scope_broad(value: str) -> bool:
    text = (value or "").strip()
    if not text:
        return True

    lowered = text.lower()
    if lowered in {"*", "any", "all"}:
        return True

    keyword_matches = [
        "0.0.0.0/0",
        "::/0",
        "internet",
        "wan",
        "dmz",
        "external",
        "outside",
        "public",
        "anywhere",
        "untrust",
    ]
    if any(keyword in lowered for keyword in keyword_matches):
        return True

    try:
        network = ipaddress.ip_network(text, strict=False)
    except Exception:
        return False

    if network.version == 4 and network.prefixlen <= 16:
        return True
    if network.version == 6 and network.prefixlen <= 32:
        return True
    return False


def _port_profile(ports: Set[int]) -> str:
    if not ports:
        return "none"
    if ports <= _WEB_PORTS:
        return "web"
    if ports <= _SSH_PORTS:
        return "ssh"
    if ports <= _RDP_PORTS:
        return "rdp"
    return "mixed"


def _max_admin_port_downgrade(
    exposed_ports: Set[int],
    profile: str,
    critical_ports: Set[int],
    high_ports: Set[int],
    medium_ports: Set[int],
) -> int:
    """Return the maximum downgrade allowed based on the ports in scope."""

    if exposed_ports & critical_ports:
        # Allow legacy SSH-specific tuning to continue downgrading when
        # organisations categorise SSH as a critical service, but retain a
        # strict floor for other critical protocols (e.g. SMB, NetBIOS).
        return 4 if profile == "ssh" else 0

    if exposed_ports & high_ports:
        if profile == "ssh":
            return 4
        if profile == "rdp":
            return 2
        return 2

    if exposed_ports & medium_ports:
        return 3

    # Low-risk and informational ports can still fall to "Low" severity when
    # scope justifies it.
    return 4


def _adjust_admin_port_severity(
    rule: Rule,
    severity: str,
    exposed_ports: Set[int],
    *,
    critical_ports: Set[int],
    high_ports: Set[int],
    medium_ports: Set[int],
) -> str:
    service_all = is_all_ports(rule.port)
    src_any = is_any(rule.src)
    dst_any = is_any(rule.dst)
    src_broad = _is_scope_broad(rule.src)
    dst_broad = _is_scope_broad(rule.dst)
    profile = _port_profile(exposed_ports)

    downgrade = 0

    if service_all:
        if src_any or dst_any:
            downgrade = max(downgrade, 2)
        elif not src_broad and not dst_broad:
            downgrade = max(downgrade, 4)
        else:
            downgrade = max(downgrade, 1)
    else:
        if profile == "web":
            downgrade = max(downgrade, 4)
        if not src_broad and not dst_broad:
            if profile in {"ssh", "web"}:
                downgrade = max(downgrade, 4)
            elif profile == "rdp":
                downgrade = max(downgrade, 2)
            else:
                downgrade = max(downgrade, 2)

    if not service_all and (src_broad ^ dst_broad) and not dst_any:
        downgrade = max(downgrade, 1)

    if downgrade:
        allowed = _max_admin_port_downgrade(
            exposed_ports, profile, critical_ports, high_ports, medium_ports
        )
        downgrade = min(downgrade, allowed)

    if downgrade:
        if profile == "web":
            start = _SEVERITY_INDEX.get(severity, 0)
            web_floor = _SEVERITY_INDEX["Cautionary"]
            target = min(start + downgrade, web_floor)
            target = max(target, start)
            return _SEVERITY_LADDER[target]
        start = _SEVERITY_INDEX.get(severity, 0)
        target = min(start + downgrade, _LOWEST_ADMIN_SEVERITY)
        return _SEVERITY_LADDER[target]
    return severity


def run_checks(vendor: str, rules: Iterable[Rule], cfg) -> List[Finding]:
    rules_cfg = _coerce_rules_config(cfg)
    rules_list = list(rules)

    unused_cfg = rules_cfg.unused_rule
    hit_threshold = max(0, int(unused_cfg.hit_count_threshold))
    include_disabled = bool(unused_cfg.include_disabled)
    hit_severity = _canonical_severity_label(unused_cfg.hit_count_severity.value)
    disabled_severity = _canonical_severity_label(unused_cfg.disabled_severity.value)

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

    for r in rules_list:
        # Allow-any
        if (
            action_allows_traffic(r.action)
            and (is_any(r.src) or is_broad_cidr(r.src, 0))
            and (is_any(r.dst) or is_broad_cidr(r.dst, 0))
        ):
            severity = override_with_risk_rating(r, "High")
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
                    severity=severity,
                    rationale="Rule allows any-to-any access",
                    source_file=r.source_file,
                    risk_rating=r.risk_rating,
                    tags=merge_tags(r.tags, ["any-to-any", "excessive-access"]),
                )
            )

        # Unused/disabled rule detection
        unused_reasons: List[str] = []
        unused_tags = ["unused-rule"]
        unused_severity = ""
        severity_rank = len(_SEVERITY_LADDER)

        if r.hit_count is not None and r.hit_count <= hit_threshold:
            threshold_clause = (
                f" (threshold ≤ {hit_threshold})" if hit_threshold else ""
            )
            volume_clause = (
                f" with {r.byte_count} byte(s) logged" if r.byte_count is not None else ""
            )
            unused_reasons.append(
                f"Rule has {r.hit_count} recorded hit(s){volume_clause}{threshold_clause}"
            )
            unused_tags.append("zero-hit")
            candidate_rank = _SEVERITY_INDEX.get(hit_severity, len(_SEVERITY_LADDER))
            if candidate_rank < severity_rank:
                severity_rank = candidate_rank
                unused_severity = hit_severity

        if include_disabled and r.enabled is not None and not r.enabled:
            unused_reasons.append("Rule is disabled in the firewall configuration")
            unused_tags.append("disabled-rule")
            candidate_rank = _SEVERITY_INDEX.get(disabled_severity, len(_SEVERITY_LADDER))
            if candidate_rank < severity_rank:
                severity_rank = candidate_rank
                unused_severity = disabled_severity

        if unused_reasons:
            if not unused_severity:
                unused_severity = "Low"
            unused_severity = override_with_risk_rating(r, unused_severity)
            risk_code = generate_risk_code("unused_rule", unused_severity, risk_code_counter)
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
                    finding_type="unused_rule",
                    severity=unused_severity,
                    rationale="; ".join(unused_reasons),
                    risk_code=risk_code,
                    source_file=r.source_file,
                    risk_rating=r.risk_rating,
                    tags=merge_tags(r.tags, unused_tags),
                    hit_count=r.hit_count,
                    byte_count=r.byte_count,
                    rule_enabled=r.enabled,
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
            severity = _adjust_admin_port_severity(
                r,
                severity,
                exposed_admin_ports,
                critical_ports=critical_risk_admin_ports,
                high_ports=high_risk_admin_ports,
                medium_ports=medium_risk_admin_ports,
            )
            severity = override_with_risk_rating(r, severity)
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
                    risk_rating=r.risk_rating,
                    tags=merge_tags(r.tags, ["admin-surface", "admin-port"]),
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
            cidr_severity = override_with_risk_rating(r, cidr_severity)
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
                    risk_rating=r.risk_rating,
                    tags=merge_tags(r.tags, ["broad-scope", "cidr-policy"]),
                )
            )

        if action_allows_traffic(r.action) and is_all_ports(r.port):
            severity = "High" if looks_internet_facing(r.dst_interface) else "Medium"
            severity = override_with_risk_rating(r, severity)
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
                    risk_rating=r.risk_rating,
                    tags=merge_tags(r.tags, ["all-ports", "service-any"]),
                )
            )

    findings.extend(_analyze_rule_overlap(rules_list, rules_cfg, vendor))

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
