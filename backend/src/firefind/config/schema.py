"""Configuration schema objects for FireFind rule processing."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import re
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence, Tuple


_TAG_SANITIZE_RE = re.compile(r"[^a-z0-9]+")


def _normalise_tag_label(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return _TAG_SANITIZE_RE.sub("-", text.lower()).strip("-")


class Severity(str, Enum):
    """Enumeration of supported qualitative severities."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    CAUTIONARY = "cautionary"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class Rationale:
    """Additional metadata describing the rationale for a configuration element."""

    summary: str = ""
    details: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "details": self.details,
            "references": list(self.references),
        }


@dataclass
class NumericThresholds:
    """Numeric thresholds used to classify risk levels."""

    min_score: Optional[float] = None
    max_score: Optional[float] = None
    min_findings: Optional[int] = None
    max_findings: Optional[int] = None

    def __post_init__(self) -> None:
        if self.min_score is not None and self.max_score is not None:
            if self.min_score > self.max_score:
                raise ValueError("min_score cannot be greater than max_score")
        if self.min_findings is not None and self.max_findings is not None:
            if self.min_findings > self.max_findings:
                raise ValueError("min_findings cannot be greater than max_findings")
        for value_name, value in {
            "min_findings": self.min_findings,
            "max_findings": self.max_findings,
        }.items():
            if value is not None and value < 0:
                raise ValueError(f"{value_name} cannot be negative")

    def to_dict(self) -> dict:
        return {
            "min_score": self.min_score,
            "max_score": self.max_score,
            "min_findings": self.min_findings,
            "max_findings": self.max_findings,
        }


@dataclass
class RiskLevelDefinition:
    """Definition of a risk level, including rationale metadata."""

    name: str
    label: str
    severity: Severity
    thresholds: NumericThresholds = field(default_factory=NumericThresholds)
    rationale: Rationale = field(default_factory=Rationale)

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "severity": self.severity.value,
            "thresholds": self.thresholds.to_dict(),
            "rationale": self.rationale.to_dict(),
        }


@dataclass
class CIDRLimitPolicy:
    """CIDR limit configuration for a single scope."""

    max_prefix: Optional[int] = None
    min_prefix: Optional[int] = None
    blocked: list[str] = field(default_factory=list)
    exempt: list[str] = field(default_factory=list)
    description: str = ""

    def __post_init__(self) -> None:
        for attr_name, prefix in {"max_prefix": self.max_prefix, "min_prefix": self.min_prefix}.items():
            if prefix is not None and not (0 <= int(prefix) <= 128):
                raise ValueError(f"{attr_name} must be between 0 and 128")
        for name, values in {"blocked": self.blocked, "exempt": self.exempt}.items():
            for value in values:
                try:
                    ipaddress.ip_network(value, strict=False)
                except Exception as exc:  # pragma: no cover - defensive programming
                    raise ValueError(f"Invalid CIDR '{value}' in {name}") from exc

    def to_dict(self) -> dict:
        return {
            "max_prefix": self.max_prefix,
            "min_prefix": self.min_prefix,
            "blocked": list(self.blocked),
            "exempt": list(self.exempt),
            "description": self.description,
        }


@dataclass
class CIDRLimitSet:
    """CIDR limits with analyzer/vendor/direction overrides."""

    name: str
    default: CIDRLimitPolicy = field(default_factory=CIDRLimitPolicy)
    analyzers: Dict[str, CIDRLimitPolicy] = field(default_factory=dict)
    vendors: Dict[str, CIDRLimitPolicy] = field(default_factory=dict)
    directions: Dict[str, CIDRLimitPolicy] = field(default_factory=dict)
    vendor_direction_overrides: Dict[str, Dict[str, CIDRLimitPolicy]] = field(default_factory=dict)

    def resolve(
        self,
        analyzer: Optional[str] = None,
        vendor: Optional[str] = None,
        direction: Optional[str] = None,
    ) -> CIDRLimitPolicy:
        """Resolve the most specific CIDR limit policy for the given context."""

        # Vendor + direction override wins first
        if vendor and direction:
            vendor_key = vendor.lower()
            direction_key = direction.lower()
            vendor_overrides = self.vendor_direction_overrides.get(vendor_key)
            if vendor_overrides:
                specific = vendor_overrides.get(direction_key)
                if specific:
                    return specific

        # Analyzer-specific override
        if analyzer:
            analyzer_policy = self.analyzers.get(analyzer.lower())
            if analyzer_policy:
                return analyzer_policy

        # Vendor override
        if vendor:
            vendor_policy = self.vendors.get(vendor.lower())
            if vendor_policy:
                return vendor_policy

        # Direction override
        if direction:
            direction_policy = self.directions.get(direction.lower())
            if direction_policy:
                return direction_policy

        return self.default

    def to_dict(self) -> dict:
        def _serialize(mapping: Mapping[str, CIDRLimitPolicy]) -> dict:
            return {key: policy.to_dict() for key, policy in mapping.items()}

        return {
            "default": self.default.to_dict(),
            "analyzers": _serialize(self.analyzers),
            "vendors": _serialize(self.vendors),
            "directions": _serialize(self.directions),
            "vendor_direction_overrides": {
                vendor: {direction: policy.to_dict() for direction, policy in overrides.items()}
                for vendor, overrides in self.vendor_direction_overrides.items()
            },
        }


@dataclass(order=True, frozen=True)
class PortRange:
    """Represents a port range inclusive of start/end."""

    start: int
    end: int

    def __post_init__(self) -> None:
        if not (1 <= int(self.start) <= 65535) or not (1 <= int(self.end) <= 65535):
            raise ValueError("Ports must be between 1 and 65535")
        if int(self.start) > int(self.end):
            raise ValueError("Port range start must not exceed end")

    def contains(self, value: int) -> bool:
        return int(self.start) <= value <= int(self.end)

    def to_tuple(self) -> tuple[int, int]:
        return (int(self.start), int(self.end))


@dataclass
class PortGroup:
    """Grouping of ports/ranges that can be re-used across analyzers."""

    name: str
    description: str = ""
    protocol: str = "any"
    ranges: list[PortRange] = field(default_factory=list)

    def __post_init__(self) -> None:
        normalized_proto = (self.protocol or "any").lower()
        if normalized_proto not in {"any", "tcp", "udp"}:
            raise ValueError(f"Unsupported protocol '{self.protocol}' in port group '{self.name}'")
        self.protocol = normalized_proto
        self._validate_no_overlaps()

    def _validate_no_overlaps(self) -> None:
        sorted_ranges = sorted(self.ranges)
        for i in range(1, len(sorted_ranges)):
            previous = sorted_ranges[i - 1]
            current = sorted_ranges[i]
            if previous.end >= current.start:
                raise ValueError(
                    f"Port ranges {previous.to_tuple()} and {current.to_tuple()} overlap in group '{self.name}'"
                )

    def to_dict(self) -> dict:
        return {
            "description": self.description,
            "protocol": self.protocol,
            "ranges": [range_.to_tuple() for range_ in self.ranges],
        }


@dataclass
class PortGroupCollection:
    """Collection of reusable port groups."""

    groups: Dict[str, PortGroup] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {name: group.to_dict() for name, group in self.groups.items()}


class ConditionComparator(str, Enum):
    """Supported comparators for rule conditions."""

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    GREATER_THAN = "greater_than"
    GREATER_OR_EQUAL = "greater_or_equal"
    LESS_THAN = "less_than"
    LESS_OR_EQUAL = "less_or_equal"
    MATCHES_PORT_GROUP = "matches_port_group"
    MATCHES_ADMIN_PORT = "matches_admin_port"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


@dataclass
class RuleConditionThreshold:
    """Numeric thresholds that constrain a rule condition."""

    min_value: Optional[float] = None
    max_value: Optional[float] = None
    inclusive: bool = True

    def __post_init__(self) -> None:
        if self.min_value is not None and self.max_value is not None:
            if float(self.min_value) > float(self.max_value):
                raise ValueError("Threshold min_value cannot exceed max_value")

    def to_dict(self) -> dict:
        return {
            "min_value": self.min_value,
            "max_value": self.max_value,
            "inclusive": self.inclusive,
        }


@dataclass
class RuleCondition:
    """Atomic comparison executed against an input rule field."""

    field: str
    comparator: ConditionComparator = ConditionComparator.EQUALS
    value: Optional[Any] = None
    values: Sequence[Any] = field(default_factory=tuple)
    threshold: Optional[RuleConditionThreshold] = None

    def __post_init__(self) -> None:
        if not str(self.field or "").strip():
            raise ValueError("Condition field must be provided")
        if isinstance(self.comparator, str):
            try:
                self.comparator = ConditionComparator(self.comparator)
            except ValueError as exc:
                raise ValueError(f"Unsupported comparator '{self.comparator}'") from exc
        if (
            self.comparator
            not in {ConditionComparator.EXISTS, ConditionComparator.NOT_EXISTS}
            and self.value is None
            and not self.values
            and self.threshold is None
        ):
            raise ValueError("Condition must define a value, values, or threshold")
        if self.values and not isinstance(self.values, (list, tuple)):
            raise TypeError("Condition values must be a list or tuple")

    def to_dict(self) -> dict:
        payload: dict = {
            "field": self.field,
            "comparator": self.comparator.value,
        }
        if self.value is not None:
            payload["value"] = self.value
        if self.values:
            payload["values"] = list(self.values)
        if self.threshold is not None:
            payload["threshold"] = self.threshold.to_dict()
        return payload


@dataclass
class ConditionGroup:
    """Recursive grouping of rule conditions using AND/OR semantics."""

    logic: str = "all"
    conditions: list[RuleCondition] = field(default_factory=list)
    groups: list["ConditionGroup"] = field(default_factory=list)

    def __post_init__(self) -> None:
        normalized_logic = (self.logic or "all").lower()
        if normalized_logic not in {"all", "any"}:
            raise ValueError("ConditionGroup.logic must be 'all' or 'any'")
        self.logic = normalized_logic

    def to_dict(self) -> dict:
        return {
            "logic": self.logic,
            "conditions": [condition.to_dict() for condition in self.conditions],
            "groups": [group.to_dict() for group in self.groups],
        }


@dataclass
class AnalyzerPortConfiguration:
    """Administrative port configuration for a specific analyzer."""

    baseline: set[int] = field(default_factory=set)
    per_risk_overrides: Dict[str, set[int]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "baseline": sorted(self.baseline),
            "per_risk_overrides": {
                risk: sorted(values) for risk, values in self.per_risk_overrides.items()
            },
        }


@dataclass
class AnalyzerMetadata:
    """Analyzer-specific settings that enrich a rule definition."""

    name: str
    enabled: bool = True
    notes: str = ""
    severity_overrides: Dict[str, Severity] = field(default_factory=dict)
    admin_ports: AnalyzerPortConfiguration = field(default_factory=AnalyzerPortConfiguration)

    def __post_init__(self) -> None:
        normalised: Dict[str, Severity] = {}
        for key, value in (self.severity_overrides or {}).items():
            severity_value = value
            if isinstance(severity_value, str):
                try:
                    severity_value = Severity(severity_value.lower())
                except ValueError as exc:
                    raise ValueError(f"Unsupported severity override '{value}'") from exc
            normalised[key.lower()] = severity_value
        self.severity_overrides = normalised

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "notes": self.notes,
            "severity_overrides": {
                key: value.value for key, value in self.severity_overrides.items()
            },
            "admin_ports": self.admin_ports.to_dict(),
        }


@dataclass
class RuleOverlapSettings:
    """Tuning parameters for redundant and shadowed rule detection."""

    max_rules_evaluated: int = 500
    max_rule_pairs: int = 5000
    redundant_severity: Severity = Severity.LOW
    shadowed_severity: Severity = Severity.MEDIUM

    def __post_init__(self) -> None:
        if int(self.max_rules_evaluated) < 0:
            raise ValueError("max_rules_evaluated cannot be negative")
        if int(self.max_rule_pairs) < 0:
            raise ValueError("max_rule_pairs cannot be negative")

    def to_dict(self) -> dict:
        return {
            "max_rules_evaluated": int(self.max_rules_evaluated),
            "max_rule_pairs": int(self.max_rule_pairs),
            "redundant_severity": self.redundant_severity.value,
            "shadowed_severity": self.shadowed_severity.value,
        }


@dataclass
class UnusedRuleSettings:
    """Configuration for detecting unused or disabled firewall rules."""

    hit_count_threshold: int = 0
    include_disabled: bool = True
    hit_count_severity: Severity = Severity.CAUTIONARY
    disabled_severity: Severity = Severity.LOW

    def __post_init__(self) -> None:
        if int(self.hit_count_threshold) < 0:
            raise ValueError("hit_count_threshold cannot be negative")

    def to_dict(self) -> dict:
        return {
            "hit_count_threshold": int(self.hit_count_threshold),
            "include_disabled": bool(self.include_disabled),
            "hit_count_severity": self.hit_count_severity.value,
            "disabled_severity": self.disabled_severity.value,
        }


@dataclass
class RuleDefinition:
    """Description of an analyzer rule and its activation criteria."""

    rule_id: str
    label: str
    description: str = ""
    conditions: ConditionGroup = field(default_factory=ConditionGroup)
    analyzers: Dict[str, AnalyzerMetadata] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.rule_id,
            "label": self.label,
            "description": self.description,
            "conditions": self.conditions.to_dict(),
            "analyzers": {
                name: metadata.to_dict() for name, metadata in self.analyzers.items()
            },
        }


@dataclass
class RulesConfig:
    """Normalized rules configuration with backwards-compatibility helpers."""

    admin_ports: set[int] = field(default_factory=set)
    critical_risk_admin_ports: set[int] = field(default_factory=set)
    high_risk_admin_ports: set[int] = field(default_factory=set)
    medium_risk_admin_ports: set[int] = field(default_factory=set)
    low_risk_admin_ports: set[int] = field(default_factory=set)
    broad_cidr_prefix_max: int = 8
    risk_levels: Dict[str, RiskLevelDefinition] = field(default_factory=dict)
    cidr_limits: Dict[str, CIDRLimitSet] = field(default_factory=dict)
    port_groups: PortGroupCollection = field(default_factory=PortGroupCollection)
    rule_definitions: Dict[str, RuleDefinition] = field(default_factory=dict)
    rule_overlap: RuleOverlapSettings = field(default_factory=RuleOverlapSettings)
    unused_rule: UnusedRuleSettings = field(default_factory=UnusedRuleSettings)
    default_rule_tags: Tuple[str, ...] = field(default_factory=tuple)
    functional_tag_aliases: Dict[str, Tuple[str, ...]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "admin_ports": sorted(self.admin_ports),
            "critical_risk_admin_ports": sorted(self.critical_risk_admin_ports),
            "high_risk_admin_ports": sorted(self.high_risk_admin_ports),
            "medium_risk_admin_ports": sorted(self.medium_risk_admin_ports),
            "low_risk_admin_ports": sorted(self.low_risk_admin_ports),
            "broad_cidr_prefix_max": int(self.broad_cidr_prefix_max),
            "risk_levels": {name: definition.to_dict() for name, definition in self.risk_levels.items()},
            "cidr_limits": {name: limit_set.to_dict() for name, limit_set in self.cidr_limits.items()},
            "port_groups": self.port_groups.to_dict(),
            "rules": {name: definition.to_dict() for name, definition in self.rule_definitions.items()},
            "rule_overlap": self.rule_overlap.to_dict(),
            "unused_rule": self.unused_rule.to_dict(),
            "default_rule_tags": list(self.default_rule_tags),
            "functional_tag_aliases": {
                key: list(values) for key, values in self.functional_tag_aliases.items()
            },
        }

    def get_legacy_mapping(self) -> MutableMapping[str, object]:
        """Return a dict-like view for legacy callers that expect ``dict``."""

        data = self.to_dict()
        data.update(
            {
                "admin_ports": sorted(self.admin_ports),
                "critical_risk_admin_ports": sorted(self.critical_risk_admin_ports),
                "high_risk_admin_ports": sorted(self.high_risk_admin_ports),
                "medium_risk_admin_ports": sorted(self.medium_risk_admin_ports),
                "low_risk_admin_ports": sorted(self.low_risk_admin_ports),
                "default_rule_tags": list(self.default_rule_tags),
                "functional_tag_aliases": {
                    key: list(values)
                    for key, values in self.functional_tag_aliases.items()
                },
            }
        )
        return data

    @staticmethod
    def _normalize_ports(values: Iterable[int | str]) -> set[int]:
        normalized: set[int] = set()
        for value in values or []:
            try:
                normalized.add(int(value))
            except (TypeError, ValueError):
                continue
        return normalized

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "RulesConfig":
        def _normalize_port_set(value: object) -> set[int]:
            if value is None:
                return set()
            if isinstance(value, (str, bytes)):
                iterable: Iterable[object] = [value]
            elif isinstance(value, Iterable):
                iterable = value
            else:
                iterable = [value]
            return cls._normalize_ports(iterable)

        def _iter_values(value: object) -> Iterable[object]:
            if isinstance(value, (str, bytes)):
                return [value]
            if isinstance(value, Iterable):
                return value
            return [value]

        admin_ports = cls._normalize_ports(data.get("admin_ports", []))
        critical_ports = cls._normalize_ports(data.get("critical_risk_admin_ports", []))
        high_ports = cls._normalize_ports(data.get("high_risk_admin_ports", []))
        medium_ports = cls._normalize_ports(data.get("medium_risk_admin_ports", []))
        low_ports = cls._normalize_ports(data.get("low_risk_admin_ports", []))

        broad_cidr_prefix = int(data.get("broad_cidr_prefix_max", 8))

        risk_levels_raw = data.get("risk_levels", {}) or {}
        risk_levels: Dict[str, RiskLevelDefinition] = {}
        if isinstance(risk_levels_raw, Mapping):
            for name, item in risk_levels_raw.items():
                if not isinstance(item, Mapping):
                    continue
                thresholds = NumericThresholds(**(item.get("thresholds", {}) or {}))
                rationale = Rationale(**(item.get("rationale", {}) or {}))
                severity_value = item.get("severity", "").lower() or Severity.LOW.value
                try:
                    severity = Severity(severity_value)
                except ValueError:
                    severity = Severity.LOW
                risk_levels[name] = RiskLevelDefinition(
                    name=name,
                    label=str(item.get("label", name.title())),
                    severity=severity,
                    thresholds=thresholds,
                    rationale=rationale,
                )

        cidr_limits_raw = data.get("cidr_limits", {}) or {}
        cidr_limits: Dict[str, CIDRLimitSet] = {}
        if isinstance(cidr_limits_raw, Mapping):
            for name, item in cidr_limits_raw.items():
                if not isinstance(item, Mapping):
                    continue
                default_policy = CIDRLimitPolicy(**(item.get("default", {}) or {}))

                def _build_policy_map(raw: Mapping[str, object]) -> Dict[str, CIDRLimitPolicy]:
                    policies: Dict[str, CIDRLimitPolicy] = {}
                    for key, raw_policy in raw.items():
                        if isinstance(raw_policy, Mapping):
                            policies[key.lower()] = CIDRLimitPolicy(**raw_policy)
                    return policies

                analyzers = _build_policy_map(item.get("analyzers", {}) or {})
                vendors = _build_policy_map(item.get("vendors", {}) or {})
                directions = _build_policy_map(item.get("directions", {}) or {})
                vendor_direction_overrides: Dict[str, Dict[str, CIDRLimitPolicy]] = {}
                overrides_raw = item.get("vendor_direction_overrides", {}) or {}
                if isinstance(overrides_raw, Mapping):
                    for vendor, direction_map in overrides_raw.items():
                        if not isinstance(direction_map, Mapping):
                            continue
                        vendor_direction_overrides[vendor.lower()] = {
                            direction.lower(): CIDRLimitPolicy(**policy)
                            for direction, policy in direction_map.items()
                            if isinstance(policy, Mapping)
                        }

                cidr_limits[name] = CIDRLimitSet(
                    name=name,
                    default=default_policy,
                    analyzers=analyzers,
                    vendors=vendors,
                    directions=directions,
                    vendor_direction_overrides=vendor_direction_overrides,
                )

        port_groups_raw = data.get("port_groups", {}) or {}
        groups: Dict[str, PortGroup] = {}
        if isinstance(port_groups_raw, Mapping):
            for name, item in port_groups_raw.items():
                if not isinstance(item, Mapping):
                    continue
                ranges_raw = item.get("ranges") or item.get("entries") or []
                ranges: list[PortRange] = []
                for raw_value in ranges_raw:
                    range_obj = _parse_port_entry(raw_value)
                    ranges.append(range_obj)
                groups[name] = PortGroup(
                    name=name,
                    description=str(item.get("description", "")),
                    protocol=str(item.get("protocol", "any")),
                    ranges=ranges,
                )

        port_groups = PortGroupCollection(groups=groups)

        overlap_settings = RuleOverlapSettings()
        overlap_raw = data.get("rule_overlap", {}) or {}
        if isinstance(overlap_raw, Mapping):
            max_rules_value = overlap_raw.get("max_rules_evaluated", overlap_settings.max_rules_evaluated)
            max_pairs_value = overlap_raw.get("max_rule_pairs", overlap_settings.max_rule_pairs)
            redundant_severity_value = overlap_raw.get(
                "redundant_severity", overlap_settings.redundant_severity.value
            )
            shadowed_severity_value = overlap_raw.get(
                "shadowed_severity", overlap_settings.shadowed_severity.value
            )

            try:
                redundant_severity = Severity(str(redundant_severity_value).lower())
            except ValueError:
                redundant_severity = overlap_settings.redundant_severity

            try:
                shadowed_severity = Severity(str(shadowed_severity_value).lower())
            except ValueError:
                shadowed_severity = overlap_settings.shadowed_severity

            overlap_settings = RuleOverlapSettings(
                max_rules_evaluated=int(max_rules_value),
                max_rule_pairs=int(max_pairs_value),
                redundant_severity=redundant_severity,
                shadowed_severity=shadowed_severity,
            )

        unused_settings = UnusedRuleSettings()
        unused_raw = data.get("unused_rule", {}) or {}
        if isinstance(unused_raw, Mapping):
            threshold_value = unused_raw.get(
                "hit_count_threshold", unused_settings.hit_count_threshold
            )
            include_disabled_value = unused_raw.get(
                "include_disabled", unused_settings.include_disabled
            )
            hit_severity_value = unused_raw.get(
                "hit_count_severity", unused_settings.hit_count_severity.value
            )
            disabled_severity_value = unused_raw.get(
                "disabled_severity", unused_settings.disabled_severity.value
            )

            try:
                hit_severity = Severity(str(hit_severity_value).lower())
            except ValueError:
                hit_severity = unused_settings.hit_count_severity

            try:
                disabled_severity = Severity(str(disabled_severity_value).lower())
            except ValueError:
                disabled_severity = unused_settings.disabled_severity

            unused_settings = UnusedRuleSettings(
                hit_count_threshold=int(threshold_value),
                include_disabled=bool(include_disabled_value),
                hit_count_severity=hit_severity,
                disabled_severity=disabled_severity,
            )

        rules_raw = data.get("rules", {}) or {}
        rule_definitions: Dict[str, RuleDefinition] = {}
        if isinstance(rules_raw, Mapping):
            for name, item in rules_raw.items():
                if not isinstance(item, Mapping):
                    continue

                rule_id = str(item.get("id", name))
                label = str(item.get("label", rule_id.replace("_", " ").title()))
                description = str(item.get("description", ""))
                conditions = _parse_condition_group(item.get("conditions"))

                analyzers_raw = item.get("analyzers", {}) or {}
                analyzers: Dict[str, AnalyzerMetadata] = {}
                if isinstance(analyzers_raw, Mapping):
                    for analyzer_name, analyzer_item in analyzers_raw.items():
                        if not isinstance(analyzer_item, Mapping):
                            continue

                        analyzer_key = str(analyzer_name)
                        admin_ports_raw = analyzer_item.get("admin_ports", {}) or {}
                        port_config = AnalyzerPortConfiguration()
                        if isinstance(admin_ports_raw, Mapping):
                            baseline_raw = admin_ports_raw.get("baseline", [])
                            port_config.baseline = _normalize_port_set(baseline_raw)
                            overrides_raw = admin_ports_raw.get("per_risk_overrides", {}) or {}
                            if isinstance(overrides_raw, Mapping):
                                for risk_name, values in overrides_raw.items():
                                    port_config.per_risk_overrides[str(risk_name).lower()] = _normalize_port_set(
                                        values
                                    )

                        severity_raw = analyzer_item.get("severity_overrides", {}) or {}
                        severity_overrides: Dict[str, str] = {}
                        if isinstance(severity_raw, Mapping):
                            for key, value in severity_raw.items():
                                if value is None:
                                    continue
                                severity_overrides[str(key)] = str(value)

                        analyzers[analyzer_key] = AnalyzerMetadata(
                            name=analyzer_key,
                            enabled=bool(analyzer_item.get("enabled", True)),
                            notes=str(analyzer_item.get("notes", "")),
                            severity_overrides=severity_overrides,
                            admin_ports=port_config,
                        )

                rule_definitions[rule_id] = RuleDefinition(
                    rule_id=rule_id,
                    label=label,
                    description=description,
                    conditions=conditions,
                    analyzers=analyzers,
                )

        default_rule_tags_raw = data.get("default_rule_tags", []) or []
        default_rule_tags_list: list[str] = []
        seen_default_tags: set[str] = set()
        for raw in _iter_values(default_rule_tags_raw):
            slug = _normalise_tag_label(raw)
            if slug and slug not in seen_default_tags:
                seen_default_tags.add(slug)
                default_rule_tags_list.append(slug)
        default_rule_tags = tuple(default_rule_tags_list)

        functional_aliases_raw = data.get("functional_tag_aliases", {}) or {}
        functional_tag_aliases: Dict[str, Tuple[str, ...]] = {}
        if isinstance(functional_aliases_raw, Mapping):
            for key, values in functional_aliases_raw.items():
                slug_key = _normalise_tag_label(key)
                if not slug_key:
                    continue
                resolved: list[str] = []
                seen_slug: set[str] = set()
                for candidate in _iter_values(values):
                    slug_value = _normalise_tag_label(candidate)
                    if slug_value and slug_value not in seen_slug:
                        seen_slug.add(slug_value)
                        resolved.append(slug_value)
                if resolved:
                    functional_tag_aliases[slug_key] = tuple(resolved)

        return cls(
            admin_ports=admin_ports,
            critical_risk_admin_ports=critical_ports,
            high_risk_admin_ports=high_ports,
            medium_risk_admin_ports=medium_ports,
            low_risk_admin_ports=low_ports,
            broad_cidr_prefix_max=broad_cidr_prefix,
            risk_levels=risk_levels,
            cidr_limits=cidr_limits,
            port_groups=port_groups,
            rule_definitions=rule_definitions,
            rule_overlap=overlap_settings,
            unused_rule=unused_settings,
            default_rule_tags=default_rule_tags,
            functional_tag_aliases=functional_tag_aliases,
        )


def _parse_port_entry(raw_value: object) -> PortRange:
    """Parse a YAML entry describing a port or range."""

    if isinstance(raw_value, Mapping):
        start = raw_value.get("start")
        end = raw_value.get("end", start)
        if start is None:
            raise ValueError("Port range mapping must include 'start'")
        return PortRange(int(start), int(end))

    if isinstance(raw_value, (list, tuple)) and len(raw_value) == 2:
        return PortRange(int(raw_value[0]), int(raw_value[1]))

    text = str(raw_value or "").strip()
    if not text:
        raise ValueError("Empty port entry encountered")

    if "/" in text:
        _, _, text = text.partition("/")

    if "-" in text:
        start_text, end_text = text.split("-", 1)
        return PortRange(int(start_text), int(end_text))

    return PortRange(int(text), int(text))


def _parse_condition_group(raw: object) -> ConditionGroup:
    """Convert raw mapping data into a ``ConditionGroup`` instance."""

    if not isinstance(raw, Mapping):
        return ConditionGroup()

    logic = raw.get("logic")
    entries = raw.get("conditions")
    if "all" in raw:
        logic = "all"
        entries = raw.get("all")
    elif "any" in raw:
        logic = "any"
        entries = raw.get("any")

    parsed_conditions: list[RuleCondition] = []
    parsed_groups: list[ConditionGroup] = []

    for entry in _coerce_sequence(entries):
        parsed = _parse_condition_entry(entry)
        if isinstance(parsed, RuleCondition):
            parsed_conditions.append(parsed)
        elif isinstance(parsed, ConditionGroup):
            parsed_groups.append(parsed)

    return ConditionGroup(logic=logic or "all", conditions=parsed_conditions, groups=parsed_groups)


def _parse_condition_entry(entry: object) -> Optional[object]:
    if isinstance(entry, Mapping):
        if "field" in entry:
            return _parse_rule_condition(entry)
        if any(key in entry for key in ("logic", "conditions", "all", "any")):
            return _parse_condition_group(entry)
    return None


def _parse_rule_condition(raw: Mapping[str, Any]) -> RuleCondition:
    field = str(raw.get("field", "")).strip()
    comparator = raw.get("comparator") or raw.get("operator") or ConditionComparator.EQUALS.value
    value = raw.get("value")
    values = _coerce_sequence(raw.get("values") or raw.get("any_of"))
    threshold_data = raw.get("threshold") or raw.get("thresholds")
    threshold: Optional[RuleConditionThreshold] = None
    if isinstance(threshold_data, Mapping):
        threshold = RuleConditionThreshold(
            min_value=_maybe_float(
                threshold_data.get("min_value", threshold_data.get("min"))
            ),
            max_value=_maybe_float(
                threshold_data.get("max_value", threshold_data.get("max"))
            ),
            inclusive=bool(threshold_data.get("inclusive", True)),
        )

    return RuleCondition(
        field=field,
        comparator=comparator,
        value=value,
        values=values,
        threshold=threshold,
    )


def _coerce_sequence(value: object) -> tuple[Any, ...]:
    if value is None:
        return tuple()
    if isinstance(value, Mapping):
        return tuple(value.values())
    if isinstance(value, (list, tuple)):
        return tuple(value)
    if isinstance(value, set):
        return tuple(sorted(value))
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
        return tuple(value)
    return (value,)


def _maybe_float(value: object) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None