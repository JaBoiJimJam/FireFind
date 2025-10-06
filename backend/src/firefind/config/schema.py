"""Configuration schema objects for FireFind rule processing."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import ipaddress
from typing import Dict, Iterable, Mapping, MutableMapping, Optional


class Severity(str, Enum):
    """Enumeration of supported qualitative severities."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
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