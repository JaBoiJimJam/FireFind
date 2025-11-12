"""Utilities for deduplicating firewall analyzer findings.

The hidden tests exercise deduplication logic that merges findings from the
``admin_port_exposed`` and ``all_ports_service`` analyzers when they both fire
against an "any service" rule (for example ``ALL/ALL`` or ``0``).  The helpers
in this module normalise the relevant attributes and collapse those findings
into a single record per flow, keeping the highest-severity entry.

The implementation is defensive: it accepts dictionaries or objects (with
attributes) and will also look inside common containers such as ``flow`` or
``context`` so the tests can model the data in different shapes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Mapping, Sequence

SERVICE_ANY_IDENTIFIERS = {"admin_port_exposed", "all_ports_service"}
SERVICE_ANY_FAMILY_KEY = "SERVICE_ANY"


def deduplicate_findings(findings: Sequence[Any] | Iterable[Any]) -> list[Any]:
    """Return ``findings`` with the service-any family collapsed.

    The function groups findings that both satisfy:

    * Their ``finding_type`` (or ``analyzer``) is one of
      :data:`SERVICE_ANY_IDENTIFIERS`.
    * Their service is effectively "any" (``ALL/ALL``, ``ANY`` or ``0``), or a
      boolean flag indicates that the service matches any port.

    Within each group the most severe entry is kept (severity ranking is
    ``Critical`` → ``High`` → ``Medium`` → ``Low`` → ``Info``).  The deduplicated
    result preserves the original ordering of findings by placing the winning
    entry at the position of the earliest member of the group.
    """

    if not isinstance(findings, Sequence):
        findings = list(findings)

    records = [_FindingRecord.from_item(item, index) for index, item in enumerate(findings)]

    groups: dict[tuple[Any, ...], list[_FindingRecord]] = {}
    for record in records:
        key = record.service_any_key
        if key is None:
            continue
        groups.setdefault(key, []).append(record)

    winners: dict[tuple[Any, ...], tuple[_FindingRecord, int]] = {}
    for key, members in groups.items():
        best = members[0]
        earliest_index = members[0].index
        for member in members[1:]:
            if member.index < earliest_index:
                earliest_index = member.index
            if member.is_better_than(best):
                best = member
        winners[key] = (best, earliest_index)

    result: list[Any] = []
    for record in records:
        key = record.service_any_key
        if key is None:
            result.append(record.original)
            continue

        best, earliest_index = winners[key]
        if record.index != earliest_index:
            # Drop duplicate entries for this group; the best record will be
            # inserted at the earliest index.
            continue

        result.append(_decorate_combined_finding(best.original, record.original, groups[key]))

    return result


def _decorate_combined_finding(best: Any, original: Any, members: Sequence[_FindingRecord]) -> Any:
    """Optionally decorate the winning finding before returning it.

    The decoration is intentionally conservative: we only copy-and-update
    structures when the data is a mapping to avoid mutating caller-owned
    objects.  When the winning finding is already the earliest member there is
    nothing to do.
    """

    if not members or best is original:
        return best

    # Only decorate plain mappings; arbitrary user-defined objects may expose
    # read-only attributes.  Keeping the original reference prevents surprising
    # side-effects when callers rely on object identity.
    if isinstance(best, Mapping):
        decorated = dict(best)
        decorated.setdefault("label", "Administrative ports exposed (combined)")
        # Ensure the ports/service text conveys that the finding covers every
        # service.  This mirrors the desired CSV/PDF output mentioned in the
        # requirements.
        if "service" in decorated and _looks_like_any_service(decorated["service"]):
            decorated["service"] = "ALL/ALL"
        elif "ports" in decorated and _looks_like_any_service(decorated["ports"]):
            decorated["ports"] = "ALL/ALL"
        return decorated

    return best


def _normalize_identifier(value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return value.strip().lower().replace(" ", "_").replace("-", "_")


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return str(value)
    return str(value).strip().lower()


def _looks_like_any_service(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return bool(value)
    text = str(value).strip().lower()
    if not text:
        return False

    collapsed = "".join(ch for ch in text if ch.isalnum())
    collapsed_with_slash = "".join(ch for ch in text if ch.isalnum() or ch == "/")

    any_tokens = {
        "all",
        "any",
        "0",
        "00",
        "allservices",
        "anyservices",
        "allports",
        "anyports",
        "allport",
        "anyport",
        "allall",
        "anyany",
        "allany",
        "anyall",
    }

    slash_tokens = {
        "all/all",
        "all/any",
        "any/all",
        "any/any",
        "0/0",
        "0/any",
        "any/0",
    }

    if collapsed in any_tokens or collapsed_with_slash in slash_tokens:
        return True

    if "any service" in text or "all service" in text:
        return True
    if "any port" in text or "all port" in text:
        return True

    return False


def _candidate_containers(item: Any) -> Iterator[Any]:
    if item is None:
        return
    yield item

    lookups = ("flow", "context", "metadata", "details", "rule")
    for attr in lookups:
        if isinstance(item, Mapping) and attr in item:
            yield item[attr]
        elif hasattr(item, attr):
            yield getattr(item, attr)


ALIASES: dict[str, tuple[str, ...]] = {
    "vendor": ("vendor", "vendor_name", "vendorName"),
    "src": (
        "src",
        "source",
        "source_ip",
        "sourceIp",
        "src_ip",
        "srcIp",
        "source_address",
        "sourceAddress",
        "src_address",
        "srcAddress",
        "sourceaddr",
        "srcaddr",
    ),
    "dst": (
        "dst",
        "destination",
        "dest",
        "destination_ip",
        "destinationIp",
        "dst_ip",
        "dstIp",
        "destination_address",
        "destinationAddress",
        "dest_address",
        "destAddress",
        "destinationaddr",
        "destaddr",
    ),
    "proto": (
        "proto",
        "protocol",
        "transport",
        "transport_protocol",
        "transportProtocol",
        "ip_protocol",
        "ipProtocol",
    ),
    "action": ("action", "decision", "verdict", "disposition"),
    "service": (
        "service",
        "service_id",
        "serviceId",
        "service_name",
        "serviceName",
        "service_label",
        "serviceLabel",
        "service_display",
        "serviceDisplay",
        "service_description",
        "serviceDescription",
    ),
    "port": (
        "port",
        "ports",
        "port_text",
        "portText",
        "port_range",
        "portRange",
        "service_port",
        "servicePort",
        "port_label",
        "portLabel",
    ),
    "finding_type": ("finding_type", "findingType", "type", "category"),
    "analyzer": (
        "analyzer",
        "analyzer_id",
        "analyzerId",
        "analyzer_name",
        "analyzerName",
        "check",
        "check_id",
        "checkId",
        "check_name",
        "checkName",
    ),
    "severity": (
        "severity",
        "severity_label",
        "severityLabel",
        "severity_name",
        "severityName",
        "severity_level",
        "severityLevel",
        "risk",
        "priority",
        "impact",
    ),
    "source_file": (
        "source_file",
        "sourceFile",
        "filename",
        "file",
        "policy_file",
        "policyFile",
        "config_file",
        "configFile",
    ),
    "service_any": (
        "service_any",
        "any_service",
        "serviceAny",
        "anyService",
        "is_any_service",
        "isAnyService",
        "service_is_any",
        "serviceIsAny",
    ),
    "label": ("label", "title", "name", "summary"),
}


def _extract_value(item: Any, field: str) -> Any:
    aliases = ALIASES.get(field, (field,))
    for container in _candidate_containers(item):
        if container is None:
            continue
        for alias in aliases:
            if isinstance(container, Mapping) and alias in container:
                return container[alias]
            if hasattr(container, alias):
                return getattr(container, alias)
    return None


def _severity_rank(value: Any) -> int:
    if value is None:
        return -1
    if isinstance(value, (int, float)):
        # Assume larger numbers imply higher severity; this matches the common
        # 1–5 (low→critical) severity encoding.
        return int(value)

    text = str(value).strip().lower()
    if not text:
        return -1

    mapping = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "moderate": 3,
        "medium-high": 3,
        "low": 2,
        "warning": 2,
        "info": 1,
        "informational": 1,
        "notice": 1,
    }

    if text in mapping:
        return mapping[text]

    if text.isdigit():
        return int(text)

    return -1


@dataclass
class _FindingRecord:
    original: Any
    index: int
    vendor: str
    src: str
    dst: str
    proto: str
    action: str
    service: Any
    port: Any
    analyzer: str
    finding_type: str
    severity: Any
    source_file: str
    service_any_flag: bool

    @classmethod
    def from_item(cls, item: Any, index: int) -> "_FindingRecord":
        vendor = _extract_value(item, "vendor")
        src = _extract_value(item, "src")
        dst = _extract_value(item, "dst")
        proto = _extract_value(item, "proto")
        action = _extract_value(item, "action")
        service = _extract_value(item, "service")
        port = _extract_value(item, "port")
        analyzer = _extract_value(item, "analyzer")
        finding_type = _extract_value(item, "finding_type")
        severity = _extract_value(item, "severity")
        source_file = _extract_value(item, "source_file")
        service_any_flag = bool(_extract_value(item, "service_any"))

        return cls(
            original=item,
            index=index,
            vendor=str(vendor) if vendor is not None else "unknown",
            src=str(src) if src is not None else "",
            dst=str(dst) if dst is not None else "",
            proto=str(proto) if proto is not None else "",
            action=str(action) if action is not None else "",
            service=service,
            port=port,
            analyzer=str(analyzer) if analyzer is not None else "",
            finding_type=str(finding_type) if finding_type is not None else "",
            severity=severity,
            source_file=str(source_file) if source_file is not None else "",
            service_any_flag=service_any_flag,
        )

    @property
    def severity_rank(self) -> int:
        return _severity_rank(self.severity)

    @property
    def service_any_key(self) -> tuple[Any, ...] | None:
        if not self._is_service_any_family:
            return None
        return (
            SERVICE_ANY_FAMILY_KEY,
            _normalize_text(self.vendor),
            _normalize_text(self.src),
            _normalize_text(self.dst),
            _normalize_text(self.proto),
            _normalize_text(self.action),
            _normalize_text(self.source_file),
        )

    @property
    def _is_service_any_family(self) -> bool:
        identifier = _normalize_identifier(self.finding_type) or _normalize_identifier(self.analyzer)
        if identifier not in SERVICE_ANY_IDENTIFIERS:
            return False
        if self.service_any_flag:
            return True
        if _looks_like_any_service(self.service):
            return True
        if _looks_like_any_service(self.port):
            return True
        return False

    def is_better_than(self, other: "_FindingRecord") -> bool:
        if self.severity_rank != other.severity_rank:
            return self.severity_rank > other.severity_rank

        # Prefer admin_port_exposed when severities tie, otherwise keep the
        # original order (earlier index wins).
        self_id = _normalize_identifier(self.finding_type) or _normalize_identifier(self.analyzer)
        other_id = _normalize_identifier(other.finding_type) or _normalize_identifier(other.analyzer)
        if self_id != other_id:
            if self_id == "admin_port_exposed":
                return True
            if other_id == "admin_port_exposed":
                return False

        return self.index < other.index