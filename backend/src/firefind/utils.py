from __future__ import annotations

"""Shared utility functions for FireFind modules."""

from dataclasses import dataclass
from pathlib import Path
import re
import ipaddress
from typing import TYPE_CHECKING, Callable, Iterable, Mapping, Sequence, Tuple, List, Optional
import yaml

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq

from .model import Rule

if TYPE_CHECKING:
    from .config import RulesConfig
from .vendors import apply_vendor_normalizer
from .vendors.utils import normalize_header, pick_first_present, normalize_action


@dataclass(frozen=True)
class RuleValidationIssue:
    """Structured description of a validation failure for a raw rule row."""

    code: str
    message: str
    field: str | None = None


class RuleValidationError(ValueError):
    """Raised when a row cannot be converted into a :class:`Rule`."""

    def __init__(
        self,
        issues: Sequence[RuleValidationIssue],
        row: Mapping[str, object] | None = None,
    ) -> None:
        if not issues:
            raise ValueError("RuleValidationError requires at least one issue")
        self.issues: Tuple[RuleValidationIssue, ...] = tuple(issues)
        self.row: Mapping[str, object] | None = row
        super().__init__("; ".join(issue.message for issue in self.issues))


# Mapping of common service object names to well-known ports.  These values are
# primarily based on anonymised client exports whose ``service`` column lists
# human-readable names (e.g. ``HTTP``) rather than explicit ``TCP/80`` entries.
# The dictionary intentionally focuses on the most common services that affect
# exposure analysis; unknown names simply fall back to the raw text.
def _build_service_name_ports() -> dict[str, list[int]]:
    base = {
        "HTTP": [80],
        "HTTPS": [443],
        "SSH": [22],
        "TELNET": [23],
        "FTP": [21],
        "FTPS": [990, 989, 21],
        "DNS": [53],
        "DNS_": [53],
        "DOMAIN-TCP": [53],
        "DOMAIN-UDP": [53],
        "DOMAIN-UDP_": [53],
        "SMTP": [25],
        "SMTPS": [465],
        "POP3": [110],
        "IMAP": [143],
        "LDAP": [389],
        "LDAP-SSL": [636],
        "RDP": [3389],
        "SQL": [1433],
        "MS-SQL-SERVER": [1433],
        "MYSQL": [3306],
        "POSTGRES": [5432],
        "HTTP_PROXY": [8080],
        "VNC": [5900],
        "SYSLOG": [514],
        "SHELL": [514],
        "NBT_": [137, 138, 139],
        "NATAGRAM": [138],
        "NBNAME": [137],
        "NBNAME_TCP": [137],
        "NBSESSION": [139],
        "KERBEROS": [88],
        "KERBEROS_": [88],
        "KERBEROS_V5_TCP": [88],
        "KERBEROS_V5_UDP": [88],
        "KERBEROS-TCP-V4": [88],
        "KERBEROS-UDP-V4_": [88],
        "NTP-UDP": [123],
        "NTP-TCP": [123],
        "TCP_135": [135],
        "TCP_3268": [3268],
        "TCP_3269": [3269],
        "TCP_464": [464],
        "TCP_8810-8811": [8810, 8811],
        "TCP-HIGH-PORTS": [1024, 65535],
        "TCP-49152_65535": [49152, 65535],
        "TCP-49152_65435": [49152, 65435],
        "MICROSOFT-DS": [445],
        "MICROSOFT_DS": [445],
        "LDPW0RM": [515],
        "PING": [],
        "ICMP": [],
        "SMTP-TLS": [465],
        "SMTP SUBMISSION": [587],
        "SMTP_SUBMISSION": [587],
    }
    # Populate a few common inline service aliases observed in exports.
    for prefix, port in ("TCP", 25), ("TCP", 587), ("TCP", 465), ("UDP", 53):
        key = f"{prefix}_{port}"
        base.setdefault(key, [port])
        base.setdefault(key.replace("_", "-"), [port])
    return base


SERVICE_NAME_PORTS = _build_service_name_ports()


def _numeric_range_from_match(match: re.Match[str]) -> list[int]:
    start_text = match.group("start")
    end_text = match.group("end")
    if not start_text:
        return []
    try:
        start = int(start_text)
    except ValueError:
        return []
    if not 1 <= start <= 65535:
        return []
    if not end_text:
        return [start]
    try:
        end = int(end_text)
    except ValueError:
        return [start]
    if end < start:
        start, end = end, start
    return [port for port in range(start, end + 1) if 1 <= port <= 65535]


_SERVICE_ALIAS_PATTERNS: Tuple[Tuple[re.Pattern[str], Callable[[re.Match[str]], list[int]]], ...] = (
    (
        re.compile(
            r"^(?P<prefix>TCP|UDP)[-_]?(?P<start>\d{1,5})(?:[-_](?P<end>\d{1,5}))?$",
            re.IGNORECASE,
        ),
        _numeric_range_from_match,
    ),
    (
        re.compile(
            r"^DM_INLINE_SERVICE[-_]?(?P<start>\d{1,5})(?:[-_](?P<end>\d{1,5}))?$",
            re.IGNORECASE,
        ),
        _numeric_range_from_match,
    ),
    (
        re.compile(
            r"^SMTP[S]?[-_]?(?P<start>\d{1,5})(?:[-_](?P<end>\d{1,5}))?$",
            re.IGNORECASE,
        ),
        _numeric_range_from_match,
    ),
)


def _service_ports_from_alias(label: str) -> list[int] | None:
    ports = SERVICE_NAME_PORTS.get(label)
    if ports is not None:
        return ports
    for pattern, resolver in _SERVICE_ALIAS_PATTERNS:
        match = pattern.match(label)
        if match:
            resolved = resolver(match)
            if resolved:
                return resolved
    return None


_TAG_SANITIZE_RE = re.compile(r"[^a-z0-9]+")
_IP_CANDIDATE_RE = re.compile(r"[0-9A-Fa-f:.]+(?:/[0-9]{1,3})?")
_ADDRESS_WILDCARDS = {"any", "all", "*"}


def _iter_ip_candidates(token: str) -> Iterable[str]:
    for match in _IP_CANDIDATE_RE.finditer(token):
        candidate = match.group(0)
        if candidate and ("." in candidate or ":" in candidate):
            yield candidate


def _try_parse_ip(value: str) -> bool:
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _validate_address_value(value: str, field: str) -> List[RuleValidationIssue]:
    trimmed = str(value or "").strip()
    if not trimmed:
        return []

    segments = [
        segment.strip()
        for segment in re.split(r"[;,]", trimmed.replace("\n", " "))
        if segment.strip()
    ]
    if not segments:
        segments = [trimmed]

    invalid: set[str] = set()
    for segment in segments:
        lowered = segment.lower()
        if lowered in _ADDRESS_WILDCARDS:
            continue
        candidates = list(_iter_ip_candidates(segment))
        if not candidates:
            continue
        for candidate in candidates:
            if not _try_parse_ip(candidate):
                invalid.add(candidate)

    if not invalid:
        return []

    values = ", ".join(sorted(invalid))
    return [
        RuleValidationIssue(
            code="invalid_address",
            field=field,
            message=f"Invalid {field} value(s): {values}",
        )
    ]


def _is_valid_port_token(token: str) -> bool:
    cleaned = token.strip()
    if not cleaned:
        return False
    upper = cleaned.upper()
    if upper in {"ANY", "ALL", "*"}:
        return True
    if "/" in cleaned:
        proto, _, remainder = cleaned.partition("/")
        if not proto or not remainder:
            return False
        return _is_valid_port_token(remainder)
    if "-" in cleaned:
        start, end = cleaned.split("-", 1)
        if not (start.isdigit() and end.isdigit()):
            return False
        start_val = int(start)
        end_val = int(end)
        return 1 <= start_val <= end_val <= 65535
    if cleaned.isdigit():
        port_val = int(cleaned)
        return 1 <= port_val <= 65535
    return False


def _validate_port_value(value: str) -> List[RuleValidationIssue]:
    trimmed = str(value or "").strip()
    if not trimmed:
        return [
            RuleValidationIssue(
                code="missing_required",
                field="port",
                message="Missing port specification",
            )
        ]

    tokens = [token.strip() for token in trimmed.split(",") if token.strip()]
    if not tokens:
        return [
            RuleValidationIssue(
                code="invalid_port",
                field="port",
                message="Port specification is empty",
            )
        ]

    invalid = [token for token in tokens if not _is_valid_port_token(token)]
    if not invalid:
        return []

    joined = ", ".join(sorted({token for token in invalid}))
    return [
        RuleValidationIssue(
            code="invalid_port",
            field="port",
            message=f"Invalid port value(s): {joined}",
        )
    ]


def _coerce_optional_int(value: object) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    text = str(value).strip()
    if not text:
        return None

    cleaned = text.replace(",", "")
    try:
        if "." in cleaned:
            return int(float(cleaned))
        return int(cleaned)
    except (TypeError, ValueError):
        return None


_TRUE_TOKENS = {"1", "true", "yes", "enabled", "enable", "on", "active"}
_FALSE_TOKENS = {"0", "false", "no", "disabled", "disable", "off", "inactive"}


def _coerce_optional_bool(value: object) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)

    text = str(value).strip().lower()
    if not text:
        return None
    if text in _TRUE_TOKENS:
        return True
    if text in _FALSE_TOKENS:
        return False
    return None


def _validate_rule_inputs(
    row: Mapping[str, object],
    *,
    raw_values: Mapping[str, str],
    normalized_values: Mapping[str, str],
) -> None:
    issues: List[RuleValidationIssue] = []

    missing = [
        field
        for field in ("rule_id", "src", "dst")
        if not (raw_values.get(field) or "").strip()
    ]
    if missing:
        issues.append(
            RuleValidationIssue(
                code="missing_required",
                field=",".join(sorted(missing)),
                message=f"Missing required field(s): {', '.join(sorted(missing))}",
            )
        )

    for field in ("src", "dst"):
        issues.extend(
            _validate_address_value(normalized_values.get(field, ""), field)
        )

    issues.extend(_validate_port_value(normalized_values.get("port", "")))

    if issues:
        raise RuleValidationError(issues, row=row)


def _normalise_tag_label(value: object) -> str:
    """Return a lowercase slug suitable for tag identifiers."""

    text = str(value or "").strip()
    if not text:
        return ""
    slug = _TAG_SANITIZE_RE.sub("-", text.lower()).strip("-")
    return slug


def merge_tags(*sources: Iterable[object]) -> Tuple[str, ...]:
    """Combine tag sources into a de-duplicated tuple of slugified tags."""

    seen: set[str] = set()
    merged: list[str] = []
    for source in sources or ():
        if not source:
            continue
        for candidate in source:
            slug = _normalise_tag_label(candidate)
            if not slug or slug in seen:
                continue
            seen.add(slug)
            merged.append(slug)
    return tuple(merged)


def _split_tag_candidates(value: str, separators: Sequence[str]) -> Iterable[str]:
    """Split a raw string into candidate tag tokens."""

    if not value:
        return []
    cleaned = str(value).replace("\n", " ")
    if not separators:
        stripped = cleaned.strip()
        return [stripped] if stripped else []
    pattern = "[" + re.escape("".join(separators)) + "]"
    tokens = re.split(pattern, cleaned)
    return [token.strip() for token in tokens if token.strip()]


def _ensure_iterable(value: object) -> Iterable[object]:
    if isinstance(value, (str, bytes)):
        return [value]
    if isinstance(value, Iterable):
        return value
    return [value]


def _extract_rule_tags(
    row: Mapping[str, object],
    mapping: Mapping[str, object],
    *,
    config: "RulesConfig" | Mapping[str, object] | None = None,
) -> Tuple[str, ...]:
    """Derive tags for a rule using vendor mapping metadata and config aliases."""

    tags_spec = mapping.get("tags") if isinstance(mapping, Mapping) else None

    config_defaults: Iterable[str] = ()
    config_aliases: Mapping[str, Tuple[str, ...]] = {}
    if config is not None:
        if isinstance(config, Mapping):
            config_defaults = config.get("default_rule_tags", ()) or ()
            raw_aliases = config.get("functional_tag_aliases", {}) or {}
        else:
            config_defaults = getattr(config, "default_rule_tags", ()) or ()
            raw_aliases = getattr(config, "functional_tag_aliases", {}) or {}
        if isinstance(raw_aliases, Mapping):
            config_aliases = {
                _normalise_tag_label(key): tuple(
                    merge_tags(_ensure_iterable(value))
                )
                for key, value in raw_aliases.items()
                if _normalise_tag_label(key)
            }

    vendor_defaults: Iterable[str] = ()
    vendor_aliases: Mapping[str, Tuple[str, ...]] = {}
    separators: Sequence[str] = [",", ";", "|"]
    raw_values: list[str] = []

    if isinstance(tags_spec, Mapping):
        columns = tags_spec.get("columns") or tags_spec.get("fields") or []
        if isinstance(columns, (str, bytes)):
            columns = [columns]
        for column in columns:
            names: Iterable[str]
            if isinstance(column, Iterable) and not isinstance(column, (str, bytes)):
                names = column
            else:
                names = [column]
            value = pick_first_present(row, list(names))
            if value:
                raw_values.append(str(value))
        vendor_defaults = tags_spec.get("defaults") or tags_spec.get("static") or ()
        mapping_spec = tags_spec.get("mapping") or {}
        if isinstance(mapping_spec, Mapping):
            vendor_aliases = {
                _normalise_tag_label(key): tuple(
                    merge_tags(_ensure_iterable(values))
                )
                for key, values in mapping_spec.items()
                if _normalise_tag_label(key)
            }
        separator_spec = tags_spec.get("separators") or tags_spec.get("separator")
        if isinstance(separator_spec, (str, bytes)):
            separators = [str(separator_spec)]
        elif isinstance(separator_spec, Iterable):
            separators = [str(sep) for sep in separator_spec if str(sep)] or separators
    elif isinstance(tags_spec, (list, tuple, set)):
        for column in tags_spec:
            value = pick_first_present(row, [column])
            if value:
                raw_values.append(str(value))
    elif isinstance(tags_spec, (str, bytes)):
        value = pick_first_present(row, [tags_spec])
        if value:
            raw_values.append(str(value))

    tags: list[str] = []
    seen: set[str] = set()

    def _add(values: Iterable[object]) -> None:
        for slug in merge_tags(values):
            if slug and slug not in seen:
                seen.add(slug)
                tags.append(slug)

    _add(config_defaults)
    _add(vendor_defaults)

    for raw_value in raw_values:
        for token in _split_tag_candidates(raw_value, separators):
            key = _normalise_tag_label(token)
            if not key:
                continue
            alias_values = vendor_aliases.get(key) or config_aliases.get(key)
            if alias_values:
                _add(alias_values)
            else:
                _add([key])

    return tuple(tags)


_SERVICE_VALUE_PREFIX_RE = re.compile(
    r"^(?:group\s*member|member|service\s*member|service\s*name)\s*:\s*",
    re.IGNORECASE,
)


def _strip_service_prefix(value: str) -> str:
    cleaned = value
    while True:
        stripped = _SERVICE_VALUE_PREFIX_RE.sub("", cleaned, count=1)
        if stripped == cleaned:
            break
        cleaned = stripped.lstrip()
    return cleaned


def _tokenise_service_values(text: str) -> Iterable[str]:
    if not text:
        return []
    interim = _strip_service_prefix(str(text))
    cleaned = (
        interim.replace("\n", " ")
        .replace(",", " ")
        .replace(";", " ")
        .replace("/ ", "/")
    )
    cleaned = re.sub(r"\s+", " ", cleaned.strip())
    return [part for part in cleaned.split(" ") if part]


def _prepare_port_tokens(tokens: Iterable[str]) -> list[str]:
    """Normalise ``tokens`` describing ports while removing duplicates."""

    wildcard = None
    numeric_ports: list[int] = []
    seen_numeric: set[int] = set()
    explicit_tokens: list[str] = []
    seen_explicit: set[str] = set()

    for token in tokens:
        cleaned = token.strip()
        if not cleaned:
            continue
        upper = cleaned.upper()

        if upper in {"ALL", "ANY", "*"}:
            wildcard = "ALL"
            break

        mapped_ports = _service_ports_from_alias(upper) or _service_ports_from_alias(
            cleaned
        )
        if mapped_ports is not None:
            added = False
            for port in mapped_ports:
                if isinstance(port, int) and 1 <= port <= 65535 and port not in seen_numeric:
                    seen_numeric.add(port)
                    numeric_ports.append(port)
                    added = True
            if added:
                continue
            if any(
                isinstance(port, int) and 1 <= port <= 65535
                for port in mapped_ports
            ):
                continue
            wildcard = "ALL"
            break

        if "/" in cleaned and any(ch.isdigit() for ch in cleaned):
            normalised = cleaned.replace(" ", "")
            lowered = normalised.lower()
            if lowered not in seen_explicit:
                seen_explicit.add(lowered)
                explicit_tokens.append(normalised)
            continue

        if "-" in cleaned:
            range_parts = cleaned.split("-", 1)
            if all(part.isdigit() for part in range_parts):
                lowered = cleaned.lower()
                if lowered not in seen_explicit:
                    seen_explicit.add(lowered)
                    explicit_tokens.append(cleaned)
                continue

        if cleaned.isdigit():
            port = int(cleaned)
            if 1 <= port <= 65535 and port not in seen_numeric:
                seen_numeric.add(port)
                numeric_ports.append(port)
            continue

        lowered = cleaned.lower()
        if lowered not in seen_explicit:
            seen_explicit.add(lowered)
            explicit_tokens.append(cleaned)

    if wildcard:
        return [wildcard]

    ordered: list[str] = []
    if numeric_ports:
        ordered.extend(str(port) for port in sorted(numeric_ports))
    ordered.extend(explicit_tokens)
    return ordered


def load_yaml(path: Path) -> dict:
    """Load a YAML file and return an empty dict if the file is empty or doesn't exist."""
    try:
        if not Path(path).exists():
            return {}
        with Path(path).open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


_ROUND_TRIP_YAML = YAML()
_ROUND_TRIP_YAML.preserve_quotes = True
_ROUND_TRIP_YAML.explicit_start = False
_ROUND_TRIP_YAML.width = 120
_ROUND_TRIP_YAML.indent(mapping=2, sequence=4, offset=2)


def _to_commented(value):
    if isinstance(value, Mapping):
        commented = CommentedMap()
        for key, item in value.items():
            commented[key] = _to_commented(item)
        return commented
    if isinstance(value, list):
        seq = CommentedSeq()
        for item in value:
            seq.append(_to_commented(item))
        return seq
    return value


def _sync_commented(target: CommentedMap, update: Mapping[str, object]) -> CommentedMap:
    for key in list(target.keys()):
        if key not in update:
            del target[key]

    for key, value in update.items():
        if isinstance(value, Mapping):
            existing = target.get(key)
            if not isinstance(existing, CommentedMap):
                existing = CommentedMap()
            target[key] = _sync_commented(existing, value)
        elif isinstance(value, list):
            target[key] = _to_commented(value)
        else:
            target[key] = value
    return target


def dump_yaml(path: Path, data: Mapping[str, object]) -> None:
    """Persist ``data`` to ``path`` while preserving comments when possible."""

    path = Path(path)
    base = CommentedMap()
    if path.exists():
        try:
            loaded = _ROUND_TRIP_YAML.load(path.read_text(encoding="utf-8"))
            if isinstance(loaded, CommentedMap):
                base = loaded
        except Exception:  # pragma: no cover - defensive fallback
            base = CommentedMap()

    updated = _sync_commented(base, data)
    with path.open("w", encoding="utf-8") as handle:
        _ROUND_TRIP_YAML.dump(updated, handle)


def pick_mapping(vendor_mappings: dict, vendor: str) -> dict:
    """Return the column mapping for the given vendor."""
    if not vendor_mappings:
        return {}
    v = vendor.lower()
    for k, val in vendor_mappings.items():
        if k.lower() == v:
            result = dict(val or {})
            result["__vendor__"] = k
            return result
    mapping = vendor_mappings.get(vendor, {})
    if isinstance(mapping, dict):
        result = dict(mapping)
        result["__vendor__"] = vendor
        return result
    return {}


def sniff_proto_port(row: dict, service_hint: str = "") -> Tuple[str, str]:
    """Extract protocol and port information from a raw row."""
    svc_port = pick_first_present(
        row,
        [
            "Service.1",
            "Service Port",
            "Service Ports",
            "Port",
            "Ports",
            "Dst Port",
            "Destination Port",
            "DPort",
        ],
    )
    if svc_port.strip():
        tokens = _tokenise_service_values(str(svc_port))
        normalised = _prepare_port_tokens(tokens)
        if normalised:
            return ("any", ",".join(normalised))

    service_hint_normalised = str(service_hint or "").strip()

    for key, value in row.items():
        norm_key = normalize_header(str(key)) if key is not None else ""
        if not norm_key:
            continue
        if norm_key == "service":
            continue
        if (
            service_hint_normalised
            and str(value or "").strip() == service_hint_normalised
        ):
            continue
        if not any(
            part in norm_key
            for part in (
                "service",
                "port",
                "svc",
                "sport",
                "dport",
            )
        ):
            continue
        tokens = _tokenise_service_values(str(value or ""))
        normalised = _prepare_port_tokens(tokens)
        if normalised:
            return ("any", ",".join(normalised))

    for value in row.values():
        tokens = list(_tokenise_service_values(str(value or "")))
        if not tokens:
            continue
        filtered: list[str] = []
        for token in tokens:
            cleaned = token.strip()
            if not cleaned:
                continue
            if "/" in cleaned and any(ch.isdigit() for ch in cleaned):
                head = cleaned.split("/", 1)[0]
                if any(ch.isalpha() for ch in head):
                    filtered.append(cleaned)
                continue
            if "-" in cleaned:
                range_parts = cleaned.split("-", 1)
                if all(part.isdigit() for part in range_parts):
                    filtered.append(cleaned)
        if not filtered:
            continue
        normalised = _prepare_port_tokens(filtered)
        if normalised:
            return ("any", ",".join(normalised))

    svc_name = service_hint or pick_first_present(row, ["Service"])
    if svc_name.strip():
        tokens = list(_tokenise_service_values(str(svc_name)))
        if not tokens:
            return ("any", str(svc_name).strip())
        normalised = _prepare_port_tokens(tokens)
        if normalised:
            return ("any", ",".join(normalised))

        return ("any", str(svc_name).strip())

    return ("any", "any")


def normalize_risk_rating(value: str) -> str:
    """Return a canonical severity label from vendor risk rating text."""

    if value is None:
        return ""

    cleaned = str(value).strip()
    if not cleaned:
        return ""

    normalized = cleaned.lower()
    normalized = normalized.replace("risk", "")
    for sep in ("-", "_", "\u2013", "\u2014"):
        normalized = normalized.replace(sep, " ")
    normalized = " ".join(part for part in normalized.split() if part)
    collapsed = normalized.replace(" ", "")

    if not collapsed:
        return ""

    if collapsed.startswith("crit"):
        return "Critical"
    if collapsed.startswith("high"):
        return "High"
    if collapsed.startswith("med"):
        return "Medium"
    if collapsed.startswith("low"):
        return "Low"
    if collapsed.startswith("info"):
        return "Info"
    if collapsed.startswith("caut") or collapsed.endswith("tionary"):
        return "Cautionary"

    return cleaned.capitalize()


def to_rule(
    row: dict,
    mapping: dict,
    *,
    vendor: str | None = None,
    config: "RulesConfig" | Mapping[str, object] | None = None,
) -> Rule | None:
    """Map a raw row into a :class:`Rule` or return ``None`` for noise."""
    vendor_name = vendor or mapping.get("__vendor__", "")
    normalized_row = apply_vendor_normalizer(vendor_name, row, mapping)

    def _pick_value(keys: object) -> str:
        if isinstance(keys, (str, bytes)):
            candidates = [keys]
        elif isinstance(keys, Iterable):
            candidates = [key for key in keys if isinstance(key, (str, bytes))]
        else:
            candidates = []
        return pick_first_present(normalized_row, candidates) if candidates else ""

    rid_raw = _pick_value(mapping.get("rule_id", []))
    rid = rid_raw or "(unknown)"
    action_raw = _pick_value(mapping.get("action", [])) or "allow"
    action = normalize_action(action_raw)
    src_raw = _pick_value(mapping.get("src", []))
    src = src_raw or "any"
    dst_raw = _pick_value(mapping.get("dst", []))
    dst = dst_raw or "any"
    service = _pick_value(mapping.get("service", ["Service"])) or ""
    proto, port = sniff_proto_port(normalized_row, service_hint=service)
    if proto.strip().lower() in {"", "any"}:
        proto = _pick_value(mapping.get("proto", ["Protocol", "Proto"])) or "any"
    comment = _pick_value(mapping.get("comment", [])) or ""
    srcintf = _pick_value(mapping.get("srcintf", ["Srcintf", "Src Interface"])) or ""
    dstintf = _pick_value(mapping.get("dstintf", ["Dstintf", "Dst Interface"])) or ""
    source_file = str(normalized_row.get("_source_file", ""))
    risk_rating_fields = mapping.get("risk_rating", [])
    risk_rating_raw = (
        _pick_value(risk_rating_fields)
        if risk_rating_fields
        else ""
    )
    risk_rating = normalize_risk_rating(risk_rating_raw)

    hit_count = _coerce_optional_int(_pick_value(mapping.get("hit_count", [])))
    byte_count = _coerce_optional_int(_pick_value(mapping.get("byte_count", [])))
    enabled = _coerce_optional_bool(_pick_value(mapping.get("enabled", [])))

    _validate_rule_inputs(
        normalized_row,
        raw_values={
            "rule_id": rid_raw,
            "src": src_raw,
            "dst": dst_raw,
        },
        normalized_values={
            "rule_id": rid,
            "src": src,
            "dst": dst,
            "port": port,
        },
    )

    tags = _extract_rule_tags(normalized_row, mapping, config=config)

    return Rule(
        rule_id=rid,
        src=src,
        dst=dst,
        proto=proto,
        port=port,
        action=action,
        comment=comment,
        src_interface=srcintf,
        dst_interface=dstintf,
        service=service,
        source_file=source_file,
        risk_rating=risk_rating,
        tags=tags,
        hit_count=hit_count,
        byte_count=byte_count,
        enabled=enabled,
    )
