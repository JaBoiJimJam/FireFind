from __future__ import annotations

"""Shared utility functions for FireFind modules."""

from pathlib import Path
from typing import Iterable, Mapping, Tuple
import re
import yaml

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq

from .model import Rule
from .vendors import apply_vendor_normalizer
from .vendors.utils import normalize_header, pick_first_present, normalize_action


# Mapping of common service object names to well-known ports.  These values are
# primarily based on anonymised client exports whose ``service`` column lists
# human-readable names (e.g. ``HTTP``) rather than explicit ``TCP/80`` entries.
# The dictionary intentionally focuses on the most common services that affect
# exposure analysis; unknown names simply fall back to the raw text.
SERVICE_NAME_PORTS = {
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
    "TCP-587": [587],
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
    "MICROSOFT-DS": [445],
    "ADPORTS": [88, 135, 137, 138, 139, 389, 445, 464, 3268, 3269],
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
    "LPDW0RM": [515],
    "PING": [],
    "ICMP": [],
}

_PORT_MARKER_PREFIXES = (
    "TCP",
    "UDP",
    "HTTP",
    "HTTPS",
    "SSH",
    "TELNET",
    "SMTP",
    "RDP",
    "FTP",
)


_PORT_FALLBACK_EXCLUDED_HEADERS = {
    "seq_#",
    "id",
    "rid",
    "name",
    "action",
    "source",
    "destination",
    "schedule",
    "comments",
    "install_on",
    "created_time",
    "last_modified_time",
    "last_modified_by",
    "hit_counts",
    "risk_rating",
    "tl_comment",
    "log",
    "nat",
    "traffic_shaping",
}


def _filter_numeric_tokens(tokens: Iterable[str]) -> list[str]:
    """Return tokens that represent concrete port numbers or ranges."""

    filtered: list[str] = []
    for part in tokens:
        upper = part.upper()
        if upper == "ALL":
            filtered.append(part)
            continue
        stripped = part.replace("-", "")
        if stripped.isdigit():
            filtered.append(part)
            continue
        if "/" in part and any(ch.isdigit() for ch in part):
            filtered.append(part)
            continue
    return filtered


def _token_has_port_hint(token: str) -> bool:
    """Return ``True`` if ``token`` resembles a port or service reference."""

    upper = token.upper()
    if upper in {"ALL", "ANY", "*"}:
        return True
    if upper in SERVICE_NAME_PORTS:
        return True
    if any(upper.startswith(prefix) for prefix in _PORT_MARKER_PREFIXES):
        return True

    stripped = token.replace("-", "")
    if stripped.isdigit():
        return True

    if "/" in token:
        prefix, _, suffix = token.partition("/")
        if suffix and any(ch.isdigit() for ch in suffix):
            prefix_upper = prefix.upper()
            if not prefix:
                return True
            if prefix_upper in _PORT_MARKER_PREFIXES:
                return True
            cleaned_prefix = prefix.replace("-", "")
            if cleaned_prefix.isdigit():
                return True

    return False


def _tokens_contain_port_hint(tokens: Iterable[str]) -> bool:
    return any(_token_has_port_hint(token) for token in tokens)


def _tokenise_service_values(text: str) -> Iterable[str]:
    if not text:
        return []
    cleaned = (
        text.replace("\n", " ")
        .replace(",", " ")
        .replace(";", " ")
        .replace("/ ", "/")
    )
    return [part for part in cleaned.split() if part]


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

        if "/" in cleaned and any(ch.isdigit() for ch in cleaned):
            prefix, _, suffix = cleaned.partition("/")
            suffix_normalised = suffix.replace(" ", "")
            # Previously these tokens were converted directly into bare numbers
            # which caused us to lose the protocol prefix (``TCP/`` or ``UDP/``)
            # when presenting results.  Keep the original token so downstream
            # consumers such as the PDF/CSV reports preserve the vendor's
            # explicit notation while still allowing :func:`parse_ports` to
            # interpret the numeric component when required.
            normalised = cleaned.replace(" ", "")
            lowered = normalised.lower()
            if lowered not in seen_explicit:
                seen_explicit.add(lowered)
                explicit_tokens.append(normalised)
            # For range tokens such as ``TCP/49152-65535`` ensure we still
            # register the numeric bounds so duplicate suppression continues to
            # work when a later bare ``49152-65535`` token is encountered.
            if any(ch.isalpha() for ch in prefix):
                if "-" in suffix_normalised:
                    start, end = suffix_normalised.split("-", 1)
                    if start.isdigit() and end.isdigit() and int(start) <= int(end):
                        for port in (int(start), int(end)):
                            if 1 <= port <= 65535:
                                seen_numeric.add(port)
                elif suffix_normalised.isdigit():
                    port = int(suffix_normalised)
                    if 1 <= port <= 65535:
                        seen_numeric.add(port)
            continue

        if "-" in cleaned:
            range_parts = cleaned.split("-", 1)
            if all(part.isdigit() for part in range_parts):
                lowered = cleaned.lower()
                if lowered not in seen_explicit:
                    seen_explicit.add(lowered)
                    explicit_tokens.append(cleaned)
                continue

        # Handle common tokens such as "TCP_443" or "UDP_49152_65535" by
        # stripping protocol prefixes and normalising range delimiters so that
        # they can be interpreted as numeric ports.  Previously these strings
        # were passed through as literals which meant the downstream
        # ``parse_ports`` routine ignored them entirely.  As a result dozens of
        # client-provided risk ratings were silently dropped because the engine
        # believed no administrative ports were exposed.
        prefix_stripped = re.sub(r"^[A-Za-z]+[-_]*", "", cleaned)
        if prefix_stripped and all(ch.isdigit() or ch in "-_" for ch in prefix_stripped):
            normalised = prefix_stripped.replace("_", "-")
            if "-" in normalised:
                start, end = normalised.split("-", 1)
                if start.isdigit() and end.isdigit():
                    # Ranges will be handled by ``parse_ports`` once converted
                    # back into an explicit token.
                    tokenised = f"{int(start)}-{int(end)}"
                    lowered = tokenised.lower()
                    if lowered not in seen_explicit:
                        seen_explicit.add(lowered)
                        explicit_tokens.append(tokenised)
                    continue
            elif normalised.isdigit():
                port = int(normalised)
                if 1 <= port <= 65535 and port not in seen_numeric:
                    seen_numeric.add(port)
                    numeric_ports.append(port)
                    continue

        mapped = SERVICE_NAME_PORTS.get(upper)
        if mapped is not None:
            for port in mapped:
                if 1 <= port <= 65535 and port not in seen_numeric:
                    seen_numeric.add(port)
                    numeric_ports.append(port)
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
            "Service__1",
            "Service__2",
            "Service__3",
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

    # Some vendor exports place port lists in unlabeled columns adjacent to the
    # ``Service`` field.  These headers are normalised to ``__<n>`` during
    # ingestion, so explicitly scan those positions for known protocol markers
    # before falling back to the broader heuristics.
    for key, value in row.items():
        if not isinstance(key, str) or not key.startswith("__"):
            continue
        value_str = str(value or "").strip()
        if not value_str:
            continue
        tokens = list(_tokenise_service_values(value_str))
        if not tokens or not _tokens_contain_port_hint(tokens):
            continue
        normalised = _prepare_port_tokens(tokens)
        if not normalised:
            continue
        numeric_parts = _filter_numeric_tokens(normalised)
        if not numeric_parts:
            continue
        return ("any", ",".join(numeric_parts))

    svc_name = service_hint or pick_first_present(row, ["Service"])
    if svc_name.strip():
        tokens = list(_tokenise_service_values(str(svc_name)))
        if not tokens:
            return ("any", str(svc_name).strip())
        normalised = _prepare_port_tokens(tokens)
        numeric_parts = _filter_numeric_tokens(normalised)
        if numeric_parts:
            return ("any", ",".join(numeric_parts))

    for key, value in row.items():
        norm_key = normalize_header(str(key)) if key is not None else ""
        if norm_key in _PORT_FALLBACK_EXCLUDED_HEADERS:
            continue
        if "proto" in norm_key:
            continue
        tokens = list(_tokenise_service_values(str(value or "")))
        if not tokens or not _tokens_contain_port_hint(tokens):
            continue
        if not any(
            marker in norm_key
            for marker in ("service", "port", "svc", "sport", "dport")
        ) and not _tokens_contain_port_hint(tokens):
            continue
        normalised = _prepare_port_tokens(tokens)
        if not normalised:
            continue
        numeric_parts = _filter_numeric_tokens(normalised)
        if not numeric_parts:
            continue
        return ("any", ",".join(numeric_parts))

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


def to_rule(row: dict, mapping: dict, *, vendor: str | None = None) -> Rule | None:
    """Map a raw row into a :class:`Rule` or return ``None`` for noise."""
    vendor_name = vendor or mapping.get("__vendor__", "")
    normalized_row = apply_vendor_normalizer(vendor_name, row, mapping)

    rid = pick_first_present(normalized_row, mapping.get("rule_id", [])) or "(unknown)"
    action_raw = pick_first_present(normalized_row, mapping.get("action", [])) or "allow"
    action = normalize_action(action_raw)
    src = pick_first_present(normalized_row, mapping.get("src", [])) or "any"
    dst = pick_first_present(normalized_row, mapping.get("dst", [])) or "any"
    service = pick_first_present(normalized_row, mapping.get("service", ["Service"])) or ""
    proto, port = sniff_proto_port(normalized_row, service_hint=service)
    if proto.strip().lower() in {"", "any"}:
        proto = pick_first_present(normalized_row, mapping.get("proto", ["Protocol", "Proto"])) or "any"
    comment = pick_first_present(normalized_row, mapping.get("comment", [])) or ""
    srcintf = pick_first_present(normalized_row, mapping.get("srcintf", ["Srcintf", "Src Interface"])) or ""
    dstintf = pick_first_present(normalized_row, mapping.get("dstintf", ["Dstintf", "Dst Interface"])) or ""
    source_file = str(normalized_row.get("_source_file", ""))
    risk_rating_fields = mapping.get("risk_rating", [])
    risk_rating_raw = (
        pick_first_present(normalized_row, risk_rating_fields)
        if risk_rating_fields
        else ""
    )
    risk_rating = normalize_risk_rating(risk_rating_raw)

    if rid == "(unknown)" and src == "any" and dst == "any" and port == "any":
        return None

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
    )
