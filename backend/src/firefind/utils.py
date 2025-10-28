from __future__ import annotations

"""Shared utility functions for FireFind modules."""

from pathlib import Path
from typing import Iterable, Mapping, Tuple
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
    "SMTP": [25],
    "SMTPS": [465],
    "POP3": [110],
    "IMAP": [143],
    "RDP": [3389],
    "SQL": [1433],
    "MYSQL": [3306],
    "POSTGRES": [5432],
    "HTTP_PROXY": [8080],
    "VNC": [5900],
    "PING": [],
    "ICMP": [],
}


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

        numeric_ports: set[int] = set()
        explicit_values: list[str] = []
        seen_explicit: set[str] = set()
        for token in tokens:
            cleaned = token.strip()
            if not cleaned:
                continue
            upper = cleaned.upper()
            if upper in {"ALL", "ANY", "*"}:
                return ("any", "ALL")

            if "/" in cleaned and any(ch.isdigit() for ch in cleaned):
                normalised = cleaned.replace(" ", "")
                lowered = normalised.lower()
                if lowered not in seen_explicit:
                    seen_explicit.add(lowered)
                    explicit_values.append(normalised)
                continue

            if "-" in cleaned:
                range_parts = cleaned.split("-", 1)
                if all(part.isdigit() for part in range_parts):
                    lowered = cleaned.lower()
                    if lowered not in seen_explicit:
                        seen_explicit.add(lowered)
                        explicit_values.append(cleaned)
                    continue

            if cleaned.isdigit():
                port = int(cleaned)
                if 1 <= port <= 65535:
                    numeric_ports.add(port)
                continue

            mapped = SERVICE_NAME_PORTS.get(upper)
            if mapped is not None:
                for port in mapped:
                    if 1 <= port <= 65535:
                        numeric_ports.add(port)
                continue

            lowered = cleaned.lower()
            if lowered not in seen_explicit:
                seen_explicit.add(lowered)
                explicit_values.append(cleaned)

        combined: list[str] = []
        if numeric_ports:
            combined.extend(str(port) for port in sorted(numeric_ports))
        combined.extend(explicit_values)
        if combined:
            return ("any", ",".join(combined))

        return ("any", str(svc_name).strip())

    return ("any", "any")


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
    )
