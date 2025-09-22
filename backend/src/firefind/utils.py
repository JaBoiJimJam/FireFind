from __future__ import annotations

"""Shared utility functions for FireFind modules."""

from pathlib import Path
from typing import Iterable, Tuple
import yaml

from .model import Rule
from .vendors.utils import pick_first_present


# Mapping of common Fortinet service object names to well-known ports.  These
# values are primarily based on the Client 2 exports whose ``service`` column
# lists human-readable names (e.g. ``HTTP``) rather than explicit ``TCP/80``
# entries.  The dictionary intentionally focuses on the most common services
# that affect exposure analysis; unknown names simply fall back to the raw text.
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


def load_yaml(path: Path) -> dict:
    """Load a YAML file and return an empty dict if the file is empty."""
    with Path(path).open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def pick_mapping(vendor_mappings: dict, vendor: str) -> dict:
    """Return the column mapping for the given vendor."""
    if not vendor_mappings:
        return {}
    v = vendor.lower()
    for k, val in vendor_mappings.items():
        if k.lower() == v:
            return val
    return vendor_mappings.get(vendor, {})


def sniff_proto_port(row: dict, service_hint: str = "") -> Tuple[str, str]:
    """Extract protocol and port information from a raw row."""
    svc_port = pick_first_present(row, ["Service.1", "Service Port", "Port", "DPort"])
    if svc_port.strip():
        parts = [p.strip() for p in str(svc_port).splitlines() if p.strip()]
        return ("any", ",".join(parts))

    for _, v in row.items():
        s = str(v or "").strip().upper()
        if (s.startswith("TCP/") or s.startswith("UDP/")) and any(ch.isdigit() for ch in s):
            parts = [p.strip() for p in s.splitlines() if p.strip()]
            return ("any", ",".join(parts))

    svc_name = service_hint or pick_first_present(row, ["Service"])
    if svc_name.strip():
        tokens = list(_tokenise_service_values(str(svc_name)))
        if not tokens:
            return ("any", str(svc_name).strip())

        ports: list[int] = []
        explicit_values: list[str] = []
        for token in tokens:
            upper = token.upper()
            if upper in {"ALL", "ANY", "*"}:
                return ("any", "ALL")

            if any(ch.isdigit() for ch in token) and "/" in token:
                explicit_values.append(token)
                continue

            mapped = SERVICE_NAME_PORTS.get(upper)
            if mapped is not None:
                ports.extend(mapped)
            else:
                explicit_values.append(token)

        if ports:
            unique = sorted({p for p in ports if 1 <= p <= 65535})
            if unique:
                return ("any", ",".join(str(p) for p in unique))

        if explicit_values:
            return ("any", ",".join(explicit_values))

        return ("any", str(svc_name).strip())

    return ("any", "any")


def to_rule(row: dict, mapping: dict) -> Rule | None:
    """Map a raw row into a :class:`Rule` or return ``None`` for noise."""
    rid = pick_first_present(row, mapping.get("rule_id", [])) or "(unknown)"
    action = pick_first_present(row, mapping.get("action", [])) or "allow"
    src = pick_first_present(row, mapping.get("src", [])) or "any"
    dst = pick_first_present(row, mapping.get("dst", [])) or "any"
    service = pick_first_present(row, mapping.get("service", ["Service"])) or ""
    proto, port = sniff_proto_port(row, service_hint=service)
    comment = pick_first_present(row, mapping.get("comment", [])) or ""
    srcintf = pick_first_present(row, mapping.get("srcintf", ["Srcintf", "Src Interface"])) or ""
    dstintf = pick_first_present(row, mapping.get("dstintf", ["Dstintf", "Dst Interface"])) or ""
    source_file = str(row.get("_source_file", ""))

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
