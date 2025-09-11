from __future__ import annotations

"""Shared utility functions for FireFind modules."""

from pathlib import Path
from typing import Tuple
import yaml

from .model import Rule
from .vendors.utils import pick_first_present


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


def sniff_proto_port(row: dict) -> Tuple[str, str]:
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

    svc_name = pick_first_present(row, ["Service"])
    if svc_name.strip():
        parts = [p.strip() for p in str(svc_name).splitlines() if p.strip()]
        return ("any", ",".join(parts))

    return ("any", "any")


def to_rule(row: dict, mapping: dict) -> Rule | None:
    """Map a raw row into a :class:`Rule` or return ``None`` for noise."""
    rid = pick_first_present(row, mapping.get("rule_id", [])) or "(unknown)"
    action = pick_first_present(row, mapping.get("action", [])) or "allow"
    src = pick_first_present(row, mapping.get("src", [])) or "any"
    dst = pick_first_present(row, mapping.get("dst", [])) or "any"
    proto, port = sniff_proto_port(row)
    comment = pick_first_present(row, mapping.get("comment", [])) or ""

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
    )
