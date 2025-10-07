"""Barracuda-specific normalisation helpers."""

from __future__ import annotations

from typing import Dict

from .utils import normalize_action, pick_first_present


SERVICE_CANDIDATES = ["Service", "Services", "Service Name"]
PORT_CANDIDATES = ["Service Port", "Port", "Ports", "Destination Port", "DPort"]
PROTO_CANDIDATES = ["Protocol", "Protocols"]
ACTION_CANDIDATES = ["Action", "Policy Action", "Firewall Action"]


def normalize_row(row: Dict[str, str], mapping: Dict[str, list]) -> Dict[str, str]:
    """Return a Barracuda row normalised for downstream processing."""

    normalized: Dict[str, str] = dict(row)

    action_value = pick_first_present(row, mapping.get("action", ACTION_CANDIDATES))
    normalized["Action"] = normalize_action(action_value)

    service_value = pick_first_present(row, mapping.get("service", SERVICE_CANDIDATES))
    if service_value:
        normalized.setdefault("Service", service_value)

    port_value = pick_first_present(row, mapping.get("port", PORT_CANDIDATES) + PORT_CANDIDATES)
    if port_value:
        normalized.setdefault("Service Port", port_value)

    proto_value = pick_first_present(row, mapping.get("proto", PROTO_CANDIDATES))
    if proto_value:
        normalized.setdefault("Protocol", proto_value)
    else:
        normalized.setdefault("Protocol", "any")

    return normalized
