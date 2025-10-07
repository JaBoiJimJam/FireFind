"""Sophos-specific normalisation helpers."""

from __future__ import annotations

from typing import Dict

from .utils import normalize_action, pick_first_present


SERVICE_CANDIDATES = ["Services", "Service", "Service Details"]
PORT_CANDIDATES = ["Service Port", "Port", "Ports", "Service Ports"]
PROTO_CANDIDATES = ["Protocol", "Protocols"]


def normalize_row(row: Dict[str, str], mapping: Dict[str, list]) -> Dict[str, str]:
    """Return a Sophos row normalised for downstream processing."""

    normalized: Dict[str, str] = dict(row)

    action_candidates = mapping.get("action", ["Action", "Rule Action"])
    action_value = pick_first_present(row, action_candidates)
    normalized["Action"] = normalize_action(action_value)

    service_value = pick_first_present(row, mapping.get("service", SERVICE_CANDIDATES))
    if service_value:
        normalized.setdefault("Service", service_value)
        normalized.setdefault("Services", service_value)

    port_value = pick_first_present(row, PORT_CANDIDATES)
    if port_value:
        normalized.setdefault("Service Port", port_value)

    proto_value = pick_first_present(row, mapping.get("proto", PROTO_CANDIDATES))
    if proto_value:
        normalized.setdefault("Protocol", proto_value)
    else:
        normalized.setdefault("Protocol", "any")

    return normalized
