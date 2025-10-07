"""Fortinet-specific normalisation helpers."""

from __future__ import annotations

from typing import Dict

from .utils import normalize_action, pick_first_present


def normalize_row(row: Dict[str, str], mapping: Dict[str, list]) -> Dict[str, str]:
    """Return a Fortinet row with consistent defaults applied."""

    normalized: Dict[str, str] = dict(row)

    proto_candidates = mapping.get("proto", ["Proto", "Protocol"])
    proto = pick_first_present(row, proto_candidates)
    if not proto:
        normalized.setdefault("Proto", "any")

    action_candidates = mapping.get("action", ["Action"])
    action_value = pick_first_present(row, action_candidates)
    normalized["Action"] = normalize_action(action_value)

    port_candidates = ["Service.1", "Service Port", "Port", "DPort"]
    port_value = pick_first_present(row, port_candidates)
    if port_value:
        normalized.setdefault("Service Port", port_value)

    service_candidates = mapping.get("service", ["Service"])
    service_value = pick_first_present(row, service_candidates)
    if service_value:
        normalized.setdefault("Service", service_value)

    return normalized
