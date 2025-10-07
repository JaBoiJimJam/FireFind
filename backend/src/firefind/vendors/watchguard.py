"""WatchGuard-specific normalisation helpers."""

from __future__ import annotations

from typing import Dict

from .utils import normalize_action, pick_first_present


PROTO_CANDIDATES = ["Protocol", "Protocols"]
PORT_CANDIDATES = ["Port", "Ports", "Service Port", "Service Ports"]
ACTION_CANDIDATES = ["Action", "Policy Action", "Enable"]


def _format_service_port(proto: str, port: str) -> str:
    proto_clean = (proto or "").strip()
    port_clean = (port or "").strip()
    if not port_clean:
        return ""
    if not proto_clean:
        return port_clean
    if "/" in port_clean:
        return port_clean
    return f"{proto_clean.upper()}/{port_clean}"


def normalize_row(row: Dict[str, str], mapping: Dict[str, list]) -> Dict[str, str]:
    """Return a WatchGuard row normalised for downstream processing."""

    normalized: Dict[str, str] = dict(row)

    action_value = pick_first_present(row, mapping.get("action", ACTION_CANDIDATES))
    normalized["Action"] = normalize_action(action_value)

    proto_value = pick_first_present(row, mapping.get("proto", PROTO_CANDIDATES))
    if proto_value:
        normalized.setdefault("Protocol", proto_value)
    else:
        normalized.setdefault("Protocol", "any")

    port_value = pick_first_present(row, PORT_CANDIDATES)
    if port_value:
        formatted = _format_service_port(normalized.get("Protocol", ""), port_value)
        normalized.setdefault("Service Port", formatted or port_value)
        if formatted:
            normalized.setdefault("Port", formatted)
    else:
        normalized.setdefault("Service Port", "any")

    return normalized
