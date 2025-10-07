"""Migration helpers for normalising rules configuration dictionaries."""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Iterable, Mapping, MutableMapping

from .schema import RulesConfig


def ensure_rule_logic_structure(
    config: MutableMapping[str, Any], *, defaults: RulesConfig, original: Mapping[str, Any] | None = None
) -> None:
    """Ensure ``config`` contains the new structured rule logic definition."""

    if not isinstance(config, MutableMapping):
        raise TypeError("Configuration must be a mapping to apply migrations")

    existing_rules = config.get("rules")
    user_rules = original.get("rules") if isinstance(original, Mapping) else None
    had_rules_section = isinstance(user_rules, MutableMapping)
    rules_section = existing_rules if had_rules_section else {}
    if not had_rules_section:
        config["rules"] = rules_section

    default_rule_dicts = {
        rule_id: rule.to_dict() for rule_id, rule in defaults.rule_definitions.items()
    }

    for rule_id, default_rule in default_rule_dicts.items():
        existing = rules_section.get(rule_id)
        if not isinstance(existing, MutableMapping):
            rules_section[rule_id] = deepcopy(default_rule)
        else:
            _deep_default_merge(existing, default_rule)

    admin_rule = rules_section.get("admin_port_exposed")
    if isinstance(admin_rule, MutableMapping):
        admin_rule.setdefault("id", "admin_port_exposed")
        admin_rule.setdefault("label", "Administrative Port Exposure")
        admin_rule.setdefault(
            "description",
            "Flags allow rules that expose administrative services to untrusted networks.",
        )

        default_admin_rule = default_rule_dicts.get("admin_port_exposed", {})
        user_admin_rule = (
            user_rules.get("admin_port_exposed") if isinstance(user_rules, Mapping) else None
        )
        user_analyzers = (
            user_admin_rule.get("analyzers") if isinstance(user_admin_rule, Mapping) else None
        )
        user_analyzer = (
            user_analyzers.get("admin_port_exposed") if isinstance(user_analyzers, Mapping) else None
        )
        user_ports_config = (
            user_analyzer.get("admin_ports") if isinstance(user_analyzer, Mapping) else None
        )
        conditions = admin_rule.get("conditions")
        if not isinstance(conditions, MutableMapping):
            admin_rule["conditions"] = deepcopy(default_admin_rule.get("conditions", {}))

        analyzers = admin_rule.get("analyzers")
        if not isinstance(analyzers, MutableMapping):
            analyzers = {}
            admin_rule["analyzers"] = analyzers

        analyzer = analyzers.get("admin_port_exposed")
        existing_analyzer = analyzer if isinstance(analyzer, MutableMapping) else None
        if not isinstance(analyzer, MutableMapping):
            analyzer = {}
            analyzers["admin_port_exposed"] = analyzer

        analyzer.setdefault("enabled", True)
        analyzer.setdefault(
            "notes",
            "Derives severity tiers from configured administrative port sets.",
        )

        default_severity = (
            default_admin_rule.get("analyzers", {})
            .get("admin_port_exposed", {})
            .get("severity_overrides", {})
        )
        severity_overrides = analyzer.get("severity_overrides")
        if not isinstance(severity_overrides, MutableMapping):
            analyzer["severity_overrides"] = deepcopy(default_severity)
        else:
            _deep_default_merge(severity_overrides, default_severity)

        ports = analyzer.get("admin_ports")
        if not isinstance(ports, MutableMapping):
            ports = {}
            analyzer["admin_ports"] = ports

        if (
            not isinstance(user_ports_config, Mapping)
            or "baseline" not in user_ports_config
        ):
            ports["baseline"] = sorted(
                _normalize_admin_port_values(
                    config.get("admin_ports"), defaults.admin_ports
                )
            )

        overrides = ports.get("per_risk_overrides")
        if not isinstance(overrides, MutableMapping):
            overrides = {}
            ports["per_risk_overrides"] = overrides

        for risk_key in ("critical", "high", "medium", "low"):
            legacy_key = f"{risk_key}_risk_admin_ports"
            risk_ports = _normalize_admin_port_values(
                config.get(legacy_key), getattr(defaults, f"{legacy_key}")
            )
            user_override_ports = (
                user_ports_config.get("per_risk_overrides", {})
                if isinstance(user_ports_config, Mapping)
                else {}
            )
            if (
                risk_ports
                and (
                    not isinstance(user_override_ports, Mapping)
                    or risk_key not in user_override_ports
                )
            ):
                overrides[risk_key] = sorted(risk_ports)


def _normalize_admin_port_values(
    value: Any, fallback: Iterable[int]
) -> set[int]:
    normalized: set[int] = set()
    if isinstance(value, Mapping):
        candidates = value.values()
    elif isinstance(value, (list, tuple, set)):
        candidates = value
    elif isinstance(value, (str, bytes)):
        candidates = [value]
    elif value is None:
        candidates = []
    else:
        candidates = [value]

    for candidate in candidates:
        try:
            normalized.add(int(candidate))
        except (TypeError, ValueError):
            continue

    if not normalized:
        normalized = {int(port) for port in fallback or []}
    return normalized


def _deep_default_merge(target: MutableMapping[str, Any], defaults: Mapping[str, Any]) -> None:
    for key, value in defaults.items():
        if key not in target:
            target[key] = deepcopy(value)
            continue
        existing = target[key]
        if isinstance(existing, MutableMapping) and isinstance(value, Mapping):
            _deep_default_merge(existing, value)
