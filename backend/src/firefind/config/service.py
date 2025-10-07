"""Service helpers for manipulating FireFind rules configuration payloads."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping, MutableMapping

from .schema import RulesConfig


def extract_rule_logic(raw_config: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return the rule logic section from ``raw_config``.

    The rules collection is stored directly in the YAML file and therefore is only
    available in the raw configuration rather than the normalised
    :class:`RulesConfig` view. The helper normalises the return type to an empty
    list when the section is absent or invalid so the API surface remains
    predictable.
    """

    rules = raw_config.get("rules", []) if isinstance(raw_config, Mapping) else []
    if isinstance(rules, list):
        return [deepcopy(rule) for rule in rules if isinstance(rule, Mapping)]
    return []


def extract_thresholds(config: RulesConfig) -> dict[str, dict[str, Any]]:
    """Return a serialisable mapping of risk-level thresholds."""

    thresholds: dict[str, dict[str, Any]] = {}
    for name, definition in config.risk_levels.items():
        thresholds[name] = deepcopy(definition.thresholds.to_dict())
    return thresholds


def build_rules_update_patch(
    *,
    current_raw: Mapping[str, Any],
    current_config: RulesConfig,
    rules: list[Mapping[str, Any]] | None,
    thresholds: Mapping[str, Mapping[str, Any]] | None,
) -> MutableMapping[str, Any]:
    """Compose a YAML patch from ``rules`` and ``thresholds`` updates.

    The helper ensures that risk-level updates merge cleanly with both user
    overrides and the default configuration, preventing unrelated sections from
    being clobbered during persistence.
    """

    patch: MutableMapping[str, Any] = {}

    if rules is not None:
        patch["rules"] = [deepcopy(rule) for rule in rules]

    if thresholds:
        risk_patch: dict[str, Any] = {}
        raw_levels = (
            current_raw.get("risk_levels", {})
            if isinstance(current_raw.get("risk_levels"), Mapping)
            else {}
        )

        for level_name, update in thresholds.items():
            normalized_name = str(level_name)
            base: dict[str, Any] = {}

            if isinstance(raw_levels, Mapping) and normalized_name in raw_levels:
                base = deepcopy(raw_levels[normalized_name])
            elif normalized_name in current_config.risk_levels:
                base = deepcopy(current_config.risk_levels[normalized_name].to_dict())
            else:
                base = {
                    "label": normalized_name.replace("_", " ").title(),
                    "severity": "low",
                    "thresholds": {},
                    "rationale": {"summary": "", "details": "", "references": []},
                }

            thresholds_data = dict(base.get("thresholds") or {})
            thresholds_data.update({k: v for k, v in update.items() if v is not None})
            base["thresholds"] = thresholds_data
            risk_patch[normalized_name] = base

        if risk_patch:
            patch["risk_levels"] = risk_patch

    return patch


__all__ = [
    "build_rules_update_patch",
    "extract_rule_logic",
    "extract_thresholds",
]
