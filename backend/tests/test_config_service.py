from __future__ import annotations

from copy import deepcopy

from firefind.config import (
    DEFAULT_RULES_CONFIG,
    RulesConfig,
    build_rules_update_patch,
    extract_rule_logic,
    extract_thresholds,
)


def test_extract_rule_logic_returns_rules_list():
    raw = {"rules": [{"id": "r1"}, {"id": "r2"}]}
    result = extract_rule_logic(raw)
    assert [rule["id"] for rule in result] == ["r1", "r2"]


def test_extract_thresholds_from_config():
    config = deepcopy(DEFAULT_RULES_CONFIG)
    thresholds = extract_thresholds(config)
    assert "critical" in thresholds
    assert thresholds["critical"]["min_score"] is not None


def test_build_rules_update_patch_merges_thresholds():
    current_raw = {
        "risk_levels": {
            "critical": {
                "label": "Critical Risk",
                "severity": "critical",
                "thresholds": {"min_score": 90},
            }
        }
    }
    current_config = RulesConfig.from_dict(DEFAULT_RULES_CONFIG.to_dict())

    patch = build_rules_update_patch(
        current_raw=current_raw,
        current_config=current_config,
        rules=None,
        thresholds={
            "critical": {"min_score": 95},
            "emerging": {"min_score": 10},
        },
    )

    critical = patch["risk_levels"]["critical"]
    assert critical["label"] == "Critical Risk"
    assert critical["thresholds"]["min_score"] == 95

    emerging = patch["risk_levels"]["emerging"]
    assert emerging["label"] == "Emerging"
    assert emerging["thresholds"]["min_score"] == 10
