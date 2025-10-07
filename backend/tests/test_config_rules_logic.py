import sys
from pathlib import Path

import yaml

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BACKEND_DIR / "src"))

from firefind.config.loader import load_rules_config  # noqa: E402
from firefind.config.schema import ConditionComparator  # noqa: E402


def test_loader_populates_rule_logic_from_defaults(tmp_path):
    config_path = tmp_path / "rules.yaml"
    config_path.write_text("admin_ports:\n  - 2022\n", encoding="utf-8")

    cfg = load_rules_config(config_path)

    assert "admin_port_exposed" in cfg.rule_definitions
    rule = cfg.rule_definitions["admin_port_exposed"]
    assert rule.conditions.logic == "all"
    assert any(
        condition.field == "action"
        and condition.comparator == ConditionComparator.EQUALS
        and condition.value == "allow"
        for condition in rule.conditions.conditions
    )

    analyzer = rule.analyzers["admin_port_exposed"]
    # Baseline ports inherit from the file while overrides fall back to defaults
    assert 2022 in analyzer.admin_ports.baseline
    assert "critical" in analyzer.admin_ports.per_risk_overrides
    assert analyzer.admin_ports.per_risk_overrides["critical"]


def test_loader_merges_custom_rule_logic(tmp_path):
    config_path = tmp_path / "rules.yaml"
    config_data = {
        "admin_ports": [22, 443],
        "rules": {
            "admin_port_exposed": {
                "conditions": {
                    "logic": "any",
                    "conditions": [
                        {"field": "action", "comparator": "equals", "value": "deny"}
                    ],
                },
                "analyzers": {
                    "admin_port_exposed": {
                        "enabled": False,
                        "admin_ports": {"baseline": [22]}
                    }
                },
            }
        },
    }
    config_path.write_text(yaml.safe_dump(config_data), encoding="utf-8")

    cfg = load_rules_config(config_path)

    rule = cfg.rule_definitions["admin_port_exposed"]
    assert rule.conditions.logic == "any"
    assert rule.analyzers["admin_port_exposed"].enabled is False
    # Severity overrides should be retained from defaults even when not supplied
    assert "critical" in rule.analyzers["admin_port_exposed"].severity_overrides
