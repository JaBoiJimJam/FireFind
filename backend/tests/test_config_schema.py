import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR / "src") not in sys.path:
    sys.path.append(str(BACKEND_DIR / "src"))

from firefind.config.schema import (  # noqa: E402
    CIDRLimitPolicy,
    CIDRLimitSet,
    ConditionComparator,
    ConditionGroup,
    NumericThresholds,
    PortGroup,
    PortRange,
    RuleCondition,
    RuleConditionThreshold,
    RulesConfig,
    Severity,
    _coerce_sequence,
    _parse_condition_group,
    _parse_port_entry,
)


class TestPortParsing:
    def test_parse_port_entry_supports_string_ranges(self):
        port_range = _parse_port_entry("tcp/80-443")
        assert isinstance(port_range, PortRange)
        assert port_range.start == 80
        assert port_range.end == 443

    def test_parse_port_entry_rejects_missing_start(self):
        with pytest.raises(ValueError):
            _parse_port_entry({"end": 22})

    def test_parse_port_entry_accepts_single_value_sequences(self):
        port_range = _parse_port_entry(["53", "53"])
        assert port_range.start == 53
        assert port_range.end == 53


class TestConditionParsing:
    def test_parse_condition_group_honours_any_logic(self):
        raw = {
            "logic": "any",
            "conditions": [
                {"field": "action", "comparator": "equals", "value": "allow"},
                {
                    "logic": "all",
                    "conditions": [
                        {
                            "field": "destination_port",
                            "comparator": "equals",
                            "value": 22,
                        }
                    ],
                },
            ],
        }

        parsed = _parse_condition_group(raw)
        assert isinstance(parsed, ConditionGroup)
        assert parsed.logic == "any"
        assert len(parsed.conditions) == 1
        assert parsed.conditions[0].field == "action"
        assert len(parsed.groups) == 1
        child = parsed.groups[0]
        assert child.logic == "all"
        assert child.conditions[0].field == "destination_port"

    def test_rule_condition_requires_value_or_threshold(self):
        with pytest.raises(ValueError):
            RuleCondition(field="action", comparator=ConditionComparator.EQUALS)

    def test_rule_condition_accepts_threshold_only(self):
        condition = RuleCondition(
            field="score",
            comparator=ConditionComparator.GREATER_THAN,
            threshold=RuleConditionThreshold(min_value=75),
        )
        assert condition.threshold.min_value == 75
        assert "threshold" in condition.to_dict()


class TestSequenceCoercion:
    def test_coerce_sequence_sorts_sets(self):
        values = _coerce_sequence({"a", "b", "a"})
        assert values == tuple(sorted(values))


class TestNumericThresholds:
    def test_threshold_validation_rejects_inverted_ranges(self):
        with pytest.raises(ValueError):
            NumericThresholds(min_score=10, max_score=5)

    def test_cidr_policy_validation_rejects_invalid_prefix(self):
        with pytest.raises(ValueError):
            CIDRLimitPolicy(max_prefix=200)


class TestRiskLevels:
    def test_rules_config_round_trips_custom_risk_level(self):
        raw = {
            "risk_levels": {
                "emerging": {
                    "label": "Emerging Risk",
                    "severity": "HIGH",
                    "thresholds": {
                        "min_score": 10,
                        "max_score": 80,
                        "min_findings": 1,
                    },
                    "rationale": {"summary": "watch list"},
                }
            }
        }

        config = RulesConfig.from_dict(raw)
        assert "emerging" in config.risk_levels
        definition = config.risk_levels["emerging"]
        assert definition.label == "Emerging Risk"
        assert definition.severity is Severity.HIGH
        assert definition.thresholds.min_score == 10
        assert definition.thresholds.max_score == 80
        assert definition.rationale.summary == "watch list"

        exported = config.to_dict()["risk_levels"]["emerging"]
        assert exported["thresholds"]["min_findings"] == 1


class TestCIDRLimits:
    def test_cidr_limit_resolution_honours_override_precedence(self):
        limit = CIDRLimitSet(
            name="broad",
            default=CIDRLimitPolicy(max_prefix=24),
            analyzers={"flow": CIDRLimitPolicy(max_prefix=26)},
            vendors={"acme": CIDRLimitPolicy(max_prefix=25)},
            directions={"inbound": CIDRLimitPolicy(max_prefix=28)},
            vendor_direction_overrides={
                "acme": {"inbound": CIDRLimitPolicy(max_prefix=30)}
            },
        )

        assert limit.resolve().max_prefix == 24
        assert limit.resolve(analyzer="flow").max_prefix == 26
        assert limit.resolve(vendor="acme").max_prefix == 25
        assert limit.resolve(direction="inbound").max_prefix == 28
        # Vendor + direction override should take highest precedence
        assert limit.resolve(vendor="acme", direction="inbound").max_prefix == 30


class TestPortGroups:
    def test_port_group_normalises_protocol_and_ranges(self):
        group = PortGroup(
            name="ssh",
            protocol="TCP",
            ranges=[PortRange(22, 22), PortRange(2222, 2222)],
        )

        assert group.protocol == "tcp"
        assert all(isinstance(range_, PortRange) for range_ in group.ranges)

    def test_port_group_rejects_overlapping_ranges(self):
        with pytest.raises(ValueError):
            PortGroup(
                name="invalid",
                ranges=[PortRange(20, 30), PortRange(25, 35)],
            )