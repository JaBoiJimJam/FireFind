import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR / "src") not in sys.path:
    sys.path.append(str(BACKEND_DIR / "src"))

from firefind.config.schema import (  # noqa: E402
    CIDRLimitPolicy,
    ConditionComparator,
    ConditionGroup,
    NumericThresholds,
    PortRange,
    RuleCondition,
    RuleConditionThreshold,
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
