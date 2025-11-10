from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest
import yaml

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR / "src") not in sys.path:
    sys.path.append(str(BACKEND_DIR / "src"))

from firefind.config import (  # noqa: E402
    RulesConfigStore,
    Severity,
)


@pytest.fixture()
def config_store(tmp_path):
    config_path = tmp_path / "rules.yaml"
    history_path = tmp_path / "rules.history.jsonl"
    store = RulesConfigStore(config_path=config_path, history_path=history_path)
    return store, config_path, history_path


def test_rules_config_store_import_export_round_trip(config_store):
    store, config_path, history_path = config_store

    patch = {
        "risk_levels": {
            "emerging": {
                "label": "Emerging Risk",
                "severity": "medium",
                "thresholds": {
                    "min_score": 10,
                    "max_score": 30,
                    "min_findings": 1,
                },
                "rationale": {"summary": "Watch list"},
            }
        },
        "cidr_limits": {
            "restricted": {
                "default": {
                    "max_prefix": 24,
                    "blocked": ["10.0.0.0/8"],
                    "exempt": ["10.2.0.0/16"],
                    "description": "Restrict broad RFC1918 ranges",
                },
                "vendors": {"acme": {"max_prefix": 26}},
                "directions": {"inbound": {"max_prefix": 28}},
                "vendor_direction_overrides": {
                    "acme": {"inbound": {"max_prefix": 30}}
                },
            }
        },
        "port_groups": {
            "ssh": {
                "description": "Managed SSH ports",
                "protocol": "TCP",
                "ranges": ["22", {"start": 2222, "end": 2222}],
            }
        },
    }

    config, revision = store.update(patch, actor="qa", summary="Add structured data")

    assert revision.version == 1
    assert revision.summary == "Add structured data"
    assert config.risk_levels["emerging"].severity is Severity.MEDIUM
    assert config.risk_levels["emerging"].thresholds.max_score == 30

    cidr_limit = config.cidr_limits["restricted"]
    assert cidr_limit.default.max_prefix == 24
    assert cidr_limit.resolve().max_prefix == 24
    assert cidr_limit.resolve(vendor="acme").max_prefix == 26
    assert cidr_limit.resolve(direction="inbound").max_prefix == 28
    assert cidr_limit.resolve(vendor="acme", direction="inbound").max_prefix == 30

    port_group = config.port_groups.groups["ssh"]
    assert port_group.protocol == "tcp"
    assert any(port_range.start == 22 for port_range in port_group.ranges)
    assert any(port_range.start == 2222 for port_range in port_group.ranges)

    stored = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert stored["risk_levels"]["emerging"]["thresholds"]["min_score"] == 10
    assert stored["cidr_limits"]["restricted"]["default"]["blocked"] == [
        "10.0.0.0/8"
    ]
    assert stored["port_groups"]["ssh"]["protocol"] == "TCP"

    assert history_path.exists()
    history_records = [
        json.loads(line)
        for line in history_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(history_records) == 1
    assert history_records[0]["summary"] == "Add structured data"

    reloaded = store.load_active()
    assert "emerging" in reloaded.risk_levels
    assert reloaded.cidr_limits["restricted"].resolve(vendor="acme", direction="inbound").max_prefix == 30