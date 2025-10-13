from pathlib import Path
import sys

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BACKEND_DIR / "src"))

import pytest

from firefind.loaders.csv_xlsx_loader import load_table
from firefind.rules_engine import run_checks
from firefind.utils import load_yaml, pick_mapping, to_rule

MAPPINGS_PATH = BACKEND_DIR / "rules" / "vendor_mappings.yaml"


def _load_rule(vendor: str, sample_name: str):
    vendor_mappings = load_yaml(MAPPINGS_PATH)
    mapping = pick_mapping(vendor_mappings, vendor)

    sample_path = BACKEND_DIR / "samples" / sample_name
    if not sample_path.exists():
        pytest.skip(f"Sample file {sample_name} is not available")

    rows = list(load_table(sample_path))
    assert rows, f"Expected rows in {sample_name}"
    row = rows[0]
    row["_source_file"] = sample_path.name

    rule = to_rule(row, mapping, vendor=vendor)
    assert rule is not None
    return rule


def _assert_admin_port_finding(vendor: str, rule):
    findings = run_checks(vendor, [rule], {})
    assert any(f.finding_type == "admin_port_exposed" for f in findings)


def test_sophos_sample_produces_finding():
    rule = _load_rule("sophos", "sophos_sample.csv")
    assert rule.action == "allow"
    assert rule.port in {"22", "TCP/22"}
    _assert_admin_port_finding("sophos", rule)


def test_barracuda_sample_produces_finding():
    rule = _load_rule("barracuda", "barracuda_sample.csv")
    assert rule.action == "allow"
    assert "3389" in rule.port
    _assert_admin_port_finding("barracuda", rule)


def test_checkpoint_sample_produces_finding():
    rule = _load_rule("checkpoint", "checkpoint_sample.csv")
    assert rule.action == "allow"
    assert rule.port in {"22", "TCP/22"}
    _assert_admin_port_finding("checkpoint", rule)


def test_watchguard_sample_produces_finding():
    rule = _load_rule("watchguard", "watchguard_sample.csv")
    assert rule.action == "allow"
    assert "22" in rule.port
    _assert_admin_port_finding("watchguard", rule)
