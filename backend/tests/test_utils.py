from pathlib import Path
import sys

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BACKEND_DIR / "src"))

import pytest

from firefind.config.schema import RulesConfig
from firefind.utils import (
    RuleValidationError,
    load_yaml,
    pick_mapping,
    sniff_proto_port,
    to_rule,
)
from firefind.model import Rule


def test_load_yaml_empty(tmp_path):
    yaml_file = tmp_path / "empty.yaml"
    yaml_file.write_text("")
    assert load_yaml(yaml_file) == {}


def test_pick_mapping_case_insensitive():
    mappings = {"Generic": {"rule_id": ["Seq #"]}, "cisco": {"rule_id": ["Id"]}}
    generic = pick_mapping(mappings, "GENERIC")
    assert generic["__vendor__"] == "Generic"
    assert generic["rule_id"] == ["Seq #"]

    cisco = pick_mapping(mappings, "Cisco")
    assert cisco["__vendor__"] == "cisco"
    assert cisco["rule_id"] == ["Id"]


def test_sniff_proto_port_variants():
    row = {"Service.1": "TCP/80\nUDP/53"}
    assert sniff_proto_port(row) == ("any", "TCP/80,UDP/53")
    row2 = {"Other": "TCP/22"}
    assert sniff_proto_port(row2) == ("any", "TCP/22")
    row3 = {"Service": "HTTP"}
    assert sniff_proto_port(row3) == ("any", "80")
    row5 = {"Service": "HTTP HTTPS"}
    assert sniff_proto_port(row5) == ("any", "80,443")
    row6 = {"Service": "ALL"}
    assert sniff_proto_port(row6) == ("any", "ALL")
    row7 = {"Ports": "TCP/443"}
    assert sniff_proto_port(row7) == ("any", "TCP/443")
    netbios_row = {"Service": "NBT_ natagram nbname_tcp"}
    assert sniff_proto_port(netbios_row) == ("any", "137,138,139")
    row4 = {}
    assert sniff_proto_port(row4) == ("any", "any")


def test_to_rule_and_noise():
    mapping = {
        "rule_id": ["Seq #"],
        "action": ["Action"],
        "src": ["Source"],
        "dst": ["Dest"],
        "comment": ["Comment"],
        "service": ["Service"],
        "srcintf": ["Srcintf"],
        "dstintf": ["Dstintf"],
    }
    row = {
        "Seq #": "1",
        "Action": "allow",
        "Source": "0.0.0.0/0",
        "Dest": "1.1.1.1",
        "Service": "HTTP",
        "Srcintf": "internal",
        "Dstintf": "virtual-wan-link",
        "Comment": "test",
    }
    rule = to_rule(row, mapping, vendor="generic")
    assert isinstance(rule, Rule)
    assert rule.port == "80"
    assert rule.service == "HTTP"
    assert rule.src_interface == "internal"
    assert rule.dst_interface == "virtual-wan-link"
    assert rule.tags == ()

    noise_row = {"Seq #": "", "Source": "", "Dest": "", "Service": ""}
    with pytest.raises(RuleValidationError):
        to_rule(noise_row, mapping, vendor="generic")


def test_to_rule_extracts_tags_from_mapping_and_config():
    mapping = {
        "rule_id": ["ID"],
        "action": ["Action"],
        "src": ["Source"],
        "dst": ["Destination"],
        "tags": {
            "columns": [["Category"]],
            "defaults": ["vendor-default"],
        },
    }

    row = {
        "ID": "10",
        "Action": "allow",
        "Source": "0.0.0.0/0",
        "Destination": "10.0.0.10",
        "Category": "Secure Remote",
    }

    cfg = RulesConfig.from_dict(
        {
            "default_rule_tags": ["baseline"],
            "functional_tag_aliases": {"secure remote": ["remote-access", "vpn"]},
        }
    )

    rule = to_rule(row, mapping, vendor="generic", config=cfg)
    assert rule.tags == ("baseline", "vendor-default", "remote-access", "vpn")


def test_to_rule_missing_required_field_raises():
    mapping = {
        "rule_id": ["Seq #"],
        "src": ["Source"],
        "dst": ["Destination"],
    }

    row = {"Seq #": "", "Source": "10.0.0.0/24", "Destination": ""}

    with pytest.raises(RuleValidationError) as excinfo:
        to_rule(row, mapping, vendor="generic")

    assert any(issue.code == "missing_required" for issue in excinfo.value.issues)


def test_to_rule_invalid_ip_detection():
    mapping = {
        "rule_id": ["Seq #"],
        "src": ["Source"],
        "dst": ["Destination"],
    }

    row = {
        "Seq #": "10",
        "Source": "999.999.999.999",
        "Destination": "10.0.0.0/24",
    }

    with pytest.raises(RuleValidationError) as excinfo:
        to_rule(row, mapping, vendor="generic")

    assert any(issue.code == "invalid_address" and issue.field == "src" for issue in excinfo.value.issues)


def test_to_rule_invalid_port_detection():
    mapping = {
        "rule_id": ["Seq #"],
        "src": ["Source"],
        "dst": ["Destination"],
        "service": ["Service"],
    }

    row = {
        "Seq #": "11",
        "Source": "10.0.0.0/24",
        "Destination": "10.0.0.10",
        "Service": "TCP/invalid",
    }

    with pytest.raises(RuleValidationError) as excinfo:
        to_rule(row, mapping, vendor="generic")

    assert any(issue.code == "invalid_port" for issue in excinfo.value.issues)