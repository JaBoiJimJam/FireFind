from pathlib import Path
import sys

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BACKEND_DIR / "src"))

from firefind.utils import load_yaml, pick_mapping, sniff_proto_port, to_rule
from firefind.model import Rule


def test_load_yaml_empty(tmp_path):
    yaml_file = tmp_path / "empty.yaml"
    yaml_file.write_text("")
    assert load_yaml(yaml_file) == {}


def test_pick_mapping_case_insensitive():
    mappings = {"Fortinet": {"rule_id": ["Seq #"]}, "cisco": {"rule_id": ["Id"]}}
    assert pick_mapping(mappings, "FORTINET") == {"rule_id": ["Seq #"]}
    assert pick_mapping(mappings, "Cisco") == {"rule_id": ["Id"]}


def test_sniff_proto_port_variants():
    row = {"Service.1": "TCP/80\nUDP/53"}
    assert sniff_proto_port(row) == ("any", "TCP/80,UDP/53")
    row2 = {"Other": "TCP/22"}
    assert sniff_proto_port(row2) == ("any", "TCP/22")
    row3 = {"Service": "HTTP"}
    assert sniff_proto_port(row3) == ("any", "HTTP")
    row4 = {}
    assert sniff_proto_port(row4) == ("any", "any")


def test_to_rule_and_noise():
    mapping = {
        "rule_id": ["Seq #"],
        "action": ["Action"],
        "src": ["Source"],
        "dst": ["Dest"],
        "comment": ["Comment"],
    }
    row = {
        "Seq #": "1",
        "Action": "allow",
        "Source": "0.0.0.0/0",
        "Dest": "1.1.1.1",
        "Service.1": "TCP/80",
        "Comment": "test",
    }
    rule = to_rule(row, mapping)
    assert isinstance(rule, Rule)
    assert rule.port == "TCP/80"

    noise_row = {"Seq #": "", "Source": "", "Dest": "", "Service": ""}
    assert to_rule(noise_row, mapping) is None
