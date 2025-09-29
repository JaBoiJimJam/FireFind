from pathlib import Path
import sys

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BACKEND_DIR / "src"))

from firefind.rules_engine import parse_ports, run_checks
from firefind.service import run_analysis
from firefind.model import Rule


def test_parse_ports_single():
    assert parse_ports("80") == [80]


def test_parse_ports_range():
    assert parse_ports("20-22") == [20, 21, 22]


def test_parse_ports_malformed():
    assert parse_ports("abc") == []


def test_run_checks_allow_any():
    rule = Rule("1", "any", "any", "any", "any", "allow")
    findings = run_checks("v", [rule], {})
    assert len(findings) == 1
    assert findings[0].finding_type == "allow_any"


def test_run_checks_admin_port_exposure():
    rule = Rule("2", "1.1.1.1", "2.2.2.2", "any", "22", "allow")
    findings = run_checks("v", [rule], {"admin_ports": [22]})
    assert any(f.finding_type == "admin_port_exposed" for f in findings)


def test_admin_port_risk_rating_varies_with_port():
    rule_critical = Rule("1", "1.1.1.1", "2.2.2.2", "any", "22", "allow")
    rule_high = Rule("2", "1.1.1.1", "2.2.2.2", "any", "3389", "allow")
    rule_medium = Rule("3", "1.1.1.1", "2.2.2.2", "any", "3306", "allow")
    rule_low = Rule("4", "1.1.1.1", "2.2.2.2", "any", "25", "allow")

    cfg = {
        "admin_ports": [22, 3389, 3306, 25],
        "critical_risk_admin_ports": [22],
        "high_risk_admin_ports": [3389],
        "medium_risk_admin_ports": [3306],
        "low_risk_admin_ports": [25],
    }

    findings = run_checks(
        "v", [rule_critical, rule_high, rule_medium, rule_low], cfg
    )
    ratings = {f.rule_id: f.severity for f in findings if f.finding_type == "admin_port_exposed"}

    assert ratings["1"] == "Critical"
    assert ratings["2"] == "High"
    assert ratings["3"] == "Medium"
    assert ratings["4"] == "Low"


def test_run_checks_broad_cidr():
    rule = Rule("3", "10.0.0.0/8", "2.2.2.2", "any", "any", "allow")
    findings = run_checks("v", [rule], {"broad_cidr_prefix_max": 8})
    assert any(f.finding_type == "broad_cidr" for f in findings)


def test_run_checks_all_ports_internet():
    rule = Rule(
        "10",
        "all",
        "all",
        "any",
        "ALL",
        "allow",
        src_interface="LAN1",
        dst_interface="virtual-wan-link",
        service="ALL",
    )
    findings = run_checks("v", [rule], {})
    matching = [f for f in findings if f.finding_type == "all_ports_service"]
    assert matching, "Expected all_ports_service finding"
    assert matching[0].severity == "High"


def test_run_checks_all_ports_internal_scope():
    rule = Rule(
        "11",
        "10.0.0.0/24",
        "10.1.0.0/24",
        "any",
        "ALL",
        "allow",
        src_interface="internal",
        dst_interface="vpn",
        service="ALL",
    )
    findings = run_checks("v", [rule], {})
    matching = [f for f in findings if f.finding_type == "all_ports_service"]
    assert matching, "Expected all_ports_service finding"
    assert matching[0].severity == "Medium"


def test_run_analysis_directory_and_dedup(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    csv_content = "Seq #,Source Value,Destination Value,Service,Service.1,Action\n1,any,any,any,22,allow\n"
    (data_dir / "a.csv").write_text(csv_content)
    (data_dir / "b.csv").write_text(csv_content)

    rules_path = BACKEND_DIR / "rules" / "rules.yaml"
    mappings_path = BACKEND_DIR / "rules" / "vendor_mappings.yaml"

    findings = run_analysis(
        input_path=data_dir,
        vendor="fortinet",
        rules_path=rules_path,
        mappings_path=mappings_path,
    )

    assert len(findings) == 2
    types = {f.finding_type for f in findings}
    assert "allow_any" in types
    assert "admin_port_exposed" in types


def test_run_analysis_custom_config_loading(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    csv = "rid,src_col,dst_col,proto_col,pcol,act_col\n1,1.1.1.1,2.2.2.2,any,TCP/9999,allow\n"
    (data_dir / "rules.csv").write_text(csv)

    rules_yaml = tmp_path / "rules.yml"
    rules_yaml.write_text("admin_ports: [9999]\nbroad_cidr_prefix_max: 8\n")

    mapping_yaml = tmp_path / "mapping.yml"
    mapping_yaml.write_text(
        "custom:\n"
        "  rule_id: ['rid']\n"
        "  src: ['src_col']\n"
        "  dst: ['dst_col']\n"
        "  action: ['act_col']\n"
    )

    findings = run_analysis(
        input_path=data_dir,
        vendor="custom",
        rules_path=rules_yaml,
        mappings_path=mapping_yaml,
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.finding_type == "admin_port_exposed"
    assert f.rule_id == "1"
    assert f.src == "1.1.1.1"
    assert f.dst == "2.2.2.2"
    assert {fl.finding_type for fl in findings} == {"admin_port_exposed"}


def test_run_analysis_no_seq_column(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    csv = "rid,src_col,dst_col,svc_col,act_col\n1,1.1.1.1,2.2.2.2,TCP/9999,allow\n"
    (data_dir / "rules.csv").write_text(csv)

    rules_yaml = tmp_path / "rules.yml"
    rules_yaml.write_text("admin_ports: [9999]\n")

    mapping_yaml = tmp_path / "mapping.yml"
    mapping_yaml.write_text(
        "noseq:\n"
        "  rule_id: ['rid']\n"
        "  src: ['src_col']\n"
        "  dst: ['dst_col']\n"
        "  action: ['act_col']\n"
    )

    findings = run_analysis(
        input_path=data_dir,
        vendor="noseq",
        rules_path=rules_yaml,
        mappings_path=mapping_yaml,
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.finding_type == "admin_port_exposed"
    assert f.rule_id == "1"
    assert f.src == "1.1.1.1"
    assert f.dst == "2.2.2.2"
