from pathlib import Path
import sys

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BACKEND_DIR / "src"))

from firefind.rules_engine import ANALYZER_INVENTORY, parse_ports, run_checks
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
    types = {f.finding_type for f in findings}
    assert "allow_any" in types
    assert "broad_cidr" in types


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

    assert ratings["1"] == "Low"
    assert ratings["2"] == "Cautionary"
    assert ratings["3"] == "Low"
    assert ratings["4"] == "Low"


def test_mixed_critical_ports_stay_critical():
    rule = Rule(
        "mixed-critical",
        "10.0.0.0/24",
        "10.1.0.0/24",
        "any",
        "135,137,138,139,445",
        "allow",
    )

    cfg = {
        "admin_ports": [135, 137, 138, 139, 445],
        "critical_risk_admin_ports": [135, 137, 138, 139],
        "high_risk_admin_ports": [],
        "medium_risk_admin_ports": [445],
        "low_risk_admin_ports": [],
    }

    findings = run_checks("vendor", [rule], cfg)
    severities = [
        f.severity for f in findings if f.finding_type == "admin_port_exposed"
    ]
    assert severities == ["Critical"]


def test_http_admin_port_finding_is_cautionary():
    rule = Rule("web", "10.0.0.0/24", "0.0.0.0/0", "tcp", "80", "allow")
    findings = run_checks(
        "vendor",
        [rule],
        {
            "admin_ports": [80],
            "critical_risk_admin_ports": [],
            "high_risk_admin_ports": [],
            "medium_risk_admin_ports": [],
            "low_risk_admin_ports": [],
        },
    )

    severities = [
        f.severity for f in findings if f.finding_type == "admin_port_exposed"
    ]
    assert severities == ["Cautionary"]


def test_run_checks_broad_cidr():
    rule = Rule("3", "10.0.0.0/8", "2.2.2.2", "any", "any", "allow")
    findings = run_checks("v", [rule], {"broad_cidr_prefix_max": 8})
    assert any(f.finding_type == "broad_cidr" for f in findings)


def test_cidr_limits_vendor_override():
    rule = Rule("12", "10.0.0.0/10", "2.2.2.2", "any", "any", "allow")
    cfg = {
        "cidr_limits": {
            "broad_networks": {
                "default": {"max_prefix": 8},
                "vendors": {
                    "example_vendor": {
                        "max_prefix": 12,
                        "description": "Example vendor exports treat /12 as broad.",
                    }
                },
            }
        }
    }

    findings = run_checks("example_vendor", [rule], cfg)
    matching = [f for f in findings if f.finding_type == "broad_cidr"]
    assert matching, "Expected vendor override to trigger broad CIDR finding"
    assert "/12" in matching[0].rationale

    other_vendor = run_checks("other_vendor", [rule], cfg)
    assert not any(f.finding_type == "broad_cidr" for f in other_vendor)


def test_cidr_limits_blocked_and_exempt():
    cfg = {
        "cidr_limits": {
            "broad_networks": {
                "default": {"max_prefix": 0, "blocked": []},
                "vendors": {"example_vendor": {"max_prefix": 0, "blocked": []}},
            },
            "internet": {
                "default": {
                    "max_prefix": 8,
                    "blocked": ["0.0.0.0/0"],
                    "exempt": ["10.0.0.0/8"],
                    "description": "Escalate internet-wide exposure but allow trusted network.",
                }
            }
        }
    }

    blocked_rule = Rule("20", "0.0.0.0/0", "2.2.2.2", "any", "any", "allow")
    blocked_findings = run_checks("example_vendor", [blocked_rule], cfg)
    blocked = [f for f in blocked_findings if f.finding_type == "broad_cidr"]
    assert blocked and blocked[0].severity == "High"
    assert "blocked CIDR" in blocked[0].rationale

    exempt_rule = Rule("21", "10.0.0.0/8", "2.2.2.2", "any", "any", "allow")
    exempt_findings = run_checks("example_vendor", [exempt_rule], cfg)
    assert not any(f.finding_type == "broad_cidr" for f in exempt_findings)


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


def test_run_checks_flags_redundant_rule():
    broad_deny = Rule(
        "100",
        "192.168.0.0/16",
        "10.0.0.0/24",
        "tcp",
        "TCP/9000",
        "deny",
    )
    specific_deny = Rule(
        "200",
        "192.168.1.0/24",
        "10.0.0.0/24",
        "tcp",
        "TCP/9000",
        "deny",
    )

    findings = run_checks(
        "vendor",
        [broad_deny, specific_deny],
        {"rule_overlap": {"redundant_severity": "medium"}},
    )

    redundant = [f for f in findings if f.finding_type == "redundant_rule"]
    assert redundant, "Expected redundant rule finding"
    assert redundant[0].rule_id == "200"
    assert redundant[0].severity == "Medium"


def test_run_checks_flags_shadowed_rule():
    deny_rule = Rule(
        "300",
        "any",
        "10.0.0.0/16",
        "tcp",
        "TCP/9000",
        "deny",
    )
    allow_rule = Rule(
        "400",
        "any",
        "10.0.1.0/24",
        "tcp",
        "TCP/9000",
        "allow",
    )

    findings = run_checks(
        "vendor",
        [deny_rule, allow_rule],
        {"rule_overlap": {"shadowed_severity": "high"}},
    )

    shadowed = [f for f in findings if f.finding_type == "shadowed_rule"]
    assert shadowed, "Expected shadowed rule finding"
    assert shadowed[0].rule_id == "400"
    assert shadowed[0].severity == "High"
    assert "Rule 400" in shadowed[0].rationale


def test_run_analysis_directory_and_dedup(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    csv_content = "Seq #,Source Value,Destination Value,Service,Service.1,Action\n1,any,any,any,22,allow\n"
    (data_dir / "a.csv").write_text(csv_content)
    (data_dir / "b.csv").write_text(csv_content)

    rules_path = BACKEND_DIR / "rules" / "rules.yaml"
    mappings_path = BACKEND_DIR / "rules" / "vendor_mappings.yaml"

    analysis = run_analysis(
        input_path=data_dir,
        vendor="generic",
        rules_path=rules_path,
        mappings_path=mappings_path,
    )

    assert len(analysis.findings) == 3
    types = {f.finding_type for f in analysis.findings}
    assert {"allow_any", "admin_port_exposed", "broad_cidr"} <= types
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

    analysis = run_analysis(
        input_path=data_dir,
        vendor="custom",
        rules_path=rules_yaml,
        mappings_path=mapping_yaml,
    )

    assert len(analysis.findings) == 1
    f = analysis.findings[0]
    assert f.finding_type == "admin_port_exposed"
    assert f.rule_id == "1"
    assert f.src == "1.1.1.1"
    assert f.dst == "2.2.2.2"


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

    analysis = run_analysis(
        input_path=data_dir,
        vendor="noseq",
        rules_path=rules_yaml,
        mappings_path=mapping_yaml,
    )

    assert len(analysis.findings) == 1
    f = analysis.findings[0]
    assert f.finding_type == "admin_port_exposed"
    assert f.rule_id == "1"
    assert f.src == "1.1.1.1"
    assert f.dst == "2.2.2.2"


def test_run_checks_logs_thresholds(caplog):
    rule = Rule("1", "any", "any", "any", "any", "allow")

    caplog.set_level("INFO")
    run_checks("generic", [rule], {})

    records = [r for r in caplog.records if r.message == "Analyzer thresholds resolved"]
    assert records, "Expected structured logging output"

    record = records[0]
    assert "admin_port_exposed" in record.analyzers
    assert record.vendor == "generic"
    assert record.inventory == ANALYZER_INVENTORY
