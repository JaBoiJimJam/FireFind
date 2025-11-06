from pathlib import Path
import sys

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BACKEND_DIR / "src"))

import pytest

from firefind.model import Finding, Rule
from firefind.rules_engine import (
    ANALYZER_INVENTORY,
    _adjust_admin_port_severity,
    classify_admin_port_severity,
    is_all_ports,
    generate_risk_code,
    parse_ports,
    run_checks,
)
from firefind.service import deduplicate_findings, run_analysis


def test_parse_ports_single():
    assert parse_ports("80") == [80]


def test_parse_ports_range():
    assert parse_ports("20-22") == [20, 21, 22]


def test_parse_ports_malformed():
    assert parse_ports("abc") == []


def test_parse_ports_all_tokens():
    tcp_zero = parse_ports("tcp/0")
    udp_zero = parse_ports("udp/0")
    bare_zero = parse_ports("0")

    assert tcp_zero
    assert tcp_zero == udp_zero == bare_zero


@pytest.mark.parametrize("value", ["0", "tcp/0", "udp/0", "IP/0"])
def test_is_all_ports_extended_tokens(value):
    assert is_all_ports(value)


def test_generate_risk_code_info_prefix():
    code = generate_risk_code("allow_any", "Info", 1)
    assert code == "FR-allow_any-INFGEN-001"


def test_run_checks_allow_any():
    rule = Rule("1", "any", "any", "any", "all", "allow", risk_rating="High")
    findings = run_checks("v", [rule], {})
    types = {f.finding_type for f in findings}
    assert "allow_any" in types
    assert "broad_cidr" in types
    assert "all_ports_service" in types

    codes = {f.finding_type: f.risk_code for f in findings}
    assert codes["allow_any"] == "FR-allow_any-HIGEN-001"
    assert codes["broad_cidr"].startswith("FR-broad_cidr-")
    assert codes["all_ports_service"].startswith("FR-all_ports_service-")

    sequence = [
        int(codes["allow_any"].split("-")[-1]),
        int(codes["broad_cidr"].split("-")[-1]),
        int(codes["all_ports_service"].split("-")[-1]),
    ]
    assert sequence == sorted(sequence)
    assert len(set(sequence)) == 3


def test_rule_tags_propagate_to_findings():
    rule = Rule(
        "tagged",
        "any",
        "any",
        "any",
        "any",
        "allow",
        tags=("custom-tag",),
        risk_rating="High",
    )
    findings = run_checks("vendor", [rule], {})
    allow_any = next(f for f in findings if f.finding_type == "allow_any")
    assert "custom-tag" in allow_any.tags
    assert "excessive-access" in allow_any.tags


def test_run_checks_admin_port_exposure():
    rule = Rule("2", "1.1.1.1", "2.2.2.2", "any", "22", "allow", risk_rating="High")
    findings = run_checks("v", [rule], {"admin_ports": [22]})
    assert any(f.finding_type == "admin_port_exposed" for f in findings)


def test_run_checks_admin_port_wildcard_service_name():
    for service_label in ("Any", "Any Service"):
        rule = Rule(
            f"wild-{service_label.lower().replace(' ', '-')}",
            "1.1.1.1",
            "2.2.2.2",
            "any",
            "",
            "allow",
            service=service_label,
            risk_rating="High",
        )

        findings = run_checks("v", [rule], {})
        matching = [f for f in findings if f.finding_type == "admin_port_exposed"]

        assert matching, f"Expected admin_port_exposed finding for {service_label}"
        assert matching[0].severity == "High"


@pytest.mark.parametrize("port_value", ["0", "tcp/0", "udp/0", "IP/0"])
def test_admin_port_wildcard_tokens_escalate(port_value):
    rule = Rule(
        f"all-{port_value}",
        "0.0.0.0/0",
        "10.0.0.10",
        "any",
        port_value,
        "allow",
        source_file="test.conf",
    )

    findings = run_checks("vendor", [rule], {"admin_ports": [22]})
    severities = [
        f.severity for f in findings if f.finding_type == "admin_port_exposed"
    ]
    assert severities
    assert all(sev in {"High", "Critical"} for sev in severities)


@pytest.mark.parametrize(
    "port_value",
    ["80", "53", "88", "123", "389", "464", "636", "1433", "3268", "3269", "1434"],
)
def test_single_web_infra_admin_port_info(port_value):
    rule = Rule(
        f"info-{port_value}",
        "10.0.0.0/24",
        "10.0.0.10",
        "tcp",
        port_value,
        "allow",
        source_file="test.conf",
    )

    cfg = {
        "admin_ports": [int(port_value)],
        "critical_risk_admin_ports": [9999],
        "high_risk_admin_ports": [9998],
        "medium_risk_admin_ports": [9997],
        "low_risk_admin_ports": [9996],
    }

    findings = run_checks("vendor", [rule], cfg)
    severities = [
        f.severity for f in findings if f.finding_type == "admin_port_exposed"
    ]
    assert severities == ["Info"]


def test_single_web_port_with_high_risk_companion_not_info():
    rule = Rule(
        "combo",
        "10.0.0.0/24",
        "10.0.0.10",
        "tcp",
        "80,22",
        "allow",
        source_file="test.conf",
    )

    cfg = {
        "admin_ports": [22, 80],
        "critical_risk_admin_ports": [22],
        "high_risk_admin_ports": [22],
        "medium_risk_admin_ports": [],
        "low_risk_admin_ports": [],
    }

    findings = run_checks("vendor", [rule], cfg)
    severities = [
        f.severity for f in findings if f.finding_type == "admin_port_exposed"
    ]
    assert severities and severities[0] != "Info"


def test_admin_port_risk_rating_varies_with_port():
    rule_critical = Rule(
        "1",
        "1.1.1.1",
        "2.2.2.2",
        "any",
        "22",
        "allow",
        risk_rating="Low",
    )
    rule_high = Rule(
        "2",
        "1.1.1.1",
        "2.2.2.2",
        "any",
        "3389",
        "allow",
        risk_rating="Cautionary",
    )
    rule_medium = Rule(
        "3",
        "1.1.1.1",
        "2.2.2.2",
        "any",
        "3306",
        "allow",
        risk_rating="Low",
    )
    rule_low = Rule(
        "4",
        "1.1.1.1",
        "2.2.2.2",
        "any",
        "25",
        "allow",
        risk_rating="Low",
    )

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


def test_classify_admin_port_severity_rdp_alone_high():
    severity = classify_admin_port_severity({3389}, {22}, {3389}, set())
    assert severity == "High"


def test_classify_admin_port_severity_http_https_pair_cautionary():
    severity = classify_admin_port_severity({80, 443}, set(), set(), set())
    assert severity == "Cautionary"


@pytest.mark.parametrize("port", [80, 53, 88, 123, 389, 464, 636, 1433, 3268, 3269, 1434])
def test_classify_admin_port_severity_single_web_info(port):
    severity = classify_admin_port_severity({port}, set(), set(), set())
    assert severity == "Info"


def test_classify_admin_port_severity_rdp_web_combos_cautionary():
    high_risk_ports = {3389}
    for ports in ({3389, 80}, {3389, 443}, {3389, 80, 443}):
        severity = classify_admin_port_severity(ports, set(), high_risk_ports, set())
        assert severity == "Cautionary"


def test_scoped_ssh_admin_port_does_not_drop_below_medium():
    rule = Rule(
        "ssh-narrow",
        "10.0.0.10",
        "10.0.0.11",
        "tcp",
        "22",
        "allow",
        source_file="test.conf",
    )

    cfg = {
        "admin_ports": [22],
        "critical_risk_admin_ports": [],
        "high_risk_admin_ports": [22],
        "medium_risk_admin_ports": [],
        "low_risk_admin_ports": [],
    }

    findings = run_checks("vendor", [rule], cfg)
    severities = [
        f.severity for f in findings if f.finding_type == "admin_port_exposed"
    ]
    assert severities == ["Medium"]


def test_adjust_admin_port_severity_respects_info_floor():
    rule = Rule(
        "info-floor",
        "10.0.0.0/24",
        "10.0.0.10",
        "tcp",
        "80",
        "allow",
    )

    result = _adjust_admin_port_severity(
        rule,
        "Info",
        {80},
        critical_ports=set(),
        high_ports=set(),
        medium_ports=set(),
        low_ports=set(),
    )

    assert result == "Info"


def test_scoped_rdp_admin_port_remains_high():
    rule = Rule(
        "rdp-narrow",
        "10.0.0.10",
        "10.0.0.11",
        "tcp",
        "3389",
        "allow",
        source_file="test.conf",
    )

    cfg = {
        "admin_ports": [3389],
        "critical_risk_admin_ports": [],
        "high_risk_admin_ports": [3389],
        "medium_risk_admin_ports": [],
        "low_risk_admin_ports": [],
    }

    findings = run_checks("vendor", [rule], cfg)
    severities = [
        f.severity for f in findings if f.finding_type == "admin_port_exposed"
    ]
    assert severities == ["High"]


def test_critical_web_infra_port_remains_critical():
    rule = Rule(
        "kerberos-admin",
        "10.0.0.10",
        "10.0.0.11",
        "tcp",
        "464",
        "allow",
        source_file="test.conf",
    )

    cfg = {
        "admin_ports": [464],
        "critical_risk_admin_ports": [464],
        "high_risk_admin_ports": [],
        "medium_risk_admin_ports": [],
        "low_risk_admin_ports": [],
    }

    findings = run_checks("vendor", [rule], cfg)
    severities = [
        f.severity for f in findings if f.finding_type == "admin_port_exposed"
    ]
    assert severities == ["Critical"]


def test_web_infra_critical_scope_downgrade_blocked():
    rule = Rule(
        "kerberos-admin",
        "10.0.0.10",
        "10.0.0.11",
        "tcp",
        "464",
        "allow",
        source_file="test.conf",
    )

    downgraded = _adjust_admin_port_severity(
        rule,
        "Critical",
        {464},
        critical_ports=set(),
        high_ports=set(),
        medium_ports=set(),
        low_ports=set(),
    )
    assert downgraded == "Cautionary"

    severity = _adjust_admin_port_severity(
        rule,
        "Critical",
        {464},
        critical_ports={464},
        high_ports=set(),
        medium_ports=set(),
        low_ports=set(),
    )
    assert severity == "Critical"


def test_mixed_critical_ports_stay_critical():
    rule = Rule(
        "mixed-critical",
        "10.0.0.0/24",
        "10.1.0.0/24",
        "any",
        "135,137,138,139,445",
        "allow",
        risk_rating="Critical",
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
    rule = Rule(
        "web",
        "10.0.0.0/24",
        "0.0.0.0/0",
        "tcp",
        "80",
        "allow",
        risk_rating="Cautionary",
    )
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
    rule = Rule("3", "10.0.0.0/8", "2.2.2.2", "any", "any", "allow", risk_rating="Medium")
    findings = run_checks("v", [rule], {"broad_cidr_prefix_max": 8})
    assert any(f.finding_type == "broad_cidr" for f in findings)


def test_cidr_limits_vendor_override():
    rule = Rule(
        "12",
        "10.0.0.0/10",
        "2.2.2.2",
        "any",
        "any",
        "allow",
        risk_rating="Medium",
    )
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

    blocked_rule = Rule(
        "20",
        "0.0.0.0/0",
        "2.2.2.2",
        "any",
        "any",
        "allow",
        risk_rating="High",
    )
    blocked_findings = run_checks("example_vendor", [blocked_rule], cfg)
    blocked = [f for f in blocked_findings if f.finding_type == "broad_cidr"]
    assert blocked and blocked[0].severity == "High"
    assert "blocked CIDR" in blocked[0].rationale

    exempt_rule = Rule(
        "21",
        "10.0.0.0/8",
        "2.2.2.2",
        "any",
        "any",
        "allow",
        risk_rating="Medium",
    )
    exempt_findings = run_checks("example_vendor", [exempt_rule], cfg)
    assert not any(f.finding_type == "broad_cidr" for f in exempt_findings)


def test_unrated_rules_do_not_emit_findings():
    cfg = {"admin_ports": [22], "broad_cidr_prefix_max": 8}

    rated_admin = Rule(
        "rated-admin",
        "10.0.0.10",
        "192.0.2.1",
        "any",
        "22",
        "allow",
        risk_rating="High",
    )
    unrated_admin = Rule(
        "unrated-admin",
        "10.0.0.11",
        "192.0.2.2",
        "any",
        "22",
        "allow",
    )
    rated_broad = Rule(
        "rated-broad",
        "10.0.0.0/8",
        "192.0.2.3",
        "any",
        "any",
        "allow",
        risk_rating="Medium",
    )
    invalid_broad = Rule(
        "invalid-broad",
        "172.16.0.0/8",
        "192.0.2.4",
        "any",
        "any",
        "allow",
        risk_rating="severe",  # fails normalisation
    )

    findings = run_checks(
        "generic",
        [rated_admin, unrated_admin, rated_broad, invalid_broad],
        cfg,
    )

    admin_ids = {f.rule_id for f in findings if f.finding_type == "admin_port_exposed"}
    cidr_ids = {f.rule_id for f in findings if f.finding_type == "broad_cidr"}

    assert admin_ids == {"rated-admin"}
    assert cidr_ids == {"rated-broad"}
    skipped_ids = {"unrated-admin", "invalid-broad"}
    assert not ({f.rule_id for f in findings} & skipped_ids)


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
        risk_rating="High",
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
        risk_rating="Medium",
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
        risk_rating="Medium",
    )
    specific_deny = Rule(
        "200",
        "192.168.1.0/24",
        "10.0.0.0/24",
        "tcp",
        "TCP/9000",
        "deny",
        risk_rating="Medium",
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
        risk_rating="High",
    )
    allow_rule = Rule(
        "400",
        "any",
        "10.0.1.0/24",
        "tcp",
        "TCP/9000",
        "allow",
        risk_rating="High",
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
    csv_content = (
        "Seq #,Source Value,Destination Value,Service,Service.1,Action,Risk Feedback\n"
        "1,any,any,any,22,allow,High\n"
    )
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
    csv = (
        "rid,src_col,dst_col,proto_col,pcol,act_col,risk_col\n"
        "1,1.1.1.1,2.2.2.2,any,TCP/9999,allow,High\n"
    )
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
        "  risk_rating: ['risk_col']\n"
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
    csv = (
        "rid,src_col,dst_col,svc_col,act_col,risk_col\n"
        "1,1.1.1.1,2.2.2.2,TCP/9999,allow,High\n"
    )
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
        "  risk_rating: ['risk_col']\n"
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
    rule = Rule("1", "any", "any", "any", "any", "allow", risk_rating="Info")

    caplog.set_level("INFO")
    run_checks("generic", [rule], {})

    records = [r for r in caplog.records if r.message == "Analyzer thresholds resolved"]
    assert records, "Expected structured logging output"

    record = records[0]
    assert "admin_port_exposed" in record.analyzers
    assert record.vendor == "generic"
    assert record.inventory == ANALYZER_INVENTORY


def test_unused_rule_analyzer():
    zero_hit_rule = Rule(
        "zero-hit",
        "10.0.0.0/24",
        "10.1.0.0/24",
        "tcp",
        "443",
        "deny",
        hit_count=0,
        byte_count=0,
        enabled=True,
        risk_rating="Cautionary",
    )
    disabled_rule = Rule(
        "disabled",
        "10.0.1.0/24",
        "10.1.1.0/24",
        "tcp",
        "8443",
        "deny",
        hit_count=5,
        byte_count=128,
        enabled=False,
        risk_rating="Low",
    )
    active_rule = Rule(
        "active",
        "10.0.2.0/24",
        "10.1.2.0/24",
        "tcp",
        "22",
        "deny",
        hit_count=12,
        byte_count=2048,
        enabled=True,
        risk_rating="High",
    )

    cfg = {
        "unused_rule": {
            "hit_count_threshold": 0,
            "include_disabled": True,
            "hit_count_severity": "cautionary",
            "disabled_severity": "low",
        }
    }

    findings = run_checks("generic", [zero_hit_rule, disabled_rule, active_rule], cfg)
    unused_findings = [f for f in findings if f.finding_type == "unused_rule"]

    assert len(unused_findings) == 2

    zero_hit_finding = next(f for f in unused_findings if f.rule_id == "zero-hit")
    assert zero_hit_finding.severity == "Cautionary"
    assert zero_hit_finding.hit_count == 0
    assert "recorded hit" in zero_hit_finding.rationale

    disabled_finding = next(f for f in unused_findings if f.rule_id == "disabled")
    assert disabled_finding.severity == "Low"
    assert disabled_finding.rule_enabled is False
    assert "disabled" in disabled_finding.rationale.lower()

    assert not any(
        f.rule_id == "active" and f.finding_type == "unused_rule" for f in findings
    )


def test_deduplicate_findings_merges_tags():
    finding_primary = Finding(
        vendor="generic",
        rule_id="1",
        src="any",
        dst="any",
        proto="any",
        port="any",
        action="allow",
        finding_type="allow_any",
        severity="High",
        rationale="primary",
        tags=("alpha", "beta"),
    )
    finding_secondary = Finding(
        vendor="generic",
        rule_id="1",
        src="any",
        dst="any",
        proto="any",
        port="any",
        action="allow",
        finding_type="allow_any",
        severity="Medium",
        rationale="primary",
        tags=("beta", "gamma"),
    )

    deduped = deduplicate_findings([finding_primary, finding_secondary])
    assert len(deduped) == 1
    assert deduped[0].tags == ("alpha", "beta", "gamma")