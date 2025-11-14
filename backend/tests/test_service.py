from pathlib import Path
import sys

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent

if str(BACKEND_DIR / "src") not in sys.path:
    sys.path.append(str(BACKEND_DIR / "src"))

from firefind import service
from firefind.model import Finding
from firefind.service import deduplicate_findings, run_analysis


@pytest.fixture(autouse=True)
def _reset_dedup_mode() -> None:
    original = service.ADMIN_PORT_DEDUPLICATION_MODE
    service.ADMIN_PORT_DEDUPLICATION_MODE = "all_groups"
    try:
        yield
    finally:
        service.ADMIN_PORT_DEDUPLICATION_MODE = original


def _make_finding(
    severity: str,
    risk_code: str = "",
    *,
    rule_id: str = "1",
    dst: str = "internal",
    port: str = "22",
    port_profile: str = "ssh",
    rationale: str = "Rule permits administrative port(s): [22]",
    proto: str = "tcp",
) -> Finding:
    return Finding(
        vendor="generic",
        rule_id=rule_id,
        src="any",
        dst=dst,
        proto=proto,
        port=port,
        action="allow",
        finding_type="admin_port_exposed",
        severity=severity,
        rationale=rationale,
        port_profile=port_profile,
        risk_code=risk_code,
        source_file="sample.csv",
    )


def test_deduplicate_prefers_higher_severity() -> None:
    medium = _make_finding("Medium", risk_code="FR-admin_port_exposed-MEDGEN-001")
    high = _make_finding("High", risk_code="FR-admin_port_exposed-HIGEN-002")

    deduped = deduplicate_findings([medium, high])

    assert len(deduped) == 1
    assert deduped[0].severity == "High"
    assert deduped[0].risk_code == "FR-admin_port_exposed-HIGEN-001"
    assert deduped[0].rule_id == "admin_ports_combined"
    assert deduped[0].port == "ssh (TCP/22)"
    assert deduped[0].port_profile == "combined"


def test_deduplicate_retains_existing_higher_severity() -> None:
    high = _make_finding("High", risk_code="FR-admin_port_exposed-HIGEN-010")
    medium = _make_finding("Medium", risk_code="FR-admin_port_exposed-MEDGEN-011")

    deduped = deduplicate_findings([high, medium])

    assert len(deduped) == 1
    assert deduped[0].severity == "High"
    assert deduped[0].risk_code == "FR-admin_port_exposed-HIGEN-001"
    assert deduped[0].rule_id == "admin_ports_combined"
    assert deduped[0].port == "ssh (TCP/22)"


def test_risk_codes_are_resequenced() -> None:
    first = _make_finding("High", risk_code="FR-admin_port_exposed-HIGEN-010")
    second = _make_finding(
        "High",
        risk_code="FR-admin_port_exposed-HIGEN-011",
        rule_id="2",
        dst="external",
    )

    deduped = deduplicate_findings([first, second])

    assert [f.risk_code for f in deduped] == [
        "FR-admin_port_exposed-HIGEN-001",
        "FR-admin_port_exposed-HIGEN-002",
    ]


def test_risk_codes_use_info_prefix() -> None:
    first = _make_finding("Info", rule_id="1")
    second = _make_finding("Info", rule_id="2", dst="external")

    deduped = deduplicate_findings([first, second])

    assert [f.risk_code for f in deduped] == [
        "FR-admin_port_exposed-INFGEN-001",
        "FR-admin_port_exposed-INFGEN-002",
    ]


def test_deduplicate_combines_named_port_groups() -> None:
    primary = _make_finding(
        "High",
        risk_code="FR-admin_port_exposed-HIGEN-015",
        port_profile="ldap_related_ports",
        port="389",
        rationale="Rule permits ldap_related_ports ports: [389, 636]",
    )

    secondary = _make_finding(
        "Medium",
        risk_code="FR-admin_port_exposed-MEDGEN-016",
        port="636",
        port_profile="ldap_related_ports",
        rationale=primary.rationale,
        rule_id="2",
    )

    deduped = deduplicate_findings([secondary, primary])

    assert len(deduped) == 1
    result = deduped[0]
    assert result.port_profile == "combined"
    assert result.port == "ldap_related_ports (TCP/389, TCP/636)"
    assert "ldap_related_ports" in result.rationale
    assert "+1 other matching rules" in result.rationale


def test_per_port_mode_retains_individual_ports() -> None:
    service.ADMIN_PORT_DEDUPLICATION_MODE = "per_port"

    primary = _make_finding(
        "High",
        risk_code="FR-admin_port_exposed-HIGEN-015",
        port="389",
        port_profile="ldap_related_ports",
    )
    secondary = _make_finding(
        "High",
        risk_code="FR-admin_port_exposed-HIGEN-016",
        port="636",
        port_profile="ldap_related_ports",
    )

    deduped = deduplicate_findings([secondary, primary])

    assert len(deduped) == 2
    ports = sorted(f.port for f in deduped)
    assert ports == ["389", "636"]


def test_service_any_family_combines_admin_port_wildcards() -> None:
    primary = _make_finding(
        "High",
        risk_code="FR-admin_port_exposed-HIGEN-050",
        port="ALL/ALL",
        port_profile="all-services",
        rationale="Wildcard admin service detection",
    )
    secondary = _make_finding(
        "Medium",
        risk_code="FR-admin_port_exposed-MEDGEN-051",
        port="0",
        port_profile="all-services",
        rationale="Secondary analyzer hit",
    )

    deduped = deduplicate_findings([secondary, primary])

    assert len(deduped) == 1
    result = deduped[0]
    assert result.severity == "High"
    assert result.port == "ALL/ALL"
    assert result.port_profile == "all-services"
    assert getattr(result, "label", "") == "Administrative ports exposed (ANY-service, combined)"


def test_service_any_family_groups_all_ports_service_findings() -> None:
    primary = Finding(
        vendor="generic",
        rule_id="rule-1",
        src="any",
        dst="any",
        proto="tcp",
        port="0",
        action="allow",
        finding_type="all_ports_service",
        severity="High",
        rationale="Service column permits all ports",
        risk_code="FR-all_ports_service-HIGEN-010",
        source_file="sample.csv",
    )
    secondary = Finding(
        vendor="generic",
        rule_id="rule-1",
        src="any",
        dst="any",
        proto="tcp",
        port="ALL/ALL",
        action="allow",
        finding_type="all_ports_service",
        severity="Medium",
        rationale="Additional analyzer notes",
        risk_code="FR-all_ports_service-MEDGEN-011",
        source_file="sample.csv",
    )

    deduped = deduplicate_findings([secondary, primary])

    assert len(deduped) == 1
    result = deduped[0]
    assert result.severity == "High"
    assert result.finding_type == "all_ports_service"


def test_service_any_prefers_highest_severity_across_types() -> None:
    admin = _make_finding(
        "High",
        risk_code="FR-admin_port_exposed-HIGEN-070",
        port="ALL",
        port_profile="all-services",
        rationale="Primary analyzer wildcard",
        dst="any",
    )
    all_ports = Finding(
        vendor="generic",
        rule_id="rule-99",
        src="any",
        dst="any",
        proto="udp",
        port="0",
        action="allow",
        finding_type="all_ports_service",
        severity="Medium",
        rationale="Secondary analyzer wildcard",
        risk_code="FR-all_ports_service-MEDGEN-071",
        source_file="sample.csv",
    )

    deduped = deduplicate_findings([all_ports, admin])

    assert len(deduped) == 1
    result = deduped[0]
    assert result.severity == "High"
    assert result.finding_type == "admin_port_exposed"
    assert getattr(result, "label", "").startswith(
        "Administrative ports exposed (ANY-service"
    )
    assert result.port == "ALL/ALL"


def test_service_any_recognises_ip_zero_wildcard() -> None:
    primary = _make_finding(
        "High",
        risk_code="FR-admin_port_exposed-HIGEN-080",
        port="IP/0",
        port_profile="",
        rationale="IP wildcard",
        proto="ip",
    )
    secondary = _make_finding(
        "Medium",
        risk_code="FR-admin_port_exposed-MEDGEN-081",
        port="Any",
        port_profile="",
        rationale="Additional wildcard",
        proto="udp",
    )

    deduped = deduplicate_findings([secondary, primary])

    assert len(deduped) == 1
    result = deduped[0]
    assert result.severity == "High"
    assert getattr(result, "label", "") == "Administrative ports exposed (ANY-service, combined)"
    assert result.port == "ALL/ALL"


def test_run_analysis_tracks_rejections(tmp_path: Path) -> None:
    csv_path = tmp_path / "sample.csv"
    csv_path.write_text(
        "Seq #,Action,Service,Source Value,Destination Value\n"
        "1,allow,TCP/22,999.999.999.999,10.0.0.0/24\n"
    )

    result = run_analysis(
        csv_path,
        vendor="generic",
        rules_path=BACKEND_DIR / "rules" / "rules.yaml",
        mappings_path=BACKEND_DIR / "rules" / "vendor_mappings.yaml",
    )

    assert result.rejections
    issues = result.rejections[0].issues
    assert any(issue.code == "invalid_address" for issue in issues)