from pathlib import Path

from firefind.model import Finding
from firefind.service import deduplicate_findings, run_analysis

BACKEND_DIR = Path(__file__).resolve().parent.parent


def _make_finding(severity: str, risk_code: str = "") -> Finding:
    return Finding(
        vendor="generic",
        rule_id="1",
        src="any",
        dst="internal",
        proto="tcp",
        port="22",
        action="allow",
        finding_type="admin_port_exposed",
        severity=severity,
        rationale="Rule permits administrative port(s): [22]",
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


def test_deduplicate_retains_existing_higher_severity() -> None:
    high = _make_finding("High", risk_code="FR-admin_port_exposed-HIGEN-010")
    medium = _make_finding("Medium", risk_code="FR-admin_port_exposed-MEDGEN-011")

    deduped = deduplicate_findings([high, medium])

    assert len(deduped) == 1
    assert deduped[0].severity == "High"
    assert deduped[0].risk_code == "FR-admin_port_exposed-HIGEN-001"


def test_risk_codes_are_resequenced() -> None:
    first = _make_finding("High", risk_code="FR-admin_port_exposed-HIGEN-010")
    second = _make_finding("High", risk_code="FR-admin_port_exposed-HIGEN-011")
    second.rule_id = "2"

    deduped = deduplicate_findings([first, second])

    assert [f.risk_code for f in deduped] == [
        "FR-admin_port_exposed-HIGEN-001",
        "FR-admin_port_exposed-HIGEN-002",
    ]


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