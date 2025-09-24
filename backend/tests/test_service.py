from firefind.model import Finding
from firefind.service import deduplicate_findings


def _make_finding(severity: str, risk_code: str = "") -> Finding:
    return Finding(
        vendor="fortinet",
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
    medium = _make_finding("Medium", risk_code="FR-MEDGEN-001")
    high = _make_finding("High", risk_code="FR-HIGEN-002")

    deduped = deduplicate_findings([medium, high])

    assert len(deduped) == 1
    assert deduped[0].severity == "High"
    assert deduped[0].risk_code == "FR-HIGEN-001"


def test_deduplicate_retains_existing_higher_severity() -> None:
    high = _make_finding("High", risk_code="FR-HIGEN-010")
    medium = _make_finding("Medium", risk_code="FR-MEDGEN-011")

    deduped = deduplicate_findings([high, medium])

    assert len(deduped) == 1
    assert deduped[0].severity == "High"
    assert deduped[0].risk_code == "FR-HIGEN-001"


def test_risk_codes_are_resequenced() -> None:
    first = _make_finding("High", risk_code="FR-HIGEN-010")
    second = _make_finding("High", risk_code="FR-HIGEN-011")
    second.rule_id = "2"

    deduped = deduplicate_findings([first, second])

    assert [f.risk_code for f in deduped] == ["FR-HIGEN-001", "FR-HIGEN-002"]
