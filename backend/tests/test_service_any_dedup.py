from __future__ import annotations

from backend.app.services.dedup import deduplicate_findings


def test_service_any_prefers_high_severity() -> None:
    findings = [
        {
            "vendor": "Vendor",
            "rule_id": 433,
            "src": "client",
            "dst": "outside",
            "proto": "tcp",
            "action": "allow",
            "service": "ALL/ALL",
            "finding_type": "all_ports_service",
            "severity": "Medium",
            "source_file": "outside-fw",
        },
        {
            "vendor": "Vendor",
            "rule_id": 434,
            "src": "client",
            "dst": "outside",
            "proto": "tcp",
            "action": "allow",
            "service": "ALL/ALL",
            "finding_type": "admin_port_exposed",
            "severity": "High",
            "source_file": "outside-fw",
        },
    ]

    deduped = deduplicate_findings(findings)

    assert len(deduped) == 1
    assert deduped[0]["rule_id"] == 434
    assert deduped[0]["severity"] == "High"
    assert deduped[0]["finding_type"] == "admin_port_exposed"


def test_service_any_keeps_single_finding() -> None:
    finding = {
        "vendor": "Vendor",
        "rule_id": 433,
        "src": "client",
        "dst": "outside",
        "proto": "tcp",
        "action": "allow",
        "service": "ALL/ALL",
        "finding_type": "all_ports_service",
        "severity": "Medium",
        "source_file": "outside-fw",
    }

    deduped = deduplicate_findings([finding])

    assert deduped == [finding]


def test_service_any_detects_numeric_service() -> None:
    findings = [
        {
            "vendor": "Vendor",
            "src": "client",
            "dst": "outside",
            "proto": "udp",
            "action": "allow",
            "service": 0,
            "finding_type": "all_ports_service",
            "severity": "Medium",
            "source_file": "outside-fw",
        },
        {
            "vendor": "Vendor",
            "src": "client",
            "dst": "outside",
            "proto": "udp",
            "action": "allow",
            "service": 0,
            "finding_type": "admin_port_exposed",
            "severity": "High",
            "source_file": "outside-fw",
        },
    ]

    deduped = deduplicate_findings(findings)

    assert len(deduped) == 1
    assert deduped[0]["severity"] == "High"


def test_service_any_flag_detection_with_objects() -> None:
    class Flow:
        def __init__(self, src: str, dst: str, proto: str, action: str) -> None:
            self.src = src
            self.dst = dst
            self.proto = proto
            self.action = action

    class Finding:
        def __init__(
            self,
            *,
            vendor: str,
            flow: Flow,
            finding_type: str,
            severity: str,
            source_file: str,
            service_any: bool,
        ) -> None:
            self.vendor = vendor
            self.flow = flow
            self.finding_type = finding_type
            self.severity = severity
            self.source_file = source_file
            self.service_any = service_any

    flow = Flow("client", "outside", "tcp", "allow")
    low = Finding(
        vendor="Vendor",
        flow=flow,
        finding_type="all_ports_service",
        severity="Medium",
        source_file="outside-fw",
        service_any=True,
    )
    high = Finding(
        vendor="Vendor",
        flow=flow,
        finding_type="admin_port_exposed",
        severity="High",
        source_file="outside-fw",
        service_any=True,
    )

    deduped = deduplicate_findings([low, high])

    assert deduped == [high]


def test_service_any_does_not_merge_specific_services() -> None:
    findings = [
        {
            "vendor": "Vendor",
            "src": "client",
            "dst": "outside",
            "proto": "tcp",
            "action": "allow",
            "service": "SSH",
            "finding_type": "admin_port_exposed",
            "severity": "High",
            "source_file": "outside-fw",
        },
        {
            "vendor": "Vendor",
            "src": "client",
            "dst": "outside",
            "proto": "tcp",
            "action": "allow",
            "service": "ALL/ALL",
            "finding_type": "all_ports_service",
            "severity": "Medium",
            "source_file": "outside-fw",
        },
    ]

    deduped = deduplicate_findings(findings)

    assert deduped == findings


def test_service_any_preserves_other_findings() -> None:
    shared = {
        "vendor": "Vendor",
        "src": "client",
        "dst": "outside",
        "proto": "tcp",
        "action": "allow",
        "service": "ALL/ALL",
        "severity": "High",
        "source_file": "outside-fw",
    }
    medium = {**shared, "finding_type": "all_ports_service", "severity": "Medium"}
    high = {**shared, "finding_type": "admin_port_exposed"}
    unrelated = {
        "vendor": "Vendor",
        "src": "client",
        "dst": "outside",
        "proto": "tcp",
        "action": "allow",
        "service": "HTTPS",
        "finding_type": "tls_weak_cipher",
        "severity": "Low",
        "source_file": "outside-fw",
    }

    deduped = deduplicate_findings([medium, unrelated, high])

    assert deduped[0]["finding_type"] == "admin_port_exposed"
    assert deduped[1] is unrelated
