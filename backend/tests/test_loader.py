from pathlib import Path
import sys

from openpyxl import Workbook

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BACKEND_DIR / "src"))

from firefind.loaders.csv_xlsx_loader import _read_csv_rows, _read_xlsx_rows, load_table
from firefind.service import run_analysis


def test_read_csv_rows_and_load_table(tmp_path):
    csv_path = tmp_path / "sample.csv"
    csv_content = (
        "Seq #,Service,Action\n"
        "note,ignore,ignore\n"
        "1,TCP/80,allow\n"
        "2,TCP/22,deny\n"
    )
    csv_path.write_text(csv_content)

    expected = [
        {"Seq #": "1", "Service": "TCP/80", "Action": "allow"},
        {"Seq #": "2", "Service": "TCP/22", "Action": "deny"},
    ]
    assert list(_read_csv_rows(csv_path)) == expected
    assert list(load_table(csv_path)) == expected


def test_read_csv_rows_with_banner_lines(tmp_path):
    csv_path = tmp_path / "sample_with_banner.csv"
    csv_content = (
        "\n"
        "Firewall Policy\n"
        "action,srcaddr,dstaddr,policyid,service,comments\n"
        "allow,internal,external,10,HTTP,Primary rule\n"
        "deny,guest,restricted,11,HTTPS,Secondary rule\n"
    )
    csv_path.write_text(csv_content)

    expected = [
        {
            "action": "allow",
            "srcaddr": "internal",
            "dstaddr": "external",
            "policyid": "10",
            "service": "HTTP",
            "comments": "Primary rule",
        },
        {
            "action": "deny",
            "srcaddr": "guest",
            "dstaddr": "restricted",
            "policyid": "11",
            "service": "HTTPS",
            "comments": "Secondary rule",
        },
    ]

    assert list(_read_csv_rows(csv_path)) == expected
    assert list(load_table(csv_path)) == expected


def test_read_xlsx_rows_and_load_table(tmp_path):
    xlsx_path = tmp_path / "sample.xlsx"
    wb = Workbook()
    ws = wb.active
    ws.append(["Intro"])  # non-data row before headers
    ws.append(["Seq #", "Service", "Action"])  # headers
    ws.append(["note", "ignore", "ignore"])  # non-numeric Seq #
    ws.append(["3", "TCP/443", "allow"])
    wb.save(xlsx_path)

    expected = [
        {"Seq #": "3", "Service": "TCP/443", "Action": "allow"},
    ]
    assert list(_read_xlsx_rows(xlsx_path)) == expected
    assert list(load_table(xlsx_path)) == expected


def test_run_analysis_processes_csv_without_seq(tmp_path):
    csv_path = tmp_path / "rules.csv"
    csv_path.write_text(
        "rid,src_col,dst_col,Service.1,Action\n"
        "1,1.1.1.1,2.2.2.2,22,allow\n"
    )

    rules_yaml = tmp_path / "rules.yml"
    rules_yaml.write_text("admin_ports: [22]\n")

    mapping_yaml = tmp_path / "mapping.yml"
    mapping_yaml.write_text(
        "custom:\n"
        "  rule_id: ['rid']\n"
        "  src: ['src_col']\n"
        "  dst: ['dst_col']\n"
        "  action: ['Action']\n"
    )

    findings = run_analysis(
        input_path=csv_path,
        vendor="custom",
        rules_path=rules_yaml,
        mappings_path=mapping_yaml,
    )

    assert len(findings) == 1
    assert {f.finding_type for f in findings} == {"admin_port_exposed"}
