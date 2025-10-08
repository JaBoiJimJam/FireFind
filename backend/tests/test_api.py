from pathlib import Path
import sys
from io import BytesIO

import pytest
from fastapi.testclient import TestClient
from openpyxl import Workbook

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BACKEND_DIR / "src"))

from firefind.api import app  # noqa: E402

client = TestClient(app)


def make_sample_file(fmt: str):
    """Return (filename, bytes, mime) for a small CSV or XLSX firewall export."""
    headers = [
        "Seq #",
        "Action",
        "Service",
        "Service.1",
        "Source Value",
        "Destination Value",
    ]
    row = [
        1,
        "allow",
        "TCP/22",
        "TCP/22",
        "0.0.0.0/0",
        "0.0.0.0/0",
    ]
    if fmt == "csv":
        csv_data = ",".join(headers) + "\n" + ",".join(map(str, row)) + "\n"
        return "test.csv", csv_data.encode("utf-8"), "text/csv"
    elif fmt == "xlsx":
        wb = Workbook()
        ws = wb.active
        ws.append(headers)
        ws.append(row)
        buf = BytesIO()
        wb.save(buf)
        return (
            "test.xlsx",
            buf.getvalue(),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    else:
        raise ValueError(fmt)


@pytest.mark.parametrize("fmt", ["csv", "xlsx"])
@pytest.mark.parametrize("route", ["/scan", "/api/scan"])
def test_scan_basic(tmp_path, monkeypatch, fmt, route):
    monkeypatch.chdir(tmp_path)
    filename, content, mime = make_sample_file(fmt)
    resp = client.post(route, files=[("files", (filename, content, mime))])
    assert resp.status_code == 200
    data = resp.json()

    # Validate findings structure
    assert "findings" in data and isinstance(data["findings"], list)
    expected_keys = {
        "vendor",
        "rule_id",
        "src",
        "dst",
        "proto",
        "port",
        "action",
        "finding_type",
        "severity",
        "rationale",
    }
    for f in data["findings"]:
        assert expected_keys <= f.keys()

    # Validate severity metrics
    metrics = data.get("metrics", {})
    assert metrics.get("critical") == 1
    assert metrics.get("high") == 1
    assert metrics.get("medium") == 1
    assert metrics.get("score") == 50
    assert metrics.get("total") == len(data["findings"])

    # Reports not requested
    assert "csv" not in data
    assert "pdf" not in data


def test_scan_save_csv(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    filename, content, mime = make_sample_file("csv")
    resp = client.post(
        "/api/scan?save_csv=true",
        files=[("files", (filename, content, mime))],
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "csv" in data
    csv_href = data["csv"]
    assert csv_href.startswith("/downloads/")
    csv_path = Path("out") / Path(csv_href).name
    assert csv_path.exists()
    assert "pdf" not in data


def test_scan_save_pdf(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    filename, content, mime = make_sample_file("csv")
    resp = client.post(
        "/api/scan?save_pdf=true",
        files=[("files", (filename, content, mime))],
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "pdf" in data
    pdf_href = data["pdf"]
    assert pdf_href.startswith("/downloads/")
    pdf_path = Path("out") / Path(pdf_href).name
    assert pdf_path.exists()
    assert "csv" not in data
