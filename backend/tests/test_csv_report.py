from pathlib import Path
import sys

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BACKEND_DIR / "src"))

from firefind.reporters.csv_report import write_findings_csv  # noqa: E402
from firefind.model import Finding  # noqa: E402


def test_write_findings_csv_current_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    finding = Finding(
        vendor="vendor",
        rule_id="1",
        src="src",
        dst="dst",
        proto="proto",
        port="port",
        action="allow",
        finding_type="type",
        severity="low",
        rationale="rationale",
    )
    write_findings_csv("findings.csv", [finding])
    assert (tmp_path / "findings.csv").exists()
