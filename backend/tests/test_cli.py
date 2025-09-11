from pathlib import Path
import sys

import typer
from typer.testing import CliRunner

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BACKEND_DIR / "src"))

from firefind import __version__
from firefind.cli import parse, app as cli_app

runner = CliRunner()

RULES_PATH = BACKEND_DIR / "rules" / "rules.yaml"
MAPPINGS_PATH = BACKEND_DIR / "rules" / "vendor_mappings.yaml"


def test_nonexistent_path(tmp_path):
    missing = tmp_path / "missing"
    result = runner.invoke(
        cli_app,
        [
            "--input",
            str(missing),
            "--rules",
            str(RULES_PATH),
            "--mappings",
            str(MAPPINGS_PATH),
            "--out-csv",
            str(tmp_path / "out.csv"),
            "--out-pdf",
            str(tmp_path / "out.pdf"),
        ],
    )
    assert result.exit_code != 0
    assert "does not exist" in result.output


def test_empty_directory(tmp_path):
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    result = runner.invoke(
        cli_app,
        [
            "--input",
            str(empty_dir),
            "--rules",
            str(RULES_PATH),
            "--mappings",
            str(MAPPINGS_PATH),
            "--out-csv",
            str(tmp_path / "out.csv"),
            "--out-pdf",
            str(tmp_path / "out.pdf"),
        ],
    )
    assert result.exit_code != 0
    assert "No CSV or XLSX files" in result.output


def test_directory_with_dummy_csv(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "dummy.csv").write_text("Seq #,Service,Action\n1,TCP/80,allow\n")
    result = runner.invoke(
        cli_app,
        [
            "--input",
            str(data_dir),
            "--rules",
            str(RULES_PATH),
            "--mappings",
            str(MAPPINGS_PATH),
            "--out-csv",
            str(tmp_path / "out.csv"),
            "--out-pdf",
            str(tmp_path / "out.pdf"),
        ],
    )
    assert result.exit_code == 0


def test_version_option():
    result = runner.invoke(cli_app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output
