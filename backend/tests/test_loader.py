from pathlib import Path
import sys

from openpyxl import Workbook

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BACKEND_DIR / "src"))

from firefind.loaders.csv_xlsx_loader import _read_csv_rows, _read_xlsx_rows, load_table


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
