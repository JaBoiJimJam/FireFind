from pathlib import Path
import sys


BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BACKEND_DIR / "src"))


from firefind.reporters.pdf_report import PDFReport  # noqa: E402


def test_safe_text_normalizes_smart_quotes_and_bullets():
    report = PDFReport()
    text = "Curly quotes ‘ ’ “ ” and bullet •"
    assert report.safe_text(text) == "Curly quotes ' ' \" \" and bullet -"


def test_safe_text_truncates_long_text():
    report = PDFReport()
    long_text = "a" * 100
    result = report.safe_text(long_text)
    assert result.endswith("...")
    assert len(result) == 60
