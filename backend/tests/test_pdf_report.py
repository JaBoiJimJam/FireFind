from pathlib import Path
import sys


BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BACKEND_DIR / "src"))


from firefind.reporters.pdf_report import PDFReport  # noqa: E402


def test_safe_text_normalizes_typographic_marks():
    report = PDFReport()
    text = "Curly quotes ‘ ’ “ ”, bullets • ·, dashes – —, ellipsis …"
    expected = "Curly quotes ' ' \" \", bullets - -, dashes - -, ellipsis ..."
    assert report.safe_text(text) == expected


def test_safe_text_truncates_long_text():
    report = PDFReport()
    long_text = "a" * 100
    result = report.safe_text(long_text)
    assert result.endswith("...")
    assert len(result) == 60


def test_safe_text_truncates_after_normalization():
    report = PDFReport()
    text = "a" * 59 + "…"
    result = report.safe_text(text)
    assert result == "a" * 57 + "..."
    assert len(result) == 60
