import pytest
from pydantic import ValidationError

from re_intel.models import FileAnalysisResult


def test_valid_file_analysis_result():
    result = FileAnalysisResult(
        path="sample.exe",
        name="sample.exe",
        extension=".exe",
        size_bytes=1024,
        sha256="a" * 64,
        signature="Unknown",
        entropy_bits_per_byte=4.0,
        printable_strings=[],
    )

    assert result.name == "sample.exe"
    assert result.size_bytes == 1024


def test_rejects_negative_file_size():
    with pytest.raises(ValidationError):
        FileAnalysisResult(
            path="sample.exe",
            name="sample.exe",
            extension=".exe",
            size_bytes=-1,
            sha256="a" * 64,
            signature="Unknown",
            entropy_bits_per_byte=4.0,
        )


def test_rejects_invalid_sha256():
    with pytest.raises(ValidationError):
        FileAnalysisResult(
            path="sample.exe",
            name="sample.exe",
            extension=".exe",
            size_bytes=100,
            sha256="not-a-valid-hash",
            signature="Unknown",
            entropy_bits_per_byte=4.0,
        )
