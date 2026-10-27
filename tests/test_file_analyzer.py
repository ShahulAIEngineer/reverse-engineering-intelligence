import hashlib

import pytest

from re_intel.analyzers.file_analyzer import analyze_file


def test_analyze_file_returns_metadata_and_sha256(tmp_path):
    sample = tmp_path / "sample.txt"
    content = b"Hello, reverse engineering!"
    sample.write_bytes(content)

    result = analyze_file(sample)

    assert result.name == "sample.txt"
    assert result.extension == ".txt"
    assert result.size_bytes == len(content)
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.entropy_bits_per_byte > 0
    assert "Hello, reverse engineering!" in result.printable_strings


def test_analyze_file_raises_for_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        analyze_file(tmp_path / "missing.txt")


def test_analyze_file_rejects_directory(tmp_path):
    with pytest.raises(ValueError, match="Not a regular file"):
        analyze_file(tmp_path)


def test_analyze_empty_file(tmp_path):
    sample = tmp_path / "empty.bin"
    sample.write_bytes(b"")

    result = analyze_file(sample)

    assert result.size_bytes == 0
    assert result.sha256 == hashlib.sha256(b"").hexdigest()
    assert result.entropy_bits_per_byte == 0.0


def test_detects_png_signature_hint(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x89PNG\r\n\x1a\nrest")

    result = analyze_file(sample)

    assert result.signature == "PNG image"


def test_rejects_invalid_minimum_string_length(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")

    with pytest.raises(ValueError, match="min_string_length"):
        analyze_file(sample, min_string_length=0)


def test_caps_extracted_strings(tmp_path):
    sample = tmp_path / "strings.bin"
    sample.write_bytes(b"alpha\x00bravo\x00charlie")

    result = analyze_file(sample, max_strings=1)

    assert len(result.printable_strings) == 1
