
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
    assert result.printable_strings == []


def test_detects_png_signature_hint(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x89PNG\r\n\x1a\nrest")

    result = analyze_file(sample)

    assert result.signature == "PNG image"


def test_detects_elf_signature_hint(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x7fELF" + b"\x00" * 20)

    result = analyze_file(sample)

    assert result.signature == "ELF executable/object"


def test_detects_pdf_signature_hint(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"%PDF-1.7\nexample")

    result = analyze_file(sample)

    assert result.signature == "PDF document"


def test_rejects_invalid_minimum_string_length(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")

    with pytest.raises(ValueError, match="min_string_length"):
        analyze_file(sample, min_string_length=0)


def test_rejects_negative_max_strings(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"alpha")

    with pytest.raises(ValueError, match="max_strings"):
        analyze_file(sample, max_strings=-1)


def test_caps_extracted_strings(tmp_path):
    sample = tmp_path / "strings.bin"
    sample.write_bytes(b"alpha\x00bravo\x00charlie")

    result = analyze_file(sample, max_strings=1)

    assert len(result.printable_strings) == 1
    assert result.printable_strings == ["alpha"]


def test_zero_max_strings_returns_no_strings(tmp_path):
    sample = tmp_path / "strings.bin"
    sample.write_bytes(b"alpha\x00bravo\x00charlie")

    result = analyze_file(sample, max_strings=0)

    assert result.printable_strings == []


def test_extracts_string_across_chunk_boundary(tmp_path):
    sample = tmp_path / "boundary.bin"
    prefix = b"\x00" * (1024 * 1024 - 3)
    boundary_string = b"BOUNDARY_STRING"
    sample.write_bytes(prefix + boundary_string + b"\x00")

    result = analyze_file(sample)

    assert "BOUNDARY_STRING" in result.printable_strings


def test_entropy_is_zero_for_repeated_byte(tmp_path):
    sample = tmp_path / "repeated.bin"
    sample.write_bytes(b"A" * 100)

    result = analyze_file(sample)

    assert result.entropy_bits_per_byte == 0.0


def test_detects_signature_independently_of_extension(tmp_path):
    sample = tmp_path / "misleading.txt"
    sample.write_bytes(b"\x7fELF" + b"\x00" * 16)

    result = analyze_file(sample)

    assert result.extension == ".txt"
    assert result.signature == "ELF executable/object"

import struct


def create_test_pe(
    path,
    *,
    machine=0x8664,
    characteristics=0x0002,
    section_count=3,
):
    """Create a minimal synthetic PE header for testing."""
    data = bytearray(256)
    data[:2] = b"MZ"

    pe_offset = 128
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\x00\x00"

    struct.pack_into(
        "<HHIIIHH",
        data,
        pe_offset + 4,
        machine,
        section_count,
        0,
        0,
        0,
        0,
        characteristics,
    )

    path.write_bytes(data)


def test_extracts_x64_pe_metadata(tmp_path):
    sample = tmp_path / "sample.exe"
    create_test_pe(sample, machine=0x8664, section_count=4)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.machine == "x64"
    assert result.pe_metadata.section_count == 4
    assert result.pe_metadata.is_executable is True
    assert result.pe_metadata.is_dll is False


def test_extracts_x86_dll_metadata(tmp_path):
    sample = tmp_path / "sample.dll"
    create_test_pe(
        sample,
        machine=0x014C,
        characteristics=0x2000,
    )

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.machine == "x86"
    assert result.pe_metadata.is_dll is True
    assert result.pe_metadata.is_executable is False


def test_malformed_pe_header_has_no_pe_metadata(tmp_path):
    sample = tmp_path / "malformed.exe"
    data = bytearray(80)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x7FFFFFFF)
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.signature == "Windows PE/DOS executable header (signature hint)"
    assert result.pe_metadata is None
