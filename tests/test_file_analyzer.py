
import hashlib
import struct
from pathlib import Path

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




def create_test_pe(
    path,
    *,
    machine=0x8664,
    characteristics=0x0002,
    section_count=3,
):
    """Create a minimal synthetic PE header for testing."""
    pe_offset = 128
    # Use the standard optional-header size for the selected PE format.
    optional_header_size = 240 if machine in (0x8664, 0xAA64) else 224
    section_table_offset = pe_offset + 24 + optional_header_size
    data = bytearray(section_table_offset + section_count * 40)

    data[:2] = b"MZ"
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
        optional_header_size,
        characteristics,
    )

    optional_magic = 0x020B if machine in (0x8664, 0xAA64) else 0x010B
    struct.pack_into("<H", data, pe_offset + 24, optional_magic)

    path.write_bytes(data)



def test_extracts_pe_section_metadata(tmp_path):
    sample = tmp_path / "sections.exe"
    create_test_pe(sample, machine=0x8664, section_count=1)
    data = bytearray(sample.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 4 + 16)[0]
    section_offset = pe_offset + 24 + optional_size

    data[section_offset:section_offset + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", data, section_offset + 8, 0x120, 0x1000, 0x200, 0x400)
    struct.pack_into("<I", data, section_offset + 36, 0x60000020)
    sample.write_bytes(data)

    result = analyze_file(sample)
    assert result.pe_metadata is not None
    assert len(result.pe_metadata.sections) == 1
    section = result.pe_metadata.sections[0]
    assert section.name == ".text"
    assert section.virtual_size == 0x120
    assert section.virtual_address == 0x1000
    assert section.raw_size == 0x200
    assert section.raw_offset == 0x400
    assert section.readable is True
    assert section.writable is False
    assert section.executable is True


def test_pe_sections_default_to_empty_for_model_compatibility():
    from re_intel.models import PEMetadata

    metadata = PEMetadata(
        machine="x64",
        section_count=3,
        is_dll=False,
        is_executable=True,
    )
    assert metadata.sections == []


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

def test_analyze_file_rejects_file_over_maximum_size(tmp_path):
    sample = tmp_path / "large.bin"
    sample.write_bytes(b"A" * (1024 * 1024 + 1))

    with pytest.raises(ValueError, match="maximum allowed size"):
        analyze_file(sample, max_file_size_mb=1)


def test_analyze_file_rejects_invalid_max_file_size(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello")

    with pytest.raises(ValueError, match="max_file_size_mb"):
        analyze_file(sample, max_file_size_mb=0)

def test_truncated_pe_optional_header_has_no_metadata(tmp_path):
    """A PE with a truncated optional header should not yield metadata."""
    sample = tmp_path / "truncated.exe"
    data = bytearray(152)
    data[:2] = b"MZ"

    pe_offset = 128
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\x00\x00"

    struct.pack_into(
        "<HHIIIHH",
        data,
        pe_offset + 4,
        0x8664,
        3,
        0,
        0,
        0,
        32,
        0x0002,
    )

    # The declared optional header is 32 bytes, but none are present.
    sample.write_bytes(data[: pe_offset + 24])

    result = analyze_file(sample)

    assert result.pe_metadata is None

def test_analyze_file_rejects_file_that_grows_during_read(tmp_path, monkeypatch):
    """Reject a file that grows beyond the configured limit during reading."""
    sample = tmp_path / "growing.bin"
    sample.write_bytes(b"A" * 100)

    original_open = Path.open

    class GrowingReader:
        def __init__(self, handle):
            self.handle = handle
            self.grown = False

        def __enter__(self):
            self.handle.__enter__()
            return self

        def __exit__(self, *args):
            return self.handle.__exit__(*args)

        def read(self, size=-1):
            data = self.handle.read(size)

            if size == 1024 * 1024 and data and not self.grown:
                self.grown = True
                with original_open(sample, "ab") as writer:
                    writer.write(b"B" * (1024 * 1024))

            return data

    def open_with_growth(path, *args, **kwargs):
        handle = original_open(path, *args, **kwargs)

        if path == sample and args and args[0] == "rb":
            return GrowingReader(handle)

        return handle

    monkeypatch.setattr(Path, "open", open_with_growth)

    with pytest.raises(ValueError, match="maximum allowed size"):
        analyze_file(sample, max_file_size_mb=1)

def test_rejects_pe_with_invalid_optional_header_magic(tmp_path):
    sample = tmp_path / "invalid_optional_magic.exe"
    create_test_pe(sample)
    data = bytearray(sample.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    data[pe_offset + 24 : pe_offset + 26] = b"\x00\x00"
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.pe_metadata is None


def test_rejects_pe_with_section_table_outside_file(tmp_path):
    sample = tmp_path / "section_table_outside.exe"
    create_test_pe(sample)
    data = sample.read_bytes()
    sample.write_bytes(data[:-40])

    result = analyze_file(sample)

    assert result.pe_metadata is None


def test_rejects_pe_with_zero_sections(tmp_path):
    sample = tmp_path / "zero_sections.exe"
    create_test_pe(sample, section_count=0)

    result = analyze_file(sample)

    assert result.pe_metadata is None

def test_rejects_pe_offset_beyond_file(tmp_path):
    sample = tmp_path / "pe_offset_beyond_file.exe"
    data = bytearray(128)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x1000)
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.pe_metadata is None

def test_analyze_file_rejects_file_modified_during_read(tmp_path, monkeypatch):
    """Reject a file modified during analysis without exceeding the size limit."""
    sample = tmp_path / "modified.bin"
    sample.write_bytes(b"A" * 100)

    original_open = Path.open
    modified = False

    class ModifyingReader:
        def __init__(self, handle):
            self.handle = handle

        def __enter__(self):
            self.handle.__enter__()
            return self

        def __exit__(self, *args):
            return self.handle.__exit__(*args)

        def read(self, size=-1):
            nonlocal modified
            data = self.handle.read(size)

            if size == 1024 * 1024 and data and not modified:
                modified = True
                with original_open(sample, "r+b") as writer:
                    writer.seek(0)
                    writer.write(b"B" * 100)

            return data

    def open_with_modification(path, *args, **kwargs):
        handle = original_open(path, *args, **kwargs)

        if path == sample and args and args[0] == "rb":
            return ModifyingReader(handle)

        return handle

    monkeypatch.setattr(Path, "open", open_with_modification)

    with pytest.raises(ValueError, match="File changed during analysis"):
        analyze_file(sample)


def test_rejects_x64_pe_with_pe32_optional_header_magic(tmp_path):
    sample = tmp_path / "x64_with_pe32_magic.exe"
    create_test_pe(sample, machine=0x8664)

    data = bytearray(sample.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    struct.pack_into("<H", data, pe_offset + 24, 0x010B)
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.pe_metadata is None

@pytest.mark.parametrize(
    ("machine", "optional_magic", "undersized_length"),
    [
        (0x014C, 0x010B, 95),
        (0x8664, 0x020B, 111),
    ],
)
def test_rejects_undersized_pe_optional_header(
    tmp_path, machine, optional_magic, undersized_length
):
    sample = tmp_path / f"undersized_optional_{machine:04x}.exe"
    create_test_pe(sample, machine=machine)

    data = bytearray(sample.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    struct.pack_into("<H", data, pe_offset + 4 + 16, undersized_length)
    struct.pack_into("<H", data, pe_offset + 24, optional_magic)
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.pe_metadata is None




def test_rejects_truncated_pe_signature(tmp_path):
    sample = tmp_path / "truncated_signature.exe"
    data = bytearray(130)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 128)
    data[128:130] = b"PE"
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.pe_metadata is None


def test_rejects_truncated_coff_header(tmp_path):
    sample = tmp_path / "truncated_coff.exe"
    data = bytearray(150)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 128)
    data[128:132] = b"PE\x00\x00"
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.pe_metadata is None


def test_rejects_optional_header_declared_beyond_file(tmp_path):
    sample = tmp_path / "optional_header_beyond_file.exe"
    create_test_pe(sample, machine=0x8664)

    data = bytearray(sample.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    struct.pack_into("<H", data, pe_offset + 4 + 16, 0xFFFF)
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.pe_metadata is None


def test_rejects_section_table_truncated_by_one_byte(tmp_path):
    sample = tmp_path / "section_table_truncated_by_one.exe"
    create_test_pe(sample, machine=0x8664, section_count=1)
    sample.write_bytes(sample.read_bytes()[:-1])

    result = analyze_file(sample)

    assert result.pe_metadata is None


def test_rejects_physically_truncated_pe_optional_header(tmp_path):
    sample = tmp_path / "physically_truncated_optional.exe"
    create_test_pe(sample, machine=0x8664)

    data = sample.read_bytes()
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    sample.write_bytes(data[: pe_offset + 24 + 80])

    result = analyze_file(sample)

    assert result.pe_metadata is None
