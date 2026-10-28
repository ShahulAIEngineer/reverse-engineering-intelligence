
import hashlib
import os
import struct
import uuid
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



def create_test_pe_with_imports(path, *, machine=0x8664, symbols=None):
    """Create a small synthetic PE containing a valid import directory."""
    if symbols is None:
        symbols = ["CreateFileW", "CloseHandle"]

    create_test_pe(path, machine=machine, section_count=1)
    data = bytearray(path.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional_header_size = struct.unpack_from("<H", data, pe_offset + 4 + 16)[0]
    optional_offset = pe_offset + 24
    section_offset = optional_offset + optional_header_size
    raw_offset = 0x400
    raw_size = 0x400
    if len(data) < raw_offset + raw_size:
        data.extend(b"\x00" * (raw_offset + raw_size - len(data)))

    data[section_offset : section_offset + 8] = b".rdata\x00\x00"
    struct.pack_into(
        "<IIII",
        data,
        section_offset + 8,
        raw_size,
        0x1000,
        raw_size,
        raw_offset,
    )
    struct.pack_into("<I", data, section_offset + 36, 0x40000040)

    is_64bit = machine in (0x8664, 0xAA64)
    directory_count_offset = 108 if is_64bit else 92
    directory_table_offset = 112 if is_64bit else 96
    struct.pack_into("<I", data, optional_offset + 60, raw_offset)
    struct.pack_into("<I", data, optional_offset + directory_count_offset, 16)
    struct.pack_into(
        "<II",
        data,
        optional_offset + directory_table_offset + 8,
        0x1000,
        40,
    )

    # One import descriptor followed by the required all-zero terminator.
    struct.pack_into(
        "<IIIII",
        data,
        raw_offset,
        0x1040,
        0,
        0,
        0x1028,
        0x1080,
    )
    data[raw_offset + 0x28 : raw_offset + 0x28 + 13] = b"KERNEL32.dll\x00"

    ordinal_flag = 1 << ((64 if is_64bit else 32) - 1)
    thunk_values = []
    name_cursor = 0x100
    for symbol in symbols:
        if isinstance(symbol, int):
            thunk_values.append(ordinal_flag | symbol)
            continue

        encoded_name = symbol.encode("ascii") + b"\x00"
        symbol_rva = 0x1000 + name_cursor
        struct.pack_into("<H", data, raw_offset + name_cursor, 0)
        name_start = raw_offset + name_cursor + 2
        data[name_start : name_start + len(encoded_name)] = encoded_name
        thunk_values.append(symbol_rva)
        name_cursor += 2 + len(encoded_name)
        if name_cursor % 2:
            name_cursor += 1

    thunk_values.append(0)
    packed_entries = "<" + ("Q" if is_64bit else "I") * len(thunk_values)
    struct.pack_into(packed_entries, data, raw_offset + 0x40, *thunk_values)
    struct.pack_into(packed_entries, data, raw_offset + 0x80, *thunk_values)
    path.write_bytes(data)


def create_test_pe_with_exports(path, *, machine=0x8664):
    """Create a small synthetic PE with named, forwarded, and ordinal-only exports."""
    create_test_pe(path, machine=machine, section_count=1)
    data = bytearray(path.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional_header_size = struct.unpack_from("<H", data, pe_offset + 4 + 16)[0]
    optional_offset = pe_offset + 24
    section_offset = optional_offset + optional_header_size
    raw_offset = 0x400
    raw_size = 0x400
    if len(data) < raw_offset + raw_size:
        data.extend(b"\x00" * (raw_offset + raw_size - len(data)))

    data[section_offset : section_offset + 8] = b".edata\x00\x00"
    struct.pack_into(
        "<IIII",
        data,
        section_offset + 8,
        raw_size,
        0x1000,
        raw_size,
        raw_offset,
    )
    struct.pack_into("<I", data, section_offset + 36, 0x40000040)

    is_64bit = machine in (0x8664, 0xAA64)
    directory_count_offset = 108 if is_64bit else 92
    directory_table_offset = 112 if is_64bit else 96
    struct.pack_into("<I", data, optional_offset + 60, raw_offset)
    struct.pack_into("<I", data, optional_offset + directory_count_offset, 16)
    struct.pack_into(
        "<II",
        data,
        optional_offset + directory_table_offset,
        0x1000,
        0x100,
    )

    # Export directory: three function slots, one public name, and a forwarded entry.
    struct.pack_into(
        "<IIHHIIIIIII",
        data,
        raw_offset,
        0,
        0,
        0,
        0,
        0x1028,
        1,
        3,
        1,
        0x1040,
        0x104C,
        0x1050,
    )
    data[raw_offset + 0x28 : raw_offset + 0x28 + 11] = b"sample.dll\x00"
    struct.pack_into("<III", data, raw_offset + 0x40, 0x1100, 0x1058, 0x1120)
    struct.pack_into("<I", data, raw_offset + 0x4C, 0x1080)
    struct.pack_into("<H", data, raw_offset + 0x50, 0)
    data[raw_offset + 0x58 : raw_offset + 0x58 + 15] = b"KERNEL32.Sleep\x00"
    data[raw_offset + 0x80 : raw_offset + 0x80 + 11] = b"DemoExport\x00"
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


@pytest.mark.parametrize("machine", [0x014C, 0x8664])
def test_extracts_pe_import_table_and_named_symbols(tmp_path, machine):
    sample = tmp_path / "imports.exe"
    create_test_pe_with_imports(sample, machine=machine)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.import_table_status == "parsed"
    assert len(result.pe_metadata.imports) == 1
    module = result.pe_metadata.imports[0]
    assert module.name == "KERNEL32.dll"
    assert [symbol.name for symbol in module.symbols] == ["CreateFileW", "CloseHandle"]
    assert all(symbol.ordinal is None for symbol in module.symbols)


def test_extracts_pe_import_by_ordinal(tmp_path):
    sample = tmp_path / "ordinal_import.exe"
    create_test_pe_with_imports(sample, symbols=[7, "CloseHandle"])

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    symbols = result.pe_metadata.imports[0].symbols
    assert symbols[0].name is None
    assert symbols[0].ordinal == 7
    assert symbols[1].name == "CloseHandle"


def test_reports_malformed_pe_import_directory(tmp_path):
    sample = tmp_path / "malformed_imports.exe"
    create_test_pe_with_imports(sample)
    data = bytearray(sample.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional_offset = pe_offset + 24
    optional_magic = struct.unpack_from("<H", data, optional_offset)[0]
    directory_offset = 112 if optional_magic == 0x020B else 96
    struct.pack_into("<I", data, optional_offset + directory_offset + 8, 0x9000)
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.import_table_status == "malformed"
    assert result.pe_metadata.imports == []


def test_reports_absent_pe_import_directory(tmp_path):
    sample = tmp_path / "no_import_directory.exe"
    create_test_pe(sample)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.import_table_status == "not_present"
    assert result.pe_metadata.imports == []




@pytest.mark.parametrize("machine", [0x014C, 0x8664])
def test_extracts_pe_export_table_and_forwarders(tmp_path, machine):
    sample = tmp_path / "exports.dll"
    create_test_pe_with_exports(sample, machine=machine)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.export_table_status == "parsed"
    exports = result.pe_metadata.exports
    assert len(exports) == 3
    assert exports[0].name == "DemoExport"
    assert exports[0].ordinal == 1
    assert exports[0].address_rva == 0x1100
    assert exports[0].forwarder is None
    assert exports[1].name is None
    assert exports[1].ordinal == 2
    assert exports[1].forwarder == "KERNEL32.Sleep"
    assert exports[2].name is None
    assert exports[2].ordinal == 3
    assert exports[2].address_rva == 0x1120


def test_reports_malformed_pe_export_directory(tmp_path):
    sample = tmp_path / "malformed_exports.dll"
    create_test_pe_with_exports(sample)
    data = bytearray(sample.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional_offset = pe_offset + 24
    optional_magic = struct.unpack_from("<H", data, optional_offset)[0]
    directory_offset = 112 if optional_magic == 0x020B else 96
    struct.pack_into("<I", data, optional_offset + directory_offset, 0x9000)
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.export_table_status == "malformed"
    assert result.pe_metadata.exports == []


def test_reports_absent_pe_export_directory(tmp_path):
    sample = tmp_path / "no_exports.dll"
    create_test_pe(sample)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.export_table_status == "not_present"
    assert result.pe_metadata.exports == []




@pytest.mark.parametrize(
    ("machine", "expected_format", "image_base"),
    [
        (0x014C, "PE32", 0x00400000),
        (0x8664, "PE32+", 0x0000000140000000),
    ],
)
def test_extracts_pe_optional_header_metadata(tmp_path, machine, expected_format, image_base):
    sample = tmp_path / "optional_header.exe"
    create_test_pe(sample, machine=machine, section_count=1)
    data = bytearray(sample.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional_offset = pe_offset + 24
    optional_magic = struct.unpack_from("<H", data, optional_offset)[0]
    image_base_offset = 28 if optional_magic == 0x010B else 24
    image_base_format = "<I" if optional_magic == 0x010B else "<Q"

    struct.pack_into("<I", data, optional_offset + 16, 0x1234)
    struct.pack_into(image_base_format, data, optional_offset + image_base_offset, image_base)
    struct.pack_into("<II", data, optional_offset + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional_offset + 56, 0x3000, 0x200)
    struct.pack_into("<HH", data, optional_offset + 68, 3, 0x8160)
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    optional = result.pe_metadata.optional_header
    assert optional is not None
    assert optional.format == expected_format
    assert optional.entry_point_rva == 0x1234
    assert optional.image_base == image_base
    assert optional.section_alignment == 0x1000
    assert optional.file_alignment == 0x200
    assert optional.size_of_image == 0x3000
    assert optional.size_of_headers == 0x200
    assert optional.subsystem == 3
    assert optional.subsystem_name == "Windows CUI"
    assert optional.dll_characteristics == 0x8160


def test_pe_optional_header_model_is_optional_for_legacy_results():
    from re_intel.models import PEMetadata

    metadata = PEMetadata(
        machine="x64",
        section_count=0,
        is_dll=False,
        is_executable=True,
    )
    assert metadata.optional_header is None


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
                    writer.flush()
                # Force a timestamp distinct from the initial stat on Windows.
                os.utime(
                    sample,
                    ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_000),
                )

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



def create_test_pe_with_certificate_table(path, *, machine=0x8664):
    """Create a PE with one structurally valid WIN_CERTIFICATE record."""
    create_test_pe(path, machine=machine, section_count=1)
    data = bytearray(path.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional_offset = pe_offset + 24
    optional_magic = struct.unpack_from("<H", data, optional_offset)[0]
    is_64bit = optional_magic == 0x020B
    directory_count_offset = 108 if is_64bit else 92
    directory_table_offset = 112 if is_64bit else 96

    # One 12-byte record plus four bytes of 8-byte alignment padding.
    certificate_offset = 0x400
    certificate_record = struct.pack("<IHH", 12, 0x0200, 0x0002) + b"TEST"
    certificate_record += b"\x00" * 4
    if len(data) < certificate_offset + len(certificate_record):
        data.extend(b"\x00" * (certificate_offset + len(certificate_record) - len(data)))
    data[certificate_offset : certificate_offset + len(certificate_record)] = (
        certificate_record
    )

    struct.pack_into("<I", data, optional_offset + 60, 0x200)
    struct.pack_into("<I", data, optional_offset + directory_count_offset, 16)
    struct.pack_into(
        "<II",
        data,
        optional_offset + directory_table_offset + 4 * 8,
        certificate_offset,
        len(certificate_record),
    )
    path.write_bytes(data)


@pytest.mark.parametrize("machine", [0x014C, 0x8664])
def test_extracts_pe_certificate_table_metadata(tmp_path, machine):
    sample = tmp_path / "signed.exe"
    create_test_pe_with_certificate_table(sample, machine=machine)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    table = result.pe_metadata.certificate_table
    assert table.status == "parsed"
    assert table.file_offset == 0x400
    assert table.size == 16
    assert len(table.entries) == 1
    entry = table.entries[0]
    assert entry.file_offset == 0x400
    assert entry.length == 12
    assert entry.revision == 0x0200
    assert entry.certificate_type == 0x0002
    assert entry.certificate_type_name == "PKCS #7 SignedData"


def test_reports_absent_pe_certificate_table(tmp_path):
    sample = tmp_path / "unsigned.exe"
    create_test_pe(sample)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.certificate_table.status == "not_present"
    assert result.pe_metadata.certificate_table.entries == []


def test_reports_malformed_pe_certificate_directory_range(tmp_path):
    sample = tmp_path / "bad_certificate_directory.exe"
    create_test_pe_with_certificate_table(sample)
    data = bytearray(sample.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional_offset = pe_offset + 24
    directory_table_offset = 112
    struct.pack_into(
        "<II",
        data,
        optional_offset + directory_table_offset + 4 * 8,
        0xFFFFFFF8,
        16,
    )
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.certificate_table.status == "malformed"
    assert result.pe_metadata.certificate_table.entries == []


def test_reports_malformed_pe_certificate_record_length(tmp_path):
    sample = tmp_path / "bad_certificate_record.exe"
    create_test_pe_with_certificate_table(sample)
    data = bytearray(sample.read_bytes())
    struct.pack_into("<I", data, 0x400, 4)
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.certificate_table.status == "malformed"
    assert result.pe_metadata.certificate_table.entries == []


def test_detects_pe_overlay_after_headers(tmp_path):
    sample = tmp_path / "overlay.exe"
    create_test_pe_with_certificate_table(sample)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.overlay_status == "present"
    assert result.pe_metadata.overlay_offset == 0x200
    assert result.pe_metadata.overlay_size == sample.stat().st_size - 0x200


def test_reports_no_pe_overlay(tmp_path):
    sample = tmp_path / "no_overlay.exe"
    create_test_pe(sample, section_count=1)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.overlay_status == "not_present"
    assert result.pe_metadata.overlay_size == 0


def test_marks_pe_overlay_uncertain_for_truncated_section_raw_data(tmp_path):
    sample = tmp_path / "truncated_section_raw_data.exe"
    create_test_pe(sample, section_count=1)
    data = bytearray(sample.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 4 + 16)[0]
    section_offset = pe_offset + 24 + optional_size
    struct.pack_into("<IIII", data, section_offset + 8, 0x400, 0x1000, 0x400, 0x400)
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.overlay_status == "uncertain"
    assert result.pe_metadata.overlay_offset is None
    assert result.pe_metadata.overlay_size == 0



def create_test_pe_with_codeview_debug(path, *, machine=0x8664):
    """Create a PE containing one IMAGE_DEBUG_DIRECTORY RSDS entry."""
    create_test_pe(path, machine=machine, section_count=1)
    data = bytearray(path.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional_offset = pe_offset + 24
    optional_size = struct.unpack_from("<H", data, pe_offset + 4 + 16)[0]
    section_offset = optional_offset + optional_size

    raw_offset = 0x400
    raw_size = 0x400
    if len(data) < raw_offset + raw_size:
        data.extend(b"\x00" * (raw_offset + raw_size - len(data)))
    data[section_offset : section_offset + 8] = b".rdata\x00\x00"
    struct.pack_into(
        "<IIII", data, section_offset + 8, raw_size, 0x1000, raw_size, raw_offset
    )
    struct.pack_into("<I", data, section_offset + 36, 0x40000040)

    optional_magic = struct.unpack_from("<H", data, optional_offset)[0]
    is_64bit = optional_magic == 0x020B
    count_offset = 108 if is_64bit else 92
    directories_offset = 112 if is_64bit else 96
    struct.pack_into("<I", data, optional_offset + 60, 0x200)
    struct.pack_into("<I", data, optional_offset + count_offset, 16)

    pdb_path = b"C:\\symbols\\sample.pdb\x00"
    pdb_guid_bytes = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff").bytes_le
    payload = b"RSDS" + pdb_guid_bytes + struct.pack("<I", 2) + pdb_path
    debug_rva = 0x1000
    debug_offset = raw_offset
    payload_rva = 0x1050
    payload_offset = raw_offset + 0x50

    struct.pack_into(
        "<II",
        data,
        optional_offset + directories_offset + 6 * 8,
        debug_rva,
        28,
    )
    struct.pack_into(
        "<IIHHIIII",
        data,
        debug_offset,
        0,
        0x5E2A5A00,
        4,
        0,
        2,
        len(payload),
        payload_rva,
        payload_offset,
    )
    data[payload_offset : payload_offset + len(payload)] = payload
    path.write_bytes(data)


@pytest.mark.parametrize("machine", [0x014C, 0x8664])
def test_extracts_pe_codeview_debug_directory(tmp_path, machine):
    sample = tmp_path / "debug.exe"
    create_test_pe_with_codeview_debug(sample, machine=machine)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    pe = result.pe_metadata
    assert pe.debug_directory_status == "parsed"
    assert len(pe.debug_entries) == 1
    entry = pe.debug_entries[0]
    assert entry.debug_type == 2
    assert entry.debug_type_name == "CodeView"
    assert entry.timestamp == 0x5E2A5A00
    assert entry.major_version == 4
    assert entry.codeview_format == "RSDS"
    assert entry.pdb_guid == "00112233-4455-6677-8899-aabbccddeeff"
    assert entry.pdb_age == 2
    assert entry.pdb_path == "C:\\symbols\\sample.pdb"


def test_reports_absent_pe_debug_directory(tmp_path):
    sample = tmp_path / "no_debug.exe"
    create_test_pe(sample)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.debug_directory_status == "not_present"
    assert result.pe_metadata.debug_entries == []


def test_reports_malformed_pe_debug_directory_rva(tmp_path):
    sample = tmp_path / "bad_debug_rva.exe"
    create_test_pe_with_codeview_debug(sample)
    data = bytearray(sample.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional_offset = pe_offset + 24
    directories_offset = 112
    struct.pack_into(
        "<II",
        data,
        optional_offset + directories_offset + 6 * 8,
        0x9000,
        28,
    )
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.debug_directory_status == "malformed"
    assert result.pe_metadata.debug_entries == []


def test_reports_malformed_rsds_record_without_terminator(tmp_path):
    sample = tmp_path / "bad_rsds.exe"
    create_test_pe_with_codeview_debug(sample)
    data = bytearray(sample.read_bytes())
    payload_offset = 0x400 + 0x50
    payload_length = len(
        b"RSDS"
        + uuid.UUID("00112233-4455-6677-8899-aabbccddeeff").bytes_le
        + struct.pack("<I", 2)
        + b"C:\\symbols\\sample.pdb\x00"
    )
    data[payload_offset + payload_length - 1] = ord("X")
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.debug_directory_status == "malformed"
    assert result.pe_metadata.debug_entries == []



def create_test_pe_with_resources(path, *, machine=0x8664):
    """Create a minimal nested PE resource tree with one manifest-like leaf."""
    create_test_pe(path, machine=machine, section_count=1)
    data = bytearray(path.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional_offset = pe_offset + 24
    optional_size = struct.unpack_from("<H", data, pe_offset + 4 + 16)[0]
    section_offset = optional_offset + optional_size
    raw_offset = 0x400
    raw_size = 0x400
    if len(data) < raw_offset + raw_size:
        data.extend(b"\x00" * (raw_offset + raw_size - len(data)))

    data[section_offset : section_offset + 8] = b".rsrc\x00\x00\x00"
    struct.pack_into(
        "<IIII", data, section_offset + 8, raw_size, 0x1000, raw_size, raw_offset
    )
    struct.pack_into("<I", data, section_offset + 36, 0x40000040)

    optional_magic = struct.unpack_from("<H", data, optional_offset)[0]
    is_64bit = optional_magic == 0x020B
    count_offset = 108 if is_64bit else 92
    directories_offset = 112 if is_64bit else 96
    struct.pack_into("<I", data, optional_offset + 60, 0x200)
    struct.pack_into("<I", data, optional_offset + count_offset, 16)
    struct.pack_into(
        "<II", data, optional_offset + directories_offset + 2 * 8, 0x1000, 0x100
    )

    # Root -> RT_MANIFEST (24) -> resource ID 1 -> language ID 1033 -> data entry.
    struct.pack_into("<IIHHHH", data, raw_offset, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", data, raw_offset + 16, 24, 0x80000018)
    struct.pack_into("<IIHHHH", data, raw_offset + 24, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", data, raw_offset + 40, 1, 0x80000038)
    struct.pack_into("<IIHHHH", data, raw_offset + 56, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", data, raw_offset + 72, 1033, 88)
    struct.pack_into("<IIII", data, raw_offset + 88, 0x1100, 16, 1200, 0)
    data[raw_offset + 0x100 : raw_offset + 0x110] = b"RESOURCE_PAYLOAD"
    path.write_bytes(data)


@pytest.mark.parametrize("machine", [0x014C, 0x8664])
def test_extracts_pe_resource_directory_tree(tmp_path, machine):
    sample = tmp_path / "resources.exe"
    create_test_pe_with_resources(sample, machine=machine)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    pe = result.pe_metadata
    assert pe.resource_directory_status == "parsed"
    assert len(pe.resources) == 1
    resource = pe.resources[0]
    assert resource.path == ["RT_MANIFEST", "ID:1", "LANG:1033"]
    assert resource.data_rva == 0x1100
    assert resource.size == 16
    assert resource.code_page == 1200
    assert resource.file_offset == 0x500


def test_reports_absent_pe_resource_directory(tmp_path):
    sample = tmp_path / "no_resources.exe"
    create_test_pe(sample)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.resource_directory_status == "not_present"
    assert result.pe_metadata.resources == []


def test_reports_malformed_pe_resource_directory_rva(tmp_path):
    sample = tmp_path / "bad_resource_directory.exe"
    create_test_pe_with_resources(sample)
    data = bytearray(sample.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional_offset = pe_offset + 24
    struct.pack_into("<II", data, optional_offset + 112 + 2 * 8, 0x9000, 0x100)
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.resource_directory_status == "malformed"
    assert result.pe_metadata.resources == []


def test_rejects_cyclic_pe_resource_tree(tmp_path):
    sample = tmp_path / "cyclic_resources.exe"
    create_test_pe_with_resources(sample)
    data = bytearray(sample.read_bytes())
    # Make the first resource entry point back to the root directory.
    struct.pack_into("<I", data, 0x400 + 16 + 4, 0x80000000)
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.resource_directory_status == "malformed"
    assert result.pe_metadata.resources == []


def test_rejects_pe_resource_leaf_with_unmapped_data_rva(tmp_path):
    sample = tmp_path / "bad_resource_data.exe"
    create_test_pe_with_resources(sample)
    data = bytearray(sample.read_bytes())
    struct.pack_into("<I", data, 0x400 + 88, 0x9000)
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    assert result.pe_metadata.resource_directory_status == "malformed"
    assert result.pe_metadata.resources == []



def test_generates_high_entropy_triage_finding(tmp_path):
    sample = tmp_path / "high_entropy.bin"
    sample.write_bytes(bytes(range(256)) * 4)

    result = analyze_file(sample)

    findings = {finding.rule_id: finding for finding in result.triage_findings}
    assert "FILE-HIGH-ENTROPY" in findings
    assert findings["FILE-HIGH-ENTROPY"].severity == "info"
    assert "not evidence of malware" in findings["FILE-HIGH-ENTROPY"].description


def test_generates_rwx_section_triage_finding(tmp_path):
    sample = tmp_path / "rwx.exe"
    create_test_pe(sample, section_count=1)
    data = bytearray(sample.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 4 + 16)[0]
    section_offset = pe_offset + 24 + optional_size
    data[section_offset : section_offset + 8] = b".packed\x00"
    struct.pack_into(
        "<IIII", data, section_offset + 8, 0x100, 0x1000, 0x200, 0x400
    )
    struct.pack_into("<I", data, section_offset + 36, 0xE0000020)
    sample.write_bytes(data)

    result = analyze_file(sample)

    findings = {finding.rule_id: finding for finding in result.triage_findings}
    assert "PE-SECTION-RWX" in findings
    assert "section=.packed" in findings["PE-SECTION-RWX"].evidence


def test_generates_dual_use_import_triage_finding(tmp_path):
    sample = tmp_path / "process_manipulation.exe"
    create_test_pe_with_imports(
        sample,
        symbols=["OpenProcess", "VirtualAllocEx", "WriteProcessMemory"],
    )

    result = analyze_file(sample)

    findings = {finding.rule_id: finding for finding in result.triage_findings}
    assert "PE-DUAL-USE-PROCESS-IMPORTS" in findings
    assert findings["PE-DUAL-USE-PROCESS-IMPORTS"].severity == "medium"
    assert "import=virtualallocex" in findings["PE-DUAL-USE-PROCESS-IMPORTS"].evidence


def test_generates_malformed_directory_triage_finding(tmp_path):
    sample = tmp_path / "malformed_imports.exe"
    create_test_pe_with_imports(sample)
    data = bytearray(sample.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional_offset = pe_offset + 24
    struct.pack_into("<I", data, optional_offset + 112 + 8, 0x9000)
    sample.write_bytes(data)

    result = analyze_file(sample)

    assert result.pe_metadata is not None
    findings = {finding.rule_id: finding for finding in result.triage_findings}
    assert "PE-MALFORMED-DIRECTORY" in findings
    assert "import table" in findings["PE-MALFORMED-DIRECTORY"].evidence


def test_normal_low_entropy_text_has_no_triage_findings(tmp_path):
    sample = tmp_path / "normal.txt"
    sample.write_text("This is a short ordinary text document.", encoding="utf-8")

    result = analyze_file(sample)

    assert result.triage_findings == []
