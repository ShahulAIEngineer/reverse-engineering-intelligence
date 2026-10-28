"""File analysis utilities for the reverse engineering intelligence toolkit."""

import hashlib
import math
import struct
from collections import Counter
from pathlib import Path
from typing import Literal

from re_intel.models import (
    FileAnalysisResult,
    PEExportSymbol,
    PEImportModule,
    PEImportSymbol,
    PEMetadata,
    PESection,
)

CHUNK_SIZE = 1024 * 1024
PE_OFFSET_LOCATION = 0x3C
DEFAULT_MAX_FILE_SIZE_MB = 100
BYTES_PER_MIB = 1024 * 1024
MAX_PE_IMPORT_MODULES = 512
MAX_PE_IMPORT_SYMBOLS = 10_000
MAX_PE_EXPORTS = 20_000
MAX_PE_STRING_LENGTH = 4096

SIGNATURES = (
    (b"MZ", "Windows PE/DOS executable header (signature hint)"),
    (b"\x7fELF", "ELF executable/object"),
    (b"%PDF-", "PDF document"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"\x1f\x8b", "GZIP archive"),
)

PE_MACHINES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
}


def _signature_hint(header: bytes) -> str:
    """Identify a file format using its leading bytes."""
    for signature, description in SIGNATURES:
        if header.startswith(signature):
            return description
    return "Unknown / no recognized signature"


def _entropy(counts: Counter[int], total: int) -> float:
    """Calculate Shannon entropy in bits per byte."""
    if total == 0:
        return 0.0

    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return entropy


def _rva_to_file_span(
    rva: int,
    *,
    sections: list[PESection],
    file_size: int,
    size_of_headers: int,
) -> tuple[int, int] | None:
    """Map a PE relative virtual address to a bounded file span."""
    if rva < 0:
        return None

    header_limit = min(size_of_headers, file_size)
    if rva < header_limit:
        return rva, header_limit - rva

    for section in sections:
        delta = rva - section.virtual_address
        mapped_size = max(section.virtual_size, section.raw_size)
        if delta < 0 or delta >= mapped_size:
            continue
        if delta >= section.raw_size:
            return None

        file_offset = section.raw_offset + delta
        if not 0 <= file_offset < file_size:
            return None

        available = min(section.raw_size - delta, file_size - file_offset)
        if available > 0:
            return file_offset, available
        return None

    return None


def _read_ascii_string_at_rva(
    file_handle,
    rva: int,
    *,
    sections: list[PESection],
    file_size: int,
    size_of_headers: int,
) -> str | None:
    """Read a bounded, null-terminated ASCII string from an RVA."""
    span = _rva_to_file_span(
        rva,
        sections=sections,
        file_size=file_size,
        size_of_headers=size_of_headers,
    )
    if span is None:
        return None

    file_offset, available = span
    read_limit = min(available, MAX_PE_STRING_LENGTH + 1)
    file_handle.seek(file_offset)
    data = file_handle.read(read_limit)
    terminator = data.find(b"\x00")
    if terminator <= 0:
        return None

    return data[:terminator].decode("ascii", errors="replace")


def _read_pe_import_symbols(
    file_handle,
    thunk_rva: int,
    *,
    is_64bit: bool,
    sections: list[PESection],
    file_size: int,
    size_of_headers: int,
    max_symbols: int,
) -> list[PEImportSymbol] | None:
    """Read import-by-name and import-by-ordinal entries from a thunk table."""
    if thunk_rva == 0:
        return None

    entry_size = 8 if is_64bit else 4
    ordinal_flag = 1 << ((entry_size * 8) - 1)
    integer_format = "<Q" if is_64bit else "<I"
    symbols: list[PEImportSymbol] = []

    for index in range(max_symbols + 1):
        entry_rva = thunk_rva + index * entry_size
        span = _rva_to_file_span(
            entry_rva,
            sections=sections,
            file_size=file_size,
            size_of_headers=size_of_headers,
        )
        if span is None or span[1] < entry_size:
            return None

        file_handle.seek(span[0])
        entry_data = file_handle.read(entry_size)
        if len(entry_data) != entry_size:
            return None
        value = struct.unpack(integer_format, entry_data)[0]

        if value == 0:
            return symbols
        if len(symbols) >= max_symbols:
            return None

        if value & ordinal_flag:
            symbols.append(PEImportSymbol(ordinal=value & 0xFFFF))
            continue

        # Import-by-name entries contain a 32-bit RVA even in PE32+ images.
        if value > 0xFFFFFFFF:
            return None
        hint_span = _rva_to_file_span(
            value,
            sections=sections,
            file_size=file_size,
            size_of_headers=size_of_headers,
        )
        if hint_span is None or hint_span[1] < 2:
            return None

        symbol_name = _read_ascii_string_at_rva(
            file_handle,
            value + 2,
            sections=sections,
            file_size=file_size,
            size_of_headers=size_of_headers,
        )
        if symbol_name is None:
            return None
        symbols.append(PEImportSymbol(name=symbol_name))

    return None


def _extract_pe_imports(
    file_handle,
    *,
    optional_header: bytes,
    optional_magic: int,
    sections: list[PESection],
    file_size: int,
    size_of_headers: int,
) -> tuple[list[PEImportModule], Literal["not_present", "parsed", "malformed"]]:
    """Parse a bounded PE import directory and report malformed tables explicitly."""
    count_offset = 92 if optional_magic == 0x010B else 108
    directories_offset = 96 if optional_magic == 0x010B else 112

    if len(optional_header) < count_offset + 4:
        return [], "malformed"

    directory_count = struct.unpack_from("<I", optional_header, count_offset)[0]
    if directory_count <= 1:
        return [], "not_present"
    if len(optional_header) < directories_offset + 16:
        return [], "malformed"

    import_rva, import_size = struct.unpack_from(
        "<II", optional_header, directories_offset + 8
    )
    if import_rva == 0 and import_size == 0:
        return [], "not_present"
    if import_rva == 0 or import_size < 40:
        return [], "malformed"

    descriptor_limit = min(import_size // 20, MAX_PE_IMPORT_MODULES + 1)
    imports: list[PEImportModule] = []
    total_symbols = 0
    is_64bit = optional_magic == 0x020B

    for index in range(descriptor_limit):
        descriptor_rva = import_rva + index * 20
        span = _rva_to_file_span(
            descriptor_rva,
            sections=sections,
            file_size=file_size,
            size_of_headers=size_of_headers,
        )
        if span is None or span[1] < 20:
            return [], "malformed"

        file_handle.seek(span[0])
        descriptor_data = file_handle.read(20)
        if len(descriptor_data) != 20:
            return [], "malformed"
        original_thunk, _, _, name_rva, first_thunk = struct.unpack(
            "<IIIII", descriptor_data
        )

        if not any((original_thunk, name_rva, first_thunk)):
            # A terminating descriptor must have all five fields set to zero.
            if any(descriptor_data):
                return [], "malformed"
            return imports, "parsed"

        if len(imports) >= MAX_PE_IMPORT_MODULES or name_rva == 0:
            return [], "malformed"

        module_name = _read_ascii_string_at_rva(
            file_handle,
            name_rva,
            sections=sections,
            file_size=file_size,
            size_of_headers=size_of_headers,
        )
        if module_name is None:
            return [], "malformed"

        lookup_rva = original_thunk or first_thunk
        if lookup_rva == 0:
            return [], "malformed"

        symbols = _read_pe_import_symbols(
            file_handle,
            lookup_rva,
            is_64bit=is_64bit,
            sections=sections,
            file_size=file_size,
            size_of_headers=size_of_headers,
            max_symbols=MAX_PE_IMPORT_SYMBOLS - total_symbols,
        )
        if symbols is None:
            return [], "malformed"

        total_symbols += len(symbols)
        imports.append(PEImportModule(name=module_name, symbols=symbols))

    return [], "malformed"




def _read_rva_bytes_at_rva(
    file_handle,
    rva: int,
    size: int,
    *,
    sections: list[PESection],
    file_size: int,
    size_of_headers: int,
) -> bytes | None:
    """Read a fixed-size structure only when its entire span is file-backed."""
    if size < 0:
        return None
    if size == 0:
        return b""

    span = _rva_to_file_span(
        rva,
        sections=sections,
        file_size=file_size,
        size_of_headers=size_of_headers,
    )
    if span is None or span[1] < size:
        return None

    file_handle.seek(span[0])
    data = file_handle.read(size)
    return data if len(data) == size else None


def _extract_pe_exports(
    file_handle,
    *,
    optional_header: bytes,
    optional_magic: int,
    sections: list[PESection],
    file_size: int,
    size_of_headers: int,
) -> tuple[list[PEExportSymbol], Literal["not_present", "parsed", "malformed"]]:
    """Parse a bounded PE export directory, including forwarders and ordinal-only exports."""
    count_offset = 92 if optional_magic == 0x010B else 108
    directories_offset = 96 if optional_magic == 0x010B else 112

    if len(optional_header) < count_offset + 4:
        return [], "malformed"
    directory_count = struct.unpack_from("<I", optional_header, count_offset)[0]
    if directory_count == 0:
        return [], "not_present"
    if len(optional_header) < directories_offset + 8:
        return [], "malformed"

    export_rva, export_size = struct.unpack_from("<II", optional_header, directories_offset)
    if export_rva == 0 and export_size == 0:
        return [], "not_present"
    if export_rva == 0 or export_size < 40:
        return [], "malformed"

    directory_data = _read_rva_bytes_at_rva(
        file_handle,
        export_rva,
        40,
        sections=sections,
        file_size=file_size,
        size_of_headers=size_of_headers,
    )
    if directory_data is None:
        return [], "malformed"

    (
        _,
        _,
        _,
        _,
        _,
        ordinal_base,
        function_count,
        name_count,
        functions_rva,
        names_rva,
        ordinals_rva,
    ) = struct.unpack("<IIHHIIIIIII", directory_data)

    if function_count > MAX_PE_EXPORTS or name_count > MAX_PE_EXPORTS:
        return [], "malformed"
    if function_count and functions_rva == 0:
        return [], "malformed"
    if name_count and (function_count == 0 or names_rva == 0 or ordinals_rva == 0):
        return [], "malformed"

    functions_data = _read_rva_bytes_at_rva(
        file_handle,
        functions_rva,
        function_count * 4,
        sections=sections,
        file_size=file_size,
        size_of_headers=size_of_headers,
    )
    if functions_data is None:
        return [], "malformed"

    names_data = _read_rva_bytes_at_rva(
        file_handle,
        names_rva,
        name_count * 4,
        sections=sections,
        file_size=file_size,
        size_of_headers=size_of_headers,
    )
    ordinals_data = _read_rva_bytes_at_rva(
        file_handle,
        ordinals_rva,
        name_count * 2,
        sections=sections,
        file_size=file_size,
        size_of_headers=size_of_headers,
    )
    if names_data is None or ordinals_data is None:
        return [], "malformed"

    names_by_index: dict[int, list[str]] = {}
    for index in range(name_count):
        name_rva = struct.unpack_from("<I", names_data, index * 4)[0]
        function_index = struct.unpack_from("<H", ordinals_data, index * 2)[0]
        if name_rva == 0 or function_index >= function_count:
            return [], "malformed"

        export_name = _read_ascii_string_at_rva(
            file_handle,
            name_rva,
            sections=sections,
            file_size=file_size,
            size_of_headers=size_of_headers,
        )
        if export_name is None:
            return [], "malformed"
        names_by_index.setdefault(function_index, []).append(export_name)

    exports: list[PEExportSymbol] = []
    export_end = export_rva + export_size
    for function_index in range(function_count):
        function_rva = struct.unpack_from("<I", functions_data, function_index * 4)[0]
        if function_rva == 0:
            continue

        ordinal = ordinal_base + function_index
        if ordinal > 0xFFFFFFFF:
            return [], "malformed"

        forwarder = None
        if export_rva <= function_rva < export_end:
            forwarder = _read_ascii_string_at_rva(
                file_handle,
                function_rva,
                sections=sections,
                file_size=file_size,
                size_of_headers=size_of_headers,
            )
            if forwarder is None:
                return [], "malformed"

        exported_names = names_by_index.get(function_index, [])
        if exported_names:
            exports.extend(
                PEExportSymbol(
                    name=export_name,
                    ordinal=ordinal,
                    address_rva=function_rva,
                    forwarder=forwarder,
                )
                for export_name in exported_names
            )
        else:
            exports.append(
                PEExportSymbol(
                    name=None,
                    ordinal=ordinal,
                    address_rva=function_rva,
                    forwarder=forwarder,
                )
            )

    return exports, "parsed"


def _extract_pe_metadata(path: Path) -> PEMetadata | None:
    """Extract basic PE metadata, returning None for malformed/non-PE files."""
    try:
        file_size = path.stat().st_size

        with path.open("rb") as file_handle:
            if file_handle.read(2) != b"MZ":
                return None

            file_handle.seek(PE_OFFSET_LOCATION)
            offset_data = file_handle.read(4)
            if len(offset_data) != 4:
                return None

            pe_offset = struct.unpack("<I", offset_data)[0]

            # Require room for the PE signature and complete COFF header.
            if pe_offset < 64 or pe_offset > file_size - 24:
                return None

            file_handle.seek(pe_offset)
            if file_handle.read(4) != b"PE\x00\x00":
                return None

            coff_header = file_handle.read(20)
            if len(coff_header) != 20:
                return None

            (
                machine,
                section_count,
                _,
                _,
                _,
                optional_header_size,
                characteristics,
            ) = struct.unpack("<HHIIIHH", coff_header)

            if not 1 <= section_count <= 96:
                return None

            # Validate optional-header boundaries.
            optional_header_offset = pe_offset + 24
            section_table_offset = optional_header_offset + optional_header_size

            if optional_header_size < 2 or section_table_offset > file_size:
                return None

            file_handle.seek(optional_header_offset)
            optional_header = file_handle.read(optional_header_size)

            if len(optional_header) != optional_header_size:
                return None

            # PE32 uses 0x10B; PE32+ uses 0x20B.
            optional_magic = struct.unpack_from("<H", optional_header)[0]
            if optional_magic not in (0x010B, 0x020B):
                return None

            # PE32 requires at least 96 bytes; PE32+ requires at least 112.
            minimum_optional_header_size = {
                0x010B: 96,
                0x020B: 112,
            }[optional_magic]
            if optional_header_size < minimum_optional_header_size:
                return None

            # Enforce known machine/optional-header compatibility.
            expected_magic = {
                0x014C: 0x010B,  # x86
                0x01C0: 0x010B,  # ARM
                0x01C4: 0x010B,  # ARMv7
                0x8664: 0x020B,  # x64
                0xAA64: 0x020B,  # ARM64
            }.get(machine)
            if expected_magic is not None and optional_magic != expected_magic:
                return None

            # Each section-table entry is 40 bytes.
            section_table_size = section_count * 40
            if section_table_offset + section_table_size > file_size:
                return None

            sections: list[PESection] = []
            for section_index in range(section_count):
                entry_offset = section_table_offset + section_index * 40
                file_handle.seek(entry_offset)
                section_entry = file_handle.read(40)
                if len(section_entry) != 40:
                    return None

                raw_name = section_entry[0:8].split(b"\x00", 1)[0]
                section_name = raw_name.decode("ascii", errors="replace") or "<empty>"
                virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                    "<IIII", section_entry, 8
                )
                section_characteristics = struct.unpack_from("<I", section_entry, 36)[0]
                sections.append(
                    PESection(
                        name=section_name,
                        virtual_size=virtual_size,
                        virtual_address=virtual_address,
                        raw_size=raw_size,
                        raw_offset=raw_offset,
                        readable=bool(section_characteristics & 0x40000000),
                        writable=bool(section_characteristics & 0x80000000),
                        executable=bool(section_characteristics & 0x20000000),
                    )
                )

            size_of_headers = struct.unpack_from("<I", optional_header, 60)[0]
            imports, import_table_status = _extract_pe_imports(
                file_handle,
                optional_header=optional_header,
                optional_magic=optional_magic,
                sections=sections,
                file_size=file_size,
                size_of_headers=size_of_headers,
            )
            exports, export_table_status = _extract_pe_exports(
                file_handle,
                optional_header=optional_header,
                optional_magic=optional_magic,
                sections=sections,
                file_size=file_size,
                size_of_headers=size_of_headers,
            )

            return PEMetadata(
                machine=PE_MACHINES.get(machine, f"Unknown (0x{machine:04X})"),
                section_count=section_count,
                is_dll=bool(characteristics & 0x2000),
                is_executable=bool(characteristics & 0x0002),
                sections=sections,
                import_table_status=import_table_status,
                imports=imports,
                export_table_status=export_table_status,
                exports=exports,
            )

    except (OSError, struct.error, ValueError):
        return None


def analyze_file(
    file_path: str | Path,
    *,
    min_string_length: int = 5,
    max_strings: int = 500,
    max_file_size_mb: int = DEFAULT_MAX_FILE_SIZE_MB,
) -> FileAnalysisResult:
    """Analyze file metadata, printable strings, entropy, and PE information."""
    if min_string_length < 1:
        raise ValueError("min_string_length must be at least 1")

    if max_strings < 0:
        raise ValueError("max_strings must be zero or greater")

    if max_file_size_mb < 1:
        raise ValueError("max_file_size_mb must be at least 1")

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if not path.is_file():
        raise ValueError(f"Not a regular file: {path}")

    initial_stat = path.stat()
    initial_size = initial_stat.st_size
    initial_identity = (
        initial_stat.st_dev,
        initial_stat.st_ino,
        initial_stat.st_size,
        initial_stat.st_mtime_ns,
        initial_stat.st_ctime_ns,
    )
    max_file_size_bytes = max_file_size_mb * BYTES_PER_MIB

    if initial_size > max_file_size_bytes:
        raise ValueError(
            f"File exceeds the maximum allowed size of {max_file_size_mb} MiB: {path}"
        )

    sha256 = hashlib.sha256()
    byte_counts: Counter[int] = Counter()
    strings: list[str] = []
    current_string = bytearray()
    header = b""
    bytes_read = 0

    with path.open("rb") as file_handle:
        while chunk := file_handle.read(CHUNK_SIZE):
            bytes_read += len(chunk)

            if bytes_read > max_file_size_bytes:
                raise ValueError(
                    f"File exceeds the maximum allowed size of "
                    f"{max_file_size_mb} MiB: {path}"
                )

            if not header:
                header = chunk[:16]

            sha256.update(chunk)
            byte_counts.update(chunk)

            for byte in chunk:
                if 32 <= byte <= 126:
                    current_string.append(byte)
                else:
                    if (
                        len(current_string) >= min_string_length
                        and len(strings) < max_strings
                    ):
                        strings.append(current_string.decode("ascii"))

                    current_string.clear()

    if len(current_string) >= min_string_length and len(strings) < max_strings:
        strings.append(current_string.decode("ascii"))

    final_stat = path.stat()
    final_identity = (
        final_stat.st_dev,
        final_stat.st_ino,
        final_stat.st_size,
        final_stat.st_mtime_ns,
        final_stat.st_ctime_ns,
    )

    if final_identity != initial_identity:
        raise ValueError(f"File changed during analysis: {path}")

    return FileAnalysisResult(
        path=str(path.resolve()),
        name=path.name,
        extension=path.suffix.lower(),
        size_bytes=bytes_read,
        sha256=sha256.hexdigest(),
        signature=_signature_hint(header),
        entropy_bits_per_byte=round(_entropy(byte_counts, bytes_read), 6),
        printable_strings=strings,
        pe_metadata=_extract_pe_metadata(path),
    )
