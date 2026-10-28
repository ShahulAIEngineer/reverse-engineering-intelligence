
"""File analysis utilities for the reverse engineering intelligence toolkit."""

import hashlib
import math
import struct
from collections import Counter
from pathlib import Path

from re_intel.models import FileAnalysisResult, PEMetadata

CHUNK_SIZE = 1024 * 1024
PE_OFFSET_LOCATION = 0x3C
DEFAULT_MAX_FILE_SIZE_MB = 100
BYTES_PER_MIB = 1024 * 1024

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

            # Each section-table entry is 40 bytes.
            section_table_size = section_count * 40
            if section_table_offset + section_table_size > file_size:
                return None

            return PEMetadata(
                machine=PE_MACHINES.get(machine, f"Unknown (0x{machine:04X})"),
                section_count=section_count,
                is_dll=bool(characteristics & 0x2000),
                is_executable=bool(characteristics & 0x0002),
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
