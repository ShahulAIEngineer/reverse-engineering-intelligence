
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

            if section_count > 96:
                return None

            optional_header = file_handle.read(optional_header_size)
            if len(optional_header) != optional_header_size:
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

    file_size = path.stat().st_size
    max_file_size_bytes = max_file_size_mb * BYTES_PER_MIB

    if file_size > max_file_size_bytes:
        raise ValueError(
            f"File exceeds the maximum allowed size of {max_file_size_mb} MiB: {path}"
        )

    sha256 = hashlib.sha256()
    byte_counts: Counter[int] = Counter()
    strings: list[str] = []
    current_string = bytearray()
    header = b""

    with path.open("rb") as file_handle:
        while chunk := file_handle.read(CHUNK_SIZE):
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

    if (
        len(current_string) >= min_string_length
        and len(strings) < max_strings
    ):
        strings.append(current_string.decode("ascii"))

    return FileAnalysisResult(
        path=str(path.resolve()),
        name=path.name,
        extension=path.suffix.lower(),
        size_bytes=file_size,
        sha256=sha256.hexdigest(),
        signature=_signature_hint(header),
        entropy_bits_per_byte=round(_entropy(byte_counts, file_size), 6),
        printable_strings=strings,
        pe_metadata=_extract_pe_metadata(path),
    )
