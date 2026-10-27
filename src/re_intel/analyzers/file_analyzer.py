
"""Read-only file metadata and lightweight static triage."""

import hashlib
import math
import struct
from collections import Counter
from pathlib import Path

from re_intel.models import FileAnalysisResult, PEMetadata

CHUNK_SIZE = 1024 * 1024
PE_OFFSET_LOCATION = 0x3C

_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "Windows PE/DOS executable header (signature hint)"),
    (b"\x7fELF", "ELF executable/object"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"PK\x03\x04", "ZIP-based archive/container"),
    (b"%PDF-", "PDF document"),
    (b"\xca\xfe\xba\xbe", "Mach-O/Fat binary signature"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit little-endian signature"),
)

_MACHINE_TYPES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
}


def _signature_hint(header: bytes) -> str:
    """Return a heuristic file signature hint based on initial bytes."""
    for signature, description in _SIGNATURES:
        if header.startswith(signature):
            return description
    return "Unknown / no recognized signature"


def _entropy(data_counts: Counter[int], total: int) -> float:
    """Calculate Shannon entropy in bits per byte."""
    if total == 0:
        return 0.0

    return -sum(
        (count / total) * math.log2(count / total)
        for count in data_counts.values()
        if count
    )


def _extract_pe_metadata(path: Path) -> PEMetadata | None:
    """Read basic PE metadata without executing or modifying the file."""
    try:
        file_size = path.stat().st_size

        with path.open("rb") as handle:
            dos_header = handle.read(64)
            if len(dos_header) < 64 or dos_header[:2] != b"MZ":
                return None

            pe_offset = struct.unpack_from("<I", dos_header, PE_OFFSET_LOCATION)[0]

            # Require room for the PE signature and 20-byte COFF header.
            if pe_offset < 64 or pe_offset > file_size - 24:
                return None

            handle.seek(pe_offset)
            pe_header = handle.read(24)

        if len(pe_header) != 24 or pe_header[:4] != b"PE\x00\x00":
            return None

        machine, section_count, _timestamp, _symbol_ptr, _symbol_count, _optional_size, characteristics = (
            struct.unpack_from("<HHIIIHH", pe_header, 4)
        )

        return PEMetadata(
            machine=_MACHINE_TYPES.get(machine, f"Unknown (0x{machine:04X})"),
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
) -> FileAnalysisResult:
    """Analyze a regular file without executing or modifying it."""
    path = Path(file_path)

    if min_string_length < 1:
        raise ValueError("min_string_length must be at least 1")
    if max_strings < 0:
        raise ValueError("max_strings cannot be negative")
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Not a regular file: {path}")

    digest = hashlib.sha256()
    frequencies: Counter[int] = Counter()
    extracted: list[str] = []
    pending = bytearray()
    header = b""
    total = 0
    allowed = set(range(32, 127))

    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            if total == 0:
                header = chunk[:16]

            digest.update(chunk)
            total += len(chunk)
            frequencies.update(chunk)

            if max_strings == 0:
                continue

            for value in chunk:
                if value in allowed:
                    pending.append(value)
                else:
                    if len(pending) >= min_string_length:
                        extracted.append(pending.decode("ascii"))
                        if len(extracted) >= max_strings:
                            pending.clear()
                            break
                    pending.clear()

    if (
        max_strings > 0
        and len(pending) >= min_string_length
        and len(extracted) < max_strings
    ):
        extracted.append(pending.decode("ascii"))

    return FileAnalysisResult(
        path=str(path.resolve()),
        name=path.name,
        extension=path.suffix.lower(),
        size_bytes=total,
        sha256=digest.hexdigest(),
        signature=_signature_hint(header),
        entropy_bits_per_byte=_entropy(frequencies, total),
        printable_strings=extracted,
        pe_metadata=_extract_pe_metadata(path),
    )
