"""Read-only file metadata and lightweight static triage."""

import hashlib
import math
import string
from collections import Counter
from pathlib import Path

from re_intel.models import FileAnalysisResult

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


def _signature_hint(header: bytes) -> str:
    """Return a heuristic file signature hint based on initial bytes."""
    for signature, description in _SIGNATURES:
        if header.startswith(signature):
            return description
    return "Unknown / no recognized signature"


def _entropy(data_counts: Counter[int], total: int) -> float:
    """Calculate Shannon entropy in bits per byte from a byte frequency counter."""
    if total == 0:
        return 0.0
    return -sum(
        (count / total) * math.log2(count / total)
        for count in data_counts.values()
        if count
    )


def _extract_ascii_strings(data: bytes, min_length: int = 5) -> list[str]:
    """Extract printable ASCII runs from a byte buffer."""
    allowed = set(bytes(string.printable, "ascii")) - {ord("\\x0b"), ord("\\x0c")}
    results: list[str] = []
    current = bytearray()

    for value in data:
        if value in allowed and 32 <= value <= 126:
            current.append(value)
        else:
            if len(current) >= min_length:
                results.append(current.decode("ascii", errors="replace"))
            current.clear()

    if len(current) >= min_length:
        results.append(current.decode("ascii", errors="replace"))
    return results


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
        while chunk := handle.read(1024 * 1024):
            if total == 0:
                header = chunk[:16]
            digest.update(chunk)
            total += len(chunk)
            frequencies.update(chunk)

            # Keep a run buffer across chunk boundaries.
            for value in chunk:
                if value in allowed:
                    pending.append(value)
                else:
                    if len(pending) >= min_string_length and len(extracted) < max_strings:
                        extracted.append(pending.decode("ascii", errors="replace"))
                    pending.clear()
                if len(extracted) >= max_strings:
                    pending.clear()
                    break

    if len(pending) >= min_string_length and len(extracted) < max_strings:
        extracted.append(pending.decode("ascii", errors="replace"))

    return FileAnalysisResult(
        path=str(path.resolve()),
        name=path.name,
        extension=path.suffix.lower(),
        size_bytes=total,
        sha256=digest.hexdigest(),
        signature=_signature_hint(header),
        entropy_bits_per_byte=_entropy(frequencies, total),
        printable_strings=extracted,
    )
