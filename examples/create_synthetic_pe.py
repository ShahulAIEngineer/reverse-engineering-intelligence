
"""Create a harmless synthetic PE header fixture for analyzer demonstrations.

This file contains only a minimal artificial header for testing metadata
parsing. It is not a functional Windows executable.
"""

import struct
from pathlib import Path

OUTPUT = Path(__file__).parent / "fixtures" / "synthetic_pe.bin"


def main() -> None:
    data = bytearray(512)

    # DOS header marker and PE header offset.
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)

    # Artificial PE signature and COFF header.
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        data,
        0x84,
        0x8664,  # AMD64 / x64
        3,       # Number of sections
        0,       # Timestamp
        0,       # Symbol table pointer
        0,       # Number of symbols
        0xF0,    # Optional header size
        0x0002,  # Executable-image characteristic
    )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(data)

    print(f"Created harmless synthetic PE fixture: {OUTPUT}")
    print(f"Size: {len(data)} bytes")
    print("Contains an artificial header only; no executable code.")


if __name__ == "__main__":
    main()
