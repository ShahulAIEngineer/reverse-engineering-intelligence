
"""Validated data models used by the analyzer and CLI."""

from pydantic import BaseModel, Field


class PESection(BaseModel):
    name: str = Field(min_length=1, max_length=8)
    virtual_size: int = Field(ge=0)
    virtual_address: int = Field(ge=0)
    raw_size: int = Field(ge=0)
    raw_offset: int = Field(ge=0)
    readable: bool
    writable: bool
    executable: bool


class PEMetadata(BaseModel):
    """Basic metadata parsed from a Windows PE header."""

    machine: str = Field(min_length=1)
    section_count: int = Field(ge=0)
    is_dll: bool
    is_executable: bool
    sections: list[PESection] = Field(default_factory=list)


class FileAnalysisResult(BaseModel):
    """Structured, validated metadata about a file."""

    path: str = Field(min_length=1)
    name: str = Field(min_length=1)
    extension: str
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    signature: str
    entropy_bits_per_byte: float = Field(ge=0.0, le=8.0)
    printable_strings: list[str] = Field(default_factory=list)
    pe_metadata: PEMetadata | None = None
