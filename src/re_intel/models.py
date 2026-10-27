"""Validated data models used by the analyzer and CLI."""

from pydantic import BaseModel, Field


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
