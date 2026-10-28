
"""Validated data models used by the analyzer and CLI."""

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class PESection(BaseModel):
    name: str = Field(min_length=1, max_length=8)
    virtual_size: int = Field(ge=0)
    virtual_address: int = Field(ge=0)
    raw_size: int = Field(ge=0)
    raw_offset: int = Field(ge=0)
    readable: bool
    writable: bool
    executable: bool


class PEImportSymbol(BaseModel):
    """A named or ordinal import from a PE image."""

    name: str | None = Field(default=None, min_length=1, max_length=4096)
    ordinal: int | None = Field(default=None, ge=0, le=0xFFFF)

    @model_validator(mode="after")
    def validate_symbol_kind(self) -> "PEImportSymbol":
        if (self.name is None) == (self.ordinal is None):
            raise ValueError("exactly one of name or ordinal must be provided")
        return self


class PEImportModule(BaseModel):
    """Imported symbols grouped by their source DLL."""

    name: str = Field(min_length=1, max_length=4096)
    symbols: list[PEImportSymbol] = Field(default_factory=list)


class PEExportSymbol(BaseModel):
    """An exported PE symbol, including forwarded exports when present."""

    name: str | None = Field(default=None, min_length=1, max_length=4096)
    ordinal: int = Field(ge=0, le=0xFFFFFFFF)
    address_rva: int = Field(ge=0, le=0xFFFFFFFF)
    forwarder: str | None = Field(default=None, min_length=1, max_length=4096)


class PEOptionalHeader(BaseModel):
    """Selected, validated fields from a PE32 or PE32+ optional header."""

    format: Literal["PE32", "PE32+"]
    entry_point_rva: int = Field(ge=0, le=0xFFFFFFFF)
    image_base: int = Field(ge=0, le=0xFFFFFFFFFFFFFFFF)
    section_alignment: int = Field(ge=0, le=0xFFFFFFFF)
    file_alignment: int = Field(ge=0, le=0xFFFFFFFF)
    size_of_image: int = Field(ge=0, le=0xFFFFFFFF)
    size_of_headers: int = Field(ge=0, le=0xFFFFFFFF)
    subsystem: int = Field(ge=0, le=0xFFFF)
    subsystem_name: str = Field(min_length=1, max_length=64)
    dll_characteristics: int = Field(ge=0, le=0xFFFF)


class PEMetadata(BaseModel):
    """Basic metadata parsed from a Windows PE header."""

    machine: str = Field(min_length=1)
    section_count: int = Field(ge=0)
    is_dll: bool
    is_executable: bool
    sections: list[PESection] = Field(default_factory=list)
    import_table_status: Literal["not_present", "parsed", "malformed"] = "not_present"
    imports: list[PEImportModule] = Field(default_factory=list)
    export_table_status: Literal["not_present", "parsed", "malformed"] = "not_present"
    exports: list[PEExportSymbol] = Field(default_factory=list)
    optional_header: PEOptionalHeader | None = None


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
