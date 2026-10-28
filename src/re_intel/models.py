
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


class PEResourceEntry(BaseModel):
    """Metadata for one leaf entry in a PE resource directory."""

    path: list[str] = Field(min_length=1, max_length=8)
    data_rva: int = Field(ge=0, le=0xFFFFFFFF)
    size: int = Field(ge=0, le=0xFFFFFFFF)
    code_page: int = Field(ge=0, le=0xFFFFFFFF)
    file_offset: int | None = Field(default=None, ge=0)


class PEDebugEntry(BaseModel):
    """Selected IMAGE_DEBUG_DIRECTORY fields and optional RSDS CodeView details."""

    characteristics: int = Field(ge=0, le=0xFFFFFFFF)
    timestamp: int = Field(ge=0, le=0xFFFFFFFF)
    major_version: int = Field(ge=0, le=0xFFFF)
    minor_version: int = Field(ge=0, le=0xFFFF)
    debug_type: int = Field(ge=0, le=0xFFFFFFFF)
    debug_type_name: str = Field(min_length=1, max_length=96)
    size_of_data: int = Field(ge=0, le=0xFFFFFFFF)
    address_of_raw_data: int = Field(ge=0, le=0xFFFFFFFF)
    pointer_to_raw_data: int = Field(ge=0, le=0xFFFFFFFF)
    codeview_format: Literal["RSDS"] | None = None
    pdb_guid: str | None = Field(default=None, max_length=36)
    pdb_age: int | None = Field(default=None, ge=0, le=0xFFFFFFFF)
    pdb_path: str | None = Field(default=None, max_length=4096)


class PECertificateEntry(BaseModel):
    """Structural metadata for one WIN_CERTIFICATE record."""

    file_offset: int = Field(ge=0)
    length: int = Field(ge=8, le=0xFFFFFFFF)
    revision: int = Field(ge=0, le=0xFFFF)
    certificate_type: int = Field(ge=0, le=0xFFFF)
    certificate_type_name: str = Field(min_length=1, max_length=96)


class PECertificateTable(BaseModel):
    """Structural metadata for the PE security directory certificate table.

    A parsed status means the record layout was bounded and readable. It does
    not mean that an Authenticode signature was cryptographically verified.
    """

    status: Literal["not_present", "parsed", "malformed"] = "not_present"
    file_offset: int | None = Field(default=None, ge=0)
    size: int = Field(default=0, ge=0)
    entries: list[PECertificateEntry] = Field(default_factory=list)


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
    certificate_table: PECertificateTable = Field(default_factory=PECertificateTable)
    debug_directory_status: Literal["not_present", "parsed", "malformed"] = "not_present"
    debug_entries: list[PEDebugEntry] = Field(default_factory=list)
    resource_directory_status: Literal["not_present", "parsed", "malformed"] = "not_present"
    resources: list[PEResourceEntry] = Field(default_factory=list)
    overlay_status: Literal["not_present", "present", "uncertain"] = "not_present"
    overlay_offset: int | None = Field(default=None, ge=0)
    overlay_size: int = Field(default=0, ge=0)


class TriageFinding(BaseModel):
    """A bounded, evidence-backed triage clue rather than a malware verdict."""

    rule_id: str = Field(pattern=r"^[A-Z][A-Z0-9-]{2,64}$")
    severity: Literal["info", "low", "medium", "high"]
    title: str = Field(min_length=1, max_length=128)
    description: str = Field(min_length=1, max_length=1024)
    evidence: list[str] = Field(default_factory=list, max_length=32)


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
    triage_findings: list[TriageFinding] = Field(default_factory=list)
