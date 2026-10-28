
"""Tests for the Reverse Engineering Intelligence CLI."""

import json
from pathlib import Path

import pytest

from re_intel.cli import main
from re_intel.models import (
    FileAnalysisResult,
    PECertificateEntry,
    PECertificateTable,
    PEDebugEntry,
    PEExportSymbol,
    PEImportModule,
    PEImportSymbol,
    PEMetadata,
    PEOptionalHeader,
    PEResourceEntry,
)


def invoke_cli(monkeypatch, arguments: list[str]) -> None:
    """Run the CLI with supplied arguments."""
    monkeypatch.setattr("sys.argv", ["re-intel", *arguments])
    main()




def test_summary_displays_pe_export_table(tmp_path, monkeypatch, capsys):
    """Summary output should show named and forwarded PE exports."""
    sample = tmp_path / "sample.dll"
    sample.write_bytes(b"synthetic PE export test target")
    result = FileAnalysisResult(
        path=str(sample),
        name=sample.name,
        extension=".dll",
        size_bytes=sample.stat().st_size,
        sha256="b" * 64,
        signature="Windows PE/DOS executable header (signature hint)",
        entropy_bits_per_byte=4.0,
        printable_strings=[],
        pe_metadata=PEMetadata(
            machine="x64",
            section_count=1,
            is_dll=True,
            optional_header=PEOptionalHeader(
                format="PE32+",
                entry_point_rva=0x1234,
                image_base=0x140000000,
                section_alignment=0x1000,
                file_alignment=0x200,
                size_of_image=0x3000,
                size_of_headers=0x400,
                subsystem=2,
                subsystem_name="Windows GUI",
                dll_characteristics=0x8160,
            ),
            is_executable=False,
            export_table_status="parsed",
            exports=[
                PEExportSymbol(name="DemoExport", ordinal=1, address_rva=0x1100),
                PEExportSymbol(
                    name=None,
                    ordinal=2,
                    address_rva=0x1058,
                    forwarder="KERNEL32.Sleep",
                ),
            ],
        ),
    )
    monkeypatch.setattr("re_intel.cli.analyze_file", lambda *args, **kwargs: result)

    with pytest.raises(SystemExit) as exc_info:
        invoke_cli(monkeypatch, ["summary", str(sample)])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "PE export table" in output
    assert "PE exported symbols" in output
    assert "DemoExport" in output
    assert "KERNEL32.Sleep" in output
    assert "PE optional header" in output
    assert "PE32+" in output
    assert "0x140000000" in output
    assert "Windows GUI" in output


def test_summary_displays_pe_import_table(tmp_path, monkeypatch, capsys):
    """Summary output should surface parsed PE import modules and symbols."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"synthetic PE test target")
    result = FileAnalysisResult(
        path=str(sample),
        name=sample.name,
        extension=".exe",
        size_bytes=sample.stat().st_size,
        sha256="a" * 64,
        signature="Windows PE/DOS executable header (signature hint)",
        entropy_bits_per_byte=4.0,
        printable_strings=[],
        pe_metadata=PEMetadata(
            machine="x64",
            section_count=1,
            is_dll=False,
            is_executable=True,
            import_table_status="parsed",
            imports=[
                PEImportModule(
                    name="KERNEL32.dll",
                    symbols=[
                        PEImportSymbol(name="CreateFileW"),
                        PEImportSymbol(ordinal=7),
                    ],
                )
            ],
        ),
    )
    monkeypatch.setattr("re_intel.cli.analyze_file", lambda *args, **kwargs: result)

    with pytest.raises(SystemExit) as exc_info:
        invoke_cli(monkeypatch, ["summary", str(sample)])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "PE import modules" in output
    assert "PE imported symbols" in output
    assert "KERNEL32.dll" in output
    assert "CreateFileW" in output
    assert "ordinal 7" in output


def test_batch_generates_json_report(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Batch analysis should report successfully analyzed files."""
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    (input_dir / "sample.txt").write_text(
        "Harmless sample content for analysis.",
        encoding="utf-8",
    )
    report_path = tmp_path / "reports" / "batch.json"

    with pytest.raises(SystemExit) as exc_info:
        invoke_cli(
            monkeypatch,
            ["batch", str(input_dir), "--output", str(report_path)],
        )

    assert exc_info.value.code == 0

    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report["files_discovered"] == 1
    assert report["files_analyzed"] == 1
    assert report["files_failed"] == 0
    assert report["results"][0]["name"] == "sample.txt"
    assert report["errors"] == []


def test_batch_rejects_missing_directory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Batch analysis should return an error for a missing directory."""
    report_path = tmp_path / "batch.json"

    with pytest.raises(SystemExit) as exc_info:
        invoke_cli(
            monkeypatch,
            [
                "batch",
                str(tmp_path / "missing"),
                "--output",
                str(report_path),
            ],
        )

    assert exc_info.value.code == 2
    assert not report_path.exists()


def test_batch_records_file_analysis_errors(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Batch analysis should record individual file errors."""
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    (input_dir / "sample.txt").write_text(
        "Harmless sample content for analysis.",
        encoding="utf-8",
    )
    report_path = tmp_path / "batch.json"

    def fake_analyze_file(file_path, **kwargs):
        if Path(file_path).name == "sample.txt":
            raise ValueError("Simulated analysis failure")
        raise AssertionError("Unexpected file passed to analyzer")

    monkeypatch.setattr("re_intel.cli.analyze_file", fake_analyze_file)

    with pytest.raises(SystemExit) as exc_info:
        invoke_cli(
            monkeypatch,
            ["batch", str(input_dir), "--output", str(report_path)],
        )

    assert exc_info.value.code == 1

    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report["files_discovered"] == 1
    assert report["files_analyzed"] == 0
    assert report["files_failed"] == 1
    assert report["errors"][0]["error"] == "Simulated analysis failure"


@pytest.mark.parametrize(
    "command",
    ["inspect", "strings", "summary", "batch"],
)
def test_cli_rejects_zero_file_size_limit(
    tmp_path: Path,
    monkeypatch,
    command: str,
) -> None:
    """Every command should reject a zero MiB file-size limit."""
    sample = tmp_path / "sample.txt"
    sample.write_text("Harmless test content.", encoding="utf-8")

    arguments = [command]

    if command == "batch":
        arguments.extend([str(tmp_path), "--output", str(tmp_path / "report.json")])
    else:
        arguments.append(str(sample))

    arguments.extend(["--max-file-size-mb", "0"])

    with pytest.raises(SystemExit) as exc_info:
        invoke_cli(monkeypatch, arguments)

    assert exc_info.value.code == 2


def test_inspect_rejects_file_over_configured_size(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Inspect should reject a file exceeding its configured size limit."""
    sample = tmp_path / "large.bin"
    sample.write_bytes(b"A" * (1024 * 1024 + 1))

    with pytest.raises(SystemExit) as exc_info:
        invoke_cli(
            monkeypatch,
            [
                "inspect",
                str(sample),
                "--max-file-size-mb",
                "1",
            ],
        )

    assert exc_info.value.code == 2



def test_summary_displays_pe_certificate_table_and_overlay(
    tmp_path, monkeypatch, capsys
):
    """Summary output should include certificate directory and overlay metadata."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"synthetic PE certificate and overlay target")
    result = FileAnalysisResult(
        path=str(sample),
        name=sample.name,
        extension=".exe",
        size_bytes=sample.stat().st_size,
        sha256="c" * 64,
        signature="Windows PE/DOS executable header (signature hint)",
        entropy_bits_per_byte=4.0,
        printable_strings=[],
        pe_metadata=PEMetadata(
            machine="x64",
            section_count=1,
            is_dll=False,
            is_executable=True,
            certificate_table=PECertificateTable(
                status="parsed",
                file_offset=0x400,
                size=16,
                entries=[
                    PECertificateEntry(
                        file_offset=0x400,
                        length=12,
                        revision=0x0200,
                        certificate_type=0x0002,
                        certificate_type_name="PKCS #7 SignedData",
                    )
                ],
            ),
            overlay_status="present",
            overlay_offset=0x200,
            overlay_size=528,
        ),
    )
    monkeypatch.setattr("re_intel.cli.analyze_file", lambda *args, **kwargs: result)

    with pytest.raises(SystemExit) as exc_info:
        invoke_cli(monkeypatch, ["summary", str(sample)])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "PE certificate table" in output
    assert "PE certificate entries" in output
    assert "0x00000400" in output
    assert "PKCS #7 SignedData" in output
    assert "PE overlay" in output
    assert "present" in output



def test_summary_displays_pe_debug_directory_and_codeview_path(
    tmp_path, monkeypatch, capsys
):
    """Summary should expose CodeView PDB identity without implying trust."""
    sample = tmp_path / "debug.exe"
    sample.write_bytes(b"synthetic PE debug test target")
    result = FileAnalysisResult(
        path=str(sample),
        name=sample.name,
        extension=".exe",
        size_bytes=sample.stat().st_size,
        sha256="d" * 64,
        signature="Windows PE/DOS executable header (signature hint)",
        entropy_bits_per_byte=4.0,
        printable_strings=[],
        pe_metadata=PEMetadata(
            machine="x64",
            section_count=1,
            is_dll=False,
            is_executable=True,
            debug_directory_status="parsed",
            debug_entries=[
                PEDebugEntry(
                    characteristics=0,
                    timestamp=0x5E2A5A00,
                    major_version=4,
                    minor_version=0,
                    debug_type=2,
                    debug_type_name="CodeView",
                    size_of_data=60,
                    address_of_raw_data=0x1050,
                    pointer_to_raw_data=0x450,
                    codeview_format="RSDS",
                    pdb_guid="00112233-4455-6677-8899-aabbccddeeff",
                    pdb_age=2,
                    pdb_path=r"C:\\symbols\\sample.pdb",
                )
            ],
        ),
    )
    monkeypatch.setattr("re_intel.cli.analyze_file", lambda *args, **kwargs: result)

    with pytest.raises(SystemExit) as exc_info:
        invoke_cli(monkeypatch, ["summary", str(sample)])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "PE debug directory" in output
    assert "PE debug entries" in output
    assert "PE CodeView debug metadata" in output
    assert "00112233-4455-6677-8899-aabbccddeeff" in output
    assert r"C:\\symbols\\sample.pdb" in output



def test_summary_displays_pe_resource_directory(tmp_path, monkeypatch, capsys):
    """Summary should list resource paths and their declared data metadata."""
    sample = tmp_path / "resources.exe"
    sample.write_bytes(b"synthetic PE resource test target")
    result = FileAnalysisResult(
        path=str(sample),
        name=sample.name,
        extension=".exe",
        size_bytes=sample.stat().st_size,
        sha256="e" * 64,
        signature="Windows PE/DOS executable header (signature hint)",
        entropy_bits_per_byte=4.0,
        printable_strings=[],
        pe_metadata=PEMetadata(
            machine="x64",
            section_count=1,
            is_dll=False,
            is_executable=True,
            resource_directory_status="parsed",
            resources=[
                PEResourceEntry(
                    path=["RT_MANIFEST", "ID:1", "LANG:1033"],
                    data_rva=0x1100,
                    size=16,
                    code_page=1200,
                    file_offset=0x500,
                )
            ],
        ),
    )
    monkeypatch.setattr("re_intel.cli.analyze_file", lambda *args, **kwargs: result)

    with pytest.raises(SystemExit) as exc_info:
        invoke_cli(monkeypatch, ["summary", str(sample)])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "PE resource directory" in output
    assert "PE resource entries" in output
    assert "RT_MANIFEST / ID:1 / LANG:1033" in output
    assert "0x00001100" in output



def _comparison_result(path: str, sha: str) -> dict:
    """Build a minimal valid file-analysis result for report-comparison tests."""
    return {
        "path": path,
        "name": Path(path).name,
        "extension": Path(path).suffix,
        "size_bytes": 12,
        "sha256": sha,
        "signature": "Unknown",
        "entropy_bits_per_byte": 4.0,
        "printable_strings": [],
        "pe_metadata": None,
    }


def test_compare_batch_reports_and_write_json_delta(tmp_path, monkeypatch, capsys):
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    output_path = tmp_path / "comparison.json"

    before_path.write_text(
        json.dumps(
            {
                "files_failed": 0,
                "results": [
                    _comparison_result("stable.bin", "a" * 64),
                    _comparison_result("changed.bin", "b" * 64),
                    _comparison_result("removed.bin", "c" * 64),
                ],
            }
        ),
        encoding="utf-8",
    )
    after_path.write_text(
        json.dumps(
            {
                "files_failed": 0,
                "results": [
                    _comparison_result("stable.bin", "a" * 64),
                    _comparison_result("changed.bin", "d" * 64),
                    _comparison_result("added.bin", "e" * 64),
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as exc_info:
        invoke_cli(
            monkeypatch,
            [
                "compare",
                str(before_path),
                str(after_path),
                "--output",
                str(output_path),
            ],
        )

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    # Rich may wrap long table titles across multiple lines.
    assert "Investigation Report" in output
    assert "Comparison" in output
    assert "Added" in output
    assert "Removed" in output
    assert "Modified" in output
    assert "stable.bin" not in output

    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["counts"] == {
        "added": 1,
        "removed": 1,
        "modified": 1,
        "unchanged": 1,
    }
    changes_by_path = {entry["path"]: entry for entry in report["changes"]}
    assert changes_by_path["changed.bin"]["status"] == "modified"
    assert changes_by_path["added.bin"]["before_sha256"] is None
    assert changes_by_path["removed.bin"]["after_sha256"] is None


def test_compare_single_file_reports_with_same_sha_is_unchanged(tmp_path, monkeypatch):
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    report = _comparison_result("sample.bin", "f" * 64)
    before_path.write_text(json.dumps(report), encoding="utf-8")
    after_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        invoke_cli(monkeypatch, ["compare", str(before_path), str(after_path)])

    assert exc_info.value.code == 0


def test_compare_rejects_invalid_json_report(tmp_path, monkeypatch, capsys):
    before_path = tmp_path / "invalid.json"
    after_path = tmp_path / "after.json"
    before_path.write_text("{ definitely not JSON", encoding="utf-8")
    after_path.write_text(
        json.dumps(_comparison_result("sample.bin", "f" * 64)),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as exc_info:
        invoke_cli(monkeypatch, ["compare", str(before_path), str(after_path)])

    assert exc_info.value.code == 2
    assert "Comparison failed" in capsys.readouterr().out


def test_compare_does_not_overwrite_an_input_report(tmp_path, monkeypatch, capsys):
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(
        json.dumps(_comparison_result("before.bin", "a" * 64)),
        encoding="utf-8",
    )
    after_path.write_text(
        json.dumps(_comparison_result("after.bin", "b" * 64)),
        encoding="utf-8",
    )
    original = before_path.read_text(encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        invoke_cli(
            monkeypatch,
            ["compare", str(before_path), str(after_path), "--output", str(before_path)],
        )

    assert exc_info.value.code == 2
    assert before_path.read_text(encoding="utf-8") == original
    assert "must not overwrite an input report" in capsys.readouterr().out



def test_summary_displays_triage_findings(tmp_path, monkeypatch, capsys):
    """Human-readable summaries should surface the evidence-backed triage clues."""
    from re_intel.models import TriageFinding

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    result = FileAnalysisResult(
        path=str(sample),
        name=sample.name,
        extension=sample.suffix,
        size_bytes=6,
        sha256="f" * 64,
        signature="Unknown",
        entropy_bits_per_byte=7.5,
        printable_strings=[],
        triage_findings=[
            TriageFinding(
                rule_id="FILE-HIGH-ENTROPY",
                severity="info",
                title="High byte entropy",
                description="High entropy needs contextual review.",
                evidence=["shannon_entropy_bits_per_byte=7.500000"],
            )
        ],
    )
    monkeypatch.setattr("re_intel.cli.analyze_file", lambda *args, **kwargs: result)

    with pytest.raises(SystemExit) as exc_info:
        invoke_cli(monkeypatch, ["summary", str(sample)])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "Triage findings" in output
    assert "FILE-HIGH-ENTROPY" in output
    assert "High byte entropy" in output
    assert "not a malware verdict" in output
