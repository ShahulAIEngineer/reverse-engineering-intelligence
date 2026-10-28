
"""Tests for the Reverse Engineering Intelligence CLI."""

import json
from pathlib import Path

import pytest

from re_intel.cli import main
from re_intel.models import (
    FileAnalysisResult,
    PEImportModule,
    PEImportSymbol,
    PEMetadata,
)


def invoke_cli(monkeypatch, arguments: list[str]) -> None:
    """Run the CLI with supplied arguments."""
    monkeypatch.setattr("sys.argv", ["re-intel", *arguments])
    main()


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
