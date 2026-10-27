
"""Tests for the Reverse Engineering Intelligence CLI."""

import json
from pathlib import Path

from re_intel.cli import main


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

    monkeypatch.setattr(
        "sys.argv",
        [
            "re-intel",
            "batch",
            str(input_dir),
            "--output",
            str(report_path),
        ],
    )

    try:
        main()
    except SystemExit as exc:
        assert exc.code == 0

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

    monkeypatch.setattr(
        "sys.argv",
        [
            "re-intel",
            "batch",
            str(tmp_path / "missing"),
            "--output",
            str(report_path),
        ],
    )

    try:
        main()
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("Expected the CLI to exit with code 2")

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

    monkeypatch.setattr(
        "re_intel.cli.analyze_file",
        fake_analyze_file,
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "re-intel",
            "batch",
            str(input_dir),
            "--output",
            str(report_path),
        ],
    )

    try:
        main()
    except SystemExit as exc:
        assert exc.code == 1

    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report["files_discovered"] == 1
    assert report["files_analyzed"] == 0
    assert report["files_failed"] == 1
    assert report["errors"][0]["error"] == "Simulated analysis failure"
