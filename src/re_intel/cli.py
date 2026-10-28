
"""Command-line interface for Reverse Engineering Intelligence."""

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

from re_intel.analyzers.file_analyzer import (
    DEFAULT_MAX_FILE_SIZE_MB,
    analyze_file,
)
from re_intel.models import FileAnalysisResult

console = Console()


def _inspect(args: argparse.Namespace) -> int:
    """Analyze one file and output a JSON report."""
    try:
        result = analyze_file(
            args.path,
            min_string_length=args.min_string_length,
            max_strings=args.max_strings,
            max_file_size_mb=args.max_file_size_mb,
        )
    except (OSError, ValueError) as exc:
        console.print(f"[red]Analysis failed:[/red] {exc}")
        return 2

    rendered = json.dumps(result.model_dump(), indent=2, ensure_ascii=False)

    if args.output:
        output_path = Path(args.output)
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            console.print(f"[red]Could not write report:[/red] {exc}")
            return 2

        console.print(f"[green]Report written to[/green] {output_path}")
    else:
        console.print(rendered)

    return 0


def _strings(args: argparse.Namespace) -> int:
    """Display printable ASCII strings extracted from a file."""
    try:
        result = analyze_file(
            args.path,
            min_string_length=args.min_length,
            max_strings=args.max_strings,
            max_file_size_mb=args.max_file_size_mb,
        )
    except (OSError, ValueError) as exc:
        console.print(f"[red]Analysis failed:[/red] {exc}")
        return 2

    table = Table(title=f"Printable ASCII strings — {result.name}")
    table.add_column("#", justify="right", style="dim")
    table.add_column("String")

    for index, value in enumerate(result.printable_strings, start=1):
        table.add_row(str(index), value)

    console.print(table)
    return 0


def _summary(args: argparse.Namespace) -> int:
    """Display a human-readable file analysis summary."""
    try:
        result = analyze_file(
            args.path,
            min_string_length=args.min_string_length,
            max_strings=args.max_strings,
            max_file_size_mb=args.max_file_size_mb,
        )
    except (OSError, ValueError) as exc:
        console.print(f"[red]Analysis failed:[/red] {exc}")
        return 2

    table = Table(title=f"File Analysis — {result.name}")
    table.add_column("Property", style="cyan")
    table.add_column("Value")

    table.add_row("Path", result.path)
    table.add_row("Size (bytes)", str(result.size_bytes))
    table.add_row("Extension", result.extension or "(none)")
    table.add_row("SHA-256", result.sha256)
    table.add_row("Signature", result.signature)
    table.add_row(
        "Entropy (bits/byte)",
        f"{result.entropy_bits_per_byte:.4f}",
    )
    table.add_row("Printable strings", str(len(result.printable_strings)))

    if result.pe_metadata is not None:
        pe = result.pe_metadata
        table.add_row("PE architecture", pe.machine)
        if pe.optional_header is not None:
            optional = pe.optional_header
            table.add_row("PE optional header", optional.format)
            table.add_row("PE entry point RVA", f"0x{optional.entry_point_rva:08X}")
            table.add_row("PE image base", f"0x{optional.image_base:X}")
            table.add_row("PE subsystem", optional.subsystem_name)
            table.add_row("PE section alignment", str(optional.section_alignment))
            table.add_row("PE file alignment", str(optional.file_alignment))
            table.add_row("PE image size", str(optional.size_of_image))
            table.add_row("PE headers size", str(optional.size_of_headers))
            table.add_row(
                "PE DLL characteristics", f"0x{optional.dll_characteristics:04X}"
            )
        table.add_row("PE sections", str(pe.section_count))
        table.add_row("Executable", "Yes" if pe.is_executable else "No")
        table.add_row("DLL", "Yes" if pe.is_dll else "No")
        table.add_row("PE import table", pe.import_table_status.replace("_", " "))
        table.add_row("PE import modules", str(len(pe.imports)))
        table.add_row(
            "PE imported symbols",
            str(sum(len(module.symbols) for module in pe.imports)),
        )
        table.add_row("PE export table", pe.export_table_status.replace("_", " "))
        table.add_row("PE exported symbols", str(len(pe.exports)))
        table.add_row(
            "PE certificate table",
            pe.certificate_table.status.replace("_", " "),
        )
        table.add_row("PE certificate entries", str(len(pe.certificate_table.entries)))
        table.add_row(
            "PE debug directory",
            pe.debug_directory_status.replace("_", " "),
        )
        table.add_row("PE debug entries", str(len(pe.debug_entries)))
        table.add_row(
            "PE resource directory",
            pe.resource_directory_status.replace("_", " "),
        )
        table.add_row("PE resource entries", str(len(pe.resources)))
        if pe.certificate_table.file_offset is not None:
            table.add_row(
                "PE certificate table offset",
                f"0x{pe.certificate_table.file_offset:08X}",
            )
            table.add_row(
                "PE certificate table size",
                str(pe.certificate_table.size),
            )
        table.add_row("PE overlay", pe.overlay_status.replace("_", " "))
        if pe.overlay_offset is not None:
            table.add_row("PE overlay offset", f"0x{pe.overlay_offset:08X}")
        table.add_row("PE overlay size (bytes)", str(pe.overlay_size))

        if pe.sections:
            section_table = Table(title="PE sections (details)")
            section_table.add_column("Name")
            section_table.add_column("Virtual address")
            section_table.add_column("Virtual size", justify="right")
            section_table.add_column("Raw offset")
            section_table.add_column("Raw size", justify="right")
            section_table.add_column("R/W/X")
            for section in pe.sections:
                permissions = (
                    ("R" if section.readable else "-")
                    + ("W" if section.writable else "-")
                    + ("X" if section.executable else "-")
                )
                section_table.add_row(
                    section.name,
                    f"0x{section.virtual_address:08X}",
                    str(section.virtual_size),
                    f"0x{section.raw_offset:08X}",
                    str(section.raw_size),
                    permissions,
                )
            console.print(section_table)

        if pe.imports:
            import_table = Table(title="PE imports")
            import_table.add_column("Library")
            import_table.add_column("Imported symbols")
            for module in pe.imports:
                displayed_symbols = [
                    symbol.name if symbol.name is not None else f"ordinal {symbol.ordinal}"
                    for symbol in module.symbols[:10]
                ]
                if len(module.symbols) > 10:
                    displayed_symbols.append(f"... +{len(module.symbols) - 10} more")
                import_table.add_row(module.name, ", ".join(displayed_symbols) or "(none)")
            console.print(import_table)

        if pe.resources:
            resource_table = Table(title="PE resources")
            resource_table.add_column("Path")
            resource_table.add_column("Size", justify="right")
            resource_table.add_column("Data RVA")
            resource_table.add_column("Code page", justify="right")
            for resource in pe.resources[:20]:
                resource_table.add_row(
                    " / ".join(resource.path),
                    str(resource.size),
                    f"0x{resource.data_rva:08X}",
                    str(resource.code_page),
                )
            if len(pe.resources) > 20:
                resource_table.add_row(
                    f"... +{len(pe.resources) - 20} more", "", "", ""
                )
            console.print(resource_table)

        codeview_entries = [
            entry for entry in pe.debug_entries if entry.codeview_format == "RSDS"
        ]
        if codeview_entries:
            debug_table = Table(title="PE CodeView debug metadata")
            debug_table.add_column("PDB GUID")
            debug_table.add_column("Age", justify="right")
            debug_table.add_column("PDB path")
            for entry in codeview_entries[:10]:
                debug_table.add_row(
                    entry.pdb_guid or "",
                    str(entry.pdb_age if entry.pdb_age is not None else ""),
                    entry.pdb_path or "",
                )
            if len(codeview_entries) > 10:
                debug_table.add_row("...", "", f"+{len(codeview_entries) - 10} more")
            console.print(debug_table)

        if pe.certificate_table.entries:
            certificate_table = Table(title="PE certificate table entries")
            certificate_table.add_column("File offset")
            certificate_table.add_column("Length", justify="right")
            certificate_table.add_column("Revision")
            certificate_table.add_column("Type")
            for entry in pe.certificate_table.entries[:10]:
                certificate_table.add_row(
                    f"0x{entry.file_offset:08X}",
                    str(entry.length),
                    f"0x{entry.revision:04X}",
                    entry.certificate_type_name,
                )
            if len(pe.certificate_table.entries) > 10:
                certificate_table.add_row(
                    "...",
                    f"+{len(pe.certificate_table.entries) - 10} more",
                    "",
                    "",
                )
            console.print(certificate_table)

        if pe.exports:
            export_table = Table(title="PE exports")
            export_table.add_column("Ordinal", justify="right")
            export_table.add_column("Name")
            export_table.add_column("Address RVA")
            export_table.add_column("Forwarder")
            for export in pe.exports[:20]:
                export_table.add_row(
                    str(export.ordinal),
                    export.name or "(ordinal only)",
                    f"0x{export.address_rva:08X}",
                    export.forwarder or "",
                )
            if len(pe.exports) > 20:
                export_table.add_row(
                    "...",
                    f"+{len(pe.exports) - 20} more",
                    "",
                    "",
                )
            console.print(export_table)
    else:
        table.add_row("PE metadata", "Not detected")

    console.print(table)
    return 0


def _batch(args: argparse.Namespace) -> int:
    """Analyze files in a directory and write a combined JSON report."""
    root = Path(args.directory)

    if not root.exists():
        console.print(f"[red]Directory not found:[/red] {root}")
        return 2
    if not root.is_dir():
        console.print(f"[red]Not a directory:[/red] {root}")
        return 2

    output_path = Path(args.output).resolve()
    try:
        candidates = root.rglob("*") if args.recursive else root.glob("*")
        files = sorted(
            (
                path
                for path in candidates
                if path.is_file() and path.resolve() != output_path
            ),
            key=lambda path: str(path).casefold(),
        )
    except OSError as exc:
        console.print(f"[red]Could not list directory:[/red] {exc}")
        return 2

    report = {
        "tool": "Reverse Engineering Intelligence",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "directory": str(root.resolve()),
        "recursive": args.recursive,
        "files_discovered": len(files),
        "files_analyzed": 0,
        "files_failed": 0,
        "results": [],
        "errors": [],
    }

    for path in files:
        try:
            result = analyze_file(
                path,
                min_string_length=args.min_string_length,
                max_strings=args.max_strings,
                max_file_size_mb=args.max_file_size_mb,
            )
            report["results"].append(result.model_dump())
            report["files_analyzed"] += 1
        except (OSError, ValueError) as exc:
            report["errors"].append(
                {
                    "path": str(path.resolve()),
                    "error": str(exc),
                }
            )
            report["files_failed"] += 1

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        console.print(f"[red]Could not write batch report:[/red] {exc}")
        return 2

    table = Table(title="Batch Analysis Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right")
    table.add_row("Files discovered", str(report["files_discovered"]))
    table.add_row("Files analyzed", str(report["files_analyzed"]))
    table.add_row("Files failed", str(report["files_failed"]))
    console.print(table)
    console.print(f"[green]Batch report written to[/green] {output_path}")

    return 1 if report["files_failed"] else 0


def _comparison_key(path: str) -> str:
    """Normalize report paths consistently across Windows and POSIX separators."""
    return path.replace("\\", "/").casefold().rstrip("/")


def _load_comparison_report(
    report_path: Path,
) -> tuple[dict[str, FileAnalysisResult], dict]:
    """Load and validate either a single-file or batch JSON analysis report."""
    try:
        document = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not load JSON report '{report_path}': {exc}") from exc

    if not isinstance(document, dict):
        raise ValueError(f"Report must contain a JSON object: {report_path}")

    if "results" in document:
        raw_results = document["results"]
        if not isinstance(raw_results, list):
            raise ValueError(f"Batch report 'results' must be a list: {report_path}")
    elif "sha256" in document:
        raw_results = [document]
    else:
        raise ValueError(
            f"Unsupported report format in '{report_path}': "
            "expected a single-file analysis or batch report"
        )

    results: dict[str, FileAnalysisResult] = {}
    for index, raw_result in enumerate(raw_results):
        if not isinstance(raw_result, dict):
            raise ValueError(
                f"Report '{report_path}' result {index} is not a JSON object"
            )
        try:
            result = FileAnalysisResult.model_validate(raw_result)
        except ValueError as exc:
            raise ValueError(
                f"Report '{report_path}' result {index} is invalid: {exc}"
            ) from exc

        key = _comparison_key(result.path)
        if key in results:
            raise ValueError(
                f"Report '{report_path}' contains duplicate file paths: {result.path}"
            )
        results[key] = result

    return results, document


def _compare_reports(args: argparse.Namespace) -> int:
    """Compare two JSON reports and identify added, removed, or modified files."""
    before_path = Path(args.before)
    after_path = Path(args.after)
    output_path = Path(args.output) if args.output else None

    resolved_inputs = {before_path.resolve(), after_path.resolve()}
    if output_path is not None and output_path.resolve() in resolved_inputs:
        console.print("[red]Comparison output must not overwrite an input report.[/red]")
        return 2

    try:
        before, before_document = _load_comparison_report(before_path)
        after, after_document = _load_comparison_report(after_path)
    except ValueError as exc:
        console.print(f"[red]Comparison failed:[/red] {exc}")
        return 2

    changes: list[dict[str, str | None]] = []
    counts = {"added": 0, "removed": 0, "modified": 0, "unchanged": 0}
    for key in sorted(set(before) | set(after)):
        old_result = before.get(key)
        new_result = after.get(key)

        if old_result is None:
            status = "added"
        elif new_result is None:
            status = "removed"
        elif old_result.sha256.casefold() != new_result.sha256.casefold():
            status = "modified"
        else:
            status = "unchanged"
        counts[status] += 1

        changes.append(
            {
                "path": new_result.path if new_result is not None else old_result.path,
                "status": status,
                "before_sha256": old_result.sha256 if old_result is not None else None,
                "after_sha256": new_result.sha256 if new_result is not None else None,
            }
        )

    comparison = {
        "tool": "Reverse Engineering Intelligence",
        "comparison_type": "sha256_by_normalized_path",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "before_report": str(before_path),
        "after_report": str(after_path),
        "before_files_analyzed": len(before),
        "after_files_analyzed": len(after),
        "before_files_failed": before_document.get("files_failed", 0),
        "after_files_failed": after_document.get("files_failed", 0),
        "counts": counts,
        "changes": changes,
    }

    if before_document.get("files_failed", 0) or after_document.get("files_failed", 0):
        console.print(
            "[yellow]Warning:[/yellow] at least one batch report contains failed files; "
            "the comparison covers successfully analyzed results only."
        )

    summary = Table(title="Investigation Report Comparison")
    summary.add_column("Change", style="cyan")
    summary.add_column("Files", justify="right")
    for label in ("added", "removed", "modified", "unchanged"):
        summary.add_row(label.title(), str(counts[label]))
    console.print(summary)

    changed_items = [item for item in changes if item["status"] != "unchanged"]
    if changed_items:
        detail_table = Table(title="File-level changes")
        detail_table.add_column("Path")
        detail_table.add_column("Status")
        detail_table.add_column("Before SHA-256")
        detail_table.add_column("After SHA-256")
        for item in changed_items[:100]:
            detail_table.add_row(
                str(item["path"]),
                str(item["status"]).title(),
                (item["before_sha256"] or "")[:12],
                (item["after_sha256"] or "")[:12],
            )
        if len(changed_items) > 100:
            detail_table.add_row(
                f"... +{len(changed_items) - 100} more changes", "", "", ""
            )
        console.print(detail_table)
    else:
        console.print("No file additions, removals, or SHA-256 changes detected.")

    if output_path is not None:
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(comparison, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            console.print(f"[red]Could not write comparison report:[/red] {exc}")
            return 2
        console.print(f"[green]Comparison report written to[/green] {output_path}")

    return 0


def _add_file_analysis_options(parser: argparse.ArgumentParser) -> None:
    """Add shared analysis limits to a command parser."""
    parser.add_argument("--max-strings", type=int, default=500)
    parser.add_argument(
        "--max-file-size-mb",
        type=int,
        default=DEFAULT_MAX_FILE_SIZE_MB,
        help=(
            "Maximum file size to analyze in MiB "
            f"(default: {DEFAULT_MAX_FILE_SIZE_MB})."
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="re-intel",
        description="Read-only static file inspection and triage.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    inspect_parser = commands.add_parser(
        "inspect",
        help="Analyze a file and output JSON.",
    )
    inspect_parser.add_argument(
        "path",
        help="Path to a file you are authorized to inspect.",
    )
    inspect_parser.add_argument("--output", help="Optional path for the JSON report.")
    inspect_parser.add_argument("--min-string-length", type=int, default=5)
    _add_file_analysis_options(inspect_parser)
    inspect_parser.set_defaults(handler=_inspect)

    strings_parser = commands.add_parser(
        "strings",
        help="Display printable ASCII strings.",
    )
    strings_parser.add_argument(
        "path",
        help="Path to a file you are authorized to inspect.",
    )
    strings_parser.add_argument("--min-length", type=int, default=5)
    _add_file_analysis_options(strings_parser)
    strings_parser.set_defaults(handler=_strings)

    summary_parser = commands.add_parser(
        "summary",
        help="Display a human-readable file analysis summary.",
    )
    summary_parser.add_argument(
        "path",
        help="Path to a file you are authorized to inspect.",
    )
    summary_parser.add_argument("--min-string-length", type=int, default=5)
    _add_file_analysis_options(summary_parser)
    summary_parser.set_defaults(handler=_summary)

    batch_parser = commands.add_parser(
        "batch",
        help="Analyze files in a directory and create one JSON report.",
    )
    batch_parser.add_argument(
        "directory",
        help="Directory containing files you are authorized to inspect.",
    )
    batch_parser.add_argument(
        "--output",
        required=True,
        help="Path for the combined JSON report.",
    )
    batch_parser.add_argument(
        "--recursive",
        action="store_true",
        help="Include files in nested directories.",
    )
    batch_parser.add_argument("--min-string-length", type=int, default=5)
    _add_file_analysis_options(batch_parser)
    batch_parser.set_defaults(handler=_batch)

    compare_parser = commands.add_parser(
        "compare",
        help="Compare two single-file or batch JSON reports.",
    )
    compare_parser.add_argument("before", help="Earlier JSON analysis report.")
    compare_parser.add_argument("after", help="Later JSON analysis report.")
    compare_parser.add_argument(
        "--output",
        help="Optional path to write the machine-readable comparison report.",
    )
    compare_parser.set_defaults(handler=_compare_reports)

    return parser


def main() -> None:
    """Validate common arguments and run the selected command."""
    args = build_parser().parse_args()

    min_length = getattr(
        args,
        "min_string_length",
        getattr(args, "min_length", 1),
    )
    if min_length < 1:
        console.print("[red]Minimum string length must be at least 1.[/red]")
        raise SystemExit(2)

    if hasattr(args, "max_strings") and args.max_strings < 0:
        console.print("[red]Maximum strings cannot be negative.[/red]")
        raise SystemExit(2)

    if (
        hasattr(args, "max_file_size_mb")
        and args.max_file_size_mb < 1
    ):
        console.print("[red]Maximum file size must be at least 1 MiB.[/red]")
        raise SystemExit(2)

    raise SystemExit(args.handler(args))


if __name__ == "__main__":
    main()
