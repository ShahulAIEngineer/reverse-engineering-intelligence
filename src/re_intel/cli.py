
"""Command-line interface for Reverse Engineering Intelligence."""

import argparse
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from re_intel.analyzers.file_analyzer import analyze_file

console = Console()


def _inspect(args: argparse.Namespace) -> int:
    """Analyze a file and output a JSON report."""
    try:
        result = analyze_file(
            args.path,
            min_string_length=args.min_string_length,
            max_strings=args.max_strings,
        )
    except (OSError, ValueError) as exc:
        console.print(f"[red]Analysis failed:[/red] {exc}")
        return 2

    rendered = json.dumps(
        result.model_dump(),
        indent=2,
        ensure_ascii=False,
    )

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
        table.add_row("PE sections", str(pe.section_count))
        table.add_row("Executable", "Yes" if pe.is_executable else "No")
        table.add_row("DLL", "Yes" if pe.is_dll else "No")
    else:
        table.add_row("PE metadata", "Not detected")

    console.print(table)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="re-intel",
        description="Read-only static file inspection and triage.",
    )
    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    inspect_parser = commands.add_parser(
        "inspect",
        help="Analyze a file and output JSON.",
    )
    inspect_parser.add_argument(
        "path",
        help="Path to a file you are authorized to inspect.",
    )
    inspect_parser.add_argument(
        "--output",
        help="Optional path for the JSON report.",
    )
    inspect_parser.add_argument(
        "--min-string-length",
        type=int,
        default=5,
    )
    inspect_parser.add_argument(
        "--max-strings",
        type=int,
        default=500,
    )
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
    strings_parser.add_argument("--max-strings", type=int, default=500)
    strings_parser.set_defaults(handler=_strings)

    summary_parser = commands.add_parser(
        "summary",
        help="Display a human-readable file analysis summary.",
    )
    summary_parser.add_argument(
        "path",
        help="Path to a file you are authorized to inspect.",
    )
    summary_parser.add_argument(
        "--min-string-length",
        type=int,
        default=5,
    )
    summary_parser.add_argument(
        "--max-strings",
        type=int,
        default=500,
    )
    summary_parser.set_defaults(handler=_summary)

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
        console.print(
            "[red]Minimum string length must be at least 1.[/red]"
        )
        raise SystemExit(2)

    if args.max_strings < 0:
        console.print("[red]Maximum strings cannot be negative.[/red]")
        raise SystemExit(2)

    raise SystemExit(args.handler(args))


if __name__ == "__main__":
    main()
