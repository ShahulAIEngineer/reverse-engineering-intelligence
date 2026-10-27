"""Command-line interface for Reverse Engineering Intelligence."""

import argparse
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from re_intel.analyzers.file_analyzer import analyze_file

console = Console()


def _inspect(args: argparse.Namespace) -> int:
    try:
        result = analyze_file(
            args.path,
            min_string_length=args.min_string_length,
            max_strings=args.max_strings,
        )
    except (OSError, ValueError) as exc:
        console.print(f"[red]Analysis failed:[/red] {exc}")
        return 2

    payload = result.model_dump()
    rendered = json.dumps(payload, indent=2, ensure_ascii=False)

    if args.output:
        output_path = Path(args.output)
        try:
            output_path.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            console.print(f"[red]Could not write report:[/red] {exc}")
            return 2
        console.print(f"[green]Report written to[/green] {output_path}")
    else:
        console.print(rendered)

    return 0


def _strings(args: argparse.Namespace) -> int:
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="re-intel",
        description="Read-only static file inspection and triage.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    inspect_parser = commands.add_parser("inspect", help="Analyze a file and output JSON.")
    inspect_parser.add_argument("path", help="Path to a file you are authorized to inspect.")
    inspect_parser.add_argument("--output", help="Optional path for the JSON report.")
    inspect_parser.add_argument("--min-string-length", type=int, default=5)
    inspect_parser.add_argument("--max-strings", type=int, default=500)
    inspect_parser.set_defaults(handler=_inspect)

    strings_parser = commands.add_parser("strings", help="Display printable ASCII strings.")
    strings_parser.add_argument("path", help="Path to a file you are authorized to inspect.")
    strings_parser.add_argument("--min-length", type=int, default=5)
    strings_parser.add_argument("--max-strings", type=int, default=500)
    strings_parser.set_defaults(handler=_strings)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    if getattr(args, "min_string_length", getattr(args, "min_length", 1)) < 1:
        console.print("[red]Minimum string length must be at least 1.[/red]")
        raise SystemExit(2)
    if args.max_strings < 0:
        console.print("[red]Maximum strings cannot be negative.[/red]")
        raise SystemExit(2)
    raise SystemExit(args.handler(args))


if __name__ == "__main__":
    main()
