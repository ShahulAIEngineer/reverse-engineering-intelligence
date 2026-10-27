# Reverse Engineering Intelligence

A safe, read-only static inspection toolkit for collecting basic file metadata and generating JSON reports. It does not execute, modify, unpack, or patch inspected files.

## Features

- SHA-256 hashing using chunked reads
- File size, extension, and basic file-signature identification
- Printable ASCII string extraction from files
- Shannon entropy estimate for basic triage
- Validated Pydantic result models
- JSON report output and a command-line interface
- Automated tests, Ruff checks, and GitHub Actions CI

## Requirements

- Python 3.11+
- Windows, macOS, or Linux

## Setup (Windows CMD)

Open a terminal in the project folder and run:

```cmd
python -m venv .venv
.venv\Scripts\activate
python -m pip install -e ".[dev]"
python -m pytest -v
python -m ruff check src tests
```

If PowerShell is used instead of CMD, activate with:

```powershell
.\.venv\Scripts\Activate.ps1
```

## Usage

Inspect a file and print a JSON report:

```cmd
re-intel inspect path\to\sample.bin
```

Write the report to a JSON file:

```cmd
re-intel inspect path\to\sample.bin --output report.json
```

Extract printable ASCII strings (default minimum length: 5):

```cmd
re-intel strings path\to\sample.bin --min-length 5
```

The tool performs read-only analysis. Only use it on files you own or are authorized to inspect. Treat extracted strings and file metadata as untrusted input.

## Project structure

```text
reverse-engineering-intelligence/
├── .github/workflows/ci.yml
├── docs/ARCHITECTURE.md
├── examples/
├── src/re_intel/
│   ├── analyzers/file_analyzer.py
│   ├── cli.py
│   └── models.py
├── tests/
├── .gitignore
├── .env.example
├── pyproject.toml
└── README.md
```

## Development checks

```cmd
python -m pytest -v
python -m ruff check src tests
```

## Scope and limitations

This is a foundation for authorized static analysis and triage. File-signature detection is heuristic, ASCII string extraction does not decode every encoding, and entropy is only a rough indicator—not proof of encryption, compression, or maliciousness.
