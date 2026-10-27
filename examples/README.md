# Example Files and Reports

This directory contains reproducible demonstrations of the Reverse Engineering Intelligence toolkit.

## Directory structure


examples/
|-- README.md
|-- create_synthetic_pe.py
|-- fixtures/
|   `-- synthetic_pe.bin
`-- reports/
    `-- sample-analysis.json


## 1. Generate the synthetic PE fixture

From the repository root, run:

```bash
python examples/create_synthetic_pe.py
```

This creates a 512-byte artificial PE header for testing metadata extraction. It contains no executable program code and is not a functional Windows executable.

## 2. Inspect the fixture

Generate a JSON report:

```bash
re-intel inspect examples/fixtures/synthetic_pe.bin
```

Display a human-readable summary:

```bash
re-intel summary examples/fixtures/synthetic_pe.bin
```

The expected metadata includes x64 architecture, three sections, an executable-image flag, and a DLL flag set to false. These values are deliberately encoded in the synthetic header.

## 3. Review the sample report

The `reports/sample-analysis.json` file demonstrates the JSON output format for a text file.

To validate it:

```bash
python -m json.tool examples/reports/sample-analysis.json
```

To generate a fresh report:

```bash
re-intel inspect sample.txt --output examples/reports/sample-analysis.json
```

## Scope and safety

The examples are designed for local, read-only file analysis and parser testing. The synthetic fixture is for metadata demonstrations only. Header detection does not establish that a file is valid, safe, or executable.

For reliable results, use files you own or are authorized to analyze.