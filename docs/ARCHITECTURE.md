# Architecture

## Data flow

1. The CLI receives a file or directory path from the user.
2. The analyzer validates that the target exists and is a regular file, and enforces the configured file-size limit.
3. The analyzer reads file content in bounded chunks to calculate SHA-256 and Shannon entropy.
4. It examines leading bytes for a heuristic signature hint and extracts printable ASCII strings.
5. For recognized Windows PE candidates, the analyzer validates selected header boundaries and extracts basic PE metadata.
6. PE metadata includes the machine architecture, section count, executable and DLL flags, and available section details.
7. Section metadata includes section names, virtual addresses and sizes, raw file offsets and sizes, and read/write/execute characteristics.
8. Pydantic models validate the structured analysis result.
9. The CLI presents a human-readable summary, printable strings, or JSON output. Batch mode supports analyzing multiple files and reporting per-file results and errors.

## Safety properties

- Inspected files are opened read-only by the analyzer.
- The analyzer never intentionally executes the inspected file.
- The analyzer does not intentionally modify the inspected file.
- File size is limited by configuration, and file metadata is checked before and after analysis to detect changes during reading.
- Output files are written only when the user explicitly requests an output path.
- Extracted strings and file metadata should be treated as untrusted data.

## Current scope

The project is a lightweight static inspection and triage toolkit, not a complete reverse-engineering suite or malware detector.

PE parsing validates selected structures and extracts useful metadata; it does not implement the complete PE specification. Signature hints are heuristic, and a recognized signature does not establish that a file is valid or safe.

## Future extensions

Potential follow-on modules include stronger PE validation, optional-header analysis, import-table inspection, additional file-format support, optional YARA integration, report comparisons, and a richer evidence trail. Each extension should preserve read-only handling and include appropriate automated tests.