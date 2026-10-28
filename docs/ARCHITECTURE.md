# Architecture

## Data flow

1. The CLI receives a file or directory path from the user.
2. The analyzer validates that the target exists and is a regular file, and enforces the configured file-size limit.
3. The analyzer reads file content in bounded chunks to calculate SHA-256 and Shannon entropy.
4. It examines leading bytes for a heuristic signature hint and extracts printable ASCII strings.
5. For recognized Windows PE candidates, the analyzer validates selected header boundaries and extracts basic PE metadata.
6. PE metadata includes the machine architecture, selected optional-header fields, section count, executable and DLL flags, section details, import/export tables, the resource tree, debug entries, certificate records, and overlay estimates.
7. Selected optional-header fields include PE32/PE32+ format, entry-point RVA, image base, section and file alignment, image/header sizes, subsystem, and DLL characteristics. Section metadata includes section names, virtual addresses and sizes, raw file offsets and sizes, and read/write/execute characteristics.
8. Import-table parsing maps RVAs through headers or section raw data and extracts imported DLL names plus imports by name or ordinal. Export-table parsing extracts named and ordinal-only exports and forwarded exports.
9. The security directory is handled as a file-offset range, not an RVA. The analyzer reads bounded WIN_CERTIFICATE record headers and reports absent, parsed, or malformed certificate-table metadata without verifying signatures.
10. The debug directory is mapped through the bounded section/header RVA mapper. IMAGE_DEBUG_DIRECTORY entries are parsed within fixed record-count limits; RSDS CodeView records optionally provide a GUID, age, and bounded PDB path.
11. The resource directory is traversed as a bounded tree with cycle/depth/entry limits. Resource names are decoded from bounded UTF-16 strings, and leaf records report data RVA, size, code page, and file offset without reading payload content.
12. Overlay analysis estimates trailing bytes beyond headers and section raw data; malformed or truncated section ranges produce an uncertain status. The reported overlay may include the certificate table.
13. Table parsers use bounded counts and strings and report absent or malformed tables explicitly.
14. Pydantic models validate the structured analysis result.
15. The CLI presents human-readable summaries, including PE import/export, resource-tree, certificate-table, debug-directory, and overlay metadata, printable strings, or JSON output. Batch mode supports analyzing multiple files and reporting per-file results and errors.
16. Report comparison validates single-file or batch JSON reports, matches records by normalized path, compares SHA-256 fingerprints, and emits added/removed/modified/unchanged counts plus an optional JSON delta report.

## Safety properties

- Inspected files are opened read-only by the analyzer.
- The analyzer never intentionally executes the inspected file.
- The analyzer does not intentionally modify the inspected file.
- File size is limited by configuration, and file metadata is checked before and after analysis to detect changes during reading.
- Output files are written only when the user explicitly requests an output path.
- Extracted strings and file metadata should be treated as untrusted data.

## Current scope

The project is a lightweight static inspection and triage toolkit, not a complete reverse-engineering suite or malware detector.

PE parsing validates selected structures and extracts useful metadata; it does not implement the complete PE specification. Resource traversal reports resource metadata only and does not parse, trust, or execute the resource payloads. Certificate-table parsing reports structural record metadata only: it does not validate certificate chains or cryptographically verify Authenticode signatures. CodeView PDB paths are untrusted values and do not prove that the PDB belongs to the inspected binary. Overlay offsets are estimates based on headers and section raw-data ranges. Signature hints are heuristic, and a recognized signature does not establish that a file is valid or safe.

## Future extensions

Potential follow-on modules include optional YARA integration, additional file-format support, reproducible release packaging, and a richer evidence trail. Each extension should preserve read-only handling and include appropriate automated tests.