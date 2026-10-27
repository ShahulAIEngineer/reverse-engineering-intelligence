# Architecture

## Data flow

1. The CLI receives a path from the user.
2. The analyzer validates that the target exists and is a regular file.
3. The analyzer reads the file in bounded chunks to calculate SHA-256 and Shannon entropy.
4. It samples the first bytes for a basic signature hint and extracts printable ASCII strings.
5. A Pydantic model validates the report structure.
6. The CLI prints JSON or writes the report to a user-selected output path.

## Safety properties

- Inspected files are opened read-only.
- The analyzer never executes the inspected file.
- The analyzer never changes the inspected file.
- Output is only written when the user explicitly supplies `--output`.
- Extracted strings should be treated as untrusted data.

## Future extensions

Potential follow-on modules include PE/ELF/Mach-O header parsing, import tables, YARA integration, report comparisons, and a richer evidence trail. Each should preserve read-only handling and include tests.
