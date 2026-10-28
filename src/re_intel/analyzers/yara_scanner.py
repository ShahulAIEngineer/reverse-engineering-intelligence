"""Optional YARA-X scanning for authorized static file investigations.

YARA-X is imported lazily so the core package stays usable without the optional extra.
The scanner bounds input sizes, scan time, per-pattern match counts, and recorded rules.
"""

from __future__ import annotations

import hashlib
import importlib
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

DEFAULT_MAX_FILE_SIZE_MB = 100
DEFAULT_SCAN_TIMEOUT_SECONDS = 10
MIN_SCAN_TIMEOUT_SECONDS = 1
MAX_SCAN_TIMEOUT_SECONDS = 60
MAX_RULES_FILE_SIZE_BYTES = 2 * 1024 * 1024
MAX_MATCHES_PER_PATTERN = 1000
MAX_RECORDED_MATCHING_RULES = 500


class YaraUnavailableError(RuntimeError):
    """Raised when YARA-X is not installed."""


class YaraStringMatch(BaseModel):
    """A bounded YARA string-match location; file bytes are not copied into the report."""

    offset: int = Field(ge=0)
    length: int = Field(ge=0)
    xor_key: int | None = None


class YaraPatternMatch(BaseModel):
    """Recorded matches for one rule pattern."""

    identifier: str
    reported_match_count: int = Field(ge=0)
    matches: list[YaraStringMatch] = Field(default_factory=list)


class YaraRuleMatch(BaseModel):
    """Structured details for one rule that matched."""

    identifier: str
    namespace: str
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    patterns: list[YaraPatternMatch] = Field(default_factory=list)


class YaraScanReport(BaseModel):
    """Reproducible summary of a YARA-X scan."""

    path: str
    size_bytes: int = Field(ge=0)
    sha256: str
    rules_path: str
    rules_sha256: str
    elapsed_seconds: float = Field(ge=0)
    matched_rule_count: int = Field(ge=0)
    matching_rules: list[YaraRuleMatch] = Field(default_factory=list)
    matching_rules_truncated: bool = False


def _read_bounded(path: Path, limit: int, description: str) -> bytes:
    """Read no more than limit+1 bytes, detecting growth after an initial stat."""
    size = path.stat().st_size

    if size > limit:
        raise ValueError(f"{description} exceeds the configured size limit ({limit} bytes).")
    if not path.is_file():
        raise ValueError(f"{description} must be a regular file.")

    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{description} exceeds the configured size limit ({limit} bytes).")
    return data


def _as_rule_match(rule: Any) -> YaraRuleMatch:
    """Convert the YARA-X result object to a serializable model."""
    matched_patterns: list[YaraPatternMatch] = []
    for pattern in rule.patterns:
        reported_matches = list(pattern.matches)
        if not reported_matches:
            continue
        matched_patterns.append(
            YaraPatternMatch(
                identifier=pattern.identifier,
                reported_match_count=len(reported_matches),
                matches=[
                    YaraStringMatch(
                        offset=int(match.offset),
                        length=int(match.length),
                        xor_key=(
                            int(match.xor_key)
                            if getattr(match, "xor_key", None) is not None
                            else None
                        ),
                    )
                    for match in reported_matches[:MAX_MATCHES_PER_PATTERN]
                ],
            )
        )

    return YaraRuleMatch(
        identifier=str(rule.identifier),
        namespace=str(getattr(rule, "namespace", "default")),
        tags=[str(tag) for tag in getattr(rule, "tags", ())],
        metadata={str(key): value for key, value in getattr(rule, "metadata", ())},
        patterns=matched_patterns,
    )


def scan_file_with_yara(
    path: str | Path,
    rules_path: str | Path,
    *,
    max_file_size_mb: int = DEFAULT_MAX_FILE_SIZE_MB,
    timeout_seconds: int = DEFAULT_SCAN_TIMEOUT_SECONDS,
) -> YaraScanReport:
    """Scan one authorized file with a local YARA rules file using YARA-X.

    The target and rule source are read as data only. YARA include statements are
    disabled to prevent rules from loading unexpected local files.
    """
    if max_file_size_mb < 1:
        raise ValueError("Maximum file size must be at least 1 MiB.")
    if not MIN_SCAN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_SCAN_TIMEOUT_SECONDS:
        raise ValueError(
            f"Timeout must be between {MIN_SCAN_TIMEOUT_SECONDS} and "
            f"{MAX_SCAN_TIMEOUT_SECONDS} seconds."
        )

    target_path = Path(path).expanduser().resolve()
    source_path = Path(rules_path).expanduser().resolve()
    target_limit = max_file_size_mb * 1024 * 1024
    target_data = _read_bounded(target_path, target_limit, "Target file")
    rule_data = _read_bounded(
        source_path,
        MAX_RULES_FILE_SIZE_BYTES,
        "YARA rules file",
    )

    try:
        yara_x = importlib.import_module("yara_x")
    except ImportError as exc:
        raise YaraUnavailableError(
            'YARA-X is not installed. Install it with: pip install -e ".[yara]"'
        ) from exc

    rule_source = rule_data.decode("utf-8-sig")
    started = time.perf_counter()
    try:
        compiler = yara_x.Compiler()
        compiler.enable_includes(False)
        compiler.add_source(rule_source, origin=str(source_path))
        compiled_rules = compiler.build()

        scanner = yara_x.Scanner(compiled_rules)
        scanner.set_timeout(timeout_seconds)
        scanner.max_matches_per_pattern(MAX_MATCHES_PER_PATTERN)
        scan_results = scanner.scan(target_data)
    except (yara_x.CompileError, yara_x.ScanError, yara_x.TimeoutError) as exc:
        raise ValueError(f"YARA-X scan failed: {exc}") from exc
    elapsed = time.perf_counter() - started

    all_matches = list(scan_results.matching_rules)
    recorded_matches = all_matches[:MAX_RECORDED_MATCHING_RULES]
    return YaraScanReport(
        path=str(target_path),
        size_bytes=len(target_data),
        sha256=hashlib.sha256(target_data).hexdigest(),
        rules_path=str(source_path),
        rules_sha256=hashlib.sha256(rule_data).hexdigest(),
        elapsed_seconds=elapsed,
        matched_rule_count=len(all_matches),
        matching_rules=[_as_rule_match(rule) for rule in recorded_matches],
        matching_rules_truncated=len(all_matches) > MAX_RECORDED_MATCHING_RULES,
    )
