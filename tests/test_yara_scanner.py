"""Integration tests for the optional YARA-X scanner.

These tests are skipped when the optional `yara` extra is not installed.
"""

from __future__ import annotations

import hashlib
import importlib.util

import pytest

from re_intel.analyzers.yara_scanner import scan_file_with_yara


pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("yara_x") is None,
    reason=(
        "YARA-X is optional; install with `pip install -e .[yara]` "
        "to run these tests."
    ),
)


def _write_rule(path, *, needle: str = "DEMO_MARKER") -> None:
    path.write_text(
        f'''rule demo_marker {{
    meta:
        description = "YARA-X integration test"
    strings:
        $marker = "{needle}"
    condition:
        $marker
}}
''',
        encoding="utf-8",
    )


def test_scan_reports_matching_rule_and_hashes(tmp_path) -> None:
    target = tmp_path / "sample.bin"
    rules = tmp_path / "demo.yar"
    payload = b"header DEMO_MARKER footer"
    target.write_bytes(payload)
    _write_rule(rules)

    report = scan_file_with_yara(target, rules)

    assert report.size_bytes == len(payload)
    assert report.sha256 == hashlib.sha256(payload).hexdigest()
    assert report.rules_sha256 == hashlib.sha256(rules.read_bytes()).hexdigest()
    assert report.matched_rule_count == 1
    assert [match.identifier for match in report.matching_rules] == ["demo_marker"]


def test_scan_reports_no_match_for_unrelated_content(tmp_path) -> None:
    target = tmp_path / "unrelated.bin"
    rules = tmp_path / "demo.yar"
    target.write_bytes(b"ordinary content without the signature")
    _write_rule(rules)

    report = scan_file_with_yara(target, rules)

    assert report.matched_rule_count == 0
    assert not report.matching_rules


def test_scan_rejects_target_above_configured_size_limit(tmp_path) -> None:
    target = tmp_path / "oversized.bin"
    rules = tmp_path / "demo.yar"
    target.write_bytes(b"A" * (1024 * 1024 + 1))
    _write_rule(rules)

    with pytest.raises(ValueError):
        scan_file_with_yara(target, rules, max_file_size_mb=1)


def test_scan_rejects_invalid_timeout(tmp_path) -> None:
    target = tmp_path / "sample.bin"
    rules = tmp_path / "demo.yar"
    target.write_bytes(b"DEMO_MARKER")
    _write_rule(rules)

    with pytest.raises(ValueError):
        scan_file_with_yara(target, rules, timeout_seconds=0)
