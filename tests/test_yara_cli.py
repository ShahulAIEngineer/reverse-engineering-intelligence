"""CLI tests for the YARA-X command; these do not require YARA-X itself."""

from __future__ import annotations

import json
from argparse import Namespace

from re_intel import cli


class _FakeReport:
    def __init__(self) -> None:
        self.path = "sample.bin"
        self.size_bytes = 12
        self.sha256 = "a" * 64
        self.rules_path = "demo.yar"
        self.rules_sha256 = "b" * 64
        self.matched_rule_count = 0
        self.elapsed_seconds = 0.001
        self.matching_rules = []
        self.matching_rules_truncated = False
        self._payload = {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "rules_path": self.rules_path,
            "rules_sha256": self.rules_sha256,
            "matched_rule_count": self.matched_rule_count,
            "matching_rules": [],
        }

    def model_dump_json(self, *, indent: int = 2) -> str:
        return json.dumps(self._payload, indent=indent)


def _args(target, rules, output=None) -> Namespace:
    return Namespace(
        path=str(target),
        rules=str(rules),
        output=str(output) if output is not None else None,
        max_file_size_mb=100,
        timeout=10,
    )


def test_yara_scan_parser_registers_expected_options(tmp_path) -> None:
    target = tmp_path / "sample.bin"
    rules = tmp_path / "demo.yar"

    args = cli.build_parser().parse_args(
        ["yara-scan", str(target), "--rules", str(rules)]
    )

    assert args.command == "yara-scan"
    assert args.rules == str(rules)
    assert args.timeout == cli.DEFAULT_SCAN_TIMEOUT_SECONDS
    assert args.max_file_size_mb == cli.DEFAULT_MAX_FILE_SIZE_MB
    assert args.handler is cli._yara_scan


def test_yara_scan_writes_json_report(tmp_path, monkeypatch) -> None:
    target = tmp_path / "sample.bin"
    rules = tmp_path / "demo.yar"
    output = tmp_path / "reports" / "result.json"
    target.write_bytes(b"sample content")
    rules.write_text("rule demo { condition: true }", encoding="utf-8")
    expected_report = _FakeReport()
    calls = []

    def fake_scan(path, rules_path, *, max_file_size_mb, timeout_seconds):
        calls.append((path, rules_path, max_file_size_mb, timeout_seconds))
        return expected_report

    monkeypatch.setattr(cli, "scan_file_with_yara", fake_scan)

    result = cli._yara_scan(_args(target, rules, output))

    assert result == 0
    assert json.loads(output.read_text(encoding="utf-8")) == expected_report._payload
    assert calls == [(target, rules, 100, 10)]


def test_yara_scan_refuses_to_overwrite_target(tmp_path, monkeypatch) -> None:
    target = tmp_path / "sample.bin"
    rules = tmp_path / "demo.yar"
    target.write_bytes(b"sample content")
    rules.write_text("rule demo { condition: true }", encoding="utf-8")
    called = False

    def fake_scan(*args, **kwargs):
        nonlocal called
        called = True
        return _FakeReport()

    monkeypatch.setattr(cli, "scan_file_with_yara", fake_scan)

    assert cli._yara_scan(_args(target, rules, target)) == 2
    assert called is False


def test_yara_scan_returns_error_for_scanner_failure(tmp_path, monkeypatch) -> None:
    target = tmp_path / "sample.bin"
    rules = tmp_path / "demo.yar"

    def fake_scan(*args, **kwargs):
        raise ValueError("invalid test rules")

    monkeypatch.setattr(cli, "scan_file_with_yara", fake_scan)

    assert cli._yara_scan(_args(target, rules)) == 2
