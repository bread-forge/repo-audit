"""Tests for repo_audit.security.gitleaks.GitleaksScanner."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from repo_audit.security.gitleaks import GitleaksScanner, _parse_findings


# ---------------------------------------------------------------------------
# Helpers — synthetic gitleaks payloads
# ---------------------------------------------------------------------------

SAMPLE_FINDING = {
    "RuleID": "aws-access-key",
    "Description": "AWS Access Key",
    "StartLine": 42,
    "EndLine": 42,
    "File": "config/secrets.py",
    "Secret": "AKIAIOSFODNN7EXAMPLE",
    "Match": "aws_key = 'AKIAIOSFODNN7EXAMPLE'",
    "Fingerprint": "abc123def456",
}


def _json_array(findings: list[dict]) -> str:
    return json.dumps(findings)


def _jsonl(findings: list[dict]) -> str:
    return "\n".join(json.dumps(f) for f in findings)


# ---------------------------------------------------------------------------
# _parse_findings
# ---------------------------------------------------------------------------


class TestParseFindings:
    """Tests for the internal _parse_findings helper."""

    def test_parses_json_array(self) -> None:
        raw = _json_array([SAMPLE_FINDING])
        result = _parse_findings(raw)
        assert len(result) == 1
        assert result[0]["RuleID"] == "aws-access-key"

    def test_parses_single_json_object(self) -> None:
        raw = json.dumps(SAMPLE_FINDING)
        result = _parse_findings(raw)
        assert len(result) == 1

    def test_parses_jsonl_format(self) -> None:
        """JSONL (one JSON object per line) is parsed into a list of dicts."""
        raw = _jsonl([SAMPLE_FINDING, {**SAMPLE_FINDING, "RuleID": "github-token"}])
        result = _parse_findings(raw)
        assert len(result) == 2

    def test_skips_invalid_jsonl_lines(self) -> None:
        raw = json.dumps(SAMPLE_FINDING) + "\nnot-valid-json\n"
        result = _parse_findings(raw)
        assert len(result) == 1

    def test_empty_json_array_returns_empty(self) -> None:
        result = _parse_findings("[]")
        assert result == []

    def test_non_dict_entries_filtered(self) -> None:
        raw = json.dumps([1, "string", SAMPLE_FINDING])
        result = _parse_findings(raw)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# GitleaksScanner.parse_output — secret redaction
# ---------------------------------------------------------------------------


class TestGitleaksScannerParseOutputSecretRedaction:
    """Secret values must not appear in any bead field."""

    scanner = GitleaksScanner()

    def test_secret_value_absent_from_evidence_chain(self) -> None:
        """The 'Secret' field value must not appear in evidence_chain."""
        raw = _json_array([SAMPLE_FINDING])
        findings = self.scanner.parse_output(raw, repo="/repo", cycle_id="c1")
        for entry in findings[0].evidence_chain:
            assert "AKIAIOSFODNN7EXAMPLE" not in entry

    def test_secret_match_absent_from_reasoning(self) -> None:
        """The 'Match' field value must not appear in reasoning."""
        raw = _json_array([SAMPLE_FINDING])
        findings = self.scanner.parse_output(raw, repo="/repo", cycle_id="c1")
        assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].reasoning

    def test_secret_absent_from_summary(self) -> None:
        raw = _json_array([SAMPLE_FINDING])
        findings = self.scanner.parse_output(raw, repo="/repo", cycle_id="c1")
        assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].summary

    def test_model_dump_contains_no_secret(self) -> None:
        """model_dump() (via dataclasses.asdict equivalent) must not expose the secret."""
        import dataclasses

        raw = _json_array([SAMPLE_FINDING])
        findings = self.scanner.parse_output(raw, repo="/repo", cycle_id="c1")
        dumped = str(dataclasses.asdict(findings[0]))
        assert "AKIAIOSFODNN7EXAMPLE" not in dumped


# ---------------------------------------------------------------------------
# GitleaksScanner.parse_output — file and line evidence
# ---------------------------------------------------------------------------


class TestGitleaksScannerParseOutputEvidence:
    """File path and start line must appear in evidence_chain."""

    scanner = GitleaksScanner()

    def test_file_path_in_evidence_chain(self) -> None:
        raw = _json_array([SAMPLE_FINDING])
        findings = self.scanner.parse_output(raw, repo="/repo", cycle_id="c1")
        evidence = findings[0].evidence_chain
        assert any("config/secrets.py" in e for e in evidence)

    def test_start_line_in_evidence_chain(self) -> None:
        raw = _json_array([SAMPLE_FINDING])
        findings = self.scanner.parse_output(raw, repo="/repo", cycle_id="c1")
        evidence = findings[0].evidence_chain
        assert any("42" in e for e in evidence)

    def test_evidence_combines_file_and_line(self) -> None:
        """Evidence entry is formatted as 'file:line'."""
        raw = _json_array([SAMPLE_FINDING])
        findings = self.scanner.parse_output(raw, repo="/repo", cycle_id="c1")
        evidence = findings[0].evidence_chain
        assert any("config/secrets.py:42" in e for e in evidence)


# ---------------------------------------------------------------------------
# GitleaksScanner.parse_output — severity and staleness_class
# ---------------------------------------------------------------------------


class TestGitleaksScannerParseOutputSeverity:
    """All gitleaks findings must have severity='critical' and staleness_class='critical'."""

    scanner = GitleaksScanner()

    def test_severity_is_critical(self) -> None:
        raw = _json_array([SAMPLE_FINDING])
        findings = self.scanner.parse_output(raw, repo="/repo", cycle_id="c1")
        assert findings[0].severity == "critical"

    def test_staleness_class_is_critical(self) -> None:
        raw = _json_array([SAMPLE_FINDING])
        findings = self.scanner.parse_output(raw, repo="/repo", cycle_id="c1")
        assert findings[0].staleness_class == "critical"

    def test_agent_is_gitleaks(self) -> None:
        raw = _json_array([SAMPLE_FINDING])
        findings = self.scanner.parse_output(raw, repo="/repo", cycle_id="c1")
        assert findings[0].agent == "gitleaks"

    def test_confidence_is_fixed(self) -> None:
        """Gitleaks uses a fixed confidence of 0.8."""
        raw = _json_array([SAMPLE_FINDING])
        findings = self.scanner.parse_output(raw, repo="/repo", cycle_id="c1")
        assert findings[0].confidence == pytest.approx(0.8)


# ---------------------------------------------------------------------------
# GitleaksScanner.parse_output — edge cases
# ---------------------------------------------------------------------------


class TestGitleaksScannerParseOutputEdgeCases:
    """Edge cases for parse_output."""

    scanner = GitleaksScanner()

    def test_empty_string_returns_empty_list(self) -> None:
        assert self.scanner.parse_output("", repo="/repo", cycle_id="") == []

    def test_null_string_returns_empty_list(self) -> None:
        assert self.scanner.parse_output("null", repo="/repo", cycle_id="") == []

    def test_whitespace_only_returns_empty_list(self) -> None:
        assert self.scanner.parse_output("   \n  ", repo="/repo", cycle_id="") == []

    def test_multiple_findings_all_returned(self) -> None:
        finding2 = {**SAMPLE_FINDING, "RuleID": "github-token", "Fingerprint": "xyz789"}
        raw = _json_array([SAMPLE_FINDING, finding2])
        findings = self.scanner.parse_output(raw, repo="/repo", cycle_id="")
        assert len(findings) == 2

    def test_jsonl_multiple_findings(self) -> None:
        finding2 = {**SAMPLE_FINDING, "RuleID": "github-token", "Fingerprint": "xyz789"}
        raw = _jsonl([SAMPLE_FINDING, finding2])
        findings = self.scanner.parse_output(raw, repo="/repo", cycle_id="")
        assert len(findings) == 2

    def test_cycle_id_propagated(self) -> None:
        raw = _json_array([SAMPLE_FINDING])
        findings = self.scanner.parse_output(raw, repo="/repo", cycle_id="cycle-99")
        assert findings[0].cycle_id == "cycle-99"

    def test_repo_path_propagated(self) -> None:
        raw = _json_array([SAMPLE_FINDING])
        findings = self.scanner.parse_output(raw, repo="/my/repo", cycle_id="")
        assert findings[0].repo_path == "/my/repo"

    def test_missing_fingerprint_uses_fallback_key(self) -> None:
        """A finding without Fingerprint still gets a deterministic ID."""
        finding = {k: v for k, v in SAMPLE_FINDING.items() if k != "Fingerprint"}
        raw = _json_array([finding])
        findings = self.scanner.parse_output(raw, repo="/repo", cycle_id="")
        assert len(findings[0].id) == 16

    def test_id_deterministic_for_same_fingerprint(self) -> None:
        raw = _json_array([SAMPLE_FINDING])
        f1 = self.scanner.parse_output(raw, repo="/repo", cycle_id="")
        f2 = self.scanner.parse_output(raw, repo="/repo", cycle_id="")
        assert f1[0].id == f2[0].id


# ---------------------------------------------------------------------------
# GitleaksScanner.scan — subprocess integration paths
# ---------------------------------------------------------------------------


class TestGitleaksScannerScan:
    """Tests for GitleaksScanner.scan covering subprocess error paths."""

    def test_scan_returns_empty_when_gitleaks_not_installed(self, tmp_path) -> None:
        """FileNotFoundError from subprocess => empty list, no exception."""
        scanner = GitleaksScanner()
        with patch("repo_audit.security.gitleaks.subprocess.run", side_effect=FileNotFoundError):
            findings = scanner.scan(tmp_path)
        assert findings == []

    def test_scan_returns_empty_on_tool_error_exit_code(self, tmp_path) -> None:
        """Non-0/1 exit code is treated as a tool error and returns empty."""
        scanner = GitleaksScanner()
        mock_result = MagicMock(returncode=2, stdout="")
        with patch("repo_audit.security.gitleaks.subprocess.run", return_value=mock_result):
            findings = scanner.scan(tmp_path)
        assert findings == []

    def test_scan_returns_empty_when_no_leaks(self, tmp_path) -> None:
        """Exit code 0 with empty output => no findings."""
        scanner = GitleaksScanner()
        mock_result = MagicMock(returncode=0, stdout="")
        with patch("repo_audit.security.gitleaks.subprocess.run", return_value=mock_result):
            findings = scanner.scan(tmp_path)
        assert findings == []

    def test_scan_parses_findings_on_exit_code_1(self, tmp_path) -> None:
        """Exit code 1 means secrets found; output is parsed."""
        scanner = GitleaksScanner()
        fake_stdout = _json_array([SAMPLE_FINDING])
        mock_result = MagicMock(returncode=1, stdout=fake_stdout)
        with patch("repo_audit.security.gitleaks.subprocess.run", return_value=mock_result):
            findings = scanner.scan(tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == "critical"
