"""Tests for repo_audit.security.trivy.TrivyScanner."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from repo_audit.security.trivy import TrivyScanner, _normalize_severity, _build_evidence_chain


# ---------------------------------------------------------------------------
# Helpers — synthetic Trivy JSON payloads
# ---------------------------------------------------------------------------


def _make_trivy_json(vulnerabilities: list[dict]) -> str:
    return json.dumps({"Results": [{"Vulnerabilities": vulnerabilities}]})


SAMPLE_VULN = {
    "VulnerabilityID": "CVE-2023-1234",
    "PkgName": "requests",
    "InstalledVersion": "2.27.0",
    "FixedVersion": "2.28.0",
    "Severity": "HIGH",
    "Title": "HTTP header injection in requests",
}


# ---------------------------------------------------------------------------
# _normalize_severity
# ---------------------------------------------------------------------------


class TestNormalizeSeverity:
    """Tests for _normalize_severity."""

    def test_high_lowercased(self) -> None:
        assert _normalize_severity("HIGH") == "high"

    def test_critical_lowercased(self) -> None:
        assert _normalize_severity("CRITICAL") == "critical"

    def test_medium_lowercased(self) -> None:
        assert _normalize_severity("MEDIUM") == "medium"

    def test_low_lowercased(self) -> None:
        assert _normalize_severity("LOW") == "low"

    def test_unknown_falls_back_to_medium(self) -> None:
        assert _normalize_severity("UNKNOWN") == "medium"

    def test_empty_falls_back_to_medium(self) -> None:
        assert _normalize_severity("") == "medium"

    def test_mixed_case_accepted(self) -> None:
        assert _normalize_severity("High") == "high"


# ---------------------------------------------------------------------------
# _build_evidence_chain
# ---------------------------------------------------------------------------


class TestBuildEvidenceChain:
    """Tests for _build_evidence_chain."""

    def test_cve_id_in_evidence(self) -> None:
        vuln = {"VulnerabilityID": "CVE-2023-1234"}
        evidence = _build_evidence_chain(vuln)
        assert any("CVE-2023-1234" in e for e in evidence)

    def test_package_name_and_version_in_evidence(self) -> None:
        vuln = {"PkgName": "requests", "InstalledVersion": "2.27.0"}
        evidence = _build_evidence_chain(vuln)
        assert any("requests" in e and "2.27.0" in e for e in evidence)

    def test_fixed_version_in_evidence_when_present(self) -> None:
        vuln = {"VulnerabilityID": "CVE-2023-1234", "FixedVersion": "2.28.0"}
        evidence = _build_evidence_chain(vuln)
        assert any("2.28.0" in e for e in evidence)

    def test_fixed_version_absent_when_not_provided(self) -> None:
        vuln = {"VulnerabilityID": "CVE-2023-1234"}
        evidence = _build_evidence_chain(vuln)
        assert not any("Fixed in" in e for e in evidence)

    def test_empty_vuln_returns_empty_list(self) -> None:
        evidence = _build_evidence_chain({})
        assert evidence == []

    def test_package_without_installed_version(self) -> None:
        vuln = {"PkgName": "requests"}
        evidence = _build_evidence_chain(vuln)
        assert any("requests" in e for e in evidence)


# ---------------------------------------------------------------------------
# TrivyScanner.parse_output
# ---------------------------------------------------------------------------


class TestTrivyScannerParseOutput:
    """Tests for TrivyScanner.parse_output."""

    scanner = TrivyScanner()

    def test_cve_id_in_evidence_chain(self) -> None:
        """CVE-2023-1234 must appear in the evidence_chain of the resulting bead."""
        json_str = _make_trivy_json([SAMPLE_VULN])
        findings = self.scanner.parse_output(json_str, repo="/repo", cycle_id="c1")
        assert len(findings) == 1
        evidence = findings[0].evidence_chain
        assert any("CVE-2023-1234" in e for e in evidence)

    def test_severity_mapped_to_lowercase(self) -> None:
        """Trivy 'HIGH' is mapped to 'high' on the bead."""
        json_str = _make_trivy_json([SAMPLE_VULN])
        findings = self.scanner.parse_output(json_str, repo="/repo", cycle_id="c1")
        assert findings[0].severity == "high"

    def test_staleness_class_is_dependency(self) -> None:
        """All Trivy findings carry staleness_class='dependency'."""
        json_str = _make_trivy_json([SAMPLE_VULN])
        findings = self.scanner.parse_output(json_str, repo="/repo", cycle_id="c1")
        assert findings[0].staleness_class == "dependency"

    def test_agent_is_trivy(self) -> None:
        json_str = _make_trivy_json([SAMPLE_VULN])
        findings = self.scanner.parse_output(json_str, repo="/repo", cycle_id="c1")
        assert findings[0].agent == "trivy"

    def test_cycle_id_propagated(self) -> None:
        json_str = _make_trivy_json([SAMPLE_VULN])
        findings = self.scanner.parse_output(json_str, repo="/repo", cycle_id="cycle-42")
        assert findings[0].cycle_id == "cycle-42"

    def test_repo_path_propagated(self) -> None:
        json_str = _make_trivy_json([SAMPLE_VULN])
        findings = self.scanner.parse_output(json_str, repo="/my/repo", cycle_id="")
        assert findings[0].repo_path == "/my/repo"

    def test_invalid_json_returns_empty_list(self) -> None:
        findings = self.scanner.parse_output("not valid json", repo="/repo", cycle_id="")
        assert findings == []

    def test_empty_results_returns_empty_list(self) -> None:
        json_str = json.dumps({"Results": []})
        findings = self.scanner.parse_output(json_str, repo="/repo", cycle_id="")
        assert findings == []

    def test_null_vulnerabilities_returns_empty_list(self) -> None:
        """Results entry with null Vulnerabilities is handled gracefully."""
        json_str = json.dumps({"Results": [{"Vulnerabilities": None}]})
        findings = self.scanner.parse_output(json_str, repo="/repo", cycle_id="")
        assert findings == []

    def test_multiple_vulnerabilities_all_returned(self) -> None:
        vuln2 = {**SAMPLE_VULN, "VulnerabilityID": "CVE-2023-9999", "PkgName": "urllib3"}
        json_str = _make_trivy_json([SAMPLE_VULN, vuln2])
        findings = self.scanner.parse_output(json_str, repo="/repo", cycle_id="")
        assert len(findings) == 2

    def test_unknown_severity_falls_back_to_medium(self) -> None:
        vuln = {**SAMPLE_VULN, "Severity": "UNKNOWN"}
        json_str = _make_trivy_json([vuln])
        findings = self.scanner.parse_output(json_str, repo="/repo", cycle_id="")
        assert findings[0].severity == "medium"

    def test_critical_severity_mapped(self) -> None:
        vuln = {**SAMPLE_VULN, "Severity": "CRITICAL"}
        json_str = _make_trivy_json([vuln])
        findings = self.scanner.parse_output(json_str, repo="/repo", cycle_id="")
        assert findings[0].severity == "critical"

    def test_fixed_version_in_evidence_chain(self) -> None:
        """Fixed version appears in evidence_chain when present."""
        json_str = _make_trivy_json([SAMPLE_VULN])
        findings = self.scanner.parse_output(json_str, repo="/repo", cycle_id="")
        assert any("2.28.0" in e for e in findings[0].evidence_chain)

    def test_no_fixed_version_omitted_from_evidence(self) -> None:
        vuln = {k: v for k, v in SAMPLE_VULN.items() if k != "FixedVersion"}
        json_str = _make_trivy_json([vuln])
        findings = self.scanner.parse_output(json_str, repo="/repo", cycle_id="")
        assert not any("Fixed in" in e for e in findings[0].evidence_chain)

    def test_summary_contains_cve_and_package(self) -> None:
        json_str = _make_trivy_json([SAMPLE_VULN])
        findings = self.scanner.parse_output(json_str, repo="/repo", cycle_id="")
        assert "CVE-2023-1234" in findings[0].summary
        assert "requests" in findings[0].summary

    def test_id_is_deterministic(self) -> None:
        """Same input produces the same bead ID on repeated calls."""
        json_str = _make_trivy_json([SAMPLE_VULN])
        f1 = self.scanner.parse_output(json_str, repo="/repo", cycle_id="")
        f2 = self.scanner.parse_output(json_str, repo="/repo", cycle_id="")
        assert f1[0].id == f2[0].id

    def test_confidence_based_on_evidence_length(self) -> None:
        """Confidence grows with evidence count and is capped at 0.95."""
        json_str = _make_trivy_json([SAMPLE_VULN])
        findings = self.scanner.parse_output(json_str, repo="/repo", cycle_id="")
        # SAMPLE_VULN has CVE, Package, FixedVersion => 3 evidence items => 0.6
        assert findings[0].confidence == pytest.approx(0.6)

    def test_missing_results_key_returns_empty(self) -> None:
        json_str = json.dumps({})
        findings = self.scanner.parse_output(json_str, repo="/repo", cycle_id="")
        assert findings == []


# ---------------------------------------------------------------------------
# TrivyScanner.scan — subprocess integration paths
# ---------------------------------------------------------------------------


class TestTrivyScannerScan:
    """Tests for TrivyScanner.scan covering subprocess error paths."""

    def test_scan_returns_empty_when_trivy_not_installed(self, tmp_path) -> None:
        """FileNotFoundError from subprocess => empty list, no exception."""
        scanner = TrivyScanner()
        with patch("repo_audit.security.trivy.subprocess.run", side_effect=FileNotFoundError):
            findings = scanner.scan(tmp_path, cycle_id="c1")
        assert findings == []

    def test_scan_returns_empty_when_trivy_exits_nonzero(self, tmp_path) -> None:
        """CalledProcessError from subprocess => empty list, no exception."""
        import subprocess

        scanner = TrivyScanner()
        with patch(
            "repo_audit.security.trivy.subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "trivy"),
        ):
            findings = scanner.scan(tmp_path, cycle_id="c1")
        assert findings == []

    def test_scan_parses_subprocess_output(self, tmp_path) -> None:
        """Successful subprocess run => results are parsed via parse_output."""
        scanner = TrivyScanner()
        fake_stdout = _make_trivy_json([SAMPLE_VULN])
        mock_result = MagicMock(stdout=fake_stdout)
        with patch("repo_audit.security.trivy.subprocess.run", return_value=mock_result):
            findings = scanner.scan(tmp_path, cycle_id="c1")
        assert len(findings) == 1
        assert findings[0].severity == "high"
