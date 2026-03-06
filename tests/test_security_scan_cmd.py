"""Tests for the `security-scan` CLI command in repo_audit.cli."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Stub 'beads' before importing repo_audit.cli (which imports the store).
if "beads" not in sys.modules:
    sys.modules["beads"] = MagicMock()

from typer.testing import CliRunner

from repo_audit.cli import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_store_mock() -> MagicMock:
    """Return a mock RepoAuditStore that does nothing."""
    store = MagicMock()
    store.save_finding.return_value = None
    return store


# ---------------------------------------------------------------------------
# security-scan exits 0 when scanning tools are absent
# ---------------------------------------------------------------------------


class TestSecurityScanToolsAbsent:
    """The security-scan command must exit 0 when Trivy/Gitleaks are not installed."""

    def _invoke_with_absent_tools(self, tmp_path: Path, mock_store: MagicMock):  # type: ignore[return]
        """Invoke security-scan with both scanners returning no findings."""
        with (
            patch("repo_audit.cli.TrivyScanner") as MockTrivy,
            patch("repo_audit.cli.GitleaksScanner") as MockGitleaks,
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="local/test"),
        ):
            MockTrivy.return_value.scan.return_value = []
            MockGitleaks.return_value.scan.return_value = []
            return runner.invoke(app, ["security-scan", str(tmp_path)])

    def test_exits_zero_when_trivy_not_installed(self, tmp_path: Path) -> None:
        """When TrivyScanner.scan raises FileNotFoundError internally, exit code is 0.

        We also test this at the subprocess level: patch subprocess.run to raise
        FileNotFoundError so TrivyScanner.scan() returns [] via its except handler.
        """
        with (
            patch("repo_audit.security.trivy.subprocess.run", side_effect=FileNotFoundError),
            patch("repo_audit.cli.RepoAuditStore", return_value=_make_store_mock()),
            patch("repo_audit.cli._derive_repo_slug", return_value="local/test"),
            patch("repo_audit.cli.GitleaksScanner") as MockGitleaks,
        ):
            MockGitleaks.return_value.scan.return_value = []
            result = runner.invoke(app, ["security-scan", str(tmp_path)])

        assert result.exit_code == 0

    def test_exits_zero_when_gitleaks_not_installed(self, tmp_path: Path) -> None:
        """When GitleaksScanner.scan raises FileNotFoundError internally, exit code is 0."""
        with (
            patch("repo_audit.security.gitleaks.subprocess.run", side_effect=FileNotFoundError),
            patch("repo_audit.cli.RepoAuditStore", return_value=_make_store_mock()),
            patch("repo_audit.cli._derive_repo_slug", return_value="local/test"),
            patch("repo_audit.cli.TrivyScanner") as MockTrivy,
        ):
            MockTrivy.return_value.scan.return_value = []
            result = runner.invoke(app, ["security-scan", str(tmp_path)])

        assert result.exit_code == 0

    def test_reports_zero_findings_when_tools_absent(self, tmp_path: Path) -> None:
        """Output mentions 0 persisted findings when no tools are available."""
        result = self._invoke_with_absent_tools(tmp_path, _make_store_mock())
        assert result.exit_code == 0
        assert "0 persisted" in result.output

    def test_no_store_calls_when_tools_absent(self, tmp_path: Path) -> None:
        """save_finding is never called when scanning tools return no findings."""
        mock_store = _make_store_mock()
        self._invoke_with_absent_tools(tmp_path, mock_store)
        mock_store.save_finding.assert_not_called()


# ---------------------------------------------------------------------------
# security-scan with findings present
# ---------------------------------------------------------------------------


class TestSecurityScanWithFindings:
    """security-scan persists findings from Trivy and Gitleaks when tools are present."""

    def _make_finding(self, severity: str = "high"):
        from repo_audit.verdict.finding_bead import FindingBead

        return FindingBead(
            id="abcd1234abcd1234",
            agent="trivy",
            severity=severity,  # type: ignore[arg-type]
            staleness_class="dependency",
            confidence=0.6,
            summary="CVE-2023-1234: requests",
        )

    def test_exits_zero_with_findings(self, tmp_path: Path) -> None:
        """When trivy returns findings, exit code is still 0."""
        # Patch scanner classes in the cli module (avoids shared subprocess module conflict).
        mock_store = _make_store_mock()
        with (
            patch("repo_audit.cli.TrivyScanner") as MockTrivy,
            patch("repo_audit.cli.GitleaksScanner") as MockGitleaks,
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="local/test"),
        ):
            MockTrivy.return_value.scan.return_value = [self._make_finding("high")]
            MockGitleaks.return_value.scan.return_value = []
            result = runner.invoke(app, ["security-scan", str(tmp_path)])

        assert result.exit_code == 0

    def test_persists_trivy_findings_to_store(self, tmp_path: Path) -> None:
        """Trivy findings are passed to store.save_finding."""
        mock_store = _make_store_mock()
        with (
            patch("repo_audit.cli.TrivyScanner") as MockTrivy,
            patch("repo_audit.cli.GitleaksScanner") as MockGitleaks,
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="local/test"),
        ):
            MockTrivy.return_value.scan.return_value = [self._make_finding("critical")]
            MockGitleaks.return_value.scan.return_value = []
            result = runner.invoke(app, ["security-scan", str(tmp_path)])

        assert result.exit_code == 0
        mock_store.save_finding.assert_called_once()
        saved_finding = mock_store.save_finding.call_args[0][1]
        assert saved_finding.severity == "critical"


# ---------------------------------------------------------------------------
# security-scan with invalid path
# ---------------------------------------------------------------------------


class TestSecurityScanInvalidPath:
    """security-scan exits 1 for paths that do not exist."""

    def test_exits_one_for_nonexistent_path(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["security-scan", str(tmp_path / "nonexistent")])
        assert result.exit_code == 1
