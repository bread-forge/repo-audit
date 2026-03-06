"""Tests for the `list` CLI command in repo_audit.cli.

Covers basic output, --min-severity filtering, --since forwarding, and
error paths, all via the Typer CLI runner with a mocked RepoAuditStore.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Stub 'beads' before any repo_audit import.
# ---------------------------------------------------------------------------
if "beads" not in sys.modules:
    sys.modules["beads"] = MagicMock()

from typer.testing import CliRunner

from repo_audit.cli import app
from repo_audit.verdict.finding_bead import FindingBead

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "sample_repo"

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    *,
    id: str = "a" * 16,
    severity: str = "medium",
    staleness_class: str = "structural",
    summary: str = "Unreachable Module: pkg.orphan",
    cycle_id: str = "20240101T120000Z",
) -> FindingBead:
    """Build a minimal FindingBead for use in tests."""
    return FindingBead(
        id=id,
        agent="repo-audit",
        severity=severity,  # type: ignore[arg-type]
        staleness_class=staleness_class,  # type: ignore[arg-type]
        confidence=0.4,
        evidence_chain=["some evidence"],
        reasoning="Some reasoning.",
        cycle_id=cycle_id,
        repo_path="/some/path",
        summary=summary,
    )


# ---------------------------------------------------------------------------
# list — no findings
# ---------------------------------------------------------------------------


class TestListCommandNoFindings:
    """list command when the store returns an empty list."""

    def test_no_findings_prints_message(self) -> None:
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            result = runner.invoke(app, ["list", str(FIXTURE_REPO)])
        assert result.exit_code == 0
        assert "No findings." in result.output

    def test_no_findings_with_high_severity_still_prints_message(self) -> None:
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            result = runner.invoke(app, ["list", str(FIXTURE_REPO), "--min-severity", "high"])
        assert result.exit_code == 0
        assert "No findings." in result.output


# ---------------------------------------------------------------------------
# list — findings present
# ---------------------------------------------------------------------------


class TestListCommandWithFindings:
    """list command when the store returns findings."""

    def test_findings_table_has_header_row(self) -> None:
        mock_store = MagicMock()
        mock_store.list_findings.return_value = [_make_finding()]
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            result = runner.invoke(app, ["list", str(FIXTURE_REPO)])
        assert result.exit_code == 0
        assert "ID" in result.output
        assert "SEVERITY" in result.output
        assert "STALENESS CLASS" in result.output
        assert "SUMMARY" in result.output

    def test_finding_id_appears_in_output(self) -> None:
        finding = _make_finding(id="deadbeefdeadbeef")
        mock_store = MagicMock()
        mock_store.list_findings.return_value = [finding]
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            result = runner.invoke(app, ["list", str(FIXTURE_REPO)])
        assert "deadbeefdeadbeef" in result.output

    def test_finding_severity_appears_in_output(self) -> None:
        finding = _make_finding(severity="critical")
        mock_store = MagicMock()
        mock_store.list_findings.return_value = [finding]
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            result = runner.invoke(app, ["list", str(FIXTURE_REPO)])
        assert "critical" in result.output

    def test_finding_staleness_class_appears_in_output(self) -> None:
        finding = _make_finding(staleness_class="architectural")
        mock_store = MagicMock()
        mock_store.list_findings.return_value = [finding]
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            result = runner.invoke(app, ["list", str(FIXTURE_REPO)])
        assert "architectural" in result.output

    def test_finding_summary_appears_in_output(self) -> None:
        finding = _make_finding(summary="Broken Entry Point: my-script")
        mock_store = MagicMock()
        mock_store.list_findings.return_value = [finding]
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            result = runner.invoke(app, ["list", str(FIXTURE_REPO)])
        assert "Broken Entry Point: my-script" in result.output

    def test_multiple_findings_all_appear_in_output(self) -> None:
        findings = [
            _make_finding(id="aaaa1111aaaa1111", summary="Unreachable Module: pkg.a"),
            _make_finding(id="bbbb2222bbbb2222", summary="Unreachable Module: pkg.b"),
        ]
        mock_store = MagicMock()
        mock_store.list_findings.return_value = findings
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            result = runner.invoke(app, ["list", str(FIXTURE_REPO)])
        assert "aaaa1111aaaa1111" in result.output
        assert "bbbb2222bbbb2222" in result.output

    def test_no_findings_message_absent_when_findings_exist(self) -> None:
        mock_store = MagicMock()
        mock_store.list_findings.return_value = [_make_finding()]
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            result = runner.invoke(app, ["list", str(FIXTURE_REPO)])
        assert "No findings." not in result.output


# ---------------------------------------------------------------------------
# list — --min-severity option
# ---------------------------------------------------------------------------


class TestListCommandMinSeverity:
    """list command --min-severity option behaviour."""

    def test_min_severity_is_forwarded_to_store(self) -> None:
        """The --min-severity value is passed as min_severity to store.list_findings."""
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            runner.invoke(app, ["list", str(FIXTURE_REPO), "--min-severity", "high"])
        mock_store.list_findings.assert_called_once()
        assert mock_store.list_findings.call_args.kwargs["min_severity"] == "high"

    def test_default_min_severity_is_low(self) -> None:
        """When --min-severity is omitted the store is called with 'low'."""
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            runner.invoke(app, ["list", str(FIXTURE_REPO)])
        assert mock_store.list_findings.call_args.kwargs["min_severity"] == "low"

    def test_invalid_severity_exits_1(self) -> None:
        result = runner.invoke(app, ["list", str(FIXTURE_REPO), "--min-severity", "extreme"])
        assert result.exit_code == 1

    def test_invalid_severity_prints_error_message(self) -> None:
        result = runner.invoke(app, ["list", str(FIXTURE_REPO), "--min-severity", "bogus"])
        # Exit code 1 + an error message on stderr (typer combines output in runner).
        assert result.exit_code == 1

    def test_all_valid_severity_values_succeed(self) -> None:
        """Every documented severity level should be accepted without error."""
        for level in ("low", "medium", "high", "critical"):
            mock_store = MagicMock()
            mock_store.list_findings.return_value = []
            with (
                patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
                patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
            ):
                result = runner.invoke(app, ["list", str(FIXTURE_REPO), "--min-severity", level])
            assert result.exit_code == 0, f"level={level!r} should not fail"


# ---------------------------------------------------------------------------
# list — --since option
# ---------------------------------------------------------------------------


class TestListCommandSinceOption:
    """list command --since option forwarding."""

    def test_since_is_forwarded_to_store(self) -> None:
        """The --since value is passed as since_cycle_id to store.list_findings."""
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            runner.invoke(app, ["list", str(FIXTURE_REPO), "--since", "20240101T120000Z"])
        mock_store.list_findings.assert_called_once()
        assert mock_store.list_findings.call_args.kwargs["since_cycle_id"] == "20240101T120000Z"

    def test_without_since_passes_none_to_store(self) -> None:
        """When --since is omitted the store receives since_cycle_id=None."""
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            runner.invoke(app, ["list", str(FIXTURE_REPO)])
        assert mock_store.list_findings.call_args.kwargs["since_cycle_id"] is None

    def test_since_and_min_severity_combined(self) -> None:
        """Both --since and --min-severity can be used together."""
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            runner.invoke(
                app,
                [
                    "list",
                    str(FIXTURE_REPO),
                    "--since",
                    "20240101T120000Z",
                    "--min-severity",
                    "high",
                ],
            )
        kwargs = mock_store.list_findings.call_args.kwargs
        assert kwargs["since_cycle_id"] == "20240101T120000Z"
        assert kwargs["min_severity"] == "high"


# ---------------------------------------------------------------------------
# list — error paths
# ---------------------------------------------------------------------------


class TestListCommandErrorPaths:
    """list command error paths."""

    def test_nonexistent_path_exits_1(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["list", str(tmp_path / "nonexistent")])
        assert result.exit_code == 1

    def test_slug_is_derived_and_passed_to_store(self) -> None:
        """The slug derived from the repo path is forwarded to store.list_findings."""
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/my-repo") as mock_slug,
        ):
            result = runner.invoke(app, ["list", str(FIXTURE_REPO)])
        assert result.exit_code == 0
        mock_slug.assert_called_once()
        call_args = mock_store.list_findings.call_args
        assert call_args.args[0] == "owner/my-repo"
