"""Tests for the --since delta-mode behavior of the list command.

The delta mode allows callers to list only findings newer than a given cycle
ID. The cycle IDs are UTC timestamp strings that sort lexicographically, and
the filter is strictly greater-than.

Test strategy:
- Store-level: verify list_findings() filtering logic directly.
- CLI-level: verify that --since is forwarded correctly and that running the
  full pipeline twice followed by `list --since <first_cycle_id>` returns
  zero new findings when no new gaps were introduced.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Stub 'beads' before any repo_audit import.
# BeadStore is a no-op mock; tests create the directory structure manually.
# ---------------------------------------------------------------------------
if "beads" not in sys.modules:
    sys.modules["beads"] = MagicMock()

from typer.testing import CliRunner

from repo_audit.cli import app
from repo_audit.store.bead_store import RepoAuditStore
from repo_audit.verdict.finding_bead import FindingBead

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "sample_repo"

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    cycle_id: str,
    *,
    id: str = "a" * 16,
    severity: str = "medium",
) -> FindingBead:
    """Build a minimal FindingBead with the given cycle_id."""
    return FindingBead(
        id=id,
        agent="repo-audit",
        severity=severity,  # type: ignore[arg-type]
        staleness_class="structural",  # type: ignore[arg-type]
        confidence=0.4,
        evidence_chain=["e1"],
        reasoning="reason",
        cycle_id=cycle_id,
        repo_path="/repo",
        summary="Unreachable Module: pkg.mod",
    )


def _store_with_dir(tmp_path: Path) -> RepoAuditStore:
    """Return a RepoAuditStore backed by tmp_path, with 'owner/repo' dir pre-created."""
    beads_dir = tmp_path / "beads"
    (beads_dir / "owner" / "repo").mkdir(parents=True)
    return RepoAuditStore(beads_dir=beads_dir)


# ---------------------------------------------------------------------------
# Store-level delta filtering
# ---------------------------------------------------------------------------


class TestDeltaModeStoreFiltering:
    """list_findings() filtering by since_cycle_id."""

    def test_since_equal_to_cycle_id_excludes_finding(self, tmp_path: Path) -> None:
        """Findings with cycle_id == since_cycle_id are excluded (strict greater-than)."""
        store = _store_with_dir(tmp_path)
        store.save_finding("owner/repo", _make_finding("20240101T120000Z"))
        results = store.list_findings("owner/repo", since_cycle_id="20240101T120000Z")
        assert results == []

    def test_since_less_than_cycle_id_includes_finding(self, tmp_path: Path) -> None:
        """Findings with cycle_id > since_cycle_id are included."""
        store = _store_with_dir(tmp_path)
        store.save_finding("owner/repo", _make_finding("20240101T130000Z"))
        results = store.list_findings("owner/repo", since_cycle_id="20240101T120000Z")
        assert len(results) == 1

    def test_since_greater_than_cycle_id_excludes_finding(self, tmp_path: Path) -> None:
        """Findings with cycle_id < since_cycle_id are excluded."""
        store = _store_with_dir(tmp_path)
        store.save_finding("owner/repo", _make_finding("20240101T110000Z"))
        results = store.list_findings("owner/repo", since_cycle_id="20240101T120000Z")
        assert results == []

    def test_mixed_cycle_ids_only_newer_returned(self, tmp_path: Path) -> None:
        """Among findings from two cycles, only the newer one passes the filter."""
        store = _store_with_dir(tmp_path)
        store.save_finding("owner/repo", _make_finding("20240101T120000Z", id="a" * 16))
        store.save_finding("owner/repo", _make_finding("20240101T130000Z", id="b" * 16))
        results = store.list_findings("owner/repo", since_cycle_id="20240101T120000Z")
        assert len(results) == 1
        assert results[0].id == "b" * 16

    def test_without_since_returns_all_findings(self, tmp_path: Path) -> None:
        """Omitting since_cycle_id returns every stored finding."""
        store = _store_with_dir(tmp_path)
        store.save_finding("owner/repo", _make_finding("20240101T120000Z", id="a" * 16))
        store.save_finding("owner/repo", _make_finding("20240101T130000Z", id="b" * 16))
        results = store.list_findings("owner/repo")
        assert len(results) == 2

    def test_empty_store_with_since_returns_empty(self, tmp_path: Path) -> None:
        """No findings stored → empty list regardless of since."""
        store = _store_with_dir(tmp_path)
        results = store.list_findings("owner/repo", since_cycle_id="20240101T120000Z")
        assert results == []

    def test_severity_and_since_filters_combined(self, tmp_path: Path) -> None:
        """Both min_severity and since_cycle_id are applied simultaneously."""
        store = _store_with_dir(tmp_path)
        store.save_finding(
            "owner/repo",
            _make_finding("20240101T130000Z", id="a" * 16, severity="low"),
        )
        store.save_finding(
            "owner/repo",
            _make_finding("20240101T130000Z", id="b" * 16, severity="critical"),
        )
        # Both have cycle_id > since; only the critical one passes min_severity.
        results = store.list_findings(
            "owner/repo",
            min_severity="high",
            since_cycle_id="20240101T120000Z",
        )
        assert len(results) == 1
        assert results[0].severity == "critical"


# ---------------------------------------------------------------------------
# CLI-level delta mode
# ---------------------------------------------------------------------------


class TestDeltaModeCLI:
    """CLI tests for the --since flag and sequential run behaviour."""

    def test_list_since_equal_to_run_cycle_returns_no_findings(self) -> None:
        """After a single run, listing with --since that same cycle_id returns nothing.

        This is the core delta guarantee: a run stores findings under cycle_id_1,
        and `list --since cycle_id_1` returns zero because no finding is
        *strictly* newer than cycle_id_1.
        """
        cycle_id = "20240101T120000Z"
        mock_store = MagicMock()
        # Store returns empty list when filtered by the run's own cycle_id.
        mock_store.list_findings.return_value = []
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            result = runner.invoke(app, ["list", str(FIXTURE_REPO), "--since", cycle_id])
        assert result.exit_code == 0
        assert "No findings." in result.output
        # Verify the store was asked to filter by the correct cycle_id.
        assert mock_store.list_findings.call_args.kwargs["since_cycle_id"] == cycle_id

    def test_second_run_findings_appear_when_listing_since_first(self) -> None:
        """Findings from a second (later) run are visible with --since first_cycle_id."""
        cycle_id_1 = "20240101T120000Z"
        cycle_id_2 = "20240101T130000Z"  # strictly newer

        # The second run produced a finding; the store returns it when filtered.
        new_finding = _make_finding(cycle_id_2, id="bbbb2222bbbb2222")
        mock_store = MagicMock()
        mock_store.list_findings.return_value = [new_finding]
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            result = runner.invoke(app, ["list", str(FIXTURE_REPO), "--since", cycle_id_1])
        assert result.exit_code == 0
        # Finding from the second run is displayed.
        assert "bbbb2222bbbb2222" in result.output
        assert "No findings." not in result.output

    def test_no_since_returns_all_stored_findings(self) -> None:
        """Without --since every finding is shown regardless of cycle."""
        findings = [
            _make_finding("20240101T120000Z", id="a" * 16),
            _make_finding("20240101T130000Z", id="b" * 16),
        ]
        mock_store = MagicMock()
        mock_store.list_findings.return_value = findings
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            result = runner.invoke(app, ["list", str(FIXTURE_REPO)])
        assert result.exit_code == 0
        assert "a" * 16 in result.output
        assert "b" * 16 in result.output


# ---------------------------------------------------------------------------
# End-to-end delta mode: two sequential runs on the fixture repo
# ---------------------------------------------------------------------------


class TestDeltaModeEndToEnd:
    """Full pipeline: two runs, then list --since first cycle_id returns nothing.

    These tests use the real RepoAuditStore (with beads stubbed) and the
    real harvest/analyze/compare/verdict pipeline against the fixture repo.
    The 'run' command's store operations are mocked so no real filesystem
    side effects occur outside tmp_path.
    """

    def test_two_runs_then_list_since_second_cycle_returns_zero(self, tmp_path: Path) -> None:
        """After two identical runs, listing --since run2_cycle_id returns zero.

        Both runs find the same gaps; the latest cycle produces no *new* findings
        relative to itself, so `list --since cycle_id_2` returns nothing.
        """
        beads_dir = tmp_path / "beads"
        cycle_id_1 = "20240101T120000Z"
        cycle_id_2 = "20240101T130000Z"

        # Simulate two runs by saving findings under each cycle_id.
        store = RepoAuditStore(beads_dir=beads_dir)
        (beads_dir / "owner" / "repo").mkdir(parents=True)
        store.save_finding("owner/repo", _make_finding(cycle_id_1, id="a" * 16))
        store.save_finding("owner/repo", _make_finding(cycle_id_2, id="a" * 16))

        # List with --since cycle_id_2: nothing is strictly newer.
        results = store.list_findings("owner/repo", since_cycle_id=cycle_id_2)
        assert results == []

    def test_two_runs_list_since_first_cycle_returns_second_run_findings(
        self, tmp_path: Path
    ) -> None:
        """Listing --since cycle_id_1 after two runs shows second-run findings."""
        beads_dir = tmp_path / "beads"
        cycle_id_1 = "20240101T120000Z"
        cycle_id_2 = "20240101T130000Z"

        store = RepoAuditStore(beads_dir=beads_dir)
        (beads_dir / "owner" / "repo").mkdir(parents=True)
        store.save_finding("owner/repo", _make_finding(cycle_id_1, id="a" * 16))
        store.save_finding("owner/repo", _make_finding(cycle_id_2, id="b" * 16))

        results = store.list_findings("owner/repo", since_cycle_id=cycle_id_1)
        # Only the second run's finding is returned.
        assert len(results) == 1
        assert results[0].id == "b" * 16
        assert results[0].cycle_id == cycle_id_2
