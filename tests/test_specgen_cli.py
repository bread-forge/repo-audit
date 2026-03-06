"""Tests for the `specgen` CLI command in repo_audit.cli.

Covers: dry-run output (no files written), normal run (writes .md files),
second run (skips already-covered clusters), no-findings early exit, and
the --since option forwarding.
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
    id: str,
    severity: str = "low",
    modules: list[str] | None = None,
    summary: str = "",
) -> FindingBead:
    """Build a minimal FindingBead, optionally attaching a blast_radius mock."""
    finding = FindingBead(
        id=id,
        agent="test-agent",
        severity=severity,  # type: ignore[arg-type]
        staleness_class="structural",  # type: ignore[arg-type]
        confidence=0.5,
        summary=summary or f"Finding {id}",
    )
    if modules is not None:
        br = MagicMock()
        br.modules_affected = modules
        finding.blast_radius = br  # type: ignore[attr-defined]
    return finding


def _invoke_specgen(
    findings: list[FindingBead],
    tmp_path: Path,
    extra_args: list[str] | None = None,
) -> "Result":  # type: ignore[name-defined]  # noqa: F821
    """Invoke the specgen command with a mocked store returning *findings*."""
    mock_store = MagicMock()
    mock_store.list_findings.return_value = findings
    args = ["specgen", str(FIXTURE_REPO), "--out-dir", str(tmp_path)]
    if extra_args:
        args.extend(extra_args)
    with (
        patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
        patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
    ):
        return runner.invoke(app, args)


# ---------------------------------------------------------------------------
# No findings
# ---------------------------------------------------------------------------


class TestSpecgenNoFindings:
    """specgen exits cleanly with a message when the store has no findings."""

    def test_no_findings_exits_0(self, tmp_path: Path) -> None:
        result = _invoke_specgen([], tmp_path)
        assert result.exit_code == 0

    def test_no_findings_prints_message(self, tmp_path: Path) -> None:
        result = _invoke_specgen([], tmp_path)
        assert "No findings" in result.output

    def test_no_findings_writes_no_files(self, tmp_path: Path) -> None:
        _invoke_specgen([], tmp_path)
        assert list(tmp_path.glob("*.md")) == []


# ---------------------------------------------------------------------------
# Dry-run mode
# ---------------------------------------------------------------------------


class TestSpecgenDryRun:
    """--dry-run prints the cluster plan and writes no files."""

    def test_dry_run_exits_0(self, tmp_path: Path) -> None:
        findings = [_make_finding("aaa")]
        result = _invoke_specgen(findings, tmp_path, ["--dry-run"])
        assert result.exit_code == 0

    def test_dry_run_prints_cluster_plan(self, tmp_path: Path) -> None:
        findings = [_make_finding("aaa")]
        result = _invoke_specgen(findings, tmp_path, ["--dry-run"])
        assert "Cluster plan" in result.output

    def test_dry_run_reports_cluster_count(self, tmp_path: Path) -> None:
        findings = [_make_finding("aaa"), _make_finding("bbb")]
        result = _invoke_specgen(findings, tmp_path, ["--dry-run"])
        assert "2 cluster(s)" in result.output

    def test_dry_run_reports_findings_count(self, tmp_path: Path) -> None:
        findings = [_make_finding("aaa"), _make_finding("bbb")]
        result = _invoke_specgen(findings, tmp_path, ["--dry-run"])
        assert "2 finding(s)" in result.output

    def test_dry_run_lists_finding_ids_in_output(self, tmp_path: Path) -> None:
        findings = [_make_finding("aaa1111")]
        result = _invoke_specgen(findings, tmp_path, ["--dry-run"])
        assert "aaa1111" in result.output

    def test_dry_run_writes_no_files_to_out_dir(self, tmp_path: Path) -> None:
        findings = [_make_finding("aaa"), _make_finding("bbb")]
        _invoke_specgen(findings, tmp_path, ["--dry-run"])
        assert list(tmp_path.glob("*.md")) == []

    def test_dry_run_out_dir_not_created(self, tmp_path: Path) -> None:
        """dry-run does not create the output directory if it did not exist."""
        out_dir = tmp_path / "specs"
        findings = [_make_finding("aaa")]
        mock_store = MagicMock()
        mock_store.list_findings.return_value = findings
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            runner.invoke(
                app,
                ["specgen", str(FIXTURE_REPO), "--out-dir", str(out_dir), "--dry-run"],
            )
        assert not out_dir.exists()

    def test_dry_run_shared_modules_groups_findings_in_plan(self, tmp_path: Path) -> None:
        """Findings sharing a module appear in the same cluster entry in the plan."""
        a = _make_finding("aaaa", modules=["auth"])
        b = _make_finding("bbbb", modules=["auth"])
        result = _invoke_specgen([a, b], tmp_path, ["--dry-run"])
        assert result.exit_code == 0
        # One cluster should contain both ids
        assert "1 cluster(s)" in result.output


# ---------------------------------------------------------------------------
# Normal run — writes files
# ---------------------------------------------------------------------------


class TestSpecgenNormalRun:
    """Normal (non-dry-run) specgen writes .md files to the output directory."""

    def test_normal_run_exits_0(self, tmp_path: Path) -> None:
        result = _invoke_specgen([_make_finding("aaa")], tmp_path)
        assert result.exit_code == 0

    def test_normal_run_writes_md_file(self, tmp_path: Path) -> None:
        _invoke_specgen([_make_finding("aaa")], tmp_path)
        md_files = list(tmp_path.glob("*.md"))
        assert len(md_files) == 1

    def test_normal_run_filename_follows_pattern(self, tmp_path: Path) -> None:
        _invoke_specgen([_make_finding("aaa")], tmp_path)
        md_files = list(tmp_path.glob("*.md"))
        assert md_files[0].name.startswith("spec-cluster-")
        assert md_files[0].name.endswith(".md")

    def test_normal_run_file_contains_finding_id(self, tmp_path: Path) -> None:
        _invoke_specgen([_make_finding("my_unique_id")], tmp_path)
        md_files = list(tmp_path.glob("*.md"))
        content = md_files[0].read_text(encoding="utf-8")
        assert "my_unique_id" in content

    def test_normal_run_prints_wrote_message(self, tmp_path: Path) -> None:
        result = _invoke_specgen([_make_finding("aaa")], tmp_path)
        assert "Wrote" in result.output
        assert "spec file" in result.output

    def test_normal_run_one_finding_per_cluster_one_file(self, tmp_path: Path) -> None:
        """Two unrelated findings produce two spec files (one cluster each)."""
        findings = [_make_finding("aaa"), _make_finding("bbb")]
        _invoke_specgen(findings, tmp_path)
        md_files = list(tmp_path.glob("*.md"))
        assert len(md_files) == 2

    def test_normal_run_creates_out_dir_if_missing(self, tmp_path: Path) -> None:
        """specgen creates the output directory when it does not yet exist."""
        out_dir = tmp_path / "new_specs"
        findings = [_make_finding("aaa")]
        mock_store = MagicMock()
        mock_store.list_findings.return_value = findings
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            runner.invoke(
                app,
                ["specgen", str(FIXTURE_REPO), "--out-dir", str(out_dir)],
            )
        assert out_dir.is_dir()

    def test_normal_run_file_has_valid_front_matter(self, tmp_path: Path) -> None:
        """Written spec file starts with YAML front-matter block."""
        _invoke_specgen([_make_finding("aaa")], tmp_path)
        md_files = list(tmp_path.glob("*.md"))
        content = md_files[0].read_text(encoding="utf-8")
        assert content.startswith("---\n")
        assert "\n---" in content


# ---------------------------------------------------------------------------
# Second run — skips already-covered clusters
# ---------------------------------------------------------------------------


class TestSpecgenSecondRunDedup:
    """A second specgen run skips clusters whose findings are already covered."""

    def _run_specgen_real_store(self, findings: list[FindingBead], out_dir: Path) -> str:
        """Invoke specgen twice with the same findings, returning second run output."""
        mock_store = MagicMock()
        mock_store.list_findings.return_value = findings

        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            # First run — writes files.
            runner.invoke(
                app,
                ["specgen", str(FIXTURE_REPO), "--out-dir", str(out_dir)],
            )
            # Second run — should find covered files and skip.
            result = runner.invoke(
                app,
                ["specgen", str(FIXTURE_REPO), "--out-dir", str(out_dir)],
            )
        return result.output

    def test_second_run_prints_no_new_clusters_message(self, tmp_path: Path) -> None:
        """After a first run, a second run reports that no new clusters exist."""
        output = self._run_specgen_real_store([_make_finding("covered_id")], tmp_path)
        assert "No new clusters" in output

    def test_second_run_does_not_write_additional_files(self, tmp_path: Path) -> None:
        """Second run creates no new files when all clusters are already covered."""
        finding = _make_finding("aaa")
        mock_store = MagicMock()
        mock_store.list_findings.return_value = [finding]

        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            runner.invoke(
                app,
                ["specgen", str(FIXTURE_REPO), "--out-dir", str(tmp_path)],
            )
            count_after_first = len(list(tmp_path.glob("*.md")))
            runner.invoke(
                app,
                ["specgen", str(FIXTURE_REPO), "--out-dir", str(tmp_path)],
            )
            count_after_second = len(list(tmp_path.glob("*.md")))

        assert count_after_second == count_after_first

    def test_new_finding_added_after_first_run_is_written(self, tmp_path: Path) -> None:
        """A finding not yet covered by any spec file is written on the second run."""
        original = _make_finding("original_id")
        new_finding = _make_finding("new_id")

        mock_store = MagicMock()

        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            # First run — writes a spec for original_id.
            mock_store.list_findings.return_value = [original]
            runner.invoke(
                app,
                ["specgen", str(FIXTURE_REPO), "--out-dir", str(tmp_path)],
            )

            # Second run — new_id is not yet covered; a spec for it should be written.
            mock_store.list_findings.return_value = [original, new_finding]
            result = runner.invoke(
                app,
                ["specgen", str(FIXTURE_REPO), "--out-dir", str(tmp_path)],
            )

        # The second run must report that it wrote spec file(s).
        assert result.exit_code == 0
        assert "Wrote" in result.output
        # At least one spec file in the directory must reference new_id.
        all_content = "".join(f.read_text(encoding="utf-8") for f in tmp_path.glob("*.md"))
        assert "new_id" in all_content


# ---------------------------------------------------------------------------
# --since option forwarding
# ---------------------------------------------------------------------------


class TestSpecgenSinceOption:
    """--since is forwarded to store.list_findings as since_cycle_id."""

    def test_since_is_forwarded_to_store(self, tmp_path: Path) -> None:
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            runner.invoke(
                app,
                [
                    "specgen",
                    str(FIXTURE_REPO),
                    "--out-dir",
                    str(tmp_path),
                    "--since",
                    "20240101T120000Z",
                ],
            )
        mock_store.list_findings.assert_called_once()
        assert mock_store.list_findings.call_args.kwargs["since_cycle_id"] == "20240101T120000Z"

    def test_without_since_passes_none_to_store(self, tmp_path: Path) -> None:
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        with (
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        ):
            runner.invoke(
                app,
                ["specgen", str(FIXTURE_REPO), "--out-dir", str(tmp_path)],
            )
        assert mock_store.list_findings.call_args.kwargs["since_cycle_id"] is None


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


class TestSpecgenErrorPaths:
    """specgen exits with an error for invalid inputs."""

    def test_invalid_repo_path_exits_1(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            ["specgen", str(tmp_path / "nonexistent"), "--out-dir", str(tmp_path)],
        )
        assert result.exit_code == 1
