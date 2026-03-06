"""Tests for repo_audit.cli.

The `beads` package is not installed; it is stubbed via sys.modules before
importing cli so that the import chain succeeds.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Stub 'beads' before importing repo_audit.cli (which imports the store).
# ---------------------------------------------------------------------------
if "beads" not in sys.modules:
    sys.modules["beads"] = MagicMock()

from typer.testing import CliRunner

from repo_audit.cli import _derive_repo_slug, app

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "sample_repo"

runner = CliRunner()


# ---------------------------------------------------------------------------
# _derive_repo_slug
# ---------------------------------------------------------------------------


class TestDeriveRepoSlug:
    """Tests for _derive_repo_slug."""

    def test_ssh_url_format(self, tmp_path: Path) -> None:
        """git@github.com:owner/repo.git → owner/repo"""
        with patch("repo_audit.cli.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="git@github.com:owner/repo.git\n"
            )
            slug = _derive_repo_slug(tmp_path)
        assert slug == "owner/repo"

    def test_https_url_format(self, tmp_path: Path) -> None:
        """https://github.com/owner/repo.git → owner/repo"""
        with patch("repo_audit.cli.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="https://github.com/owner/repo.git\n"
            )
            slug = _derive_repo_slug(tmp_path)
        assert slug == "owner/repo"

    def test_https_url_without_git_suffix(self, tmp_path: Path) -> None:
        """https://github.com/owner/repo → owner/repo"""
        with patch("repo_audit.cli.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="https://github.com/owner/repo\n"
            )
            slug = _derive_repo_slug(tmp_path)
        assert slug == "owner/repo"

    def test_fallback_when_git_fails(self, tmp_path: Path) -> None:
        """When git remote fails, fall back to local/<dirname>."""
        with patch("repo_audit.cli.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(128, "git")
            slug = _derive_repo_slug(tmp_path)
        assert slug == f"local/{tmp_path.name}"

    def test_fallback_slug_format(self, tmp_path: Path) -> None:
        """Fallback slug uses 'local/<dirname>' format."""
        with patch("repo_audit.cli.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "git")
            slug = _derive_repo_slug(tmp_path)
        assert slug.startswith("local/")
        assert tmp_path.name in slug


# ---------------------------------------------------------------------------
# collect command
# ---------------------------------------------------------------------------


class TestCollectCommand:
    """Tests for the `collect` CLI command."""

    def test_collect_outputs_json_to_stdout(self) -> None:
        result = runner.invoke(app, ["collect", str(FIXTURE_REPO)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "readme" in data
        assert "specs" in data
        assert "entry_points" in data
        assert "docstrings" in data

    def test_collect_readme_field_not_none(self) -> None:
        result = runner.invoke(app, ["collect", str(FIXTURE_REPO)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["readme"] is not None

    def test_collect_entry_points_present(self) -> None:
        result = runner.invoke(app, ["collect", str(FIXTURE_REPO)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "sample-run" in data["entry_points"]

    def test_collect_writes_to_output_file(self, tmp_path: Path) -> None:
        out = tmp_path / "artifacts.json"
        result = runner.invoke(app, ["collect", str(FIXTURE_REPO), "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "readme" in data

    def test_collect_output_file_mentions_path(self, tmp_path: Path) -> None:
        out = tmp_path / "artifacts.json"
        result = runner.invoke(app, ["collect", str(FIXTURE_REPO), "--output", str(out)])
        assert result.exit_code == 0
        assert str(out) in result.output

    def test_collect_invalid_path_exits_1(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["collect", str(tmp_path / "nonexistent")])
        assert result.exit_code == 1

    def test_collect_on_empty_dir_exits_0(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["collect", str(tmp_path)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["readme"] is None


# ---------------------------------------------------------------------------
# analyze command
# ---------------------------------------------------------------------------


class TestAnalyzeCommand:
    """Tests for the `analyze` CLI command."""

    def test_analyze_outputs_json_to_stdout(self) -> None:
        result = runner.invoke(app, ["analyze", str(FIXTURE_REPO)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "import_graph" in data
        assert "reachable_from_entry_points" in data

    def test_analyze_import_graph_has_sample_modules(self) -> None:
        result = runner.invoke(app, ["analyze", str(FIXTURE_REPO)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "sample.core" in data["import_graph"]
        assert "sample.__main__" in data["import_graph"]

    def test_analyze_reachable_includes_core(self) -> None:
        result = runner.invoke(app, ["analyze", str(FIXTURE_REPO)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "sample.core" in data["reachable_from_entry_points"]

    def test_analyze_writes_to_output_file(self, tmp_path: Path) -> None:
        out = tmp_path / "analysis.json"
        result = runner.invoke(app, ["analyze", str(FIXTURE_REPO), "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "import_graph" in data

    def test_analyze_output_file_mentions_path(self, tmp_path: Path) -> None:
        out = tmp_path / "analysis.json"
        result = runner.invoke(app, ["analyze", str(FIXTURE_REPO), "--output", str(out)])
        assert result.exit_code == 0
        assert str(out) in result.output

    def test_analyze_invalid_path_exits_1(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["analyze", str(tmp_path / "nonexistent")])
        assert result.exit_code == 1

    def test_analyze_non_python_repo_returns_empty_graph(self, tmp_path: Path) -> None:
        """Directory with no .py files yields an empty import graph."""
        result = runner.invoke(app, ["analyze", str(tmp_path)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["import_graph"] == {}
        assert data["reachable_from_entry_points"] == []


# ---------------------------------------------------------------------------
# run command
# ---------------------------------------------------------------------------


class TestRunCommand:
    """Tests for the `run` CLI command."""

    def test_run_exits_0_and_persists(self, tmp_path: Path) -> None:
        """run should succeed, write cache files, and call save on the store."""
        mock_store_instance = MagicMock()
        with (
            patch("repo_audit.cli.CACHE_DIR", tmp_path / "cache"),
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store_instance),
            patch("repo_audit.cli._derive_repo_slug", return_value="local/sample_repo"),
        ):
            result = runner.invoke(app, ["run", str(FIXTURE_REPO)])

        assert result.exit_code == 0
        mock_store_instance.save_artifacts.assert_called_once()
        mock_store_instance.save_analysis.assert_called_once()

    def test_run_writes_artifacts_json_to_cache(self, tmp_path: Path) -> None:
        """Cache directory receives artifacts.json after run."""
        mock_store_instance = MagicMock()
        cache_dir = tmp_path / "cache"
        with (
            patch("repo_audit.cli.CACHE_DIR", cache_dir),
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store_instance),
            patch("repo_audit.cli._derive_repo_slug", return_value="local/sample_repo"),
        ):
            runner.invoke(app, ["run", str(FIXTURE_REPO)])

        artifacts_json = cache_dir / "local" / "sample_repo" / "artifacts.json"
        assert artifacts_json.exists()
        data = json.loads(artifacts_json.read_text(encoding="utf-8"))
        assert "readme" in data

    def test_run_writes_analysis_json_to_cache(self, tmp_path: Path) -> None:
        """Cache directory receives analysis.json after run."""
        mock_store_instance = MagicMock()
        cache_dir = tmp_path / "cache"
        with (
            patch("repo_audit.cli.CACHE_DIR", cache_dir),
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store_instance),
            patch("repo_audit.cli._derive_repo_slug", return_value="local/sample_repo"),
        ):
            runner.invoke(app, ["run", str(FIXTURE_REPO)])

        analysis_json = cache_dir / "local" / "sample_repo" / "analysis.json"
        assert analysis_json.exists()
        data = json.loads(analysis_json.read_text(encoding="utf-8"))
        assert "import_graph" in data

    def test_run_invalid_path_exits_1(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["run", str(tmp_path / "nonexistent")])
        assert result.exit_code == 1

    def test_run_reports_slug_in_output(self, tmp_path: Path) -> None:
        mock_store_instance = MagicMock()
        with (
            patch("repo_audit.cli.CACHE_DIR", tmp_path / "cache"),
            patch("repo_audit.cli.RepoAuditStore", return_value=mock_store_instance),
            patch("repo_audit.cli._derive_repo_slug", return_value="owner/sample"),
        ):
            result = runner.invoke(app, ["run", str(FIXTURE_REPO)])

        assert result.exit_code == 0
        assert "owner/sample" in result.output
