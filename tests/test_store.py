"""Tests for repo_audit.store (RepoAuditStore and helpers).

The `beads` package is not installed in this repo; it is stubbed out via
sys.modules so that bead_store.py can be imported without error.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Stub the 'beads' package before any repo_audit.store import.
# BeadStore.__init__ is expected to create directory structure; the stub is a
# no-op, so tests create the required directories manually.
# ---------------------------------------------------------------------------
if "beads" not in sys.modules:
    _beads_stub = MagicMock()
    sys.modules["beads"] = _beads_stub

import json

import pytest

from repo_audit.analyzer.result import AnalysisResult
from repo_audit.collector.artifacts import CollectedArtifacts
from repo_audit.store.bead_store import (
    RepoAuditStore,
    _atomic_write,
    _validate_slug,
)


# ---------------------------------------------------------------------------
# _validate_slug
# ---------------------------------------------------------------------------


class TestValidateSlug:
    """Tests for _validate_slug."""

    def test_valid_slug_does_not_raise(self) -> None:
        _validate_slug("owner/repo")  # should not raise

    def test_slug_without_slash_raises(self) -> None:
        with pytest.raises(ValueError, match="owner/repo"):
            _validate_slug("noslash")

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValueError):
            _validate_slug("")

    def test_slug_with_multiple_slashes_is_accepted(self) -> None:
        """A slug like 'org/sub/repo' contains a slash so it passes validation."""
        _validate_slug("org/sub/repo")  # should not raise


# ---------------------------------------------------------------------------
# _atomic_write
# ---------------------------------------------------------------------------


class TestAtomicWrite:
    """Tests for _atomic_write."""

    def test_writes_json_to_path(self, tmp_path: Path) -> None:
        target = tmp_path / "data.json"
        _atomic_write(target, {"key": "value", "num": 42})
        assert target.exists()
        data = json.loads(target.read_text(encoding="utf-8"))
        assert data == {"key": "value", "num": 42}

    def test_overwrites_existing_file(self, tmp_path: Path) -> None:
        target = tmp_path / "data.json"
        _atomic_write(target, {"v": 1})
        _atomic_write(target, {"v": 2})
        data = json.loads(target.read_text(encoding="utf-8"))
        assert data["v"] == 2

    def test_no_tmp_file_left_behind(self, tmp_path: Path) -> None:
        target = tmp_path / "data.json"
        _atomic_write(target, {"x": 1})
        tmp_file = target.with_suffix(".tmp")
        assert not tmp_file.exists()

    def test_output_is_valid_json(self, tmp_path: Path) -> None:
        target = tmp_path / "data.json"
        _atomic_write(target, {"nested": {"a": [1, 2, 3]}})
        parsed = json.loads(target.read_text(encoding="utf-8"))
        assert parsed["nested"]["a"] == [1, 2, 3]


# ---------------------------------------------------------------------------
# RepoAuditStore — artifacts round-trip
# ---------------------------------------------------------------------------


class TestRepoAuditStoreArtifacts:
    """Tests for save_artifacts / load_artifacts round-trip."""

    @pytest.fixture()
    def store_dir(self, tmp_path: Path) -> Path:
        """Return a tmp beads_dir with the owner/repo directory pre-created."""
        bead_dir = tmp_path / "beads"
        (bead_dir / "owner" / "repo").mkdir(parents=True)
        return bead_dir

    @pytest.fixture()
    def store(self, store_dir: Path) -> RepoAuditStore:
        return RepoAuditStore(beads_dir=store_dir)

    def test_load_returns_none_when_missing(self, store: RepoAuditStore) -> None:
        assert store.load_artifacts("owner/repo") is None

    def test_save_creates_artifacts_json(self, store: RepoAuditStore, store_dir: Path) -> None:
        artifacts = CollectedArtifacts(readme="# Hello")
        store.save_artifacts("owner/repo", artifacts)
        assert (store_dir / "owner" / "repo" / "artifacts.json").exists()

    def test_round_trip_basic(self, store: RepoAuditStore) -> None:
        """save then load returns equivalent CollectedArtifacts."""
        original = CollectedArtifacts(
            readme="# Readme",
            entry_points={"cli": "pkg:main"},
        )
        store.save_artifacts("owner/repo", original)
        loaded = store.load_artifacts("owner/repo")
        assert loaded is not None
        assert loaded.readme == "# Readme"
        assert loaded.entry_points == {"cli": "pkg:main"}

    def test_round_trip_with_none_fields(self, store: RepoAuditStore) -> None:
        """None-valued optional fields survive the JSON round-trip."""
        original = CollectedArtifacts(readme=None, claude_md=None)
        store.save_artifacts("owner/repo", original)
        loaded = store.load_artifacts("owner/repo")
        assert loaded is not None
        assert loaded.readme is None
        assert loaded.claude_md is None

    def test_round_trip_preserves_docstrings_with_none_values(self, store: RepoAuditStore) -> None:
        original = CollectedArtifacts(docstrings={"mod.py": "docstring", "empty.py": None})
        store.save_artifacts("owner/repo", original)
        loaded = store.load_artifacts("owner/repo")
        assert loaded is not None
        assert loaded.docstrings["mod.py"] == "docstring"
        assert loaded.docstrings["empty.py"] is None

    def test_save_validates_slug(self, store: RepoAuditStore) -> None:
        with pytest.raises(ValueError):
            store.save_artifacts("noslash", CollectedArtifacts())

    def test_load_validates_slug(self, store: RepoAuditStore) -> None:
        with pytest.raises(ValueError):
            store.load_artifacts("noslash")


# ---------------------------------------------------------------------------
# RepoAuditStore — analysis round-trip
# ---------------------------------------------------------------------------


class TestRepoAuditStoreAnalysis:
    """Tests for save_analysis / load_analysis round-trip."""

    @pytest.fixture()
    def store_dir(self, tmp_path: Path) -> Path:
        bead_dir = tmp_path / "beads"
        (bead_dir / "owner" / "repo").mkdir(parents=True)
        return bead_dir

    @pytest.fixture()
    def store(self, store_dir: Path) -> RepoAuditStore:
        return RepoAuditStore(beads_dir=store_dir)

    def test_load_returns_none_when_missing(self, store: RepoAuditStore) -> None:
        assert store.load_analysis("owner/repo") is None

    def test_save_creates_analysis_json(self, store: RepoAuditStore, store_dir: Path) -> None:
        result = AnalysisResult(import_graph={"a": ["b"]}, reachable_from_entry_points=["a"])
        store.save_analysis("owner/repo", result)
        assert (store_dir / "owner" / "repo" / "analysis.json").exists()

    def test_round_trip_basic(self, store: RepoAuditStore) -> None:
        original = AnalysisResult(
            import_graph={"pkg.a": ["os"], "pkg.b": ["sys"]},
            reachable_from_entry_points=["os", "pkg.a", "pkg.b", "sys"],
        )
        store.save_analysis("owner/repo", original)
        loaded = store.load_analysis("owner/repo")
        assert loaded is not None
        assert loaded.import_graph == {"pkg.a": ["os"], "pkg.b": ["sys"]}
        assert loaded.reachable_from_entry_points == ["os", "pkg.a", "pkg.b", "sys"]

    def test_round_trip_empty_result(self, store: RepoAuditStore) -> None:
        original = AnalysisResult()
        store.save_analysis("owner/repo", original)
        loaded = store.load_analysis("owner/repo")
        assert loaded is not None
        assert loaded.import_graph == {}
        assert loaded.reachable_from_entry_points == []

    def test_save_validates_slug(self, store: RepoAuditStore) -> None:
        with pytest.raises(ValueError):
            store.save_analysis("noslash", AnalysisResult())

    def test_load_validates_slug(self, store: RepoAuditStore) -> None:
        with pytest.raises(ValueError):
            store.load_analysis("noslash")

    def test_separate_slugs_do_not_collide(self, tmp_path: Path) -> None:
        """Different slugs write to different paths."""
        bead_dir = tmp_path / "beads"
        (bead_dir / "owner" / "repo1").mkdir(parents=True)
        (bead_dir / "owner" / "repo2").mkdir(parents=True)
        store = RepoAuditStore(beads_dir=bead_dir)

        r1 = AnalysisResult(reachable_from_entry_points=["mod1"])
        r2 = AnalysisResult(reachable_from_entry_points=["mod2"])
        store.save_analysis("owner/repo1", r1)
        store.save_analysis("owner/repo2", r2)

        loaded1 = store.load_analysis("owner/repo1")
        loaded2 = store.load_analysis("owner/repo2")
        assert loaded1 is not None
        assert loaded2 is not None
        assert loaded1.reachable_from_entry_points == ["mod1"]
        assert loaded2.reachable_from_entry_points == ["mod2"]
