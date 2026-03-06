"""Tests for repo_audit.specgen.dedup.

Covers load_covered_finding_ids (scanning spec files for covered ids) and
filter_new_clusters (removing already-covered clusters from the work queue).
"""

from __future__ import annotations

from pathlib import Path

from repo_audit.specgen.dedup import filter_new_clusters, load_covered_finding_ids
from repo_audit.verdict.finding_bead import FindingBead


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(id: str) -> FindingBead:
    """Build a minimal FindingBead."""
    return FindingBead(
        id=id,
        agent="test-agent",
        severity="low",  # type: ignore[arg-type]
        staleness_class="structural",  # type: ignore[arg-type]
        confidence=0.5,
        summary=f"Finding {id}",
    )


def _write_spec(out_dir: Path, filename: str, finding_ids: list[str]) -> None:
    """Write a minimal spec file with the given finding ids in source_findings."""
    ids_block = "\n".join(f"  - {fid}" for fid in finding_ids)
    content = (
        "---\n"
        f"source_findings:\n{ids_block}\n"
        "blast_radius: []\n"
        "priority: P3\n"
        "depends_on: []\n"
        "---\n\n"
        "## Overview\n\nsome text\n"
    )
    (out_dir / filename).write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# load_covered_finding_ids — directory states
# ---------------------------------------------------------------------------


class TestLoadCoveredFindingIdsDirectory:
    """load_covered_finding_ids with various directory states."""

    def test_nonexistent_directory_returns_empty_set(self, tmp_path: Path) -> None:
        """A directory that does not exist yields an empty covered set."""
        result = load_covered_finding_ids(tmp_path / "does_not_exist")
        assert result == set()

    def test_empty_directory_returns_empty_set(self, tmp_path: Path) -> None:
        """An existing but empty directory yields an empty covered set."""
        result = load_covered_finding_ids(tmp_path)
        assert result == set()

    def test_directory_with_no_md_files_returns_empty_set(self, tmp_path: Path) -> None:
        """Non-.md files in the directory are ignored."""
        (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")
        result = load_covered_finding_ids(tmp_path)
        assert result == set()


# ---------------------------------------------------------------------------
# load_covered_finding_ids — spec file parsing
# ---------------------------------------------------------------------------


class TestLoadCoveredFindingIdsParsing:
    """load_covered_finding_ids correctly extracts finding ids from spec files."""

    def test_single_spec_file_single_id(self, tmp_path: Path) -> None:
        _write_spec(tmp_path, "spec-cluster-000.md", ["abc123"])
        result = load_covered_finding_ids(tmp_path)
        assert result == {"abc123"}

    def test_single_spec_file_multiple_ids(self, tmp_path: Path) -> None:
        _write_spec(tmp_path, "spec-cluster-000.md", ["abc123", "def456", "ghi789"])
        result = load_covered_finding_ids(tmp_path)
        assert result == {"abc123", "def456", "ghi789"}

    def test_multiple_spec_files_ids_merged(self, tmp_path: Path) -> None:
        """IDs from all spec files are merged into one flat set."""
        _write_spec(tmp_path, "spec-cluster-000.md", ["aaa", "bbb"])
        _write_spec(tmp_path, "spec-cluster-001.md", ["ccc", "ddd"])
        result = load_covered_finding_ids(tmp_path)
        assert result == {"aaa", "bbb", "ccc", "ddd"}

    def test_duplicate_ids_across_files_deduplicated(self, tmp_path: Path) -> None:
        """The same id in two files appears only once in the result set."""
        _write_spec(tmp_path, "spec-cluster-000.md", ["shared_id"])
        _write_spec(tmp_path, "spec-cluster-001.md", ["shared_id", "unique_id"])
        result = load_covered_finding_ids(tmp_path)
        assert result == {"shared_id", "unique_id"}

    def test_file_without_front_matter_is_skipped(self, tmp_path: Path) -> None:
        """A .md file with no front-matter block does not raise and is skipped."""
        (tmp_path / "plain.md").write_text("# Just a heading\n\nNo YAML here.", encoding="utf-8")
        result = load_covered_finding_ids(tmp_path)
        assert result == set()

    def test_file_with_front_matter_but_no_source_findings_skipped(self, tmp_path: Path) -> None:
        """A file with front-matter that lacks source_findings is silently ignored."""
        content = "---\nblast_radius: []\npriority: P3\ndepends_on: []\n---\n\n## Overview\n"
        (tmp_path / "spec.md").write_text(content, encoding="utf-8")
        result = load_covered_finding_ids(tmp_path)
        assert result == set()

    def test_valid_and_malformed_files_mixed(self, tmp_path: Path) -> None:
        """Valid files still contribute their ids even when other files are malformed."""
        _write_spec(tmp_path, "spec-cluster-000.md", ["valid_id"])
        (tmp_path / "broken.md").write_text("not front matter at all", encoding="utf-8")
        result = load_covered_finding_ids(tmp_path)
        assert "valid_id" in result


# ---------------------------------------------------------------------------
# filter_new_clusters
# ---------------------------------------------------------------------------


class TestFilterNewClusters:
    """filter_new_clusters removes covered clusters and preserves uncovered ones."""

    def test_empty_covered_ids_returns_all_clusters(self) -> None:
        """When covered_ids is empty every cluster is returned unchanged."""
        clusters = [[_make_finding("aaa")], [_make_finding("bbb")]]
        result = filter_new_clusters(clusters, set())
        assert result == clusters

    def test_empty_clusters_returns_empty_list(self) -> None:
        """Empty cluster list always yields an empty result."""
        result = filter_new_clusters([], {"some_id"})
        assert result == []

    def test_cluster_with_covered_finding_is_removed(self) -> None:
        """A cluster whose finding id is in covered_ids is dropped."""
        covered = [_make_finding("covered_id")]
        uncovered = [_make_finding("new_id")]
        result = filter_new_clusters([covered, uncovered], {"covered_id"})
        assert len(result) == 1
        assert result[0][0].id == "new_id"

    def test_cluster_with_all_covered_findings_is_removed(self) -> None:
        """A cluster where every finding is covered is dropped."""
        cluster = [_make_finding("aaa"), _make_finding("bbb")]
        result = filter_new_clusters([cluster], {"aaa", "bbb"})
        assert result == []

    def test_cluster_with_partial_overlap_is_removed(self) -> None:
        """A cluster with even one covered finding is dropped (non-empty intersection)."""
        cluster = [_make_finding("old"), _make_finding("new")]
        result = filter_new_clusters([cluster], {"old"})
        assert result == []

    def test_cluster_with_no_covered_findings_is_kept(self) -> None:
        """A cluster with no overlap with covered_ids is kept."""
        cluster = [_make_finding("fresh_a"), _make_finding("fresh_b")]
        result = filter_new_clusters([cluster], {"unrelated_id"})
        assert len(result) == 1
        assert result[0] is cluster

    def test_all_clusters_covered_returns_empty(self) -> None:
        """When every cluster is covered the result is an empty list."""
        clusters = [
            [_make_finding("a1"), _make_finding("a2")],
            [_make_finding("b1")],
        ]
        covered = {"a1", "b1"}
        result = filter_new_clusters(clusters, covered)
        assert result == []

    def test_original_order_preserved(self) -> None:
        """Surviving clusters appear in the same order as the input."""
        c0 = [_make_finding("keep0")]
        c1 = [_make_finding("drop1")]
        c2 = [_make_finding("keep2")]
        c3 = [_make_finding("keep3")]
        result = filter_new_clusters([c0, c1, c2, c3], {"drop1"})
        ids = [c[0].id for c in result]
        assert ids == ["keep0", "keep2", "keep3"]

    def test_input_clusters_list_not_mutated(self) -> None:
        """filter_new_clusters returns a new list; the original is unchanged."""
        clusters = [[_make_finding("aaa")], [_make_finding("bbb")]]
        original_length = len(clusters)
        filter_new_clusters(clusters, {"aaa"})
        assert len(clusters) == original_length

    def test_returns_list_not_generator(self) -> None:
        """Return value is a list, not a lazy generator."""
        result = filter_new_clusters([[_make_finding("x")]], set())
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Round-trip: formatter output feeds load_covered_finding_ids
# ---------------------------------------------------------------------------


class TestDedupRoundTrip:
    """load_covered_finding_ids correctly reads files written by format_spec."""

    def test_format_spec_output_is_parseable_by_load_covered(self, tmp_path: Path) -> None:
        """A file written by format_spec is correctly parsed by load_covered_finding_ids."""
        from repo_audit.specgen.formatter import format_spec

        finding = FindingBead(
            id="roundtrip_id",
            agent="test-agent",
            severity="medium",  # type: ignore[arg-type]
            staleness_class="structural",  # type: ignore[arg-type]
            confidence=0.5,
            summary="A finding for round-trip test",
        )
        filename, content = format_spec([finding], 0)
        (tmp_path / filename).write_text(content, encoding="utf-8")

        covered = load_covered_finding_ids(tmp_path)
        assert "roundtrip_id" in covered

    def test_format_spec_multi_finding_cluster_all_ids_parseable(self, tmp_path: Path) -> None:
        """All finding ids in a multi-finding cluster are recoverable after writing."""
        from repo_audit.specgen.formatter import format_spec

        findings = [
            FindingBead(
                id=f"id_{i}",
                agent="test-agent",
                severity="low",  # type: ignore[arg-type]
                staleness_class="structural",  # type: ignore[arg-type]
                confidence=0.5,
                summary=f"Finding {i}",
            )
            for i in range(3)
        ]
        filename, content = format_spec(findings, 0)
        (tmp_path / filename).write_text(content, encoding="utf-8")

        covered = load_covered_finding_ids(tmp_path)
        assert covered == {"id_0", "id_1", "id_2"}
