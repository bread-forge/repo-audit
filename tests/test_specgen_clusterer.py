"""Tests for repo_audit.specgen.clusterer.

Covers module-overlap grouping, max-size splitting, deterministic ordering,
and edge cases (empty input, no blast radius, singletons, transitive joins).
"""

from __future__ import annotations

from unittest.mock import MagicMock

from repo_audit.specgen.clusterer import MAX_CLUSTER_SIZE, cluster_findings
from repo_audit.verdict.finding_bead import FindingBead


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
        blast_radius = MagicMock()
        blast_radius.modules_affected = modules
        finding.blast_radius = blast_radius  # type: ignore[attr-defined]
    return finding


# ---------------------------------------------------------------------------
# Empty input
# ---------------------------------------------------------------------------


class TestClusterFindingsEmpty:
    """cluster_findings with an empty input list."""

    def test_empty_input_returns_empty_list(self) -> None:
        """Empty findings list produces an empty cluster list."""
        result = cluster_findings([])
        assert result == []


# ---------------------------------------------------------------------------
# Module-overlap grouping
# ---------------------------------------------------------------------------


class TestClusterFindingsModuleOverlap:
    """Grouping based on shared modules in blast_radius."""

    def test_shared_module_groups_two_findings(self) -> None:
        """Two findings sharing a module end up in the same cluster."""
        a = _make_finding("aaa", modules=["auth", "db"])
        b = _make_finding("bbb", modules=["db", "cache"])
        result = cluster_findings([a, b])
        assert len(result) == 1
        assert {f.id for f in result[0]} == {"aaa", "bbb"}

    def test_disjoint_modules_produce_separate_clusters(self) -> None:
        """Findings with no shared modules remain in separate clusters."""
        a = _make_finding("aaa", modules=["auth"])
        b = _make_finding("bbb", modules=["cache"])
        result = cluster_findings([a, b])
        assert len(result) == 2

    def test_transitive_grouping_via_shared_module(self) -> None:
        """A->B and B->C via module overlap pulls all three into one cluster."""
        a = _make_finding("aaa", modules=["auth"])
        b = _make_finding("bbb", modules=["auth", "db"])
        c = _make_finding("ccc", modules=["db"])
        result = cluster_findings([a, b, c])
        assert len(result) == 1
        assert {f.id for f in result[0]} == {"aaa", "bbb", "ccc"}

    def test_no_blast_radius_findings_each_in_own_cluster(self) -> None:
        """Findings with no blast_radius have no module overlap; each is isolated."""
        a = _make_finding("aaa")  # no modules
        b = _make_finding("bbb")  # no modules
        result = cluster_findings([a, b])
        assert len(result) == 2
        cluster_ids = {result[0][0].id, result[1][0].id}
        assert cluster_ids == {"aaa", "bbb"}

    def test_empty_modules_list_does_not_connect_findings(self) -> None:
        """blast_radius with an empty modules_affected list counts as no overlap."""
        a = _make_finding("aaa", modules=[])
        b = _make_finding("bbb", modules=[])
        result = cluster_findings([a, b])
        assert len(result) == 2

    def test_single_finding_produces_one_singleton_cluster(self) -> None:
        """A single finding yields exactly one cluster of size one."""
        a = _make_finding("aaa", modules=["auth"])
        result = cluster_findings([a])
        assert len(result) == 1
        assert result[0][0].id == "aaa"

    def test_three_independent_findings_three_clusters(self) -> None:
        """Three findings with fully disjoint modules each form their own cluster."""
        a = _make_finding("aaa", modules=["auth"])
        b = _make_finding("bbb", modules=["db"])
        c = _make_finding("ccc", modules=["cache"])
        result = cluster_findings([a, b, c])
        assert len(result) == 3

    def test_mixed_connected_and_isolated_findings(self) -> None:
        """Some findings share modules; others are isolated."""
        a = _make_finding("aaa", modules=["auth"])
        b = _make_finding("bbb", modules=["auth"])  # connects to a
        c = _make_finding("ccc", modules=["cache"])  # isolated
        result = cluster_findings([a, b, c])
        assert len(result) == 2
        sizes = sorted(len(c) for c in result)
        assert sizes == [1, 2]


# ---------------------------------------------------------------------------
# Max-size splitting
# ---------------------------------------------------------------------------


class TestClusterFindingsMaxSizeSplitting:
    """Splitting components that exceed MAX_CLUSTER_SIZE."""

    def test_component_of_max_plus_one_is_split_into_two(self) -> None:
        """MAX_CLUSTER_SIZE+1 findings in one component produce two sub-groups."""
        findings = [
            _make_finding(f"{i:04d}", modules=["shared"]) for i in range(MAX_CLUSTER_SIZE + 1)
        ]
        result = cluster_findings(findings)
        assert len(result) == 2
        assert len(result[0]) == MAX_CLUSTER_SIZE
        assert len(result[1]) == 1

    def test_component_of_exactly_max_size_not_split(self) -> None:
        """Exactly MAX_CLUSTER_SIZE findings in one component stay as one cluster."""
        findings = [_make_finding(f"{i:04d}", modules=["shared"]) for i in range(MAX_CLUSTER_SIZE)]
        result = cluster_findings(findings)
        assert len(result) == 1
        assert len(result[0]) == MAX_CLUSTER_SIZE

    def test_large_component_all_sub_groups_at_most_max_size(self) -> None:
        """All sub-groups after splitting never exceed MAX_CLUSTER_SIZE."""
        n = MAX_CLUSTER_SIZE * 3 + 2
        findings = [_make_finding(f"{i:04d}", modules=["shared"]) for i in range(n)]
        result = cluster_findings(findings)
        for cluster in result:
            assert len(cluster) <= MAX_CLUSTER_SIZE

    def test_large_component_total_count_preserved(self) -> None:
        """Splitting preserves the total number of findings across sub-groups."""
        n = MAX_CLUSTER_SIZE * 2 + 3
        findings = [_make_finding(f"{i:04d}", modules=["shared"]) for i in range(n)]
        result = cluster_findings(findings)
        total = sum(len(c) for c in result)
        assert total == n


# ---------------------------------------------------------------------------
# Deterministic ordering
# ---------------------------------------------------------------------------


class TestClusterFindingsDeterministicOrdering:
    """Output is fully deterministic regardless of input ordering."""

    def test_clusters_sorted_by_minimum_finding_id(self) -> None:
        """Clusters appear in ascending order of the minimum finding id they contain."""
        a = _make_finding("aaa", modules=["auth"])
        b = _make_finding("bbb", modules=["db"])
        # Pass in reverse order; expect 'aaa' cluster first.
        result = cluster_findings([b, a])
        assert result[0][0].id == "aaa"
        assert result[1][0].id == "bbb"

    def test_members_within_cluster_sorted_by_id(self) -> None:
        """Findings within a cluster appear in ascending finding-id order."""
        a = _make_finding("zzz", modules=["shared"])
        b = _make_finding("aaa", modules=["shared"])
        c = _make_finding("mmm", modules=["shared"])
        result = cluster_findings([a, b, c])
        assert len(result) == 1
        ids = [f.id for f in result[0]]
        assert ids == sorted(ids)

    def test_same_input_produces_same_output_twice(self) -> None:
        """Calling cluster_findings twice with the same list returns equal results."""
        findings = [
            _make_finding("ccc", modules=["auth", "db"]),
            _make_finding("aaa", modules=["db"]),
            _make_finding("bbb", modules=["cache"]),
        ]
        result1 = cluster_findings(findings)
        result2 = cluster_findings(findings)
        ids1 = [[f.id for f in c] for c in result1]
        ids2 = [[f.id for f in c] for c in result2]
        assert ids1 == ids2

    def test_split_sub_groups_ordered_by_first_member_id(self) -> None:
        """After splitting, sub-groups themselves are ordered by their first member id."""
        # ids starting with '0' come before '9'
        findings = [
            _make_finding(f"{i:04d}", modules=["shared"]) for i in range(MAX_CLUSTER_SIZE + 1)
        ]
        result = cluster_findings(findings)
        # The first cluster's first id must be <= the second cluster's first id.
        assert result[0][0].id <= result[1][0].id
